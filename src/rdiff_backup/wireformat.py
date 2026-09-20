# Copyright 2025 The rdiff-backup project
#
# This file is part of rdiff-backup.
#
# rdiff-backup is free software; you can redistribute it and/or modify
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# rdiff-backup is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with rdiff-backup; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
"""
Safe replacement for pickle on the client/server connection.

The connection pipe carries attacker-reachable bytes whenever a
lower-privileged or unauthenticated process can write to it (see CWE-502).
pickle.loads() lets such bytes choose an arbitrary callable to invoke via
its REDUCE opcode. msgpack's decoder has no such opcode: it only ever
produces plain scalars/containers, plus whatever a *registered* ext-type
decoder below returns. Reconstructing a project exception is always a
plain dict lookup by a fixed registry key -- never getattr()/import by an
attacker-supplied string -- so a name that isn't registered can never
reach any callable.

Modules that define an exception which legitimately crosses the
connection must call register_exception() once, right after the class
definition.
"""

import re
import typing

import msgpack

_ExcT = typing.TypeVar("_ExcT", bound=type)

# ext-type codes used on the wire; part of the wire protocol, do not reuse.
EXT_TUPLE = 1
EXT_REQUEST = 2
EXT_EXCEPTION = 3
EXT_MARKER = 4
EXT_EXTRA = 5
EXT_OBJECT = 6
EXT_SET = 7
EXT_REGEX = 8

# name -> class, populated by register_exception(). Decode only ever does
# a lookup in this dict; it never imports or resolves a class by name.
_EXCEPTION_REGISTRY = {}

# name -> class, populated by register_marker(). Used for sentinel classes
# that are sent by identity (the class itself, not an instance), such as
# iterfile.py's MiscIterFlush/MiscIterFlushRepeat. Decode is a dict lookup,
# same safety property as _EXCEPTION_REGISTRY.
_MARKER_REGISTRY = {}

# name -> class, populated by register_object(). For plain-data classes (not
# exceptions) that cross the connection as return values of remote calls,
# e.g. fs_abilities.FSAbilities. Same closed-registry safety property as
# _EXCEPTION_REGISTRY: decode only ever does a dict lookup by a fixed key,
# never getattr()/import by an attacker-supplied string.
_OBJECT_REGISTRY = {}
_OBJECT_KEY_BY_TYPE = {}


class WireFormatError(Exception):
    """Raised when data on the pipe can't be safely decoded"""

    pass


class RemoteError(Exception):
    """
    Fallback for a remote exception whose type isn't in the registry

    Keeps the connection alive without ever reconstructing (and calling
    the constructor of) an exception class we haven't explicitly vetted.
    """

    def __init__(self, remote_type_name, message):
        super().__init__(message)
        self.remote_type_name = remote_type_name

    def __str__(self):
        return "{rtn}: {msg}".format(rtn=self.remote_type_name, msg=super().__str__())


def register_exception(cls: _ExcT) -> _ExcT:
    """
    Register an exception class as safe to reconstruct from the wire

    Must be called exactly once, immediately after the class definition,
    by the module that defines it. Returns cls unchanged so it can be
    used as a decorator.
    """
    key = "{mod}.{name}".format(mod=cls.__module__, name=cls.__qualname__)
    _EXCEPTION_REGISTRY[key] = cls
    return cls


def register_marker(cls: _ExcT) -> _ExcT:
    """
    Register a sentinel class as safe to send/reconstruct by identity

    Must be called exactly once, immediately after the class definition,
    by the module that defines it. Returns cls unchanged so it can be
    used as a decorator.
    """
    key = "{mod}.{name}".format(mod=cls.__module__, name=cls.__qualname__)
    _MARKER_REGISTRY[key] = cls
    return cls


def register_object(cls: _ExcT) -> _ExcT:
    """
    Register a plain-data class as safe to reconstruct from the wire

    Unlike register_exception(), reconstruction never calls cls's own
    __init__ (its signature isn't part of the wire contract): decode does
    cls.__new__(cls) and then repopulates __dict__ from the wire-supplied
    values, the same thing pickle's default __reduce_ex__ does for a plain
    object. Every attribute value is itself recursively encoded/decoded, so
    nested containers, exceptions, rpaths etc. all survive -- unlike the
    exception registry's extra-attributes handling, which only keeps
    primitives.

    Must be called exactly once, immediately after the class definition, by
    the module that defines it. Returns cls unchanged so it can be used as
    a decorator.
    """
    key = "{mod}.{name}".format(mod=cls.__module__, name=cls.__qualname__)
    _OBJECT_REGISTRY[key] = cls
    _OBJECT_KEY_BY_TYPE[cls] = key
    return cls


class ConnectionRequest:
    """
    Placeholder used only during encode/decode of the real ConnectionRequest

    connection.py owns the actual ConnectionRequest class; this module
    can't import it (connection.py imports wireformat, not the reverse).
    The ext-type encoder/decoder below are told about the real class via
    set_request_class().
    """

    pass


_request_class = None


def set_request_class(cls):
    """Tell wireformat which class to use for the EXT_REQUEST ext type"""
    global _request_class
    _request_class = cls


# encode_fn(obj) -> plain-data payload, or None if obj isn't one of the
# extra types it handles. decode_fn(payload) -> the reconstructed obj.
# Lets connection.py teach this module about types it can't import
# directly (rpath.RPath and friends need a live connection to
# reconstruct, e.g. specifics.connection_dict), so they still round-trip
# correctly when nested inside a tuple/list/dict rather than only when
# sent as the top-level object.
_extra_encode_hook = None
_extra_decode_hook = None


def set_extra_hooks(encode_fn, decode_fn):
    """Register encode/decode callbacks for types wireformat can't import"""
    global _extra_encode_hook, _extra_decode_hook
    _extra_encode_hook = encode_fn
    _extra_decode_hook = decode_fn


def _encode(obj):
    """Recursively rewrite obj so every remaining container is a plain
    list/dict/scalar that msgpack can pack natively; anything that needs
    to survive with its original Python type (tuple, ConnectionRequest,
    exceptions) becomes an ExtType wrapping its own re-encoded payload."""
    if isinstance(obj, tuple):
        return msgpack.ExtType(EXT_TUPLE, packb(list(obj)))
    elif isinstance(obj, (set, frozenset)):
        return msgpack.ExtType(EXT_SET, packb(list(obj)))
    elif isinstance(obj, re.Pattern):
        # re.compile() on a wire-supplied pattern/flags is no different a
        # risk than re.compile() on any other user-supplied selection
        # string rdiff-backup already compiles today; no new attack surface.
        return msgpack.ExtType(EXT_REGEX, packb((obj.pattern, obj.flags)))
    elif isinstance(obj, list):
        return [_encode(item) for item in obj]
    elif isinstance(obj, dict):
        # note: a dict keyed by a list would break here (_encode(k) returns
        # an unhashable list); no wire payload does this today.
        return {_encode(k): _encode(v) for k, v in obj.items()}
    elif _request_class is not None and isinstance(obj, _request_class):
        return msgpack.ExtType(EXT_REQUEST, packb((obj.function_string, obj.num_args)))
    elif isinstance(obj, BaseException):
        key = "{mod}.{name}".format(
            mod=type(obj).__module__, name=type(obj).__qualname__
        )
        # reconstruction always goes through the registry, never through
        # an attacker-chosen class name.
        #
        # Only .args and "plain-data" extra attributes (str/int/float/bool/
        # None) cross the wire. Any other attribute type -- an rpath, a
        # list, a custom object -- is silently dropped, with no error. This
        # is safe for now because every registered project exception is a
        # bodyless `pass` with no extra attributes to lose. It stops being
        # safe the day someone adds an exception that sets one, e.g.
        # `self.path = some_rpath`: that attribute will just vanish on the
        # receiving end.  Something to consider...
        extra = {
            k: v
            for k, v in vars(obj).items()
            if k != "args" and isinstance(v, (str, int, float, bool, type(None)))
        }
        payload = (key, type(obj).__name__, obj.args, extra, str(obj))
        return msgpack.ExtType(EXT_EXCEPTION, packb(payload))
    elif isinstance(obj, type):
        key = "{mod}.{name}".format(mod=obj.__module__, name=obj.__qualname__)
        if key not in _MARKER_REGISTRY:
            raise WireFormatError(
                "Class {key} isn't registered as a marker".format(key=key)
            )
        return msgpack.ExtType(EXT_MARKER, packb(key))
    elif type(obj) in _OBJECT_KEY_BY_TYPE:
        key = _OBJECT_KEY_BY_TYPE[type(obj)]
        payload = (key, vars(obj))
        return msgpack.ExtType(EXT_OBJECT, packb(payload))
    else:
        if _extra_encode_hook is not None:
            payload = _extra_encode_hook(obj)
            if payload is not None:
                return msgpack.ExtType(EXT_EXTRA, packb(payload))
        return obj


def _ext_hook(code, data):
    if code == EXT_TUPLE:
        return tuple(unpackb(data))
    elif code == EXT_SET:
        return set(unpackb(data))
    elif code == EXT_REGEX:
        pattern, flags = unpackb(data)
        return re.compile(pattern, flags)
    elif code == EXT_REQUEST:
        if _request_class is None:
            raise WireFormatError("Received a request but none is registered")
        function_string, num_args = unpackb(data)
        return _request_class(function_string, num_args)
    elif code == EXT_EXCEPTION:
        key, type_name, args, extra, message = unpackb(data)
        cls = _EXCEPTION_REGISTRY.get(key)
        if cls is None:
            return RemoteError(type_name, message)
        instance = cls(*args)
        for attr_name, attr_value in extra.items():
            setattr(instance, attr_name, attr_value)
        return instance
    elif code == EXT_MARKER:
        key = unpackb(data)
        cls = _MARKER_REGISTRY.get(key)
        if cls is None:
            raise WireFormatError(
                "Received unregistered marker class {key}".format(key=key)
            )
        return cls
    elif code == EXT_EXTRA:
        if _extra_decode_hook is None:
            raise WireFormatError(
                "Received extra-type data but no decoder is registered"
            )
        return _extra_decode_hook(unpackb(data))
    elif code == EXT_OBJECT:
        key, state = unpackb(data)
        cls = _OBJECT_REGISTRY.get(key)
        if cls is None:
            raise WireFormatError(
                "Received unregistered object class {key}".format(key=key)
            )
        instance = cls.__new__(cls)
        instance.__dict__.update(state)
        return instance
    else:
        raise WireFormatError("Unknown wire ext type code {code}".format(code=code))


def packb(obj):
    """Serialize obj to bytes for the connection pipe"""
    return msgpack.packb(_encode(obj), use_bin_type=True)


def unpackb(buf):
    """Deserialize bytes read off the connection pipe back into obj"""
    try:
        return msgpack.unpackb(buf, raw=False, ext_hook=_ext_hook, strict_map_key=False)
    except WireFormatError:
        # raised by _ext_hook itself (e.g. unregistered marker); already
        # the right shape, don't re-wrap it.
        raise
    except Exception as exc:
        # anything else from msgpack's parser or from _ext_hook (e.g. a
        # registered exception class rejecting the wire-supplied args) --
        # always fails closed as WireFormatError, never propagates a raw
        # unexpected exception type to callers.
        raise WireFormatError(
            "Data on the connection couldn't be decoded: {exc}".format(exc=exc)
        )


# register the stdlib exceptions that are actually raised and expected to
# cross the connection today (see connection.py's reval()/_extract_exception
# and the request handlers in _repo_shadow.py, fs_abilities.py, etc.)
for _cls in (
    OSError,
    # OSError.__new__ auto-dispatches to one of these based on errno (PEP
    # 3151), so any of them can show up on the wire even if never raised
    # directly by name in this codebase.
    BlockingIOError,
    ChildProcessError,
    ConnectionError,
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    ConnectionResetError,
    FileExistsError,
    FileNotFoundError,
    InterruptedError,
    IsADirectoryError,
    NotADirectoryError,
    PermissionError,
    ProcessLookupError,
    TimeoutError,
    ValueError,
    TypeError,
    KeyError,
    NameError,
    AttributeError,
    RuntimeError,
    NotImplementedError,
    StopIteration,
    MemoryError,
    IndexError,
    Exception,
    BaseException,
    SystemExit,
    KeyboardInterrupt,
):
    register_exception(_cls)
del _cls
