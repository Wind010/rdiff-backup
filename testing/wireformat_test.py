"""
Test src/rdiff_backup/wireformat.py in isolation, without a live connection
"""

import re
import unittest

import msgpack

from rdiff_backup import (
    connection,
    wireformat,
)  # noqa: F401 (registers ConnectionRequest)


class RoundTripTest(unittest.TestCase):
    """Plain scalars/containers round-trip through packb/unpackb unchanged"""

    def testScalars(self):
        for obj in (None, True, False, 0, -5, 3.5, "hello", b"raw\xffbytes"):
            self.assertEqual(wireformat.unpackb(wireformat.packb(obj)), obj)

    def testList(self):
        self.assertEqual(
            wireformat.unpackb(wireformat.packb([1, "a", None])), [1, "a", None]
        )

    def testDict(self):
        obj = {"a": 1, "b": [1, 2, {"c": 3}]}
        self.assertEqual(wireformat.unpackb(wireformat.packb(obj)), obj)

    def testTuple(self):
        """Tuples must come back as tuples, not lists, and nest correctly"""
        obj = (1, "two", (3, 4), [5, 6])
        result = wireformat.unpackb(wireformat.packb(obj))
        self.assertEqual(result, obj)
        self.assertIsInstance(result, tuple)
        self.assertIsInstance(result[2], tuple)
        self.assertIsInstance(result[3], list)

    def testSet(self):
        obj = {1, "two", 3.0}
        result = wireformat.unpackb(wireformat.packb(obj))
        self.assertEqual(result, obj)
        self.assertIsInstance(result, set)

    def testFrozensetComesBackAsSet(self):
        """msgpack has no set/frozenset distinction on the wire"""
        result = wireformat.unpackb(wireformat.packb(frozenset({1, 2})))
        self.assertEqual(result, {1, 2})
        self.assertIsInstance(result, set)

    def testNestedSet(self):
        obj = {"a": [1, {2, 3}]}
        self.assertEqual(wireformat.unpackb(wireformat.packb(obj)), obj)

    def testRegexPattern(self):
        pattern = re.compile(r"foo.*bar", re.I | re.S)
        result = wireformat.unpackb(wireformat.packb(pattern))
        self.assertIsInstance(result, re.Pattern)
        self.assertEqual(result.pattern, pattern.pattern)
        self.assertEqual(result.flags, pattern.flags)
        self.assertTrue(result.match("FOO\nbar"))

    def testBytesRegexPattern(self):
        pattern = re.compile(b"a+b")
        result = wireformat.unpackb(wireformat.packb(pattern))
        self.assertEqual(result.pattern, b"a+b")
        self.assertTrue(result.match(b"aaab"))


class ConnectionRequestTest(unittest.TestCase):
    """EXT_REQUEST round-trips to the real ConnectionRequest class"""

    def testRoundTrip(self):
        request = connection.ConnectionRequest("pow", 2)
        result = wireformat.unpackb(wireformat.packb(request))
        self.assertIsInstance(result, connection.ConnectionRequest)
        self.assertEqual(result.function_string, "pow")
        self.assertEqual(result.num_args, 2)


class ExceptionTest(unittest.TestCase):
    """EXT_EXCEPTION: registry-gated reconstruction, safe fallback otherwise"""

    def testRegisteredRoundTrip(self):
        exc = ValueError("bad value")
        result = wireformat.unpackb(wireformat.packb(exc))
        self.assertIsInstance(result, ValueError)
        self.assertEqual(result.args, ("bad value",))

    def testPlainDataExtraAttributesSurvive(self):
        exc = OSError(13, "Permission denied")
        exc.errno_str = "EACCES"
        result = wireformat.unpackb(wireformat.packb(exc))
        self.assertIsInstance(result, PermissionError)  # PEP 3151 dispatch
        self.assertEqual(result.errno_str, "EACCES")

    def testUnregisteredClassFallsBackToRemoteError(self):
        class NotRegistered(Exception):
            pass

        result = wireformat.unpackb(wireformat.packb(NotRegistered("oops")))
        self.assertIsInstance(result, wireformat.RemoteError)
        self.assertNotIsInstance(result, NotRegistered)
        self.assertIn("oops", str(result))

    def testUnregisteredClassNeverCallsConstructor(self):
        """The class name on the wire must never resolve to a live callable"""
        calls = []

        class Suspicious(Exception):
            def __init__(self, *args):
                calls.append(args)
                super().__init__(*args)

        packed = wireformat.packb(Suspicious("payload"))
        calls.clear()  # constructing the local instance above also appended
        wireformat.unpackb(packed)
        self.assertEqual(calls, [], "unregistered class must never be constructed")

    def testRegisteredClassRejectingArgsFailsClosed(self):
        """A registered class ctor raising on bad wire data must surface as
        WireFormatError, not an arbitrary/uncaught exception type"""

        class _StrictCtor(Exception):
            def __init__(self, only_one_allowed):
                super().__init__(only_one_allowed)

        strict_key = "{mod}.{name}".format(
            mod=_StrictCtor.__module__, name=_StrictCtor.__qualname__
        )
        wireformat._EXCEPTION_REGISTRY[strict_key] = _StrictCtor
        try:
            # build the EXT_EXCEPTION payload by hand: wireformat.packb()
            # alone would just wrap this plain tuple as EXT_TUPLE, not
            # dispatch through the EXT_EXCEPTION ext_hook branch.
            payload = (strict_key, "_StrictCtor", ("too", "many", "args"), {}, "msg")
            raw = msgpack.packb(
                msgpack.ExtType(wireformat.EXT_EXCEPTION, wireformat.packb(payload)),
                use_bin_type=True,
            )
            with self.assertRaises(wireformat.WireFormatError):
                wireformat.unpackb(raw)
        finally:
            del wireformat._EXCEPTION_REGISTRY[strict_key]


class ObjectRegistryTest(unittest.TestCase):
    """EXT_OBJECT: registry-gated reconstruction of plain-data classes"""

    class _Widget:
        def __init__(self, name, count):
            self.name = name
            self.count = count

    def setUp(self):
        wireformat.register_object(self._Widget)

    def tearDown(self):
        key = "{mod}.{name}".format(
            mod=self._Widget.__module__, name=self._Widget.__qualname__
        )
        del wireformat._OBJECT_REGISTRY[key]
        del wireformat._OBJECT_KEY_BY_TYPE[self._Widget]

    def testRegisteredRoundTrip(self):
        widget = self._Widget("bolt", 5)
        result = wireformat.unpackb(wireformat.packb(widget))
        self.assertIsInstance(result, self._Widget)
        self.assertEqual(result.name, "bolt")
        self.assertEqual(result.count, 5)

    def testConstructorNeverCalled(self):
        """Reconstruction must use __new__, never the class's own __init__"""
        calls = []

        class _Loud:
            def __init__(self, *args, **kwargs):
                calls.append((args, kwargs))

        wireformat.register_object(_Loud)
        try:
            instance = _Loud("hi")
            instance.extra = "value"
            calls.clear()  # constructing the instance above also appended
            result = wireformat.unpackb(wireformat.packb(instance))
            self.assertEqual(calls, [], "reconstruction must not call __init__")
            self.assertEqual(result.extra, "value")
        finally:
            key = "{mod}.{name}".format(mod=_Loud.__module__, name=_Loud.__qualname__)
            del wireformat._OBJECT_REGISTRY[key]
            del wireformat._OBJECT_KEY_BY_TYPE[_Loud]

    def testNestedAttributesRoundTrip(self):
        """Unlike the exception registry's extra attrs, any encodable value
        survives here, not just primitives"""
        widget = self._Widget("bolt", [1, {"a": 2}, (3, 4)])
        result = wireformat.unpackb(wireformat.packb(widget))
        self.assertEqual(result.count, [1, {"a": 2}, (3, 4)])

    def testUnregisteredClassRejectedOnEncode(self):
        class NotRegistered:
            pass

        with self.assertRaises(TypeError):
            wireformat.packb(NotRegistered())

    def testUnregisteredClassRejectedOnDecode(self):
        """A crafted payload naming an unregistered class must never resolve"""
        raw = msgpack.packb(
            msgpack.ExtType(
                wireformat.EXT_OBJECT, wireformat.packb(("builtins.object", {}))
            ),
            use_bin_type=True,
        )
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(raw)


class ExtraHooksTest(unittest.TestCase):
    """EXT_EXTRA: escape hatch for types wireformat can't import directly

    Exercises the mechanism connection.py uses for rpath.RPath and friends,
    without depending on rpath itself.
    """

    class _External:
        def __init__(self, tag):
            self.tag = tag

    def setUp(self):
        self._saved_hooks = (
            wireformat._extra_encode_hook,
            wireformat._extra_decode_hook,
        )

        def encode(obj):
            if isinstance(obj, self._External):
                return ("external", obj.tag)
            return None

        def decode(payload):
            kind, tag = payload
            assert kind == "external"
            return self._External(tag)

        wireformat.set_extra_hooks(encode, decode)

    def tearDown(self):
        wireformat.set_extra_hooks(*self._saved_hooks)

    def testRoundTrip(self):
        result = wireformat.unpackb(wireformat.packb(self._External("foo")))
        self.assertIsInstance(result, self._External)
        self.assertEqual(result.tag, "foo")

    def testNestedInContainer(self):
        """The bug this closes: a hook-handled type buried in a container"""
        obj = {"items": [self._External("a"), self._External("b")]}
        result = wireformat.unpackb(wireformat.packb(obj))
        self.assertEqual([item.tag for item in result["items"]], ["a", "b"])

    def testUnrecognizedObjectStillFails(self):
        """The hook returning None for a type it doesn't know must still
        fail closed, not silently pass the raw object to msgpack"""

        class _Unhandled:
            pass

        with self.assertRaises(TypeError):
            wireformat.packb(_Unhandled())

    def testNoHooksRegisteredRaisesOnDecode(self):
        raw = msgpack.packb(
            msgpack.ExtType(wireformat.EXT_EXTRA, wireformat.packb("x")),
            use_bin_type=True,
        )
        wireformat.set_extra_hooks(None, None)
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(raw)


class MarkerTest(unittest.TestCase):
    """EXT_MARKER: sentinel classes sent/received by identity"""

    def testRoundTripIdentity(self):
        from rdiff_backup import iterfile

        result = wireformat.unpackb(wireformat.packb(iterfile.MiscIterFlush))
        self.assertIs(result, iterfile.MiscIterFlush)

    def testUnregisteredClassRejectedOnEncode(self):
        class NotAMarker:
            pass

        with self.assertRaises(wireformat.WireFormatError):
            wireformat.packb(NotAMarker)

    def testUnregisteredClassRejectedOnDecode(self):
        """A crafted payload naming an unregistered class must never resolve"""
        bad_key = "builtins.object"
        raw = msgpack.packb(
            msgpack.ExtType(wireformat.EXT_MARKER, wireformat.packb(bad_key)),
            use_bin_type=True,
        )
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(raw)


class MalformedDataTest(unittest.TestCase):
    """Corrupt/truncated bytes must fail closed as WireFormatError"""

    def testTruncatedBuffer(self):
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(b"\x81")  # msgpack header for a 1-entry map, no body

    def testGarbageBuffer(self):
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(b"\xff\xff\xff")

    def testUnknownExtTypeCode(self):
        raw = msgpack.packb(
            msgpack.ExtType(99, b"whatever"),
            use_bin_type=True,
        )
        with self.assertRaises(wireformat.WireFormatError):
            wireformat.unpackb(raw)


if __name__ == "__main__":
    unittest.main()
