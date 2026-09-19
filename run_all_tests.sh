#!/bin/bash
set -u
cd /Users/wind/git/github/rdiff-backup
export PATH="/Users/wind/git/github/rdiff-backup/.venv/bin:$PATH"
SCRATCH=/private/tmp/claude-501/-Users-wind-git-github-rdiff-backup/0212dcdb-5f54-4ae8-988b-9ce8c15e7261/scratchpad
> "$SCRATCH/results.txt"
> "$SCRATCH/results_full.txt"
while read -r t; do
  name=$(basename "$t" .py)
  out=$(PYTHONPATH=testing .venv/bin/python -m unittest "$name" 2>&1)
  status=$(echo "$out" | tail -1)
  echo "=== $name : $status ===" >> "$SCRATCH/results.txt"
  echo "$out" >> "$SCRATCH/results_full.txt"
done < "$SCRATCH/testlist.txt"
echo DONE >> "$SCRATCH/results.txt"
