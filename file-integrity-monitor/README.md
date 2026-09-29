# File Integrity Monitor

This project checks if files inside a folder changed.

It makes a baseline using SHA-256 hashes. Later, you can run it again and it will tell you if a file was added, changed, or deleted.

## Make a baseline

```bash
python monitor.py init ./test-folder
```

That creates `baseline.json`.

## Check for changes

```bash
python monitor.py check ./test-folder
```

Example:

```text
Added:
  + notes.txt

Modified:
  * config.ini

Deleted:
  - old.txt
```

You can also choose where the baseline file is saved:

```bash
python monitor.py init ./test-folder --baseline my-baseline.json
```

This is a small learning version of the same basic idea used by file integrity monitoring tools.
