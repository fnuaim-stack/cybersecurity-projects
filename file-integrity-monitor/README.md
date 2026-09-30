# File Integrity Monitor

This tool creates a SHA-256 baseline for a folder and checks it later for changes.

The newer baseline also stores file size and timestamps, while still using the hash to decide whether file content actually changed.

## Create a baseline

```bash
python monitor.py init ./test-folder
```

## Check it later

```bash
python monitor.py check ./test-folder
```

## Ignore noisy files

Exclude patterns can be repeated:

```bash
python monitor.py init ./test-folder \
  --exclude "*.log" \
  --exclude "node_modules/*"
```

The saved baseline remembers its exclude patterns, so normal checks can reuse them.

## JSON output

```bash
python monitor.py check ./test-folder --json changes.json
```

The report includes added, modified, deleted files and hash/size details for modified files.

The Workbench wraps the same tool in the Integrity tab.
