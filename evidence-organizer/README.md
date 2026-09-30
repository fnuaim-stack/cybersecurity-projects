# Evidence Organizer

A local evidence folder/helper for authorized assessments.

I wanted a cleaner way to keep screenshots, PCAPs, exports, notes, and other proof together without manually making folders and losing track of which file belongs to which finding.

## Create a case

```bash
python evidence.py init ./lab-case \
  --name "Web Lab Assessment" \
  --scope "192.168.56.0/24 and app.example.test"
```

It creates:

```text
lab-case/
├── screenshots/
├── pcaps/
├── exports/
├── notes/
├── other/
└── manifest.json
```

## Add evidence

```bash
python evidence.py add ./lab-case screenshot.png \
  --finding "Missing access control" \
  --note "Admin page visible to normal lab user"
```

The file is copied into the right folder and SHA-256 hashed.

## Verify later

```bash
python evidence.py verify ./lab-case
```

It reports:

- OK
- CHANGED
- MISSING

So I can tell if an evidence file was edited or removed after it was recorded.

## Build an index

```bash
python evidence.py index ./lab-case --output evidence.md
```

That creates a simple Markdown table with file names, hashes, findings, and notes.

Everything stays local. This is meant for screenshots, PCAPs, scan exports, and notes from labs or assessments I am authorized to perform.
