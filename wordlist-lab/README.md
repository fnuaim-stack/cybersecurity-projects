# Wordlist Lab

A local wordlist cleanup/transformation utility.

This does not log in anywhere and does not perform password spraying or cracking. It only prepares text lists that I provide.

## Basic cleanup

Merge and deduplicate files:

```bash
python wordlist_lab.py words1.txt words2.txt --output clean.txt
```

Filter by length:

```bash
python wordlist_lab.py words.txt \
  --min-length 8 \
  --max-length 20 \
  --output filtered.txt
```

Keep entries containing text:

```bash
python wordlist_lab.py words.txt --contains lab --output lab-only.txt
```

## Simple transforms

```bash
python wordlist_lab.py words.txt \
  --transform lower \
  --transform capitalize \
  --suffix 2026 \
  --suffix '!' \
  --output variants.txt
```

Add prefixes:

```bash
python wordlist_lab.py words.txt --prefix dev- --output prefixed.txt
```

## Safety cap

Generated output is capped at 100,000 entries by default so a small command does not accidentally make a massive file.

Change it if needed:

```bash
python wordlist_lab.py words.txt --output out.txt --max-output 200000
```

## Stats

```bash
python wordlist_lab.py words.txt \
  --output clean.txt \
  --stats-json stats.json
```

Useful for local labs, CTF prep, test-data generation, and cleaning lists before authorized password-audit work.
