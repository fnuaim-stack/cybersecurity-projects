# CTF Toolbox

A small local toolbox for the repetitive encoding/inspection stuff I keep doing in labs and CTFs.

## Commands

Base64:

```bash
python toolbox.py b64-encode "hello"
python toolbox.py b64-decode "aGVsbG8="
```

URL-safe base64:

```bash
python toolbox.py b64-decode "eyJzdWIiOiIxMjMifQ" --urlsafe
```

Hex:

```bash
python toolbox.py hex-encode "hello"
python toolbox.py hex-decode "68656c6c6f"
```

URL encoding:

```bash
python toolbox.py url-encode "hello world"
python toolbox.py url-decode "hello%20world"
```

Decode a JWT:

```bash
python toolbox.py jwt-decode "header.payload.signature"
```

The JWT command only decodes the header/payload. It does not forge tokens and does not claim the signature is valid.

Identify a hash format:

```bash
python toolbox.py hash-id "5d41402abc4b2a76b9719d911017c592"
```

Calculate a local digest:

```bash
python toolbox.py digest sha256 "hello"
```

This is mainly a convenience tool for labs, CTFs, and local data inspection.
