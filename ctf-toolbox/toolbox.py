import argparse
import base64
import binascii
import hashlib
import json
import re
from urllib.parse import quote, unquote


HASH_PATTERNS = [
    ("MD5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("SHA-1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("SHA-224", re.compile(r"^[a-fA-F0-9]{56}$")),
    ("SHA-256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("SHA-384", re.compile(r"^[a-fA-F0-9]{96}$")),
    ("SHA-512", re.compile(r"^[a-fA-F0-9]{128}$")),
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("yescrypt", re.compile(r"^\$y\$")),
    ("scrypt", re.compile(r"^\$7\$")),
    ("Argon2", re.compile(r"^\$argon2(?:id|i|d)\$")),
    ("Unix SHA-256 crypt", re.compile(r"^\$5\$")),
    ("Unix SHA-512 crypt", re.compile(r"^\$6\$")),
]


def add_padding(value):
    return value + "=" * (-len(value) % 4)


def b64_encode(value, urlsafe=False):
    raw = value.encode("utf-8")
    encoded = (
        base64.urlsafe_b64encode(raw)
        if urlsafe
        else base64.b64encode(raw)
    )
    return encoded.decode("ascii")


def b64_decode(value, urlsafe=False):
    value = add_padding(value.strip())
    try:
        decoded = (
            base64.urlsafe_b64decode(value)
            if urlsafe
            else base64.b64decode(value, validate=not urlsafe)
        )
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"Invalid base64: {error}") from error

    return decoded.decode("utf-8", errors="replace")


def hex_encode(value):
    return value.encode("utf-8").hex()


def hex_decode(value):
    cleaned = re.sub(r"\s+", "", value)
    try:
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except ValueError as error:
        raise ValueError(f"Invalid hex: {error}") from error


def decode_jwt(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts.")

    try:
        header = json.loads(
            base64.urlsafe_b64decode(add_padding(parts[0])).decode("utf-8")
        )
        payload = json.loads(
            base64.urlsafe_b64decode(add_padding(parts[1])).decode("utf-8")
        )
    except (ValueError, json.JSONDecodeError, binascii.Error, UnicodeDecodeError) as error:
        raise ValueError(f"Could not decode JWT: {error}") from error

    return {
        "header": header,
        "payload": payload,
        "signature_present": bool(parts[2]),
        "note": "Decoded only. Signature validity is not checked.",
    }


def identify_hash(value):
    matches = [
        name
        for name, pattern in HASH_PATTERNS
        if pattern.search(value.strip())
    ]

    if not matches:
        return ["unknown"]

    return matches


def digest_text(value, algorithm):
    try:
        digest = hashlib.new(algorithm)
    except ValueError as error:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from error

    digest.update(value.encode("utf-8"))
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Small local CTF/inspection toolbox."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    b64e = sub.add_parser("b64-encode")
    b64e.add_argument("value")
    b64e.add_argument("--urlsafe", action="store_true")

    b64d = sub.add_parser("b64-decode")
    b64d.add_argument("value")
    b64d.add_argument("--urlsafe", action="store_true")

    hexe = sub.add_parser("hex-encode")
    hexe.add_argument("value")

    hexd = sub.add_parser("hex-decode")
    hexd.add_argument("value")

    urle = sub.add_parser("url-encode")
    urle.add_argument("value")

    urld = sub.add_parser("url-decode")
    urld.add_argument("value")

    jwt = sub.add_parser("jwt-decode")
    jwt.add_argument("token")

    ident = sub.add_parser("hash-id")
    ident.add_argument("value")

    digest = sub.add_parser("digest")
    digest.add_argument("algorithm", help="Example: md5, sha1, sha256, sha512")
    digest.add_argument("value")

    args = parser.parse_args()

    try:
        if args.command == "b64-encode":
            print(b64_encode(args.value, args.urlsafe))
        elif args.command == "b64-decode":
            print(b64_decode(args.value, args.urlsafe))
        elif args.command == "hex-encode":
            print(hex_encode(args.value))
        elif args.command == "hex-decode":
            print(hex_decode(args.value))
        elif args.command == "url-encode":
            print(quote(args.value, safe=""))
        elif args.command == "url-decode":
            print(unquote(args.value))
        elif args.command == "jwt-decode":
            print(json.dumps(decode_jwt(args.token), indent=2))
        elif args.command == "hash-id":
            print("\n".join(identify_hash(args.value)))
        elif args.command == "digest":
            print(digest_text(args.value, args.algorithm))
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
