import argparse
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path

MANIFEST_NAME = "manifest.json"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def slugify(value):
    safe = "".join(
        char.lower() if char.isalnum() else "-"
        for char in value.strip()
    )
    while "--" in safe:
        safe = safe.replace("--", "-")
    return safe.strip("-") or "assessment"


def manifest_path(case_dir):
    return Path(case_dir) / MANIFEST_NAME


def load_manifest(case_dir):
    path = manifest_path(case_dir)
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def save_manifest(case_dir, data):
    manifest_path(case_dir).write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def init_case(case_dir, name, scope=""):
    case_dir = Path(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)

    for folder in ("screenshots", "pcaps", "exports", "notes", "other"):
        (case_dir / folder).mkdir(exist_ok=True)

    path = manifest_path(case_dir)
    if path.exists():
        raise FileExistsError(f"Case already exists: {case_dir}")

    data = {
        "name": name,
        "scope": scope,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "items": [],
    }
    save_manifest(case_dir, data)
    return data


def category_for(path):
    suffix = Path(path).suffix.lower()

    if suffix in {".png", ".jpg", ".jpeg", ".webp"}:
        return "screenshots"
    if suffix in {".pcap", ".pcapng"}:
        return "pcaps"
    if suffix in {".json", ".xml", ".har", ".csv"}:
        return "exports"
    if suffix in {".txt", ".md", ".log"}:
        return "notes"
    return "other"


def unique_destination(folder, filename):
    destination = folder / filename
    if not destination.exists():
        return destination

    stem = destination.stem
    suffix = destination.suffix
    counter = 2

    while True:
        candidate = folder / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def add_evidence(case_dir, source, note="", finding=""):
    case_dir = Path(case_dir)
    source = Path(source)

    if not source.is_file():
        raise FileNotFoundError(f"Evidence file not found: {source}")

    data = load_manifest(case_dir)
    category = category_for(source)
    destination = unique_destination(case_dir / category, source.name)
    shutil.copy2(source, destination)

    relative = destination.relative_to(case_dir).as_posix()
    item = {
        "id": len(data["items"]) + 1,
        "path": relative,
        "category": category,
        "sha256": sha256_file(destination),
        "size": destination.stat().st_size,
        "added_at": datetime.now().isoformat(timespec="seconds"),
        "finding": finding,
        "note": note,
    }

    data["items"].append(item)
    data["updated_at"] = datetime.now().isoformat(timespec="seconds")
    save_manifest(case_dir, data)
    return item


def verify_case(case_dir):
    case_dir = Path(case_dir)
    data = load_manifest(case_dir)
    results = []

    for item in data.get("items", []):
        path = case_dir / item["path"]

        if not path.exists():
            results.append(
                {
                    "id": item["id"],
                    "path": item["path"],
                    "status": "missing",
                }
            )
            continue

        actual = sha256_file(path)
        results.append(
            {
                "id": item["id"],
                "path": item["path"],
                "status": "ok" if actual == item["sha256"] else "changed",
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
            }
        )

    return results


def build_markdown(data):
    lines = [
        f"# Evidence Index - {data['name']}",
        "",
        f"- Created: {data['created_at']}",
        f"- Updated: {data['updated_at']}",
        f"- Scope: {data.get('scope') or 'Not recorded'}",
        f"- Items: {len(data.get('items', []))}",
        "",
        "| ID | Category | File | SHA-256 | Finding | Note |",
        "|---:|---|---|---|---|---|",
    ]

    for item in data.get("items", []):
        lines.append(
            f"| {item['id']} | {item['category']} | {item['path']} | "
            f"`{item['sha256'][:16]}...` | "
            f"{item.get('finding') or '-'} | {item.get('note') or '-'} |"
        )

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Organize and hash evidence files for an authorized assessment."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init")
    init_parser.add_argument("case_dir")
    init_parser.add_argument("--name", required=True)
    init_parser.add_argument("--scope", default="")

    add_parser = sub.add_parser("add")
    add_parser.add_argument("case_dir")
    add_parser.add_argument("file")
    add_parser.add_argument("--note", default="")
    add_parser.add_argument("--finding", default="")

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("case_dir")
    verify_parser.add_argument("--json", dest="json_path")

    index_parser = sub.add_parser("index")
    index_parser.add_argument("case_dir")
    index_parser.add_argument("--output", default="evidence-index.md")

    args = parser.parse_args()

    try:
        if args.command == "init":
            data = init_case(args.case_dir, args.name, args.scope)
            print(f"Case created: {args.case_dir}")
            print(f"Name: {data['name']}")

        elif args.command == "add":
            item = add_evidence(
                args.case_dir,
                args.file,
                note=args.note,
                finding=args.finding,
            )
            print(f"Added #{item['id']}: {item['path']}")
            print(f"SHA-256: {item['sha256']}")

        elif args.command == "verify":
            results = verify_case(args.case_dir)
            for item in results:
                print(f"[{item['status'].upper()}] {item['path']}")

            if args.json_path:
                Path(args.json_path).write_text(
                    json.dumps(results, indent=2),
                    encoding="utf-8",
                )

        elif args.command == "index":
            data = load_manifest(args.case_dir)
            output = Path(args.output)
            output.write_text(build_markdown(data), encoding="utf-8")
            print(f"Evidence index written to {output}")

    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
