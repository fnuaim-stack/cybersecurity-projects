import argparse
import fnmatch
import hashlib
import json
from datetime import datetime
from pathlib import Path

DEFAULT_BASELINE = "baseline.json"


def file_hash(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def should_exclude(path, folder, exclude_patterns, ignored_paths):
    resolved = path.resolve()

    if resolved in ignored_paths:
        return True

    relative = str(path.relative_to(folder)).replace("\\", "/")
    return any(fnmatch.fnmatch(relative, pattern) for pattern in exclude_patterns)


def build_snapshot(folder, exclude_patterns=None, ignored_paths=None):
    exclude_patterns = exclude_patterns or []
    ignored_paths = {Path(path).resolve() for path in (ignored_paths or [])}
    snapshot = {}

    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue

        if should_exclude(path, folder, exclude_patterns, ignored_paths):
            continue

        stat = path.stat()
        relative = str(path.relative_to(folder)).replace("\\", "/")
        snapshot[relative] = {
            "sha256": file_hash(path),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }

    return snapshot


def normalize_entry(entry):
    if isinstance(entry, str):
        return {"sha256": entry, "size": None, "mtime_ns": None}
    return {
        "sha256": entry.get("sha256"),
        "size": entry.get("size"),
        "mtime_ns": entry.get("mtime_ns"),
    }


def save_baseline(folder, baseline_path, exclude_patterns=None):
    exclude_patterns = exclude_patterns or []
    snapshot = build_snapshot(
        folder,
        exclude_patterns,
        ignored_paths={baseline_path},
    )

    data = {
        "version": 2,
        "folder": str(folder.resolve()),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "exclude_patterns": exclude_patterns,
        "files": snapshot,
        "file_count": len(snapshot),
    }

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(f"Baseline saved to {baseline_path}")
    print(f"Files recorded: {len(snapshot)}")
    if exclude_patterns:
        print(f"Exclude patterns: {', '.join(exclude_patterns)}")

    return data


def compare_baseline(folder, baseline_path, exclude_patterns=None):
    if not baseline_path.exists():
        raise FileNotFoundError("Baseline file not found. Run init first.")

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old_files = baseline.get("files", {})

    patterns = (
        exclude_patterns
        if exclude_patterns is not None
        else baseline.get("exclude_patterns", [])
    )

    current_files = build_snapshot(
        folder,
        patterns,
        ignored_paths={baseline_path},
    )

    old_names = set(old_files)
    current_names = set(current_files)

    added = sorted(current_names - old_names)
    deleted = sorted(old_names - current_names)
    modified = []
    changed_details = {}

    for name in sorted(old_names & current_names):
        old = normalize_entry(old_files[name])
        new = normalize_entry(current_files[name])

        if old["sha256"] != new["sha256"]:
            modified.append(name)
            changed_details[name] = {
                "old_sha256": old["sha256"],
                "new_sha256": new["sha256"],
                "old_size": old["size"],
                "new_size": new["size"],
            }

    return {
        "folder": str(folder.resolve()),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "exclude_patterns": patterns,
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "changed_details": changed_details,
        "changed_count": len(added) + len(modified) + len(deleted),
        "current_file_count": len(current_files),
    }


def check_baseline(folder, baseline_path, exclude_patterns=None):
    result = compare_baseline(folder, baseline_path, exclude_patterns)
    print(f"Checked: {result['folder']}")
    print(f"Files checked: {result['current_file_count']}")

    if result["changed_count"] == 0:
        print("No changes found.")
        return result

    if result["added"]:
        print("\nAdded:")
        for name in result["added"]:
            print(f"  + {name}")

    if result["modified"]:
        print("\nModified:")
        for name in result["modified"]:
            detail = result["changed_details"].get(name, {})
            size_note = ""
            if detail.get("old_size") is not None and detail.get("new_size") is not None:
                size_note = f" ({detail['old_size']} -> {detail['new_size']} bytes)"
            print(f"  * {name}{size_note}")

    if result["deleted"]:
        print("\nDeleted:")
        for name in result["deleted"]:
            print(f"  - {name}")

    return result


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_shared_arguments(parser):
    parser.add_argument("folder", help="Folder to monitor")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        help="Glob to ignore, repeatable. Example: --exclude '*.log'",
    )
    parser.add_argument("--json", dest="json_path")


def main():
    parser = argparse.ArgumentParser(
        description="SHA-256 file integrity monitor with reusable baselines."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a baseline")
    add_shared_arguments(init_parser)

    check_parser = subparsers.add_parser("check", help="Check for file changes")
    add_shared_arguments(check_parser)

    args = parser.parse_args()
    folder = Path(args.folder).resolve()
    baseline_path = Path(args.baseline).resolve()

    if not folder.is_dir():
        parser.error(f"Folder not found: {folder}")

    try:
        if args.command == "init":
            result = save_baseline(
                folder,
                baseline_path,
                exclude_patterns=args.exclude or [],
            )
        else:
            result = check_baseline(
                folder,
                baseline_path,
                exclude_patterns=args.exclude,
            )
    except FileNotFoundError as error:
        parser.error(str(error))

    if args.json_path:
        write_json(args.json_path, result)
        print(f"Saved JSON result to: {args.json_path}")


if __name__ == "__main__":
    main()
