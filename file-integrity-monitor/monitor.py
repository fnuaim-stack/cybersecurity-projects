import argparse
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


def build_snapshot(folder, ignored_names):
    snapshot = {}

    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue

        if path.name in ignored_names:
            continue

        relative = str(path.relative_to(folder))
        snapshot[relative] = file_hash(path)

    return snapshot


def save_baseline(folder, baseline_path):
    ignored = {baseline_path.name}
    snapshot = build_snapshot(folder, ignored)

    data = {
        "folder": str(folder.resolve()),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "files": snapshot,
    }

    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Baseline saved to {baseline_path}")
    print(f"Files recorded: {len(snapshot)}")


def check_baseline(folder, baseline_path):
    if not baseline_path.exists():
        raise SystemExit("Baseline file not found. Run init first.")

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old_files = baseline.get("files", {})
    current_files = build_snapshot(folder, {baseline_path.name})

    old_names = set(old_files)
    current_names = set(current_files)

    added = sorted(current_names - old_names)
    deleted = sorted(old_names - current_names)
    modified = sorted(
        name
        for name in old_names & current_names
        if old_files[name] != current_files[name]
    )

    print(f"Checked: {folder.resolve()}")

    if not added and not deleted and not modified:
        print("No changes found.")
        return

    if added:
        print("\nAdded:")
        for name in added:
            print(f"  + {name}")

    if modified:
        print("\nModified:")
        for name in modified:
            print(f"  * {name}")

    if deleted:
        print("\nDeleted:")
        for name in deleted:
            print(f"  - {name}")


def main():
    parser = argparse.ArgumentParser(description="Small SHA-256 file integrity monitor.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a baseline")
    init_parser.add_argument("folder", help="Folder to monitor")
    init_parser.add_argument("--baseline", default=DEFAULT_BASELINE)

    check_parser = subparsers.add_parser("check", help="Check for file changes")
    check_parser.add_argument("folder", help="Folder to monitor")
    check_parser.add_argument("--baseline", default=DEFAULT_BASELINE)

    args = parser.parse_args()
    folder = Path(args.folder).resolve()
    baseline_path = Path(args.baseline).resolve()

    if not folder.is_dir():
        parser.error(f"Folder not found: {folder}")

    if args.command == "init":
        save_baseline(folder, baseline_path)
    else:
        check_baseline(folder, baseline_path)


if __name__ == "__main__":
    main()
