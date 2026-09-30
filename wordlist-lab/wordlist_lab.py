import argparse
import json
from collections import Counter
from pathlib import Path

MAX_OUTPUT_DEFAULT = 100000


def load_words(paths):
    words = []

    for path in paths:
        for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                words.append(value)

    return words


def apply_filters(words, min_length=1, max_length=128, contains=None):
    output = []

    for word in words:
        if len(word) < min_length or len(word) > max_length:
            continue
        if contains and contains.lower() not in word.lower():
            continue
        output.append(word)

    return output


def transforms_for(word, modes, prefixes, suffixes):
    values = {word}

    if "lower" in modes:
        values.add(word.lower())
    if "upper" in modes:
        values.add(word.upper())
    if "capitalize" in modes:
        values.add(word.capitalize())
    if "swapcase" in modes:
        values.add(word.swapcase())

    bases = list(values)

    for prefix in prefixes:
        for base in bases:
            values.add(prefix + base)

    for suffix in suffixes:
        for base in bases:
            values.add(base + suffix)

    return values


def build_wordlist(
    words,
    *,
    dedupe=True,
    sort_output=False,
    min_length=1,
    max_length=128,
    contains=None,
    modes=None,
    prefixes=None,
    suffixes=None,
    max_output=MAX_OUTPUT_DEFAULT,
):
    modes = set(modes or [])
    prefixes = prefixes or []
    suffixes = suffixes or []

    filtered = apply_filters(
        words,
        min_length=min_length,
        max_length=max_length,
        contains=contains,
    )

    output = []
    seen = set()

    for word in filtered:
        candidates = transforms_for(word, modes, prefixes, suffixes)

        for candidate in candidates:
            if len(candidate) < min_length or len(candidate) > max_length:
                continue

            if dedupe:
                if candidate in seen:
                    continue
                seen.add(candidate)

            output.append(candidate)

            if len(output) >= max_output:
                return sorted(output) if sort_output else output

    return sorted(output) if sort_output else output


def stats(words):
    lengths = Counter(len(word) for word in words)
    return {
        "count": len(words),
        "unique": len(set(words)),
        "min_length": min((len(word) for word in words), default=0),
        "max_length": max((len(word) for word in words), default=0),
        "lengths": {str(length): count for length, count in sorted(lengths.items())},
    }


def main():
    parser = argparse.ArgumentParser(
        description="Clean and transform local wordlists for labs and testing."
    )
    parser.add_argument("inputs", nargs="+", help="Input text files")
    parser.add_argument("--output", required=True, help="Output wordlist")
    parser.add_argument("--min-length", type=int, default=1)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--contains", help="Keep only entries containing this text")
    parser.add_argument(
        "--transform",
        action="append",
        choices=["lower", "upper", "capitalize", "swapcase"],
        default=[],
    )
    parser.add_argument("--prefix", action="append", default=[])
    parser.add_argument("--suffix", action="append", default=[])
    parser.add_argument("--keep-duplicates", action="store_true")
    parser.add_argument("--sort", action="store_true")
    parser.add_argument(
        "--max-output",
        type=int,
        default=MAX_OUTPUT_DEFAULT,
        help=f"Maximum generated entries (default: {MAX_OUTPUT_DEFAULT})",
    )
    parser.add_argument("--stats-json", help="Save output statistics as JSON")
    args = parser.parse_args()

    if args.min_length < 1:
        parser.error("--min-length must be at least 1")
    if args.max_length < args.min_length:
        parser.error("--max-length must be >= --min-length")
    if args.max_output < 1 or args.max_output > 1000000:
        parser.error("--max-output must be between 1 and 1000000")

    try:
        source = load_words(args.inputs)
    except OSError as error:
        parser.error(str(error))

    result = build_wordlist(
        source,
        dedupe=not args.keep_duplicates,
        sort_output=args.sort,
        min_length=args.min_length,
        max_length=args.max_length,
        contains=args.contains,
        modes=args.transform,
        prefixes=args.prefix,
        suffixes=args.suffix,
        max_output=args.max_output,
    )

    Path(args.output).write_text(
        "\n".join(result) + ("\n" if result else ""),
        encoding="utf-8",
    )

    before = stats(source)
    after = stats(result)

    print(f"Loaded: {before['count']} entries")
    print(f"Unique input: {before['unique']}")
    print(f"Wrote: {after['count']} entries")
    print(f"Output: {args.output}")

    if len(result) >= args.max_output:
        print(f"Output reached the configured cap of {args.max_output} entries.")

    if args.stats_json:
        Path(args.stats_json).write_text(
            json.dumps({"input": before, "output": after}, indent=2),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
