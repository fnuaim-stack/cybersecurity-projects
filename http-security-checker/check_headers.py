import argparse
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime

SECURITY_HEADERS = {
    "strict-transport-security": "Helps force HTTPS connections.",
    "content-security-policy": "Helps limit what content the browser is allowed to load.",
    "x-content-type-options": "Helps stop MIME type guessing.",
    "x-frame-options": "Helps reduce clickjacking risk.",
    "referrer-policy": "Controls how much referrer information is sent.",
    "permissions-policy": "Controls access to browser features.",
}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def check_headers(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cybersecurity-projects-header-checker/1.0"},
    )

    context = ssl.create_default_context()

    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}

        present = {}
        missing = []

        for header, note in SECURITY_HEADERS.items():
            if header in headers:
                present[header] = headers[header]
            else:
                missing.append({"header": header, "note": note})

        return {
            "url": response.geturl(),
            "status": response.status,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "present": present,
            "missing": missing,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Check a website for a few common HTTP security headers."
    )
    parser.add_argument("url", help="Website URL or hostname")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--json", dest="json_path", help="Save the result as JSON")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    url = normalize_url(args.url)

    try:
        result = check_headers(url, args.timeout)
    except urllib.error.HTTPError as error:
        parser.error(f"HTTP error: {error.code} {error.reason}")
    except urllib.error.URLError as error:
        parser.error(f"Could not connect: {error.reason}")
    except TimeoutError:
        parser.error("The request timed out.")

    print(f"\nURL: {result['url']}")
    print(f"HTTP status: {result['status']}")

    print("\nPresent:")
    if result["present"]:
        for header, value in result["present"].items():
            print(f"[OK] {header}: {value}")
    else:
        print("None of the checked headers were found.")

    print("\nMissing:")
    if result["missing"]:
        for item in result["missing"]:
            print(f"[--] {item['header']} - {item['note']}")
    else:
        print("None from this small checklist.")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=2)
        print(f"\nSaved result to {args.json_path}")


if __name__ == "__main__":
    main()
