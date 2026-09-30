import argparse
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path

SECURITY_HEADERS = {
    "strict-transport-security": "Helps force HTTPS connections.",
    "content-security-policy": "Helps control which content the browser may load.",
    "x-content-type-options": "Helps stop MIME type guessing.",
    "x-frame-options": "Helps reduce clickjacking risk.",
    "referrer-policy": "Controls how much referrer information is sent.",
    "permissions-policy": "Controls access to browser features.",
}


class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.history = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.history.append(
            {
                "status": code,
                "from": req.full_url,
                "to": urllib.parse.urljoin(req.full_url, newurl),
            }
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _flatten_name(parts):
    values = {}
    for group in parts:
        for key, value in group:
            values[key] = value
    return values


def get_tls_info(url, timeout):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None

    port = parsed.port or 443
    context = ssl.create_default_context()

    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=parsed.hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                tls_version = tls_socket.version()
    except (OSError, ssl.SSLError) as error:
        return {"error": str(error)}

    expires_at = cert.get("notAfter")
    days_remaining = None

    if expires_at:
        try:
            expiry = datetime.strptime(
                expires_at,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "subject": _flatten_name(cert.get("subject", ())),
        "issuer": _flatten_name(cert.get("issuer", ())),
        "expires_at": expires_at,
        "days_remaining": days_remaining,
    }


def analyze_cookies(headers):
    raw_cookies = headers.get_all("Set-Cookie") or []
    cookies = []
    issues = []

    for raw in raw_cookies:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except Exception:
            parsed = SimpleCookie()

        names = list(parsed.keys()) or ["unknown"]
        lower = raw.lower()

        for name in names:
            secure = "; secure" in lower
            httponly = "; httponly" in lower
            samesite = "samesite=" in lower

            item = {
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
            }
            cookies.append(item)

            if not secure:
                issues.append(
                    {
                        "cookie": name,
                        "issue": "Secure flag is missing",
                        "note": "Review whether the cookie should only be sent over HTTPS.",
                    }
                )
            if not httponly:
                issues.append(
                    {
                        "cookie": name,
                        "issue": "HttpOnly flag is missing",
                        "note": "Review whether client-side JavaScript needs access to this cookie.",
                    }
                )
            if not samesite:
                issues.append(
                    {
                        "cookie": name,
                        "issue": "SameSite attribute is missing",
                        "note": "Review whether a SameSite policy is appropriate for this cookie.",
                    }
                )

    return cookies, issues


def check_headers(url, timeout):
    tracker = RedirectTracker()
    opener = urllib.request.build_opener(
        tracker,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cybersecurity-projects-header-checker/2.0"},
    )

    with opener.open(request, timeout=timeout) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}

        present = {}
        missing = []

        for header, note in SECURITY_HEADERS.items():
            if header in headers:
                present[header] = headers[header]
            else:
                missing.append({"header": header, "note": note})

        cookies, cookie_issues = analyze_cookies(response.headers)
        final_url = response.geturl()

        return {
            "requested_url": url,
            "url": final_url,
            "status": response.status,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "redirects": tracker.history,
            "response": {
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "content_length": headers.get("content-length"),
            },
            "present": present,
            "missing": missing,
            "cookies": cookies,
            "cookie_issues": cookie_issues,
            "tls": get_tls_info(final_url, timeout),
        }


def main():
    parser = argparse.ArgumentParser(
        description="Passive HTTP response, header, cookie, redirect, and TLS checker."
    )
    parser.add_argument("url", help="Website URL or hostname")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--json", dest="json_path", help="Save the result as JSON")
    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be greater than 0 and at most 30 seconds")

    url = normalize_url(args.url)

    try:
        result = check_headers(url, args.timeout)
    except urllib.error.HTTPError as error:
        parser.error(f"HTTP error: {error.code} {error.reason}")
    except urllib.error.URLError as error:
        parser.error(f"Could not connect: {error.reason}")
    except TimeoutError:
        parser.error("The request timed out.")

    print(f"\nRequested: {result['requested_url']}")
    print(f"Final URL: {result['url']}")
    print(f"HTTP status: {result['status']}")
    print(f"Redirects: {len(result['redirects'])}")

    if result["response"]["server"]:
        print(f"Server: {result['response']['server']}")

    print("\nPresent security headers:")
    if result["present"]:
        for header, value in result["present"].items():
            print(f"[OK] {header}: {value}")
    else:
        print("None of the checked headers were found.")

    print("\nMissing security headers:")
    if result["missing"]:
        for item in result["missing"]:
            print(f"[--] {item['header']} - {item['note']}")
    else:
        print("None from this checklist.")

    print("\nCookie review:")
    if result["cookie_issues"]:
        for item in result["cookie_issues"]:
            print(f"[--] {item['cookie']}: {item['issue']}")
    elif result["cookies"]:
        print("No cookie flag issues found by this small checklist.")
    else:
        print("No Set-Cookie headers found.")

    tls = result.get("tls")
    if tls:
        print("\nTLS:")
        if tls.get("error"):
            print(f"Could not inspect certificate: {tls['error']}")
        else:
            print(f"Cipher: {tls.get('cipher') or 'unknown'}")
            print(f"Certificate expires: {tls.get('expires_at') or 'unknown'}")
            if tls.get("days_remaining") is not None:
                print(f"Days remaining: {tls['days_remaining']}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        print(f"\nSaved result to {args.json_path}")


if __name__ == "__main__":
    main()
