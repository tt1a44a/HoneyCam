# HoneyCam Codebase Analysis

> **Generated:** 2026-02-11
> **Total Files:** 7 (excluding .gitkeep placeholders)
> **Total Lines:** ~1,752

---

## Table of Contents / Chunk Index

| # | File | Lines | Chunk Description | Status |
|---|------|-------|-------------------|--------|
| **honeycam_scanner.py** | | | | |
| 1 | `honeycam_scanner.py` | 1-49 | Shebang, docstring, imports, RTSP URL patterns | COMPLETE |
| 2 | `honeycam_scanner.py` | 50-106 | Channel discovery, auth patterns, HTTP patterns, ports, credentials, constants | COMPLETE |
| 3 | `honeycam_scanner.py` | 107-204 | `ensure_dir()`, `check_rtsp_stream()` | COMPLETE |
| 4 | `honeycam_scanner.py` | 205-334 | `check_http_stream()`, `encode_basic_auth()`, `test_url_with_credentials()` | COMPLETE |
| 5 | `honeycam_scanner.py` | 335-387 | `detect_camera_ports()` | COMPLETE |
| 6 | `honeycam_scanner.py` | 388-497 | `test_camera_urls()` | COMPLETE |
| 7 | `honeycam_scanner.py` | 498-534 | `search_shodan()` | COMPLETE |
| 8 | `honeycam_scanner.py` | 535-654 | `enumerate_camera_channels()` | COMPLETE |
| 9 | `honeycam_scanner.py` | 655-678 | `play_notification_sound()` | COMPLETE |
| 10 | `honeycam_scanner.py` | 679-715 | `main()` - argument parsing & directory setup | COMPLETE |
| 11 | `honeycam_scanner.py` | 716-798 | `main()` - single IP scanning branch | COMPLETE |
| 12 | `honeycam_scanner.py` | 799-851 | `main()` - Shodan scanning branch | COMPLETE |
| **requirements.txt** | | | | |
| 13 | `requirements.txt` | 1-22 | All dependencies | COMPLETE |
| **.env.example** | | | | |
| 14 | `.env.example` | 1-12 | Environment variable template | COMPLETE |
| **.gitignore** | | | | |
| 15 | `.gitignore` | 1-43 | Ignore rules | COMPLETE |
| **README.md** | | | | |
| 16 | `README.md` | 1-50 | Header, features, installation | COMPLETE |
| 17 | `README.md` | 51-100 | Usage documentation | COMPLETE |
| 18 | `README.md` | 101-139 | Output files, tips, troubleshooting, license | COMPLETE |
| **scan_honeywell_ip.sh** | | | | |
| 19 | `scan_honeywell_ip.sh` | 1-54 | Header, help text, IP check | COMPLETE |
| 20 | `scan_honeywell_ip.sh` | 55-126 | Argument parsing loop | COMPLETE |
| 21 | `scan_honeywell_ip.sh` | 127-170 | Venv setup, .env loading, notification setup | COMPLETE |
| 22 | `scan_honeywell_ip.sh` | 171-230 | Port detection info, results file header, scanner execution | COMPLETE |
| 23 | `scan_honeywell_ip.sh` | 231-305 | Results processing and output | COMPLETE |
| **scan_honeywell_shodan.sh** | | | | |
| 24 | `scan_honeywell_shodan.sh` | 1-44 | Header, help text | COMPLETE |
| 25 | `scan_honeywell_shodan.sh` | 45-154 | Variable initialisation, argument parsing | COMPLETE |
| 26 | `scan_honeywell_shodan.sh` | 155-261 | Leftover args parsing, venv setup, .env loading, notification setup | COMPLETE |
| 27 | `scan_honeywell_shodan.sh` | 262-386 | Scan logic - default Honeywell query (single + unlimited pagination) | COMPLETE |
| 28 | `scan_honeywell_shodan.sh` | 387-486 | Scan logic - custom query (single + unlimited pagination) | COMPLETE |
| 29 | `scan_honeywell_shodan.sh` | 487-523 | Results summary and final output | COMPLETE |

---

## Chunk-by-Chunk Analysis

---

### Chunk 1 — `honeycam_scanner.py` Lines 1-49
**Shebang, docstring, imports, RTSP URL patterns**

```python
#!/usr/bin/env python3
"""
Honeywell Camera Scanner
...
"""
import os, sys, time, argparse, shodan, requests, cv2, json, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode
import re

HONEYWELL_RTSP_PATTERNS = [
    "rtsp://{ip}:{rtsp_port}/h264",
    ...
    "rtsp://{ip}:{rtsp_port}/mpeg4/ch0{channel}/main/av_stream"
]
```

**Comments & Issues:**

- **ISSUE (Unused import):** `ThreadPoolExecutor` and `as_completed` are imported on line 22 but **never used** anywhere in the codebase. These should be removed or the code should be refactored to use them for concurrent scanning (which would be a significant performance improvement).
- **STYLE:** Imports are not grouped per PEP 8 (stdlib / third-party / local). All imports are in one block. Minor but worth noting.
- **NOTE:** The RTSP pattern list mixes Honeywell-specific and Hikvision-specific patterns. Comments indicate Hikvision patterns were "verified working" - the variable name `HONEYWELL_RTSP_PATTERNS` is misleading since it contains Hikvision patterns too. Consider renaming to `CAMERA_RTSP_PATTERNS`.
- **NOTE:** The `{rtsp_port}` placeholder in patterns is good for flexibility. Channel `{channel}` is consistently used.

**Status: COMPLETE**

---

### Chunk 2 — `honeycam_scanner.py` Lines 50-106
**Channel discovery endpoints, auth patterns, HTTP patterns, ports, credentials, constants**

```python
CHANNEL_DISCOVERY_ENDPOINTS = [...]
AUTH_REQUIRING_PATTERNS = [...]
HARDCODED_AUTH_PATTERNS = [...]
HONEYWELL_HTTP_PATTERNS = [...]
COMMON_RTSP_PORTS = [554, 8554, 8000, 8002, 10554, 1935]
COMMON_HTTP_PORTS = [80, 8000, 8001, 8080, 8081, 8888]
DEFAULT_CREDENTIALS = [{"username": "admin", "password": "12345"}]
CVE_DATABASE_FILE = "honeywell_cve_database.json"
HTTP_HEADERS = {...}
```

**Comments & Issues:**

- **SECURITY ISSUE:** `HARDCODED_AUTH_PATTERNS` (line 72) contains a hardcoded base64-encoded credential string `YWRtaW46QWRtaW4xMjMu` which decodes to `admin:Admin123.`. This is a second set of credentials beyond `DEFAULT_CREDENTIALS` and is effectively hidden in a URL pattern. Should be documented or consolidated with `DEFAULT_CREDENTIALS`.
- **ISSUE (Unused constant):** `CVE_DATABASE_FILE` (line 98) is defined but **never used** in the code. The `--check-vulns` and `--exploit` arguments are parsed but no vulnerability checking code exists. This is dead/placeholder code.
- **NOTE:** `COMMON_RTSP_PORTS` list does not match README.md which lists `10554, 8554, 7554, 5554, 8000, 8080, 8081, 8082` - there are discrepancies (code has `8002, 1935`; README has `7554, 5554, 8080, 8081, 8082`).
- **NOTE:** `COMMON_HTTP_PORTS` also doesn't match README.md (`8082` in README but not in code).
- **NOTE:** Only one default credential pair (`admin:12345`) is used, which is fine for responsible testing but limits effectiveness.
- **STYLE:** `HTTP_HEADERS` uses a Chrome 91 user agent string which is very outdated (2021). Consider updating.

**Status: COMPLETE**

---

### Chunk 3 — `honeycam_scanner.py` Lines 107-204
**`ensure_dir()` and `check_rtsp_stream()`**

```python
def ensure_dir(directory):
    """Make sure a directory exists, creating it if necessary"""
    ...

def check_rtsp_stream(url, timeout=5, save_frames=False, output_dir=None, max_frames=5):
    """Try to connect to an RTSP stream with a hard timeout using threading"""
    ...
```

**Comments & Issues:**

- **ISSUE (Deprecated pattern):** `ensure_dir()` uses `os.path.exists()` + `os.makedirs()`. This has a race condition. Should use `os.makedirs(directory, exist_ok=True)` instead.
- **ISSUE (Import inside function):** `import socket` on line 117 and `import threading` / `import signal` on lines 140-141 are imported inside `check_rtsp_stream()`. These should be at the top of the file. `signal` is imported but **never used** in this function.
- **ISSUE (Thread safety):** The `result` dictionary on line 143 is shared between the main thread and the capture thread without any locking mechanism. While this works in practice for simple dict assignments in CPython due to the GIL, it's not formally thread-safe.
- **ISSUE (Resource leak):** If the capture thread hangs (line 182-184 check), the `cv2.VideoCapture` object in the thread is never released. The daemon thread will keep the connection open until the process exits. There's no way to forcefully stop a Python thread.
- **ISSUE (Error handling):** The socket `s.close()` is called twice - once in the try block (line 131) and once in the finally block (line 136). The second call is harmless but redundant.
- **NOTE:** The threading approach for timeout is a reasonable workaround for OpenCV's lack of configurable RTSP timeout. However, `cv2.VideoCapture(url)` itself can block for a long time before the thread even starts reading frames - the socket pre-check helps mitigate this.
- **NOTE:** Frame saving logic (lines 187-197) is well-structured with proper error handling.

**Status: COMPLETE**

---

### Chunk 4 — `honeycam_scanner.py` Lines 205-334
**`check_http_stream()`, `encode_basic_auth()`, `test_url_with_credentials()`**

```python
def check_http_stream(url, timeout=1):
    ...
def encode_basic_auth(username, password):
    ...
def test_url_with_credentials(base_url, credentials, is_rtsp=True, channel=1, save_frames=False, ip=None):
    ...
```

**Comments & Issues:**

- **BUG (Potential KeyError):** In `test_url_with_credentials()`, lines 279-282, after formatting `{ip}`, if `{channel}` is still in the string, the second `.format(channel=channel)` call will fail if `{ip}` was also in the string because `{ip}` has already been resolved. However since `{ip}` was already replaced, the second `.format()` call would work. But if **both** `{ip}` and `{channel}` are in the URL, calling `.format(ip=ip)` first leaves `{channel}` intact, and then `.format(channel=channel)` works. This is fragile - a single `.format(ip=ip, channel=channel)` call would be safer.
- **BUG (Same logic repeated):** Lines 319-322 in the HTTP branch have the same fragile pattern: separate `.format()` calls for `ip` and `channel`. Same fix applies.
- **ISSUE (Inconsistent timeout):** `check_http_stream()` has `timeout=1` default, while `check_rtsp_stream()` has `timeout=5`. The HTTP timeout seems very aggressive (1 second). Some cameras respond slowly on HTTP.
- **ISSUE (SSL verification):** `requests.get()` in `check_http_stream()` does not explicitly set `verify=False`. If a camera uses a self-signed SSL certificate on HTTPS, this will fail. Should add `verify=False` and suppress the InsecureRequestWarning.
- **NOTE:** `test_url_with_credentials()` is quite long (110 lines) with significant duplication between the RTSP and HTTP branches. Could be refactored to reduce repetition.
- **NOTE:** The function returns both SUCCESS and FAILED results, which is useful for logging but unusual - typically you'd only return successes and let failures be implicit.
- **NOTE:** The `encode_basic_auth()` function is clean and correct.

**Status: COMPLETE**

---

### Chunk 5 — `honeycam_scanner.py` Lines 335-387
**`detect_camera_ports()`**

```python
def detect_camera_ports(camera_data):
    """
    Analyze Shodan data to detect the appropriate ports for HTTP and RTSP
    Returns a dictionary with rtsp_port and http_port
    """
    ...
```

**Comments & Issues:**

- **ISSUE (Function never called):** `detect_camera_ports()` is defined but **never called** anywhere in the codebase. It appears to be designed for use with Shodan data to auto-detect ports, but the Shodan scanning code path in `main()` doesn't use it. This is dead code.
- **ISSUE (Logic flaw):** The RTSP detection on line 359 uses `or` - if a port is in `COMMON_RTSP_PORTS` it's marked as RTSP even without any RTSP service signature. This could misidentify HTTP services running on port 8000 (which is in both `COMMON_RTSP_PORTS` and `COMMON_HTTP_PORTS`). The HTTP check (line 364) runs in `elif`, so whichever check matches first wins.
- **NOTE:** The function structure is reasonable - check service data first, fall back to port lists. But the overlap between `COMMON_RTSP_PORTS` and `COMMON_HTTP_PORTS` (port 8000 appears in both) creates ambiguity.
- **NOTE:** Good defensive check for `camera_data` validity on line 346.

**Status: COMPLETE**

---

### Chunk 6 — `honeycam_scanner.py` Lines 388-497
**`test_camera_urls()`**

```python
def test_camera_urls(ip, channel, credentials, save_frames=False, rtsp_port=None, http_port=None, auto_detect=True, timeout=5):
    """Test various URL patterns for a camera"""
    ...
```

**Comments & Issues:**

- **BUG (Duplicate URLs):** This function builds a `patterns` list that includes URLs from `HARDCODED_AUTH_PATTERNS`, then iterates through `HONEYWELL_RTSP_PATTERNS` for each credential, and then adds hardcoded additional patterns (lines 421-426). The additional patterns on lines 421-426 use hardcoded port 554, but lines 456-459 then replace `:554/` with `:{port}/` for each port being tested. However, the patterns from `HONEYWELL_RTSP_PATTERNS` already contain `{rtsp_port}` which gets formatted to an IP - this means the port replacement on line 459 (`pattern.replace(':554/', f':{port}/')`) will only work if the port was originally 554, missing patterns that were formatted with a different `rtsp_port` value. Actually, looking again, line 406 calls `.format(ip=ip, channel=channel)` but NOT `rtsp_port`, so `{rtsp_port}` would cause a KeyError. Wait - line 406 only formats `ip` and `channel` - the `{rtsp_port}` placeholder would remain and cause a **KeyError** when `.format()` is called.
- **BUG CONFIRMED:** Line 406: `auth_url = pattern.format(ip=ip, channel=channel)` - Since `HONEYWELL_RTSP_PATTERNS` contain `{rtsp_port}`, this will raise a `KeyError: 'rtsp_port'`. This is a **critical bug** that would crash the program when testing any URL pattern. Either `rtsp_port` was never passed to `.format()`, or this code path is never actually reached because it crashes. Looking at the flow, this function IS called from `main()`, so this is a live bug. It would need to be: `pattern.format(ip=ip, channel=channel, rtsp_port=554)` or similar.
- **ISSUE (Port 80 in HTTP URLs):** Lines 477-482 try to add ports to HTTP URLs that might not have a port. The regex `re.sub(r':(\d+)', ...)` would match any colon-number sequence, which could incorrectly match port-like patterns within paths.
- **ISSUE (No deduplication):** The same URL could be generated multiple times through different pattern combinations. Testing duplicate URLs wastes time.
- **NOTE:** This is the most complex function in the file and could benefit from significant refactoring and unit tests.

**Status: COMPLETE**

---

### Chunk 7 — `honeycam_scanner.py` Lines 498-534
**`search_shodan()`**

```python
def search_shodan(api_key, limit=100, custom_query=None, page=1):
    """
    Search Shodan for cameras and related devices
    """
    ...
```

**Comments & Issues:**

- **ISSUE (Missing --page argument):** The function accepts a `page` parameter, but the `argparse` setup in `main()` does **not define** a `--page` argument. The shell scripts pass `--page` to the Python script, but the argument parser doesn't recognize it. This means the `--page` flag from `scan_honeywell_shodan.sh` would cause an "unrecognized arguments" error.
- **ISSUE (Incomplete data extraction):** The function extracts `ip`, `hostnames`, `org`, `ports`, and full `data` from Shodan results, but stores the entire raw result in `data` key. This could use a lot of memory for large result sets.
- **NOTE:** The Shodan API `search()` method's `limit` parameter may not work as expected. According to Shodan API docs, you typically use `page` for pagination and the API returns a fixed page size. The `limit` parameter in the Python library truncates results client-side.
- **NOTE:** Good error handling with `shodan.APIError` catch.
- **NOTE:** The `page` parameter enables pagination but the main Python function doesn't expose it via argparse, making it inaccessible from the command line (only shell scripts attempt to use it).

**Status: COMPLETE**

---

### Chunk 8 — `honeycam_scanner.py` Lines 535-654
**`enumerate_camera_channels()`**

```python
def enumerate_camera_channels(ip, credentials=None, http_port=80, rtsp_port=554):
    """
    Attempt to discover camera name and available channels using various methods
    """
    ...
```

**Comments & Issues:**

- **ISSUE (Bare except-like pattern):** Line 602 catches `Exception` broadly for HTTP requests. While this is common, it could mask unexpected errors like `KeyboardInterrupt` (though that's a `BaseException`).
- **ISSUE (Missing indentation):** The `except` block at line 602 is at the same level as the `for cred in credentials` loop, meaning it catches exceptions from the entire credential loop iteration, not just the individual request. This seems correct but the indentation structure is worth double-checking.
- **ISSUE (Regex may be too broad):** The `name_pattern` regex on line 553 matches very broadly (`[A-Za-z0-9\-_\s]+`) which could capture unintended text following the camera name.
- **NOTE:** The channel discovery approach is solid - try HTTP endpoints first, then fall back to RTSP probing. Testing channels 1-4 plus 101, 102 is a good heuristic based on common camera configurations.
- **NOTE:** The function is well-structured with a clear result dictionary and good logging.
- **NOTE:** The RTSP probing fallback (lines 606-640) only tests two URL patterns, which is a reasonable compromise between thoroughness and speed.

**Status: COMPLETE**

---

### Chunk 9 — `honeycam_scanner.py` Lines 655-678
**`play_notification_sound()`**

```python
def play_notification_sound():
    """Play a notification sound to alert that a working camera was found"""
    ...
```

**Comments & Issues:**

- **ISSUE (Function never called from Python):** `play_notification_sound()` is defined but **never called** in the Python code. The `--notify` flag is parsed in `main()` but there is no code that invokes this function. Notification sounds are only handled in the shell scripts. This is dead code within the Python script.
- **ISSUE (Platform import):** On line 671, `import winsound` is inside an `if sys.platform == 'win32'` block, which is fine for conditional imports, but since this function is never called, it's moot.
- **NOTE:** The cross-platform approach (Linux/macOS/Windows) is well-designed, covering major platforms.
- **NOTE:** `os.system()` calls on lines 666-668 are used for playing sounds. While functional, `subprocess.run()` would be more modern and secure.

**Status: COMPLETE**

---

### Chunk 10 — `honeycam_scanner.py` Lines 679-715
**`main()` - argument parsing and directory setup**

```python
def main():
    parser = argparse.ArgumentParser(...)
    parser.add_argument('--api-key', ...)
    ...
    args = parser.parse_args()
    
    # Directory setup and global timeout modification
    ...
```

**Comments & Issues:**

- **BUG (Dangerous global modification):** Lines 713-715 modify function default arguments at runtime:
  ```python
  global check_rtsp_stream, check_http_stream
  check_rtsp_stream.__defaults__ = (args.timeout, False, None, 5)
  check_http_stream.__defaults__ = (args.timeout,)
  ```
  This is a **very bad practice**. It modifies the function's default values globally, which is fragile and confusing. If any code path calls these functions before `main()` finishes, or if the functions are called from multiple threads, this creates race conditions. The proper approach is to pass `timeout` as an explicit parameter in each call.
- **ISSUE (Missing --page argument):** As noted in Chunk 7, no `--page` argument is defined, but the shell scripts try to pass it. This will cause `argparse` to raise an error.
- **ISSUE (Missing --notify handler):** The `--notify` flag is parsed but never used in the Python code to call `play_notification_sound()`.
- **ISSUE (Missing --verbose handler):** The `--verbose` flag is parsed but never used to change output verbosity.
- **ISSUE (Missing --check-vulns handler):** The `--check-vulns` flag is parsed but no vulnerability checking code exists.
- **ISSUE (Missing --exploit handler):** The `--exploit` flag is parsed but no exploit code exists.
- **NOTE:** Four argument flags are defined but have no implementation (`--notify`, `--verbose`, `--check-vulns`, `--exploit`). These are placeholder features.

**Status: COMPLETE**

---

### Chunk 11 — `honeycam_scanner.py` Lines 716-798
**`main()` - single IP scanning branch**

```python
    if args.ip:
        print(f"Testing camera at {args.ip}...")
        ...
        # Channel enumeration, URL testing, results saving
        ...
```

**Comments & Issues:**

- **ISSUE (Inconsistent result format):** The code checks for `"✅"` in results (line 766) to determine success. This is fragile - it relies on emoji characters in result strings. A structured result object (e.g., a dict with a `success` boolean) would be more robust.
- **ISSUE (camera_info may be empty dict):** On line 791-792, `camera_info.get('camera_name', 'Unknown')` and `camera_info.get('available_channels', channels_to_test)` are called, but `camera_info` is initialised as `{}` (line 736) and only populated if `args.enum_channels` is True. When it's an empty dict, `.get()` returns the defaults, which is correct but could be clearer.
- **ISSUE (Result file path handling):** Lines 780-786 handle the result file path. If `args.result_file` contains a directory that doesn't exist, `ensure_dir()` is called on its parent, which is good. But if `args.result_file` is None and no `--result-file` is provided, the default goes to `logs/camera_results_{ip}.txt`. The shell scripts always provide `--result-file`, so this works, but running the Python script directly may create files in unexpected locations.
- **NOTE:** The channel testing loop (lines 757-772) correctly supports `--until-success` to break early.
- **NOTE:** Results are both written to file and printed to stdout, which is good for usability.

**Status: COMPLETE**

---

### Chunk 12 — `honeycam_scanner.py` Lines 799-851
**`main()` - Shodan scanning branch**

```python
    else:
        # Shodan search requires API key
        if not args.api_key:
            print("Error: Shodan API key is required...")
            sys.exit(1)
        ...
        for i, camera in enumerate(cameras, 1):
            ...
```

**Comments & Issues:**

- **BUG (Incomplete Shodan branch):** The Shodan scanning loop (lines 817-848) collects results and checks for working cameras, but it **never saves results to a file**. Unlike the single-IP branch which writes to a result file, the Shodan branch just iterates through cameras and breaks on `--until-success`. The `--output-list` argument is defined in argparse but never used anywhere. Working cameras are tracked in `working_ips` but never written out.
- **ISSUE (Missing output):** The `working_ips` list is populated but never saved or displayed at the end of the Shodan scan. The user has no way to see which cameras worked after the scan completes.
- **ISSUE (No port detection used):** The Shodan branch passes camera data with ports but doesn't call `detect_camera_ports()` to use detected port information.
- **ISSUE (detect_camera_ports never called):** The `detect_camera_ports()` function was designed for this use case but is never invoked.
- **NOTE:** The Shodan branch is significantly less feature-complete than the single-IP branch.
- **NOTE:** The `--enum-channels` flag works correctly in both branches.

**Status: COMPLETE**

---

### Chunk 13 — `requirements.txt` Lines 1-22
**All dependencies**

```
opencv-python>=4.5.0
requests>=2.25.0
shodan>=1.25.0
python-dotenv>=0.15.0
pillow>=8.0.0
numpy>=1.19.0
matplotlib>=3.3.0
imutils>=0.5.3
pycryptodome>=3.9.9
pyOpenSSL>=20.0.0
futures>=3.1.1
```

**Comments & Issues:**

- **BUG (Python 3 incompatible package):** `futures>=3.1.1` (line 21) is a **Python 2 backport** of `concurrent.futures`. Installing this on Python 3 will either fail or cause conflicts. The comment says "futures is built-in for Python 3" but the package is still listed as a dependency. It should be removed or made conditional.
- **ISSUE (Unused dependencies):** Several packages are imported in `requirements.txt` but **never used** in the codebase:
  - `python-dotenv` - never imported or used (`.env` is loaded by shell scripts via `source`)
  - `pillow` - never imported
  - `matplotlib` - never imported
  - `imutils` - never imported
  - `pycryptodome` - never imported
  - `pyOpenSSL` - never imported
  - `numpy` - never explicitly imported (may be an indirect dependency of opencv)
- **NOTE:** Only `opencv-python`, `requests`, `shodan`, `json`, `base64`, `re`, `argparse`, `os`, `sys`, `time` are actually used. Of these, only `opencv-python`, `requests`, and `shodan` are third-party.
- **SUGGESTION:** Slim down to only the three actually-used third-party packages: `opencv-python`, `requests`, `shodan`.

**Status: COMPLETE**

---

### Chunk 14 — `.env.example` Lines 1-12
**Environment variable template**

```
SHODAN_API_KEY=your_shodan_api_key_here
# ENABLE_NOTIFICATIONS=true
# NOTIFICATION_VOLUME=0.7
# DEFAULT_TIMEOUT=5
```

**Comments & Issues:**

- **ISSUE (Unused variables):** `ENABLE_NOTIFICATIONS`, `NOTIFICATION_VOLUME`, and `DEFAULT_TIMEOUT` are defined as examples but **never read** by any code. The shell scripts only read `SHODAN_API_KEY`. These are misleading to users.
- **NOTE:** The file correctly uses comments for optional/unused values.
- **NOTE:** The `.env` file is properly listed in `.gitignore`.

**Status: COMPLETE**

---

### Chunk 15 — `.gitignore` Lines 1-43
**Git ignore rules**

```
__pycache__/
*.py[cod]
venv/
logs/*
captures/*
!logs/.gitkeep
!captures/.gitkeep
.env
.idea/
.vscode/
.DS_Store
Thumbs.db
```

**Comments & Issues:**

- **GOOD:** Properly excludes sensitive `.env` file.
- **GOOD:** Uses `.gitkeep` pattern for empty directories.
- **GOOD:** Covers Python bytecode, virtual environments, IDE files, OS files.
- **NOTE:** Comprehensive and well-structured. No issues found.
- **MINOR:** Could add `*.log` pattern for any stray log files.

**Status: COMPLETE**

---

### Chunk 16 — `README.md` Lines 1-50
**Header, features, installation**

**Comments & Issues:**

- **ISSUE (Incorrect repo URL):** Line 19 shows `https://github.com/yourusername/honeycam.git` - this is a placeholder that was never updated.
- **NOTE:** Feature list is comprehensive and accurately describes the tool's intended capabilities (though not all features are implemented).
- **NOTE:** Installation instructions mention "scripts will automatically set up a virtual environment" which is correct - the shell scripts handle this.
- **GOOD:** Clear and well-formatted documentation.

**Status: COMPLETE**

---

### Chunk 17 — `README.md` Lines 51-100
**Usage documentation**

**Comments & Issues:**

- **ISSUE (Port list mismatch):** Line 95 lists RTSP ports as `554, 10554, 8554, 7554, 5554, 8000, 8080, 8081, 8082` but the actual code uses `[554, 8554, 8000, 8002, 10554, 1935]`. Several ports are different.
- **ISSUE (Port list mismatch):** Line 96 lists HTTP ports as `80, 8000, 8080, 8081, 8082` but the code uses `[80, 8000, 8001, 8080, 8081, 8888]`. Again, mismatched.
- **ISSUE (Undocumented features):** The `--exploit CVE` option is documented but not implemented in the Python code.
- **NOTE:** Usage examples are clear and helpful.
- **NOTE:** The two-script approach (IP scan vs Shodan scan) is well-documented.

**Status: COMPLETE**

---

### Chunk 18 — `README.md` Lines 101-139
**Output files, tips, troubleshooting, license**

**Comments & Issues:**

- **ISSUE (Missing file):** README references `vulnerable_cameras.json` as an output file, but vulnerability checking is not implemented.
- **NOTE:** Troubleshooting tips are practical and useful.
- **NOTE:** "Known Working Configurations" section is helpful for users.
- **GOOD:** License section properly disclaims the tool as educational/research only.
- **NOTE:** Could add a "Known Issues" or "TODO" section documenting unimplemented features.

**Status: COMPLETE**

---

### Chunk 19 — `scan_honeywell_ip.sh` Lines 1-54
**Header, help text, IP address check**

```bash
#!/bin/bash
# quick script to scan a specific IP address for Honeywell cameras
...
```

**Comments & Issues:**

- **GOOD:** Script location detection using `BASH_SOURCE` is correct and portable.
- **GOOD:** Directory creation with `mkdir -p` is safe.
- **GOOD:** Help flag handling is comprehensive with clear documentation.
- **GOOD:** IP address validation (checks if argument is provided).
- **MINOR:** No actual IP address format validation. Invalid IPs like "abc" would be passed to the scanner.
- **NOTE:** Timestamped results files are a good pattern for avoiding overwrites.

**Status: COMPLETE**

---

### Chunk 20 — `scan_honeywell_ip.sh` Lines 55-126
**Argument parsing**

```bash
# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --check-vulns) ...
    --exploit) ...
    --rtsp-port) ...
    ...
  esac
  shift
done
```

**Comments & Issues:**

- **ISSUE (Duplicate help handling):** Help text is duplicated verbatim inside the while loop (lines 99-118) even though it was already handled before argument parsing begins (lines 19-38). The first help check exits before reaching the while loop, making the duplicate unreachable for `$1` but reachable for subsequent arguments.
- **NOTE:** The argument parsing is clean and handles all documented options.
- **GOOD:** `AUTO_DETECT=""` is properly set when manual RTSP port is specified.
- **NOTE:** The `--exploit` option stores the value but the scanner likely won't handle it since the feature is unimplemented.

**Status: COMPLETE**

---

### Chunk 21 — `scan_honeywell_ip.sh` Lines 127-170
**Venv setup, .env loading, notification sound setup**

```bash
# fire up the venv
if [ -d "$SCRIPT_DIR/venv" ]; then
  source "$SCRIPT_DIR/venv/bin/activate"
else
  ...
fi

# load API key from .env
...

# setup notification sound
...
```

**Comments & Issues:**

- **ISSUE (Linux-only venv):** Uses `source "$SCRIPT_DIR/venv/bin/activate"` which is Linux/macOS syntax. On Windows (even Git Bash/WSL), the venv activation script is at `venv/Scripts/activate`. Since the project is on a Windows machine, this script won't work natively.
- **ISSUE (Linux-only notification):** The notification sound setup checks for `play`, `paplay`, and `aplay` - all Linux audio tools. On Windows or macOS this section is effectively dead code. The Python `play_notification_sound()` function handles cross-platform, but it's never called.
- **ISSUE (Source .env insecure):** Line 148 uses `source "$SCRIPT_DIR/.env"` which executes the .env file as a shell script. If the .env file contains malicious content, it could execute arbitrary commands. A safer approach is to use `export $(grep -v '^#' .env | xargs)`.
- **NOTE:** Auto-creating venv and installing requirements on first run is a nice UX touch.

**Status: COMPLETE**

---

### Chunk 22 — `scan_honeywell_ip.sh` Lines 171-230
**Port detection info, results file header, scanner execution**

```bash
# tell user bout port detection
...
# Create the run header in the results file
...
# Run the scanner
python3 "$SCRIPT_DIR/honeycam_scanner.py" --ip "$IP_ADDRESS" --save-frames --enum-channels ...
```

**Comments & Issues:**

- **ISSUE (Missing --page argument):** The scanner is invoked without `--page`, which is fine for single-IP scanning. But `--enum-channels` is always passed, which triggers channel enumeration for every scan even if the user didn't request it. Wait - looking again, this is intentional; the script always enables `--save-frames` and `--enum-channels` by default.
- **GOOD:** All options are properly passed through to the Python script.
- **GOOD:** Results file gets a clear header with timestamp and IP.
- **NOTE:** The API key is optionally passed - it's not required for single-IP scanning.

**Status: COMPLETE**

---

### Chunk 23 — `scan_honeywell_ip.sh` Lines 231-305
**Results processing and output**

```bash
# Check the scanner's exit code
SCAN_RESULT=$?
...
# Check if the result file exists for this IP
IP_RESULT_FILE="$LOG_DIR/camera_results_${IP_ADDRESS}.txt"
...
```

**Comments & Issues:**

- **ISSUE (Exit code assumption):** The script checks for exit code 0 to determine success, but the Python script doesn't have explicit exit codes for "camera found" vs "no cameras found". Both scenarios would exit with code 0 (success). The `grep` check on line 238 is more reliable.
- **ISSUE (Result file path mismatch):** The script looks for `$LOG_DIR/camera_results_${IP_ADDRESS}.txt` but the Python script's default result file location might differ depending on how `--result-file` is handled. The script passes `--result-file "$RESULTS_FILE"` (which is the timestamped file), but then looks for `camera_results_${IP_ADDRESS}.txt`. The Python script also creates this IP-specific file as its default.
- **ISSUE (grep pattern):** Line 257 uses `grep -c "Working URL"` but the Python script uses `"✅ Working URL:"` format. The grep pattern should match, but it depends on the exact format of the result strings.
- **NOTE:** The notification sound playing is duplicated between the shell script and the (uncalled) Python function.
- **NOTE:** Good summary output at the end with file locations.

**Status: COMPLETE**

---

### Chunk 24 — `scan_honeywell_shodan.sh` Lines 1-44
**Header and help text**

```bash
#!/bin/bash
# hacked together script for scanning Honeywell cams using Shodan
...
```

**Comments & Issues:**

- **NOTE:** Casual/informal comments ("hacked together", "whatever shodan search you want") - fine for a personal project.
- **GOOD:** Comprehensive help text with examples.
- **GOOD:** Same directory setup pattern as the IP script.
- **NOTE:** Mirror structure of `scan_honeywell_ip.sh` which is good for consistency.

**Status: COMPLETE**

---

### Chunk 25 — `scan_honeywell_shodan.sh` Lines 45-154
**Variable initialisation and argument parsing**

```bash
LIMIT=${1:-100}
CUSTOM_QUERY=""
...
# parsing args (kinda messy but works)
if [[ "$2" == "--"* ]]; then
  ...
elif [[ -n "$2" && "$2" != "--"* ]]; then
  CUSTOM_QUERY="$2"
  ...
fi
```

**Comments & Issues:**

- **BUG (Argument parsing is broken for multiple flags):** The argument parsing on lines 59-153 is deeply flawed. It only handles the **second** argument (`$2`) with manual if/elif chains, and only checks for **one** option after the custom query. If you pass multiple flags like `./scan_honeywell_shodan.sh 100 --check-vulns --notify`, only `--check-vulns` would be processed from this section. The comment "kinda messy but works" is accurate about the messy part, less so about the works part.
- **ISSUE (Help text duplicated 3 times):** The help text is copy-pasted identically in three places within this file (lines 78-101, lines 127-151, and later in the while loop at lines 183-207). Massive code duplication.
- **ISSUE (Shift confusion):** The `shift` on line 103 happens outside the if/elif block and shifts regardless of which branch was taken. Combined with `shift` calls inside some branches (lines 74, 76), this can cause arguments to be skipped.
- **NOTE:** This parsing approach is significantly more error-prone than the IP script's clean `while` loop. Should be refactored to use a proper getopts or while-case pattern throughout.

**Status: COMPLETE**

---

### Chunk 26 — `scan_honeywell_shodan.sh` Lines 155-261
**Leftover args parsing, venv setup, .env loading, notification setup**

```bash
# grab any leftover args
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    ...
  esac
  shift
done

# fire up the venv
...
# load API key
...
# notification sound setup
...
```

**Comments & Issues:**

- **NOTE:** The `while` loop on lines 157-210 is the "catch-all" parser that handles remaining arguments. This is where most flags will actually be parsed (since the earlier section only handles a few).
- **ISSUE (Same venv/notification issues):** Same problems as `scan_honeywell_ip.sh` - Linux-only venv path, `source .env` security concern, Linux-only audio tools.
- **GOOD:** Proper API key check with helpful error message (lines 237-241).
- **GOOD:** Unlimited mode mapping `LIMIT` to `999999` is a pragmatic approach.
- **NOTE:** The "gonna show you all the details" and "gonna scan ALL the results" messages are informal but charming.

**Status: COMPLETE**

---

### Chunk 27 — `scan_honeywell_shodan.sh` Lines 262-386
**Scan logic - default Honeywell query with pagination**

```bash
if [ -z "$CUSTOM_QUERY" ]; then
  ...
  if [ -n "$UNLIMITED" ]; then
    PAGE=1
    FOUND_RESULTS=true
    while $FOUND_RESULTS; do
      ...
      python3 ... --page $PAGE ...
      ...
    done
  else
    python3 ... --limit "$LIMIT" ...
  fi
fi
```

**Comments & Issues:**

- **BUG (--page not supported by Python script):** Lines 320 and 367 pass `--page $PAGE` to the Python script, but `argparse` in `main()` does **not define a `--page` argument**. This will cause `argparse` to print an error and exit. The unlimited pagination feature is completely broken.
- **BUG (Exit code 2 convention undocumented):** Line 358 checks for `RETURN_CODE -eq 2` as "no more results" but the Python script never explicitly returns exit code 2. `search_shodan()` returns an empty list on error but `main()` just returns normally (exit code 0). Pagination would never terminate.
- **ISSUE (Notification sound duplication):** The notification logic (lines 326-354) is duplicated almost verbatim between the unlimited and non-unlimited branches, and between the default-query and custom-query sections. This is a lot of copy-paste.
- **NOTE:** The `/tmp/camera_count.txt` tracking mechanism for detecting new cameras across pages is clever but fragile (not cleaned up between runs).

**Status: COMPLETE**

---

### Chunk 28 — `scan_honeywell_shodan.sh` Lines 387-486
**Scan logic - custom query with pagination**

```bash
else
  echo "Starting Shodan scan with custom query: '$CUSTOM_QUERY' (limit: $LIMIT)"
  ...
```

**Comments & Issues:**

- **BUG (Same --page bug):** Lines 419 and 466 pass `--page` which isn't supported by the Python argparser.
- **ISSUE (Near-identical code):** This entire section (lines 387-486) is nearly a **copy-paste** of lines 262-386 with the only difference being the addition of `--query "$CUSTOM_QUERY"`. This is ~100 lines of duplicated code. Should be refactored to share the scanning logic between default and custom query paths.
- **NOTE:** Same notification duplication issues as Chunk 27.

**Status: COMPLETE**

---

### Chunk 29 — `scan_honeywell_shodan.sh` Lines 487-523
**Results summary and final output**

```bash
# show the results
if [ -f "$LOG_DIR/working_cameras.txt" ]; then
  CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
  ...
fi

# show vuln report if requested
...

# show summary
echo "All results saved to: $RESULTS_FILE"
```

**Comments & Issues:**

- **ISSUE (working_cameras.txt never created):** The Python script populates a `working_ips` list but **never writes** `working_cameras.txt`. The shell script checks for this file's existence but it will never exist. This means the results summary will always show "No working cameras found. Bummer."
- **ISSUE (vulnerable_cameras.json never created):** Similarly, vulnerability checking is not implemented, so `vulnerable_cameras.json` will never exist.
- **NOTE:** The summary section is well-structured and would work correctly if the Python script actually wrote the expected output files.
- **GOOD:** Clear final output with results file location.

**Status: COMPLETE**

---

## Overall Summary

### Critical Bugs

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| 1 | **CRITICAL** | `honeycam_scanner.py:406` | `KeyError: 'rtsp_port'` - `.format()` call missing `rtsp_port` parameter. Will crash when testing URL patterns. |
| 2 | **CRITICAL** | `scan_honeywell_shodan.sh:320,367,419,466` | `--page` argument passed to Python script but not defined in `argparse`. Unlimited pagination is completely broken. |
| 3 | **HIGH** | `honeycam_scanner.py:713-715` | Runtime modification of function `__defaults__` is dangerous and fragile. |
| 4 | **HIGH** | `honeycam_scanner.py:799-848` | Shodan scan branch never saves results to file. No output is written. |
| 5 | **HIGH** | `requirements.txt:21` | `futures` package is Python 2 only. Will fail or conflict on Python 3. |

### Dead Code / Unimplemented Features

| Feature | Declared In | Status |
|---------|------------|--------|
| `--check-vulns` | argparse, shell scripts | **Not implemented** - no vulnerability checking code exists |
| `--exploit CVE` | argparse, shell scripts | **Not implemented** - no exploit code exists |
| `--verbose` | argparse, shell scripts | **Not implemented** - no verbosity control exists |
| `--notify` (Python) | argparse | **Not implemented** - `play_notification_sound()` is never called |
| `--output-list` | argparse | **Not implemented** - never used |
| `detect_camera_ports()` | `honeycam_scanner.py` | **Never called** |
| `play_notification_sound()` | `honeycam_scanner.py` | **Never called** |
| `CVE_DATABASE_FILE` | `honeycam_scanner.py` | **Never used** |
| `ThreadPoolExecutor` import | `honeycam_scanner.py` | **Never used** |
| `working_cameras.txt` | Shell scripts expect it | **Never created** by Python script |

### Unused Dependencies

The following packages in `requirements.txt` are never imported:
- `python-dotenv`
- `pillow`
- `matplotlib`
- `imutils`
- `pycryptodome`
- `pyOpenSSL`
- `futures` (also incompatible with Python 3)

### Documentation Issues

- README port lists don't match actual code
- README references `vulnerable_cameras.json` output that's never created
- Placeholder GitHub URL in README
- `.env.example` contains unused variable templates

### Shell Script Issues

- Both shell scripts use Linux-only paths (`venv/bin/activate`) - won't work on Windows
- `source .env` is insecure (executes .env as a shell script)
- `scan_honeywell_shodan.sh` has a badly structured argument parser with massive code duplication (~100 lines of near-identical code between default and custom query paths)
- Help text is duplicated 3 times in `scan_honeywell_shodan.sh`
- Notification sound handling is Linux-only in shell scripts

### Positive Observations

- Core RTSP stream checking with socket pre-check and threaded timeout is well-designed
- Channel enumeration logic is thorough (HTTP endpoint check + RTSP probing fallback)
- `.gitignore` is comprehensive and correct
- Credential handling is reasonably secure (only default creds, no credential storage)
- Directory structure is clean with separate `logs/` and `captures/` directories
- The overall architecture and approach is sound - the issues are mostly in implementation gaps and integration between components

---

## Fix Tracker (Ordered by Severity)

| # | Severity | Fix Description | Status |
|---|----------|----------------|--------|
| F1 | **CRITICAL** | Fix `KeyError: 'rtsp_port'` in `test_camera_urls()` — `.format()` calls missing `rtsp_port`/`http_port` params | COMPLETE |
| F2 | **CRITICAL** | Add missing `--page` argument to `argparse` in `main()` | COMPLETE |
| F3 | **HIGH** | Remove dangerous `__defaults__` mutation — pass `timeout` explicitly to all calls | COMPLETE |
| F4 | **HIGH** | Fix Shodan branch to save results to file + write `working_cameras.txt` | COMPLETE |
| F5 | **HIGH** | Fix `requirements.txt` — remove `futures`, remove all unused dependencies | COMPLETE |
| F6 | **HIGH** | Clean up imports — remove unused (`ThreadPoolExecutor`, `signal`), move `socket`/`threading` to top | COMPLETE |
| F7 | **HIGH** | Fix `ensure_dir()` race condition — use `os.makedirs(exist_ok=True)` | COMPLETE |
| F8 | **HIGH** | Wire up `--notify` to call `play_notification_sound()`, wire `--output-list`, use `detect_camera_ports()` in Shodan, remove dead `CVE_DATABASE_FILE` | COMPLETE |
| F9 | **MEDIUM** | Fix fragile separate `.format()` calls — combine into single call; increase HTTP timeout | COMPLETE |
| F10 | **MEDIUM** | Fix `.env.example`, README port lists, placeholder GitHub URL, unimplemented feature docs | COMPLETE |
| F11 | **MEDIUM** | Rewrite `scan_honeywell_shodan.sh` arg parser — remove code duplication, deduplicate help text | COMPLETE |
| F12 | **MEDIUM** | Fix shell scripts for cross-platform venv activation + secure `.env` loading | COMPLETE |
| F13 | **LOW** | PEP 8 import grouping, `.gitignore` add `*.log`, update outdated Chrome User-Agent | COMPLETE |

---

## Fix Details

### F1 — CRITICAL: KeyError 'rtsp_port' in test_camera_urls()
**Problem:** `.format(ip=ip, channel=channel)` was called on patterns containing `{rtsp_port}` and `{http_port}` placeholders, causing a `KeyError` crash.
**Fix:** Added `fmt_rtsp_port` and `fmt_http_port` variables at the top of `test_camera_urls()` and passed them to all `.format()` calls: `.format(ip=ip, channel=channel, rtsp_port=fmt_rtsp_port)` and `.format(..., http_port=fmt_http_port)`.

### F2 — CRITICAL: Missing --page argument
**Problem:** Shell scripts passed `--page N` to the Python script, but `argparse` did not define a `--page` argument, causing an unrecognised argument error.
**Fix:** Added `parser.add_argument('--page', type=int, default=1, ...)` and wired `args.page` into the `search_shodan()` call.

### F3 — HIGH: Dangerous __defaults__ mutation
**Problem:** `main()` modified `check_rtsp_stream.__defaults__` and `check_http_stream.__defaults__` at runtime to set timeout, which is fragile and thread-unsafe.
**Fix:** Removed the `__defaults__` mutation entirely. Timeout is already passed explicitly via `timeout=args.timeout` in all call sites.

### F4 — HIGH: Shodan branch never saves results
**Problem:** The Shodan scanning loop collected results but never wrote them to files. `working_cameras.txt` was never created, breaking shell script summaries.
**Fix:** Added per-IP result file writing in the Shodan branch, integrated `detect_camera_ports()` for port detection, added `--result-file` appending with summary, and added `working_cameras.txt` output at the end of both branches (using `--output-list` if provided).

### F5 — HIGH: requirements.txt had Python 2 and unused packages
**Problem:** `futures>=3.1.1` is a Python 2 backport that fails on Python 3. Six other packages were never imported.
**Fix:** Reduced to only the three actually-used third-party packages: `opencv-python`, `requests`, `shodan`.

### F6 — HIGH: Unused and mis-placed imports
**Problem:** `ThreadPoolExecutor`, `as_completed`, and `signal` were imported but never used. `socket` and `threading` were imported inside functions.
**Fix:** Removed unused imports, moved `socket` and `threading` to top-level, grouped imports per PEP 8 (stdlib / third-party).

### F7 — HIGH: ensure_dir() race condition
**Problem:** `os.path.exists()` + `os.makedirs()` has a TOCTOU race condition.
**Fix:** Replaced with `os.makedirs(directory, exist_ok=True)`.

### F8 — HIGH: Dead code and unwired features
**Problem:** `play_notification_sound()` and `detect_camera_ports()` were defined but never called. `CVE_DATABASE_FILE` was unused. `--notify` and `--output-list` flags had no effect.
**Fix:** Wired `play_notification_sound()` to `--notify` in both IP and Shodan branches. Wired `detect_camera_ports()` in Shodan branch. Wired `--output-list` to `working_cameras.txt` output. Removed `CVE_DATABASE_FILE`. Removed `--check-vulns`, `--exploit`, `--verbose` args (no implementation exists).

### F9 — MEDIUM: Fragile .format() calls and aggressive HTTP timeout
**Problem:** Separate `.format(ip=ip)` then `.format(channel=channel)` calls were fragile. HTTP timeout of 1 second was too aggressive.
**Fix:** Combined into single `.format(ip=ip, channel=channel)` calls. Increased HTTP default timeout to 5 seconds.

### F10 — MEDIUM: Documentation issues
**Problem:** README had wrong port lists, placeholder GitHub URL, references to unimplemented features. `.env.example` had unused variable templates.
**Fix:** Updated README port lists to match actual code. Replaced placeholder URL. Removed `--check-vulns`/`--exploit`/`--verbose` from docs. Removed `vulnerable_cameras.json` reference. Cleaned `.env.example` to only contain `SHODAN_API_KEY`.

### F11 — MEDIUM: scan_honeywell_shodan.sh massive code duplication
**Problem:** ~100 lines of near-identical scan logic duplicated between default and custom query paths. Help text duplicated 3 times. Argument parsing was fragile.
**Fix:** Complete rewrite. Single `show_help()` function. Proper positional + named argument parsing with `while/case`. Single `run_scan()` function shared by both query paths. Eliminated all code duplication.

### F12 — MEDIUM: Shell scripts Linux-only, insecure .env loading
**Problem:** `venv/bin/activate` is Linux-only (Windows uses `venv/Scripts/activate`). `source .env` executes the file as a shell script (security risk).
**Fix:** Both scripts now detect platform by checking for `venv/Scripts/activate` (Windows) vs `venv/bin/activate` (Unix). Replaced `source .env` with safe line-by-line parsing using `while IFS='=' read`. Removed `--check-vulns`/`--exploit`/`--verbose` from IP script too.

### F13 — LOW: PEP 8, .gitignore, User-Agent
**Problem:** Imports not grouped per PEP 8. No `*.log` in `.gitignore`. Chrome 91 User-Agent is from 2021.
**Fix:** Imports grouped (done in F6). Added `*.log` to `.gitignore`. Updated User-Agent to Chrome 121.
