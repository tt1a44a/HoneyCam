# Honeycam Camera Scanner

A tool for automated discovery and testing of Honeywell and Hikvision IP cameras. Three discovery modes: scan a single IP, sweep a network with masscan, or search Shodan. Fingerprints camera vendors from RTSP/HTTP banners and tests RTSP stream URLs.

## Key Features

- **Masscan Integration**: Scan entire networks or CIDR ranges for cameras without a Shodan API key
- **Camera Fingerprinting**: Identifies Hikvision and Honeywell cameras from RTSP and HTTP banners
- **Auto-Port Detection**: Automatically detects RTSP and HTTP ports for cameras
- **Multiple Camera Protocols**: Tests various RTSP URL patterns commonly used by Honeywell/Hikvision cameras
- **Channel Enumeration**: Discovers available channels on cameras
- **Credential Testing**: Attempts default credentials
- **Frame Capture**: Can save screenshot of detected video streams
- **Flexible Searching**: Single IP, masscan network sweep, or Shodan API

## Installation

1. Clone this repository:
   ```
   git clone <your-repo-url>
   cd HoneyCam
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Install masscan for network scanning mode:
   ```bash
   # Debian/Ubuntu
   sudo apt install masscan

   # macOS
   brew install masscan

   # From source: https://github.com/robertdavidgraham/masscan
   ```

4. (Optional) Create a `.env` file with your Shodan API key:
   ```
   cp .env.example .env
   # Edit .env with your preferred text editor and add your API key
   ```

5. The shell scripts will automatically set up a virtual environment and install dependencies when first run.

## Usage

The toolkit provides two main scripts:

### 1. Scan Individual IP Address

```bash
./scan_honeywell_ip.sh <ip_address> [OPTIONS]
```

Options:
- `--rtsp-port PORT` - Specify custom RTSP port (default: auto-detect common ports)
- `--http-port PORT` - Specify custom HTTP port (default: auto-detect common ports)
- `--notify` - Play a sound when a camera is found
- `--timeout SEC` - Set connection timeout in seconds (default: 5)

Example:
```bash
./scan_honeywell_ip.sh 192.168.1.100 --rtsp-port 554 --http-port 80
```

### 2. Search Shodan for Cameras

```bash
./scan_honeywell_shodan.sh [limit] [custom_query] [OPTIONS]
```

Parameters:
- `limit` - Maximum number of results to process (default: 100)
- `custom_query` - Custom Shodan search query (default: searches for Honeywell cameras)

Options:
- `--rtsp-port PORT` - Specify custom RTSP port
- `--http-port PORT` - Specify custom HTTP port
- `--until-success` - Stop after finding the first working camera
- `--unlimited` - Process all available Shodan results
- `--notify` - Play a sound when cameras are found
- `--timeout SEC` - Set connection timeout in seconds (default: 5)

Examples:
```bash
# Search Shodan for 50 Honeywell cameras
./scan_honeywell_shodan.sh 50

# Use custom Shodan query with unlimited results
./scan_honeywell_shodan.sh 500 "product:hikvision country:us" --unlimited --notify
```

### 3. Scan a Network with Masscan

Scan a CIDR range or list of targets for cameras without needing a Shodan API key:

```bash
# Scan a local subnet
python honeycam_scanner.py --scan 192.168.1.0/24

# Scan a larger range with higher packet rate
python honeycam_scanner.py --scan 10.0.0.0/8 --rate 10000

# Scan from a file of targets (one CIDR or IP per line)
python honeycam_scanner.py --scan targets.txt

# Scan specific ports only
python honeycam_scanner.py --scan 192.168.1.0/24 --ports 554,80,8080

# Scan and save frames from working cameras
python honeycam_scanner.py --scan 192.168.1.0/24 --save-frames --notify

# Use a custom masscan path
python honeycam_scanner.py --scan 192.168.1.0/24 --masscan-path /usr/local/bin/masscan
```

Masscan options:
- `--scan TARGETS` - CIDR range, single IP, or path to a file of targets
- `--rate N` - Masscan packet rate (default: 1000)
- `--ports PORTS` - Comma-separated ports to scan (default: 554,8554,80,8080,8000,8001,8081,8888,443)
- `--masscan-path PATH` - Path to masscan binary (default: masscan)

The scan pipeline:
1. **Discovery** - masscan finds hosts with open camera ports
2. **Fingerprint** - Python probes each port via RTSP OPTIONS and HTTP GET to identify camera vendor
3. **Test** - Confirmed cameras are tested with all RTSP/HTTP URL patterns

## RTSP URL Patterns

The scanner tests various RTSP URL patterns including:
- `/h264/ch{channel}/main/av_stream`
- `/cam/realmonitor?channel={channel}&subtype=0`
- `/Streaming/Channels/{channel}01`
- `/ch{channel}/main/av_stream`
- `/live/ch{channel}`
- And more...

## Common Ports Tested

- RTSP: 554, 8554, 8000, 8002, 10554, 1935
- HTTP: 80, 8000, 8001, 8080, 8081, 8888

## Output Files

The scanner creates several files in the `logs` directory:
- `camera_results_[TIMESTAMP].txt` - Main results file for the scan run (shell scripts)
- `camera_results_[IP].txt` - Individual IP results
- `working_cameras.txt` - List of IPs with working cameras

The `captures` directory will contain frame captures from working cameras (when `--save-frames` is used).

## Using Python Script Directly

The script has three discovery modes:

```bash
# Mode 1: Test a single IP
python honeycam_scanner.py --ip 192.168.1.100 --save-frames --enum-channels

# Mode 2: Scan a network with masscan (no API key needed)
python honeycam_scanner.py --scan 192.168.1.0/24 --rate 1000

# Mode 3: Search Shodan
python honeycam_scanner.py --api-key YOUR_KEY --limit 50
```

Run `python honeycam_scanner.py --help` for full list of available options.

## Tips for Success

- Use `--auto-detect-ports` (enabled by default) to test common RTSP ports
- Shodan results are more likely to find accessible cameras
- Try different URL patterns if default ones don't work
- Be patient - scanning can take time especially with multiple channels and patterns

## Troubleshooting

- If you get "Connection refused" errors, the camera might be blocking your IP
- If you get "401 Unauthorized" errors, try different URL patterns
- If the script is very slow, try increasing the timeout value

## Known Working Configurations

Honeywell/Hikvision cameras often work with:
- RTSP Port: 554 or 10554
- URL Pattern: `/h264/ch1/main/av_stream` or `/cam/realmonitor?channel=1&subtype=0`

## License

This tool is provided for educational and research purposes only. Use responsibly and only on systems you own or have permission to test. 