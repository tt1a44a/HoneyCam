# Honeycam Camera Scanner

A tool for automated discovery and testing of Honeywell IP cameras. This toolkit can scan individual IPs or leverage Shodan to find potentially accessible cameras and test various RTSP URL patterns.

## Key Features

- **Auto-Port Detection**: Automatically detects RTSP and HTTP ports for cameras
- **Multiple Camera Protocols**: Tests various RTSP URL patterns commonly used by Honeywell/Hikvision cameras
- **Channel Enumeration**: Discovers available channels on cameras
- **Credential Testing**: Attempts default credentials
- **Frame Capture**: Can save screenshot of detected video streams
- **Flexible Searching**: Can scan individual IPs or use Shodan for discovery

## Installation

1. Clone this repository:
   ```
   git clone <your-repo-url>
   cd HoneyCam
   ```

2. Create a `.env` file with your Shodan API key:
   ```
   cp .env.example .env
   # Edit .env with your preferred text editor and add your API key
   ```

3. The scripts will automatically set up a virtual environment and install dependencies when first run.

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

For advanced usage, you can run the Python script directly:

```bash
python honeycam_scanner.py --ip 192.168.1.100 --save-frames --enum-channels --notify
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