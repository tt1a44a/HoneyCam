#!/bin/bash

# quick script to scan a specific IP address for Honeywell cameras
# usage: ./scan_honeywell_ip.sh <ip_address> [OPTIONS]
# options: --rtsp-port, --http-port, --check-vulns, --exploit, --notify, --verbose
# options are the same as in honeycam_scanner.py

# Script locations
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_DIR="$SCRIPT_DIR/logs"
CAPTURE_DIR="$SCRIPT_DIR/captures"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="$LOG_DIR/camera_results_$TIMESTAMP.txt"

# Make sure our directories exist
mkdir -p "$LOG_DIR" "$CAPTURE_DIR"

# Check for help flag
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
  echo "Honeycam Scanner - IP Address Scanning Tool"
  echo "=========================================="
  echo "Usage: $0 <ip_address> [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --rtsp-port PORT   Specify RTSP port to use"
  echo "  --http-port PORT   Specify HTTP port to use"
  echo "  --check-vulns      Check for known vulnerabilities"
  echo "  --exploit CVE      Run a proof-of-concept exploit for the specified CVE"
  echo "  --notify           Play a sound when camera is found"
  echo "  --verbose          Show detailed information during scanning"
  echo "  --timeout SEC      Set connection timeout in seconds (default: 5)"
  echo "  --help, -h         Show this help message"
  echo ""
  echo "Example:"
  echo "  $0 192.168.1.100 --rtsp-port 554 --http-port 80 --check-vulns"
  echo ""
  exit 0
fi

# Check if IP address is provided
if [ -z "$1" ]; then
  echo "ERROR: No IP address provided"
  echo "Usage: $0 <ip_address> [OPTIONS]"
  echo "Options:"
  echo "  --rtsp-port PORT   Specify RTSP port to use"
  echo "  --http-port PORT   Specify HTTP port to use"
  echo "  --check-vulns      Check for known vulnerabilities"
  echo "  --exploit CVE      Run a proof-of-concept exploit for the specified CVE"
  echo "  --notify           Play a sound when camera is found"
  echo "  --verbose          Show detailed information during scanning"
  echo "  --timeout SEC      Set connection timeout in seconds (default: 5)"
  echo "  --help, -h         Show this help message"
  exit 1
fi

# Get IP address
IP_ADDRESS="$1"
shift

# Initialize variables
CHECK_VULNS=""
EXPLOIT=""
RTSP_PORT=""
HTTP_PORT=""
NOTIFY=""
VERBOSE=""
TIMEOUT="--timeout 5"
AUTO_DETECT="--auto-detect-ports"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --check-vulns)
      CHECK_VULNS="--check-vulns"
      ;;
    --exploit)
      EXPLOIT="--exploit $2"
      shift
      ;;
    --rtsp-port)
      RTSP_PORT="--rtsp-port $2"
      AUTO_DETECT="" # turn off auto-detection for manual port
      shift
      ;;
    --http-port)
      HTTP_PORT="--http-port $2"
      shift
      ;;
    --notify)
      NOTIFY="--notify"
      ;;
    --verbose)
      VERBOSE="--verbose"
      ;;
    --timeout)
      TIMEOUT="--timeout $2"
      shift
      ;;
    --help|-h)
      # Already handled before
      echo "Honeycam Scanner - IP Address Scanning Tool"
      echo "=========================================="
      echo "Usage: $0 <ip_address> [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --rtsp-port PORT   Specify RTSP port to use"
      echo "  --http-port PORT   Specify HTTP port to use"
      echo "  --check-vulns      Check for known vulnerabilities"
      echo "  --exploit CVE      Run a proof-of-concept exploit for the specified CVE"
      echo "  --notify           Play a sound when camera is found"
      echo "  --verbose          Show detailed information during scanning"
      echo "  --timeout SEC      Set connection timeout in seconds (default: 5)"
      echo "  --help, -h         Show this help message"
      echo ""
      echo "Example:"
      echo "  $0 192.168.1.100 --rtsp-port 554 --http-port 80 --check-vulns"
      echo ""
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
  shift
done

# fire up the venv if it exists, or create it if it doesn't
if [ -d "$SCRIPT_DIR/venv" ]; then
  source "$SCRIPT_DIR/venv/bin/activate"
else
  echo "Virtual environment not found. Creating one now..."
  python3 -m venv "$SCRIPT_DIR/venv"
  source "$SCRIPT_DIR/venv/bin/activate"
  
  if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
  else
    echo "WARNING: requirements.txt not found. You may need to install dependencies manually."
  fi
fi

# load API key from .env if it exists (needed for vulnerability checking)
API_KEY=""
if [ -f "$SCRIPT_DIR/.env" ]; then
  # Source the .env file if it exists
  source "$SCRIPT_DIR/.env"
  API_KEY="$SHODAN_API_KEY"
fi

# setup notification sound if requested
if [ -n "$NOTIFY" ]; then
  # make sure we have the tools we need
  if ! command -v play &> /dev/null && ! command -v paplay &> /dev/null && ! command -v aplay &> /dev/null; then
    echo "WARNING: Can't play notification sounds. Install sox, pulseaudio or alsa-utils."
    NOTIFY=""
  else
    echo "Notification sounds enabled - will make noise when camera found"
    
    # create a temp notification sound file if it doesn't exist
    if [ ! -f "/tmp/camera_found.wav" ]; then
      echo "Creating notification sound file..."
      # use sox to create an annoying sound
      if command -v sox &> /dev/null; then
        sox -n /tmp/camera_found.wav synth 0.5 sine 880 vol 0.5 synth 0.5 sine 1760 vol 0.5
      fi
    fi
  fi
fi

# tell user bout port detection
if [ -n "$AUTO_DETECT" ]; then
  echo "Auto-detecting ports from common ports list"
else
  echo "Using manual ports (auto-detection off)"
fi

# verbose mode info
if [ -n "$VERBOSE" ]; then
  echo "Verbose mode ON - gonna show you all the details"
fi

# Create the run header in the results file
echo "====================================================" > "$RESULTS_FILE"
echo "Honeycam Scanner Run - IP: $IP_ADDRESS - $TIMESTAMP" >> "$RESULTS_FILE"
echo "====================================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Display info about the scan
echo "Scanning IP address: $IP_ADDRESS"
echo "Scanning IP address: $IP_ADDRESS" >> "$RESULTS_FILE"

if [ -n "$CHECK_VULNS" ]; then
  echo "Checking for vulnerabilities"
  echo "Checking for vulnerabilities" >> "$RESULTS_FILE"
fi

if [ -n "$EXPLOIT" ]; then
  CVE_ID=${EXPLOIT#*--exploit }
  echo "Attempting to exploit CVE: $CVE_ID"
  echo "Attempting to exploit CVE: $CVE_ID" >> "$RESULTS_FILE"
fi

if [ -n "$RTSP_PORT" ]; then
  PORT_NUM=${RTSP_PORT#*--rtsp-port }
  echo "Using RTSP port: $PORT_NUM"
  echo "Using RTSP port: $PORT_NUM" >> "$RESULTS_FILE"
fi

if [ -n "$HTTP_PORT" ]; then
  PORT_NUM=${HTTP_PORT#*--http-port }
  echo "Using HTTP port: $PORT_NUM"
  echo "Using HTTP port: $PORT_NUM" >> "$RESULTS_FILE"
fi

echo "" >> "$RESULTS_FILE"

# Run the scanner
echo "Starting scan..."
echo "Starting scan..." >> "$RESULTS_FILE"

# Add API key parameter if we have one
API_KEY_PARAM=""
if [ -n "$API_KEY" ]; then
  API_KEY_PARAM="--api-key $API_KEY"
fi

# Run the scanner with specified options
python3 "$SCRIPT_DIR/honeycam_scanner.py" --ip "$IP_ADDRESS" --save-frames --enum-channels $API_KEY_PARAM $CHECK_VULNS $EXPLOIT $RTSP_PORT $HTTP_PORT $TIMEOUT $AUTO_DETECT $NOTIFY $VERBOSE --result-file "$RESULTS_FILE"

# Check the scanner's exit code
SCAN_RESULT=$?

# Play notification sound if camera found
if [ -n "$NOTIFY" ] && [ $SCAN_RESULT -eq 0 ]; then
  # Check if we found any working cameras
  if [ -f "$LOG_DIR/working_cameras.txt" ] && grep -q "$IP_ADDRESS" "$LOG_DIR/working_cameras.txt"; then
    echo "!!! FOUND CAMERA !!!"
    echo "!!! FOUND CAMERA !!!" >> "$RESULTS_FILE"
    
    # Try different sound players
    if command -v play &> /dev/null; then
      play /tmp/camera_found.wav > /dev/null 2>&1 &
    elif command -v paplay &> /dev/null; then
      paplay /tmp/camera_found.wav > /dev/null 2>&1 &
    elif command -v aplay &> /dev/null; then
      aplay /tmp/camera_found.wav > /dev/null 2>&1 &
    fi
  fi
fi

# Check if the result file exists for this IP
IP_RESULT_FILE="$LOG_DIR/camera_results_${IP_ADDRESS}.txt"
if [ -f "$IP_RESULT_FILE" ]; then
  # Count working cameras
  WORKING_COUNT=$(grep -c "Working URL" "$IP_RESULT_FILE")
  
  echo ""
  echo "===================================="
  echo "Scan results for $IP_ADDRESS:"
  echo "===================================="
  
  if [ "$WORKING_COUNT" -gt 0 ]; then
    echo "Found $WORKING_COUNT working stream(s)!"
    echo "" >> "$RESULTS_FILE"
    echo "Found $WORKING_COUNT working stream(s) for $IP_ADDRESS" >> "$RESULTS_FILE"
    
    # Extract working URLs
    echo "Working URLs:" >> "$RESULTS_FILE"
    grep "Working URL" "$IP_RESULT_FILE" | sed 's/Working URL: /  /' >> "$RESULTS_FILE"
    grep "Working URL" "$IP_RESULT_FILE" | sed 's/Working URL: /  /'
  else
    echo "No working streams found."
    echo "No working streams found for $IP_ADDRESS." >> "$RESULTS_FILE"
  fi
  
  # Check vulnerability results if requested
  if [ -n "$CHECK_VULNS" ]; then
    VULN_COUNT=$(grep -c "Vulnerability detected" "$IP_RESULT_FILE")
    if [ "$VULN_COUNT" -gt 0 ]; then
      echo ""
      echo "Found $VULN_COUNT vulnerability/vulnerabilities!"
      echo "Found $VULN_COUNT vulnerability/vulnerabilities for $IP_ADDRESS" >> "$RESULTS_FILE"
      
      # Extract vulnerability info
      echo "Vulnerabilities:" >> "$RESULTS_FILE"
      grep -A 2 "Vulnerability detected" "$IP_RESULT_FILE" >> "$RESULTS_FILE"
      grep -A 2 "Vulnerability detected" "$IP_RESULT_FILE"
    fi
  fi
  
  # Copy IP-specific results to the combined results file
  cat "$IP_RESULT_FILE" >> "$RESULTS_FILE"
else
  echo "No results file found for $IP_ADDRESS"
  echo "No results file found for $IP_ADDRESS" >> "$RESULTS_FILE"
fi

echo ""
echo "Full results saved to: $RESULTS_FILE"
echo ""
echo "==================================" >> "$RESULTS_FILE"
echo "Scan completed on $(date)" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"