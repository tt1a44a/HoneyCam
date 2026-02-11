#!/bin/bash

# Honeycam Scanner - IP Address Scanning Tool
# Usage: ./scan_honeywell_ip.sh <ip_address> [OPTIONS]

# Script locations
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_DIR="$SCRIPT_DIR/logs"
CAPTURE_DIR="$SCRIPT_DIR/captures"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="$LOG_DIR/camera_results_$TIMESTAMP.txt"

# Make sure our directories exist
mkdir -p "$LOG_DIR" "$CAPTURE_DIR"

# --- Help text function (single definition) ---
show_help() {
  echo "Honeycam Scanner - IP Address Scanning Tool"
  echo "=========================================="
  echo "Usage: $0 <ip_address> [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --rtsp-port PORT   Specify RTSP port to use"
  echo "  --http-port PORT   Specify HTTP port to use"
  echo "  --notify           Play a sound when camera is found"
  echo "  --timeout SEC      Set connection timeout in seconds (default: 5)"
  echo "  --help, -h         Show this help message"
  echo ""
  echo "Example:"
  echo "  $0 192.168.1.100 --rtsp-port 554 --http-port 80"
  echo ""
  exit 0
}

# Check for help flag
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
  show_help
fi

# Check if IP address is provided
if [ -z "$1" ]; then
  echo "ERROR: No IP address provided"
  echo "Usage: $0 <ip_address> [OPTIONS]"
  echo "Run '$0 --help' for full options."
  exit 1
fi

# Get IP address
IP_ADDRESS="$1"
shift

# --- Parse arguments ---
RTSP_PORT=""
HTTP_PORT=""
NOTIFY=""
TIMEOUT="--timeout 5"
AUTO_DETECT="--auto-detect-ports"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --rtsp-port)
      RTSP_PORT="--rtsp-port $2"
      AUTO_DETECT=""
      shift
      ;;
    --http-port)
      HTTP_PORT="--http-port $2"
      shift
      ;;
    --notify)
      NOTIFY="--notify"
      ;;
    --timeout)
      TIMEOUT="--timeout $2"
      shift
      ;;
    --help|-h)
      show_help
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
  shift
done

# --- Virtual environment setup (cross-platform) ---
if [ -d "$SCRIPT_DIR/venv" ]; then
  if [ -f "$SCRIPT_DIR/venv/Scripts/activate" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
  else
    source "$SCRIPT_DIR/venv/bin/activate"
  fi
else
  echo "Virtual environment not found. Creating one now..."
  python3 -m venv "$SCRIPT_DIR/venv" 2>/dev/null || python -m venv "$SCRIPT_DIR/venv"
  if [ -f "$SCRIPT_DIR/venv/Scripts/activate" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
  else
    source "$SCRIPT_DIR/venv/bin/activate"
  fi

  if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
  else
    echo "WARNING: requirements.txt not found. You may need to install dependencies manually."
  fi
fi

# --- Load API key from .env (secure parsing, no source) ---
API_KEY=""
if [ -f "$SCRIPT_DIR/.env" ]; then
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    if [ "$key" == "SHODAN_API_KEY" ]; then
      API_KEY="$value"
    fi
  done < "$SCRIPT_DIR/.env"
fi

# --- Port detection info ---
if [ -n "$AUTO_DETECT" ]; then
  echo "Auto-detecting ports from common ports list"
else
  echo "Using manual ports (auto-detection off)"
fi

# --- Create results file header ---
echo "====================================================" > "$RESULTS_FILE"
echo "Honeycam Scanner Run - IP: $IP_ADDRESS - $TIMESTAMP" >> "$RESULTS_FILE"
echo "====================================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

echo "Scanning IP address: $IP_ADDRESS"
echo "Scanning IP address: $IP_ADDRESS" >> "$RESULTS_FILE"

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

# --- Run the scanner ---
echo "Starting scan..."
echo "Starting scan..." >> "$RESULTS_FILE"

API_KEY_PARAM=""
if [ -n "$API_KEY" ]; then
  API_KEY_PARAM="--api-key $API_KEY"
fi

python3 "$SCRIPT_DIR/honeycam_scanner.py" \
  --ip "$IP_ADDRESS" \
  --save-frames \
  --enum-channels \
  $API_KEY_PARAM \
  $RTSP_PORT \
  $HTTP_PORT \
  $TIMEOUT \
  $AUTO_DETECT \
  $NOTIFY \
  --result-file "$RESULTS_FILE"

SCAN_RESULT=$?

# --- Process results ---
IP_RESULT_FILE="$LOG_DIR/camera_results_${IP_ADDRESS}.txt"
if [ -f "$IP_RESULT_FILE" ]; then
  WORKING_COUNT=$(grep -c "Working URL" "$IP_RESULT_FILE" 2>/dev/null || echo "0")

  echo ""
  echo "===================================="
  echo "Scan results for $IP_ADDRESS:"
  echo "===================================="

  if [ "$WORKING_COUNT" -gt 0 ]; then
    echo "Found $WORKING_COUNT working stream(s)!"
    echo "" >> "$RESULTS_FILE"
    echo "Found $WORKING_COUNT working stream(s) for $IP_ADDRESS" >> "$RESULTS_FILE"

    echo "Working URLs:" >> "$RESULTS_FILE"
    grep "Working URL" "$IP_RESULT_FILE" | sed 's/Working URL: /  /' >> "$RESULTS_FILE"
    grep "Working URL" "$IP_RESULT_FILE" | sed 's/Working URL: /  /'
  else
    echo "No working streams found."
    echo "No working streams found for $IP_ADDRESS." >> "$RESULTS_FILE"
  fi

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
