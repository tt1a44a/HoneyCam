#!/bin/bash

# Honeycam Scanner - Shodan Search Tool
# Usage: ./scan_honeywell_shodan.sh [limit] [custom_query] [OPTIONS]
# limit = max results to process (default: 100, ignored with --unlimited)
# custom_query = Shodan search query (default: searches for Honeywell cameras)

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
  echo "Honeycam Scanner - Shodan Search Tool"
  echo "===================================="
  echo "Usage: $0 [limit] [custom_query] [OPTIONS]"
  echo ""
  echo "Parameters:"
  echo "  limit           Maximum number of results to process (default: 100)"
  echo "  custom_query    Custom Shodan search query (default: searches for Honeywell cameras)"
  echo ""
  echo "Options:"
  echo "  --rtsp-port PORT   Specify custom RTSP port"
  echo "  --http-port PORT   Specify custom HTTP port"
  echo "  --until-success    Stop after finding the first working camera"
  echo "  --unlimited        Process all available Shodan results"
  echo "  --notify           Play a sound when cameras are found"
  echo "  --timeout SEC      Set connection timeout in seconds (default: 5)"
  echo "  --help, -h         Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0 50"
  echo "  $0 500 \"product:hikvision country:us\" --unlimited --notify"
  echo ""
  exit 0
}

# Check for help flag as first arg
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
  show_help
fi

# --- Parse positional arguments first ---
LIMIT=100
CUSTOM_QUERY=""

# First positional arg: limit (if it's a number)
if [[ -n "$1" && "$1" != "--"* ]]; then
  LIMIT="$1"
  shift
fi

# Second positional arg: custom query (if not a flag)
if [[ -n "$1" && "$1" != "--"* ]]; then
  CUSTOM_QUERY="$1"
  shift
fi

# --- Parse named options ---
UNTIL_SUCCESS=""
UNLIMITED=""
RTSP_PORT=""
HTTP_PORT=""
AUTO_DETECT="--auto-detect-ports"
NOTIFY=""
TIMEOUT="--timeout 5"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --until-success)
      UNTIL_SUCCESS="--until-success"
      ;;
    --unlimited)
      UNLIMITED="--unlimited"
      ;;
    --notify)
      NOTIFY="--notify"
      ;;
    --rtsp-port)
      RTSP_PORT="--rtsp-port $2"
      AUTO_DETECT=""
      shift
      ;;
    --http-port)
      HTTP_PORT="--http-port $2"
      shift
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

# --- Virtual environment setup ---
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

# --- Load API key from .env ---
API_KEY=""
if [ -f "$SCRIPT_DIR/.env" ]; then
  while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
    # Trim whitespace
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    if [ "$key" == "SHODAN_API_KEY" ]; then
      API_KEY="$value"
    fi
  done < "$SCRIPT_DIR/.env"
fi

if [ -z "$API_KEY" ]; then
  echo "ERROR: No Shodan API key found. Please create a .env file with your SHODAN_API_KEY."
  echo "You can copy the .env.example file to .env and add your key there."
  exit 1
fi

# --- Unlimited mode ---
if [ -n "$UNLIMITED" ]; then
  LIMIT="999999"
  echo "Unlimited mode - scanning all available Shodan results"
fi

# --- Port detection info ---
if [ -n "$AUTO_DETECT" ]; then
  echo "Auto-detecting ports from Shodan data"
else
  echo "Using manual ports (auto-detection off)"
fi

# --- Create results file header ---
echo "====================================================" > "$RESULTS_FILE"
echo "Honeycam Scanner Run - $TIMESTAMP" >> "$RESULTS_FILE"
echo "====================================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Build query display ---
if [ -z "$CUSTOM_QUERY" ]; then
  echo "Starting Shodan scan for Honeywell cameras (limit: $LIMIT)"
  echo "Starting Shodan scan for Honeywell cameras (limit: $LIMIT)" >> "$RESULTS_FILE"
else
  echo "Starting Shodan scan with custom query: '$CUSTOM_QUERY' (limit: $LIMIT)"
  echo "Starting Shodan scan with custom query: '$CUSTOM_QUERY' (limit: $LIMIT)" >> "$RESULTS_FILE"
fi

if [ -n "$UNTIL_SUCCESS" ]; then
  echo "Will stop after finding first working camera"
  echo "Will stop after finding first working camera" >> "$RESULTS_FILE"
fi
if [ -n "$RTSP_PORT" ]; then
  echo "Using custom RTSP port: ${RTSP_PORT#*--rtsp-port }"
  echo "Using custom RTSP port: ${RTSP_PORT#*--rtsp-port }" >> "$RESULTS_FILE"
fi
if [ -n "$HTTP_PORT" ]; then
  echo "Using custom HTTP port: ${HTTP_PORT#*--http-port }"
  echo "Using custom HTTP port: ${HTTP_PORT#*--http-port }" >> "$RESULTS_FILE"
fi
echo "" >> "$RESULTS_FILE"

# --- Run the scan (shared logic for default and custom queries) ---
run_scan() {
  local page_arg="$1"
  python3 "$SCRIPT_DIR/honeycam_scanner.py" \
    --api-key "$API_KEY" \
    --save-frames \
    --limit "$LIMIT" \
    $page_arg \
    $TIMEOUT \
    --enum-channels \
    $UNTIL_SUCCESS \
    $RTSP_PORT \
    $HTTP_PORT \
    $AUTO_DETECT \
    $NOTIFY \
    ${CUSTOM_QUERY:+--query "$CUSTOM_QUERY"} \
    --result-file "$RESULTS_FILE"
}

if [ -n "$UNLIMITED" ]; then
  # Paginated scanning
  PAGE=1
  FOUND_RESULTS=true

  while $FOUND_RESULTS; do
    echo "==== Scanning Shodan page $PAGE ===="
    echo "==== Scanning Shodan page $PAGE ====" >> "$RESULTS_FILE"

    run_scan "--page $PAGE"
    RETURN_CODE=$?

    if [ $RETURN_CODE -eq 2 ]; then
      FOUND_RESULTS=false
      echo "No more results on Shodan. Search complete."
      echo "No more results on Shodan. Search complete." >> "$RESULTS_FILE"
    else
      PAGE=$((PAGE+1))
    fi
  done
else
  # Single page scan
  run_scan ""
fi

# --- Show results ---
WORKING_FILE="$LOG_DIR/working_cameras.txt"
if [ -f "$WORKING_FILE" ]; then
  CAM_COUNT=$(wc -l < "$WORKING_FILE")
  echo ""
  echo "==================================="
  echo "Found $CAM_COUNT working camera(s):"
  echo "==================================="
  cat "$WORKING_FILE"

  echo "" >> "$RESULTS_FILE"
  echo "==================================" >> "$RESULTS_FILE"
  echo "Found $CAM_COUNT working camera(s):" >> "$RESULTS_FILE"
  echo "==================================" >> "$RESULTS_FILE"
  cat "$WORKING_FILE" >> "$RESULTS_FILE"
else
  echo "No working cameras found."
  echo "No working cameras found." >> "$RESULTS_FILE"
fi

echo ""
echo "All results saved to: $RESULTS_FILE"
echo ""
echo "==================================" >> "$RESULTS_FILE"
echo "Scan completed on $(date)" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"
