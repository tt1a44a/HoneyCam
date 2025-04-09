#!/bin/bash

# hacked together script for scanning Honeywell cams using Shodan
# usage: ./scan_honeywell_shodan.sh [limit] [custom_query] [OPTIONS]
# options: --rtsp-port, --http-port, --check-vulns, --until-success, --unlimited, --notify, --verbose
# limit = max results to process (default: 100, ignored with --unlimited)
# custom_query = whatever shodan search you want (default: looks for honeywell cams)

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
  echo "  --check-vulns      Check for known vulnerabilities"
  echo "  --until-success    Stop after finding the first working camera" 
  echo "  --unlimited        Process all available Shodan results"
  echo "  --notify           Play a sound when cameras are found"
  echo "  --verbose          Show detailed information during scanning"
  echo "  --help, -h         Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0 50 --check-vulns"
  echo "  $0 500 \"product:hikvision country:us\" --unlimited --notify"
  echo ""
  exit 0
fi

LIMIT=${1:-100}
CUSTOM_QUERY=""
CHECK_VULNS=""
EXPLOIT=""
UNTIL_SUCCESS=""
UNLIMITED=""
RTSP_PORT=""
HTTP_PORT=""
AUTO_DETECT="--auto-detect-ports"
NOTIFY="" # for notification sound
VERBOSE="" # for verbose output

# parsing args (kinda messy but works)
if [[ "$2" == "--"* ]]; then
  # if second arg starts with --, it's an option
  if [[ "$2" == "--check-vulns" ]]; then
    CHECK_VULNS="--check-vulns"
  elif [[ "$2" == "--until-success" ]]; then
    UNTIL_SUCCESS="--until-success"
  elif [[ "$2" == "--unlimited" ]]; then
    UNLIMITED="--unlimited"
  elif [[ "$2" == "--notify" ]]; then
    NOTIFY="--notify"
  elif [[ "$2" == "--verbose" ]]; then
    VERBOSE="--verbose"
  elif [[ "$2" == "--rtsp-port" ]]; then
    RTSP_PORT="--rtsp-port $3"
    AUTO_DETECT="" # turn off auto-detection for manual port
    shift
  elif [[ "$2" == "--http-port" ]]; then
    HTTP_PORT="--http-port $3"
    shift
  elif [[ "$2" == "--help" ]] || [[ "$2" == "-h" ]]; then
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
    echo "  --check-vulns      Check for known vulnerabilities"
    echo "  --until-success    Stop after finding the first working camera" 
    echo "  --unlimited        Process all available Shodan results"
    echo "  --notify           Play a sound when cameras are found"
    echo "  --verbose          Show detailed information during scanning"
    echo "  --help, -h         Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 50 --check-vulns"
    echo "  $0 500 \"product:hikvision country:us\" --unlimited --notify"
    echo ""
    exit 0
  fi
  shift
elif [[ -n "$2" && "$2" != "--"* ]]; then
  # if second arg doesn't start with --, must be a query
  CUSTOM_QUERY="$2"
  shift
  # check for more args
  if [[ -n "$2" ]]; then
    if [[ "$2" == "--check-vulns" ]]; then
      CHECK_VULNS="--check-vulns"
    elif [[ "$2" == "--until-success" ]]; then
      UNTIL_SUCCESS="--until-success"
    elif [[ "$2" == "--unlimited" ]]; then
      UNLIMITED="--unlimited"
    elif [[ "$2" == "--notify" ]]; then
      NOTIFY="--notify"
    elif [[ "$2" == "--verbose" ]]; then
      VERBOSE="--verbose"
    elif [[ "$2" == "--rtsp-port" ]]; then
      RTSP_PORT="--rtsp-port $3"
      AUTO_DETECT="" # turn off auto-detection for manual port
      shift
    elif [[ "$2" == "--http-port" ]]; then
      HTTP_PORT="--http-port $3"
      shift
    elif [[ "$2" == "--help" ]] || [[ "$2" == "-h" ]]; then
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
      echo "  --check-vulns      Check for known vulnerabilities"
      echo "  --until-success    Stop after finding the first working camera" 
      echo "  --unlimited        Process all available Shodan results"
      echo "  --notify           Play a sound when cameras are found"
      echo "  --verbose          Show detailed information during scanning"
      echo "  --help, -h         Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0 50 --check-vulns"
      echo "  $0 500 \"product:hikvision country:us\" --unlimited --notify"
      echo ""
      exit 0
    fi
    shift
  fi
fi

# grab any leftover args
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --check-vulns)
      CHECK_VULNS="--check-vulns"
      ;;
    --until-success)
      UNTIL_SUCCESS="--until-success"
      ;;
    --unlimited)
      UNLIMITED="--unlimited"
      ;;
    --notify)
      NOTIFY="--notify"
      ;;
    --verbose)
      VERBOSE="--verbose"
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
    --help|-h)
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
      echo "  --check-vulns      Check for known vulnerabilities"
      echo "  --until-success    Stop after finding the first working camera" 
      echo "  --unlimited        Process all available Shodan results"
      echo "  --notify           Play a sound when cameras are found"
      echo "  --verbose          Show detailed information during scanning"
      echo "  --help, -h         Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0 50 --check-vulns"
      echo "  $0 500 \"product:hikvision country:us\" --unlimited --notify"
      echo ""
      exit 0
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

# load API key from .env if it exists
API_KEY=""
if [ -f "$SCRIPT_DIR/.env" ]; then
  # Source the .env file if it exists
  source "$SCRIPT_DIR/.env"
  API_KEY="$SHODAN_API_KEY"
fi

# Check if we have an API key
if [ -z "$API_KEY" ]; then
  echo "ERROR: No Shodan API key found. Please create a .env file with your SHODAN_API_KEY."
  echo "You can copy the .env.example file to .env and add your key there."
  exit 1
fi

# setup notification sound if requested
if [ -n "$NOTIFY" ]; then
  # make sure we have the tools we need
  if ! command -v play &> /dev/null && ! command -v paplay &> /dev/null && ! command -v aplay &> /dev/null; then
    echo "WARNING: Can't play notification sounds. Install sox, pulseaudio or alsa-utils."
    NOTIFY=""
  else
    echo "Notification sounds enabled - will make noise when cameras found"
    
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

# unlimited mode = big number
if [ -n "$UNLIMITED" ]; then
  LIMIT="999999"
  echo "Unlimited mode - gonna scan ALL the results til we run outta Shodan data"
fi

# tell user bout port detection
if [ -n "$AUTO_DETECT" ]; then
  echo "Auto-detecting ports from Shodan data"
else
  echo "Using manual ports (auto-detection off)"
fi

# verbose mode info
if [ -n "$VERBOSE" ]; then
  echo "Verbose mode ON - gonna show you all the details"
fi

# Create the run header in the results file
echo "====================================================" > "$RESULTS_FILE"
echo "Honeycam Scanner Run - $TIMESTAMP" >> "$RESULTS_FILE"
echo "====================================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# actual scan logic starts here
if [ -z "$CUSTOM_QUERY" ]; then
  echo "Starting Shodan scan for Honeywell cams (limit: $LIMIT)"
  echo "Starting Shodan scan for Honeywell cams (limit: $LIMIT)" >> "$RESULTS_FILE"
  
  if [ -n "$CHECK_VULNS" ]; then
    echo "Checking for vulns too"
    echo "Checking for vulnerabilities" >> "$RESULTS_FILE"
  fi
  if [ -n "$UNTIL_SUCCESS" ]; then
    echo "Will stop after finding first working cam"
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
  
  if [ -n "$UNLIMITED" ]; then
    # start with page 1 and keep going til we run dry
    PAGE=1
    FOUND_RESULTS=true
    
    while $FOUND_RESULTS; do
      echo "==== Scanning Shodan page $PAGE ===="
      echo "==== Scanning Shodan page $PAGE ====" >> "$RESULTS_FILE"
      
      python3 "$SCRIPT_DIR/honeycam_scanner.py" --api-key "$API_KEY" --save-frames --limit 100 --page $PAGE --timeout 5 --enum-channels $CHECK_VULNS $EXPLOIT $UNTIL_SUCCESS $RTSP_PORT $HTTP_PORT $AUTO_DETECT $NOTIFY $VERBOSE --result-file "$RESULTS_FILE"
      
      # check return code
      RETURN_CODE=$?
      
      # play notification if any camera was found
      if [ -n "$NOTIFY" ] && [ $RETURN_CODE -eq 0 ]; then
        PREV_CAM_COUNT=0
        if [ -f "/tmp/camera_count.txt" ]; then
          PREV_CAM_COUNT=$(cat /tmp/camera_count.txt)
        fi
        
        # count current working cameras
        CURR_CAM_COUNT=0
        if [ -f "$LOG_DIR/working_cameras.txt" ]; then
          CURR_CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
        fi
        
        # save current count
        echo $CURR_CAM_COUNT > /tmp/camera_count.txt
        
        # play sound if we found new cameras
        if [ $CURR_CAM_COUNT -gt $PREV_CAM_COUNT ]; then
          echo "!!! FOUND NEW CAMERA(S) !!!"
          echo "!!! FOUND NEW CAMERA(S) !!!" >> "$RESULTS_FILE"
          
          # try different sound players
          if command -v play &> /dev/null; then
            play /tmp/camera_found.wav > /dev/null 2>&1 &
          elif command -v paplay &> /dev/null; then
            paplay /tmp/camera_found.wav > /dev/null 2>&1 &
          elif command -v aplay &> /dev/null; then
            aplay /tmp/camera_found.wav > /dev/null 2>&1 &
          fi
        fi
      fi
      
      # check if no more results
      if [ $RETURN_CODE -eq 2 ]; then
        FOUND_RESULTS=false
        echo "No more results on Shodan. We're done here."
        echo "No more results on Shodan. Search complete." >> "$RESULTS_FILE"
      else
        PAGE=$((PAGE+1))
      fi
    done
  else
    python3 "$SCRIPT_DIR/honeycam_scanner.py" --api-key "$API_KEY" --save-frames --limit "$LIMIT" --timeout 5 --enum-channels $CHECK_VULNS $EXPLOIT $UNTIL_SUCCESS $RTSP_PORT $HTTP_PORT $AUTO_DETECT $NOTIFY $VERBOSE --result-file "$RESULTS_FILE"
    
    # play notification if configured and camera found
    if [ -n "$NOTIFY" ] && [ $? -eq 0 ] && [ -f "$LOG_DIR/working_cameras.txt" ]; then
      CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
      if [ $CAM_COUNT -gt 0 ]; then
        echo "!!! FOUND CAMERA(S) !!!"
        echo "!!! FOUND CAMERA(S) !!!" >> "$RESULTS_FILE"
        
        # try different sound players
        if command -v play &> /dev/null; then
          play /tmp/camera_found.wav > /dev/null 2>&1 &
        elif command -v paplay &> /dev/null; then
          paplay /tmp/camera_found.wav > /dev/null 2>&1 &
        elif command -v aplay &> /dev/null; then
          aplay /tmp/camera_found.wav > /dev/null 2>&1 &
        fi
      fi
    fi
  fi
else
  echo "Starting Shodan scan with custom query: '$CUSTOM_QUERY' (limit: $LIMIT)"
  echo "Starting Shodan scan with custom query: '$CUSTOM_QUERY' (limit: $LIMIT)" >> "$RESULTS_FILE"
  
  if [ -n "$CHECK_VULNS" ]; then
    echo "Checking for vulns too"
    echo "Checking for vulnerabilities" >> "$RESULTS_FILE"
  fi
  if [ -n "$UNTIL_SUCCESS" ]; then
    echo "Will stop after finding first working cam"
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
  
  if [ -n "$UNLIMITED" ]; then
    # start with page 1 and keep going til we run dry
    PAGE=1
    FOUND_RESULTS=true
    
    while $FOUND_RESULTS; do
      echo "==== Scanning Shodan page $PAGE (query: '$CUSTOM_QUERY') ===="
      echo "==== Scanning Shodan page $PAGE (query: '$CUSTOM_QUERY') ====" >> "$RESULTS_FILE"
      
      python3 "$SCRIPT_DIR/honeycam_scanner.py" --api-key "$API_KEY" --save-frames --limit 100 --page $PAGE --timeout 5 --query "$CUSTOM_QUERY" --enum-channels $CHECK_VULNS $EXPLOIT $UNTIL_SUCCESS $RTSP_PORT $HTTP_PORT $AUTO_DETECT $NOTIFY $VERBOSE --result-file "$RESULTS_FILE"
      
      # check return code
      RETURN_CODE=$?
      
      # play notification if any camera was found
      if [ -n "$NOTIFY" ] && [ $RETURN_CODE -eq 0 ]; then
        PREV_CAM_COUNT=0
        if [ -f "/tmp/camera_count.txt" ]; then
          PREV_CAM_COUNT=$(cat /tmp/camera_count.txt)
        fi
        
        # count current working cameras
        CURR_CAM_COUNT=0
        if [ -f "$LOG_DIR/working_cameras.txt" ]; then
          CURR_CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
        fi
        
        # save current count
        echo $CURR_CAM_COUNT > /tmp/camera_count.txt
        
        # play sound if we found new cameras
        if [ $CURR_CAM_COUNT -gt $PREV_CAM_COUNT ]; then
          echo "!!! FOUND NEW CAMERA(S) !!!"
          echo "!!! FOUND NEW CAMERA(S) !!!" >> "$RESULTS_FILE"
          
          # try different sound players
          if command -v play &> /dev/null; then
            play /tmp/camera_found.wav > /dev/null 2>&1 &
          elif command -v paplay &> /dev/null; then
            paplay /tmp/camera_found.wav > /dev/null 2>&1 &
          elif command -v aplay &> /dev/null; then
            aplay /tmp/camera_found.wav > /dev/null 2>&1 &
          fi
        fi
      fi
      
      # check if no more results
      if [ $RETURN_CODE -eq 2 ]; then
        FOUND_RESULTS=false
        echo "No more results on Shodan. We're done here."
        echo "No more results on Shodan. Search complete." >> "$RESULTS_FILE"
      else
        PAGE=$((PAGE+1))
      fi
    done
  else
    python3 "$SCRIPT_DIR/honeycam_scanner.py" --api-key "$API_KEY" --save-frames --limit "$LIMIT" --timeout 5 --query "$CUSTOM_QUERY" --enum-channels $CHECK_VULNS $EXPLOIT $UNTIL_SUCCESS $RTSP_PORT $HTTP_PORT $AUTO_DETECT $NOTIFY $VERBOSE --result-file "$RESULTS_FILE"
    
    # play notification if configured and camera found
    if [ -n "$NOTIFY" ] && [ $? -eq 0 ] && [ -f "$LOG_DIR/working_cameras.txt" ]; then
      CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
      if [ $CAM_COUNT -gt 0 ]; then
        echo "!!! FOUND CAMERA(S) !!!"
        echo "!!! FOUND CAMERA(S) !!!" >> "$RESULTS_FILE"
        
        # try different sound players
        if command -v play &> /dev/null; then
          play /tmp/camera_found.wav > /dev/null 2>&1 &
        elif command -v paplay &> /dev/null; then
          paplay /tmp/camera_found.wav > /dev/null 2>&1 &
        elif command -v aplay &> /dev/null; then
          aplay /tmp/camera_found.wav > /dev/null 2>&1 &
        fi
      fi
    fi
  fi
fi

# show the results
if [ -f "$LOG_DIR/working_cameras.txt" ]; then
  CAM_COUNT=$(wc -l < "$LOG_DIR/working_cameras.txt")
  echo ""
  echo "==================================="
  echo "Found $CAM_COUNT working camera(s):"
  echo "==================================="
  cat "$LOG_DIR/working_cameras.txt"
  
  echo "" >> "$RESULTS_FILE"
  echo "==================================" >> "$RESULTS_FILE"
  echo "Found $CAM_COUNT working camera(s):" >> "$RESULTS_FILE"
  echo "==================================" >> "$RESULTS_FILE"
  cat "$LOG_DIR/working_cameras.txt" >> "$RESULTS_FILE"
else
  echo "No working cameras found. Bummer."
  echo "No working cameras found." >> "$RESULTS_FILE"
fi

# show vuln report if requested
if [ -n "$CHECK_VULNS" ] && [ -f "$LOG_DIR/vulnerable_cameras.json" ]; then
  VULN_COUNT=$(grep -c "ip" "$LOG_DIR/vulnerable_cameras.json")
  echo ""
  echo "Found $VULN_COUNT vulnerable camera(s) - see $LOG_DIR/vulnerable_cameras.json"
  
  echo "" >> "$RESULTS_FILE"
  echo "Found $VULN_COUNT vulnerable camera(s)" >> "$RESULTS_FILE"
fi

# show summary
echo ""
echo "All results saved to: $RESULTS_FILE"
echo ""
echo "==================================" >> "$RESULTS_FILE"
echo "Scan completed on $(date)" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE" 