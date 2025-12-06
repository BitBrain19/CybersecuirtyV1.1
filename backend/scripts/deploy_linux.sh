#!/bin/bash
##############################
# deploy_linux.sh
# Purpose: Deploy remote_log_forwarder.py to Linux devices and create a systemd service
# Usage: sudo bash deploy_linux.sh --device-name Device01 --api-url "https://cybergard.example.com/api/v1/logs/ingest" --api-key "your_api_key_here"
##############################

set -e

# Default values
DEVICE_NAME=""
API_URL=""
API_KEY=""
CA_BUNDLE=""
SKIP_VERIFY=0
FORWARDER_PATH="/opt/cybergard/remote_log_forwarder.py"
SERVICE_NAME="cybergard-forwarder"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --device-name)
            DEVICE_NAME="$2"
            shift 2
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --ca-bundle)
            CA_BUNDLE="$2"
            shift 2
            ;;
        --skip-verify)
            SKIP_VERIFY=1
            shift
            ;;
        --forwarder-path)
            FORWARDER_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$DEVICE_NAME" ] || [ -z "$API_URL" ]; then
    echo "Usage: $0 --device-name <name> --api-url <url> [--api-key <key>] [--ca-bundle <path>] [--skip-verify]"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing CyberGard Log Forwarder for device: $DEVICE_NAME"

# Check Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install it first."
    exit 1
fi

# Create directory
FORWARDER_DIR=$(dirname "$FORWARDER_PATH")
mkdir -p "$FORWARDER_DIR"
echo "Created directory: $FORWARDER_DIR"

# Copy forwarder script (assumes same directory as this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="$SCRIPT_DIR/remote_log_forwarder.py"

if [ ! -f "$SOURCE_SCRIPT" ]; then
    echo "Error: Could not find remote_log_forwarder.py at: $SOURCE_SCRIPT"
    exit 1
fi

cp "$SOURCE_SCRIPT" "$FORWARDER_PATH"
chmod +x "$FORWARDER_PATH"
echo "Deployed forwarder script to: $FORWARDER_PATH"

# Build python command arguments
PYTHON_ARGS="--url \"$API_URL\" --device-name \"$DEVICE_NAME\""

if [ -n "$API_KEY" ]; then
    PYTHON_ARGS="$PYTHON_ARGS --api-key \"$API_KEY\""
fi

if [ -n "$CA_BUNDLE" ]; then
    PYTHON_ARGS="$PYTHON_ARGS --ca-bundle \"$CA_BUNDLE\""
fi

if [ $SKIP_VERIFY -eq 1 ]; then
    PYTHON_ARGS="$PYTHON_ARGS --skip-verify"
fi

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CyberGard Log Forwarder - $DEVICE_NAME
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $FORWARDER_PATH $PYTHON_ARGS
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
echo "Created systemd service: $SERVICE_FILE"

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "Enabled systemd service for auto-start"

# Start the service
systemctl start "$SERVICE_NAME"
echo "Started log forwarder service"

echo ""
echo "Deployment complete for $DEVICE_NAME"
echo "Service: $SERVICE_NAME"
echo ""
echo "To check status:"
echo "  systemctl status $SERVICE_NAME"
echo "To view logs:"
echo "  journalctl -u $SERVICE_NAME -f"
echo "To stop:"
echo "  systemctl stop $SERVICE_NAME"
