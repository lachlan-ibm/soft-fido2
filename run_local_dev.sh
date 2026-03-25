#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Local Development Build & Run Script ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Error: Do not run this script as root${NC}"
    exit 1
fi

# Set build number (use timestamp for local builds)
BUILD_NUMBER=${BUILD_NUMBER:-$(date +%s)}
export GITHUB_RUN_NUMBER=$BUILD_NUMBER
echo -e "${YELLOW}Using build number: $BUILD_NUMBER${NC}"

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.pyenv"

# Check if systemd user service is running
SERVICE_NAME="passkey.service"
SERVICE_WAS_RUNNING=false

echo -e "${YELLOW}Checking for running systemd service...${NC}"
if systemctl --user is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "${YELLOW}Service $SERVICE_NAME is running. Stopping it...${NC}"
    systemctl --user stop "$SERVICE_NAME"
    SERVICE_WAS_RUNNING=true
    echo -e "${GREEN}Service stopped successfully${NC}"
    sleep 2
else
    echo -e "${GREEN}Service is not running${NC}"
fi

# Cleanup function to restore service on exit
cleanup() {
    EXIT_CODE=$?
    echo ""
    echo -e "${YELLOW}=== Cleanup ===${NC}"
    
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo -e "${YELLOW}Restoring systemd service...${NC}"
        systemctl --user start "$SERVICE_NAME"
        if systemctl --user is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}Service restored successfully${NC}"
        else
            echo -e "${RED}Warning: Failed to restore service${NC}"
        fi
    fi
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}Script completed successfully${NC}"
    else
        echo -e "${RED}Script exited with error code: $EXIT_CODE${NC}"
    fi
    
    exit $EXIT_CODE
}

trap cleanup EXIT INT TERM

# Create or update virtual environment
echo ""
echo -e "${YELLOW}=== Setting up virtual environment ===${NC}"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating new virtual environment with system site packages..."
    python3 -m venv --system-site-packages "$VENV_DIR"
else
    echo "Using existing virtual environment..."
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null

# Clean previous builds
echo ""
echo -e "${YELLOW}=== Cleaning previous builds ===${NC}"
rm -rf build dist *.egg-info

# Install development dependencies
echo ""
echo -e "${YELLOW}=== Installing development dependencies ===${NC}"
pip install --no-build-isolation -r dev-requirements.txt

# Build the package
echo ""
echo -e "${YELLOW}=== Building package (version 0.3.$BUILD_NUMBER) ===${NC}"
python -m build --no-isolation

# Uninstall existing package if present
echo ""
echo -e "${YELLOW}=== Checking for existing installation ===${NC}"
if pip show soft_fido2 > /dev/null 2>&1; then
    echo "Uninstalling existing soft_fido2 package..."
    pip uninstall -y soft_fido2
fi

# Install the package in development mode
echo ""
echo -e "${YELLOW}=== Installing package in development mode ===${NC}"
pip install --no-build-isolation -e .

# Set up environment variables
echo ""
echo -e "${YELLOW}=== Setting up environment ===${NC}"

# Use a temporary FIDO_HOME for testing
TEMP_FIDO_HOME="${FIDO_HOME:-$HOME/.fido_dev}"
export FIDO_HOME="$TEMP_FIDO_HOME"
export SOFT_FIDO2_SKIP_UP=true
export SOFT_FIDO2_DEBUG_LEVEL=DEBUG

echo "FIDO_HOME: $FIDO_HOME"
echo "SOFT_FIDO2_SKIP_UP: $SOFT_FIDO2_SKIP_UP"
echo "SOFT_FIDO2_DEBUG_LEVEL: $SOFT_FIDO2_DEBUG_LEVEL"

# Create FIDO_HOME if it doesn't exist
if [ ! -d "$FIDO_HOME" ]; then
    echo "Creating FIDO_HOME directory: $FIDO_HOME"
    mkdir -p "$FIDO_HOME"
fi

# Check for /dev/uhid access
echo ""
echo -e "${YELLOW}=== Checking /dev/uhid access ===${NC}"
if [ ! -w /dev/uhid ]; then
    echo -e "${RED}Warning: No write access to /dev/uhid${NC}"
    echo "You may need to run: sudo chmod 666 /dev/uhid"
    echo "Or add your user to the appropriate group"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run the application
echo ""
echo -e "${GREEN}=== Starting application in foreground ===${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Run the module directly
python -m soft_fido2

# The cleanup function will run automatically when the script exits

# Made with Bob
