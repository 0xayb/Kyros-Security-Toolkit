#!/bin/bash
# Kyros Startup Script
# Created by: Ayoub Serarfi

echo "=================================="
echo "     Kyros - Security Toolkit"
echo "        By Ayoub Serarfi"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Kyros requires root privileges for network operations."
    echo "Restarting with sudo..."
    echo ""
    sudo "$0" "$@"
    exit $?
fi

# Check Python version
python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is not installed!"
    echo "Please install Python 3.8 or higher."
    exit 1
fi

# Check if running from virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Running from virtual environment: $VIRTUAL_ENV"
    echo ""
    python3 -m kyros "$@"
    exit $?
fi

# Check if dependencies are installed
echo "Checking dependencies..."
MISSING_DEPS=0

for package in scapy colorama psutil rich yaml; do
    python3 -c "import $package" 2>/dev/null
    if [ $? -ne 0 ]; then
        MISSING_DEPS=1
        break
    fi
done

# Install dependencies if missing
if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo "Missing dependencies detected!"
    echo "Installing required packages from requirements.txt..."
    echo ""

    # Check if requirements.txt exists
    if [ ! -f "requirements.txt" ]; then
        echo "Error: requirements.txt not found!"
        exit 1
    fi

    # Install dependencies
    pip3 install -r requirements.txt

    if [ $? -ne 0 ]; then
        echo ""
        echo "Error: Failed to install dependencies."
        echo "Please run manually: pip3 install -r requirements.txt"
        exit 1
    fi

    echo ""
    echo "Dependencies installed successfully!"
    echo ""
fi

echo "Starting Kyros..."
echo ""
python3 -m kyros "$@"
