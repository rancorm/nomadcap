#!/bin/sh
#
# echo.sh - Echo detected host details

# Source/target hardware/application address
SHA=$1
SPA=$2
THA=$3
TPA=$4

echo "Detected host! src: $SPA [$SHA], tgt: $TPA [$THA]"
