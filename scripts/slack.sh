#!/usr/bin/env bash
#
# Source/target hardware/application address
SHA=$1
SPA=$2
THA=$3
TPA=$4

WEBHOOK_URL="${SLACK_WEBHOOK:-https://hooks.slack.com/services/YOUR/WEBHOOK/PATH}"
MESSAGE="Detected host! src: $SPA [$SHA], tgt: $TPA [$THA]"
CURL=$(which curl)

$CURL -X POST "$WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"text\":\"$MESSAGE\"}"
