#!/bin/bash

cd "$(dirname "$0")" || exit 1
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin"

echo "Stopping SentryLite..."
echo

docker compose down

echo
echo "SentryLite has been stopped. Your data has been kept and will"
echo "still be there next time you run \"Start SentryLite.command\"."
echo
read -n 1 -s -r -p "Press any key to close this window..."
echo
