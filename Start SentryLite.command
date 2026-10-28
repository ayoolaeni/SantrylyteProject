#!/bin/bash

cd "$(dirname "$0")" || exit 1

# Double-clicked scripts don't always get the Terminal's PATH, so add the
# places Docker Desktop installs its command-line tools.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/Applications/Docker.app/Contents/Resources/bin"

# macOS uses port 5000 for AirPlay Receiver, so SentryLite runs on 5050 here.
export SENTRYLITE_PORT=5050

echo "============================================"
echo "  Starting SentryLite..."
echo "============================================"
echo

if ! docker info >/dev/null 2>&1; then
    echo "Docker Desktop does not appear to be running."
    echo
    echo "Please open Docker Desktop from your Applications folder, wait until"
    echo "it says \"Docker Desktop is running\", then double-click this file again."
    echo
    read -n 1 -s -r -p "Press any key to close this window..."
    exit 1
fi

if [ ! -f .env ]; then
    echo "SECRET_KEY=$(openssl rand -hex 32)" > .env
fi

echo "Docker is running. Building and starting SentryLite..."
echo "(The first time you run this, it can take a few minutes. After that,"
echo " it will start in a few seconds.)"
echo

if ! docker compose up -d --build --wait; then
    echo
    echo "============================================"
    echo "  Something went wrong starting SentryLite."
    echo "============================================"
    echo "Please take a screenshot of this window and send it back for help."
    echo
    read -n 1 -s -r -p "Press any key to close this window..."
    exit 1
fi

echo
echo "============================================"
echo "  SentryLite is running!"
echo "============================================"
echo
echo "Opening it in your browser now..."
echo
echo "  Web address:  http://localhost:5050"
echo "  Username:     admin"
echo "  Password:     admin"
echo "  (you'll be asked to set a new password the first time you log in)"
echo
echo "You can close this window - SentryLite will keep running in the"
echo "background. To stop it later, double-click \"Stop SentryLite.command\"."
echo

open "http://localhost:5050"

read -n 1 -s -r -p "Press any key to close this window..."
echo
