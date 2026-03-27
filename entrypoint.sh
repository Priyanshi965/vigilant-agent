#!/bin/sh
# entrypoint.sh — runs before uvicorn starts
# Symlinks /app/vigilant.db to the Fly.io persistent volume at /data/
# so SQLite data survives redeploys without any application code changes.

set -e

DATA_DIR="/data"
VOLUME_DB="$DATA_DIR/vigilant.db"
APP_DB="/app/vigilant.db"

# Ensure the volume directory exists
mkdir -p "$DATA_DIR"

# If the volume is empty and the app shipped a seed DB, copy it over once
if [ ! -f "$VOLUME_DB" ] && [ -f "$APP_DB" ] && [ ! -L "$APP_DB" ]; then
    echo "[entrypoint] Seeding volume DB from bundled file"
    cp "$APP_DB" "$VOLUME_DB"
fi

# Replace the in-container file with a symlink to the volume
if [ ! -L "$APP_DB" ]; then
    rm -f "$APP_DB"
    ln -s "$VOLUME_DB" "$APP_DB"
    echo "[entrypoint] Linked $APP_DB -> $VOLUME_DB"
fi

echo "[entrypoint] Starting uvicorn..."
exec "$@"
