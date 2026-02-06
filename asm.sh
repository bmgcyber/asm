#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export PATH="$DIR/bin:$PATH"
exec "$DIR/.venv/bin/python3" "$DIR/asm.py" "$@"
