#!/bin/sh
# Magi launcher.
#   magi              open the desktop app (no port, no browser)
#   magi serve        run it as a local web server instead
#   magi <command>    run a CLI command (projects, add-asset, export, ...)
set -e

LIB=/usr/lib/magi

find_electron() {
  # Arch ships versioned electron packages; take whichever is installed.
  for e in electron electron43 electron42 electron41 electron40 electron39; do
    if command -v "$e" >/dev/null 2>&1; then echo "$e"; return 0; fi
  done
  return 1
}

case "${1-}" in
  '')
    if E=$(find_electron); then
      exec "$E" "$LIB" "$@"
    fi
    echo "magi: no electron runtime found — install 'electron', or use 'magi serve'." >&2
    exit 1
    ;;
  serve)
    shift
    exec node "$LIB/magi.cjs" "$@"
    ;;
  -v|--version)
    echo "magi @VERSION@"
    ;;
  -h|--help)
    exec node "$LIB/magi-cli.cjs"
    ;;
  *)
    exec node "$LIB/magi-cli.cjs" "$@"
    ;;
esac
