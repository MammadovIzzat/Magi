#!/bin/sh
# Magi launcher.
#   magi              start the web app (http://127.0.0.1:4173)
#   magi <command>    run a CLI command (projects, add-asset, export, ...)
set -e

LIB=/usr/lib/magi

case "${1-}" in
  ''|serve)
    exec node "$LIB/magi.cjs"
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
