#!/bin/sh
# Forced command for a dedicated status key. No arbitrary command or shell.
set -eu
if [ "${SSH_ORIGINAL_COMMAND-}" != '/data/opt/lisa-station/station-ctl status' ]; then
    echo 'unsupported_command' >&2
    exit 2
fi
exec /data/opt/lisa-station/station-ctl status
