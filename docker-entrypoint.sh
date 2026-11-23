#!/usr/bin/env bash
set -euo pipefail

main() {
    local data_dir="${CRACKED_OURA_DATA_DIR:-/data}"
    local puid="${PUID:-1000}"
    local pgid="${PGID:-1000}"

    mkdir -p "$data_dir"
    # The data dir holds health data and the Oura session cookie: owner only.
    chmod 0700 "$data_dir" 2>/dev/null || true

    if [[ "$(id -u)" -eq 0 ]]; then
        if [[ "$puid" != "0" || "$pgid" != "0" ]]; then
            if [[ "$(stat -c '%u:%g' "$data_dir")" != "${puid}:${pgid}" ]]; then
                chown -R "${puid}:${pgid}" "$data_dir"
            fi
            exec setpriv --reuid="$puid" --regid="$pgid" --clear-groups -- "$@"
        fi
    fi

    exec "$@"
}

main "$@"
