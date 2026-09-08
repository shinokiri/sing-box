#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

for module in sing-mux sing-tun; do
    base="$(cat "third_party/$module/UPSTREAM_VERSION")"
    for directory in . test; do
        required="$(go -C "$directory" list -m -f '{{.Version}}' "github.com/sagernet/$module")"
        if [ "$required" != "$base" ]; then
            echo "$directory: $module changed from $base to $required; rebase the local patch before publishing." >&2
            exit 1
        fi
    done
done
