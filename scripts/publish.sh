#!/bin/bash

# Local ION server required on port 3000, or port forwarding:
# ssh -N -L 3000:localhost:3000 ion

BASE_DIR="$HOME/.trustchain/operations"
SENT_DIR="$BASE_DIR/sent"

mkdir -p "$SENT_DIR"

for file in "$BASE_DIR"/*.json; do
    [ -e "$file" ] || continue  # handle case where no files match

    echo "Sending $file"

    out_file="$file.out.json"

    http_code=$(curl \
        --tr-encoding \
        -X POST \
        -s \
        -o "$out_file" \
        -w "%{http_code}" \
        -T "$file" \
        -H "Content-Type: application/json; charset=utf-8" \
        http://localhost:3000/operations)

    if [ "$http_code" -eq 200 ]; then
        echo "Success (200). Moving files to sent/"
        mv "$file" "$out_file" "$SENT_DIR/"
    else
        echo "Request failed with status $http_code"
        echo "For details see $out_file"
    fi
done
