#!/bin/bash

# Local ION server required on port 3000, or port forwarding:
# ssh -N -L 3000:localhost:3000 ion

# If running ION on a different port, edit this line:
declare -i port=3000

# Check for the TRUSTCHAIN_DATA env variable.
# Compare length to zero for compatibility with zsh.
if [[ ${#TRUSTCHAIN_DATA} -eq 0 ]]; then
    echo "TRUSTCHAIN_DATA environment variable is unset or empty. Aborting."
    exit 1
else
    BASE_DIR="$TRUSTCHAIN_DATA/operations"
    mkdir -p "$BASE_DIR"
fi

SENT_DIR="$BASE_DIR/sent"
FAILED_DIR="$BASE_DIR/failed"

mkdir -p "$SENT_DIR"

shopt -s nullglob
num_files=("$BASE_DIR"/*.json)
num_files=${#num_files[@]}
if [ "$num_files" -eq 0 ]; then
    echo "No JSON files found in $BASE_DIR. Exiting."
    exit 0
elif [ "$num_files" -eq 1 ]; then
    echo "Found 1 DID operation."
else
    echo "Found $num_files DID operations."
fi

declare -i count
count=0
for file in "$BASE_DIR"/*.json; do
    [ -e "$file" ] || continue  # handle case where no files match

    filename=$(basename $file)
    out_file="$file.out.json"

    http_code=$(curl \
        --tr-encoding \
        --request POST \
        --silent \
        --show-error \
        --output "$out_file" \
        --write-out "%{http_code}" \
        --upload-file "$file" \
        --header "Content-Type: application/json; charset=utf-8" \
        http://localhost:$port/operations)

    if [ "$http_code" -eq 0 ]; then
        echo "ION server not found on port $port. Aborting."
        exit 1
    fi

    if [ "$http_code" -eq 200 ]; then
        if [ "$count" -eq 0 ]; then
            echo "Publishing:"
        fi
        # Print a green tick and increment the success count.
        ((++count))
        echo "- $filename ✅"
        mv "$file" "$out_file" "$SENT_DIR/"
    else
        mkdir -p "$FAILED_DIR"
        mv "$file" "$out_file" "$FAILED_DIR/"
        # Print a red cross and the HTTP error code.
        echo "$filename ❌ [HTTP code: $http_code]"
    fi
done

if [ $count -eq $num_files ]; then
    echo "All DID operations were published successfully"
    echo "Files moved to the 'sent/' subdirectory"
else
    if [ $count -eq 0 ]; then
        echo "Failed to publish any DID operations"
    else
        echo "$count of $num_files published successfully & moved to the 'sent/' subdirectory"
    fi
    echo "Failed operations moved to $FAILED_DIR"
    echo "See the out.json file(s) for details."
fi
