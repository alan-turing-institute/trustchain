#!/bin/bash

# Port forwarding to an ION server required
# ssh -N -L 3000:localhost:3000 ion

# Args:
#   $1: POST JSON file name
#   $2: Output file name
# Returns:
#   OK / Bad Request

for file in $(find "$HOME/.trustchain/operations" -name "*.json" -depth 1); do
    echo $file
    curl --tr-encoding -X POST -v -# -o "$file.out.json" -T $file -H "Content-Type: application/json; charset=utf-8" http://localhost:3000/operations
done
