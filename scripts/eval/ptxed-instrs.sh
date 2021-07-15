#!/bin/bash

zgrep -c "^[0-9a-f]" $(find -name '*.ptxed.gz' -type f) | \
    cut -d : -f 2 | awk '{s+=$1}END{print s}'
