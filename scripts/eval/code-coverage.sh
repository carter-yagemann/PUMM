#!/bin/bash
set -e

TEMP=$(mktemp -d)
FILTER=$(mktemp)

touch "$FILTER"

for trace in $(find -name '*.ptxed.gz' | sort); do
    # file name is the trace file path, encoded to avoid collisions
    ofile="$TEMP/$(echo $trace | base64)"

    # we do a hack here so we don't have to account for ASLR, namely, use the
    # page offset and encoded instruction to identify unique instructions,
    # rather than using the virtual address which changes with every trace
    #
    # this can have collisions, but it's way faster than converting each AVA
    # into a RVA and good enough for approximating code coverage
    #
    # the filter is used to remove any instructions that have already been seen,
    # leaving only the delta from prior traces
    zgrep -Eo "[0-9a-f]{3} ([0-9a-f]{2} )+" "$trace" | \
            grep -vf "$FILTER" | \
            sort | uniq > "$ofile"

    # update the filter
    cat "$ofile" >> "$FILTER"

    len=$(wc -l "$ofile" | cut -d ' ' -f 1)
    echo "$trace:$len"
done

rm "$FILTER"
rm -r "$TEMP"
