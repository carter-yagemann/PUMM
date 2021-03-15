#!/bin/bash
#
# Copyright 2021 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

PTXED="$(dirname $0)/../build/bin/ptxed"
IPT_SCRIPTS_DIR="$(dirname $0)/../src/libipt/script"
LIB_DIR="$(dirname $0)/../build/lib"

if [ ! -f "$PTXED" ]; then
    echo "$PTXED not found, did you run build.sh?"
    exit 1
fi

if [ $# -eq "1" ]; then
    cd "$1"
fi

find -maxdepth 1 -name "perf.data-aux-idx*.bin" -type f | grep -o "[0-9]\+" | \
    xargs -P $(nproc) -n 1 -I {} /bin/bash -c "\
        LD_LIBRARY_PATH="$LIB_DIR" $PTXED --att --raw-insn \
            \$($IPT_SCRIPTS_DIR/perf-get-opts.bash -m perf.data-sideband-cpu{}.pevent) \
            --pevent:vdso-x64 --event:tick --pt perf.data-aux-idx{}.bin \
            | gzip > {}.ptxed.gz"
