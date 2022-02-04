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
#
#
# This script automates running the evil monkey with different seeds.

SCRIPT_DIR="$(dirname $0)"
LD_SO="$SCRIPT_DIR/../src/hook/hook-monkey.so"

if [ ! -f "$LD_SO" ]; then
    echo "Cannot find $LD_SO, did you run make?"
    exit 1
fi

if (( $# < 2 )); then
    echo "Usage: monkey-debug.sh <seed> <cmd>"
    exit 1
fi

seed="$1"

gdb -ex "set env LD_PRELOAD = $LD_SO" \
    -ex "set \$seed = $seed" \
    -ex "start" \
    -ex "p srand($seed)" \
    -ex "set monkey_rate = 0x0fffffff" \
    -q --args ${@:2}
