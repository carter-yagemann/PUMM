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

HOOK_SO="$(dirname $0)/../src/hook/hook-scan.so"

if (( $# < 1 )); then
    echo "Usage: hook.sh <cmd>"
    exit 1
fi

if [ ! -f "$HOOK_SO" ]; then
    echo "Cannot find: $HOOK_SO"
    echo "Did you compile it?"
    exit 1
fi

LD_PRELOAD="$HOOK_SO" $@
