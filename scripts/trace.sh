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

IPT_SCRIPTS_DIR="$(dirname $0)/../src/libipt/script"

if (( $# < 1 )); then
    echo "Usage: trace.sh <cmd>"
    exit 1
fi

sudo perf record -e intel_pt//u -T --switch-events -- $@
sudo chown "$USER" perf.data

set -e
"$IPT_SCRIPTS_DIR/perf-read-aux.bash"
"$IPT_SCRIPTS_DIR/perf-read-sideband.bash"
"$(dirname $0)/procmap.sh"
