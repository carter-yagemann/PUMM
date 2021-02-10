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

set -e

LIBIPT_VERSION="v2.0.3"
XED_VERSION="12.0.1"

# clone and checkout Intel repos
git clone https://github.com/intel/libipt.git src/libipt
cd src/libipt
git checkout $LIBIPT_VERSION
cd ../..

git clone https://github.com/intelxed/xed.git src/xed
cd src/xed
git checkout $XED_VERSION
cd ../..

git clone https://github.com/intelxed/mbuild.git src/mbuild


# setup and build xed
cd src/xed
./mfile.py install
cd ../..


# setup libipt
mkdir build
cd build
XED_INCLUDE="$(find ../src/xed/kits/ -name include -type d | head -n 1)/xed"
XED_LIBDIR="$(find ../src/xed/kits/ -name lib -type d | head -n 1)"
cmake -DPTDUMP=ON -DPTXED=ON -DPTTC=ON -DSIDEBAND=ON -DPEVENT=ON \
      -DFEATURE_ELF=ON -DFEATURE_THREADS=ON \
      -DXED_INCLUDE=$XED_INCLUDE -DXED_LIBDIR=$XED_LIBDIR \
      ../src/libipt
make -j $(nproc)
cd ..
