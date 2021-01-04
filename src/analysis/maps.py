#!/usr/bin/env python
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

import re

import cle

MAPS_REGEX = '\[(0x[0-9a-f]+)\((0x[0-9a-f]+)\) @ (0[x0-9a-f]*) [0-9]{2}:[0-9]{2} [0-9]+ [0-9]+\]: [rwxp-]{4} (.*)'
MAPS_PARSER = re.compile(MAPS_REGEX)

def read_maps(maps_fp):
    """Given a filepath to a maps produced using procmap.sh (extracted
    from perf.data, produce a dictionary representation.

    Keys:
    base_va -- Base virtual address of virtual memory area (VMA).
    size -- Size of the VMA, in bytes.
    name -- Either the filepath to a real object, or the name of a pseudo-file (ex: "[vdso]").
    base_fo -- Base offset within object from which the VMA was read.
    reverse_plt -- Mapping of PLT stub RVAs to symbol names.
    cle -- A CLE loader instance. Note that it may have mapped objects differently than what
    was recorded in perf, so virtual addresses have to be carefully translated.

    Exceptions:
    Raises ValueError if a line in maps cannot be parsed.

    Returns:
    A list, one item per mapped object, with the above mentioned keys.
    """
    objs = list()
    # Reuse CLE to do most of the heavy lifting regarding the PLT, symbols, etc.
    # CLE is going to load objects into base addresses of its choosing, so any
    # addresses we borrow need to be converted into RVAs.
    ld = None

    with open(maps_fp, 'r') as ifile:
        for line in ifile:
            line = line.rstrip()  # remove newline character
            match = MAPS_PARSER.match(line)
            if match is None:
                raise ValueError("Cannot parse line: %s" % line)

            # note: name can be a full filepath or in the case of a pseudo-file,
            # something in brackets like [vdso]
            base_va, size, file_offset, name = match.groups()

            if ld is None:
                # first object loaded should be the main object
                ld = cle.Loader(name)

            # may return None if object not found
            ld_obj = ld.find_object(name)
            reverse_plt = dict()
            if not ld_obj is None:
                for ld_vaddr in ld_obj.reverse_plt:
                    sym_name = ld_obj.reverse_plt[ld_vaddr]
                    plt_stub_rva = ld_vaddr - ld_obj.mapped_base
                    reverse_plt[plt_stub_rva] = sym_name

            objs.append({'base_va': int(base_va, 16),
                         'size': int(size, 16),
                         'name': name,
                         'base_fo': int(file_offset, 16),
                         'reverse_plt': reverse_plt,
                         'cle': ld,
                        })

    return objs

def ava_to_rva(maps, ava):
    """Converts an absolute virtual address (AVA) into a relative
    virtual address (RVA) and also returns the RVA's base object.

    Returns:
    (rva, object) if a match is found, otherwise (ava, None).
    """
    assert isinstance(maps, list)
    assert isinstance(ava, int)

    for obj in maps:
        base_va = obj['base_va']
        limit = obj['base_va'] + obj['size']
        if base_va <= ava < limit:
            return (ava - base_va + obj['base_fo'], obj)

    return (ava, None)
