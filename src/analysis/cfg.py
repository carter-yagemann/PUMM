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

import gzip
import logging
from optparse import OptionParser
import os
import re
import sys
import tempfile
from zlib import adler32

import networkx as nx
from networkx.drawing.nx_pydot import write_dot

import maps

log = logging.getLogger(name=__name__)

PTXED_INSTR = re.compile('([0-9a-f]+) +([a-z]+)')

BRANCH_MNEMONICS = {
    'jb', 'jbe', 'jl', 'jle', 'jmp', 'jmpq', 'jnb', 'jnbe', 'jnl', 'jnle', 'jns',
    'jnz', 'jo', 'jp', 'js', 'jz', 'retq'
}

CALL_MNEMONICS = {
    'callq'
}

SYSCALL_MNEMONICS = {
    'syscall'
}

BORING_MNEMONICS = {
    'adc', 'add', 'addl', 'addq', 'addw', 'and', 'andb' 'andl' 'andq', 'andw', 'bnd',
    'bsf', 'bsr', 'bswap', 'bt', 'btc', 'bts', 'cdqe', 'cmovb', 'cmovbe', 'cmovbel',
    'cmovbeq', 'cmovbew', 'cmovl', 'cmovle', 'cmovnb', 'cmovnbe', 'cmovnbl', 'cmovnbq',
    'cmovbew', 'cmovl', 'cmovle', 'cmovnb', 'cmovnbe', 'cmovnbl', 'cmovnbq', 'cmovnle',
    'cmovns', 'cmovnz', 'cmovs', 'cmovz', 'cmovzl', 'cmovzq', 'cmp', 'cmpb', 'cmpl',
    'cmpq', 'cmpw', 'cmpxchgl', 'comisd', 'comisdq', 'cpuid', 'cqo', 'cvttsd2si',
    'data16', 'decl', 'div', 'divl', 'divq', 'idiv', 'imul', 'imull', 'imulq', 'leal',
    'leaq', 'lock', 'mfence', 'mov', 'movapd', 'movapsx', 'movb', 'movbel', 'movd',
    'movdqa', 'movdqax', 'movdqux', 'movhpdq', 'movl', 'movlpdq', 'movq', 'movsdq',
    'movsqq', 'movsx', 'movsxb', 'movsxd', 'movsxdl', 'movsxw', 'movupsx', 'movw',
    'movzx', 'movzxb', 'movzxw', 'mul', 'mulsdq', 'neg', 'nop', 'nopl', 'nopw', 'not',
    'or', 'orb', 'orl', 'orq', 'orw', 'pcmpeqb', 'pcmpeqbx', 'pcmpeqd', 'pcmpistri',
    'pcmpistrix', 'pminub', 'pminubx', 'pmovmskb', 'popq', 'por', 'pshufb', 'pshufd',
    'pslldq', 'psrldq', 'psubb', 'punpcklbw', 'punpcklwd', 'pushq', 'pxor', 'rdtsc',
    'rep', 'rol', 'ror', 'sar', 'sbb', 'setb', 'setbe', 'setle', 'setnb',
    'setnbe', 'setnle', 'setnz', 'setnzb', 'seto', 'setz', 'setzb', 'shl', 'shr',
    'sub', 'subb', 'subl', 'subq', 'test', 'testb', 'testl', 'testq', 'tzcnt', 'ucomisdq',
    'vmovd', 'vmovdl', 'vmovdqax', 'vmovdqay', 'vmovdqux', 'vmovdquy', 'vmovq', 'vmovqq',
    'vpalignrx', 'vpand', 'vpandn', 'vpbroadcastb', 'vpcmpeqb', 'vpcmpeqbx', 'vpcmpeqby',
    'vpcmpgtb', 'vpcmpistri', 'vpminub', 'vpmovmskb', 'vpor', 'vpslldq', 'vpsubb', 'vpxor',
    'vzeroupper', 'xchg', 'xchgl', 'xgetbv', 'xor', 'xorl', 'xorps', 'xorq', 'xrstor',
    'xsavec', 'andl', 'data', 'andq', 'andb', 'leaveq'
}

class CFGNode(object):

    # TODO - Incorporate symbol info to improve descriptions

    def __init__(self, ava, func_head=False, procmap=None):
        self.ava = ava
        self.func_head = func_head
        self.rva = None
        self.obj = None

        if not procmap is None:
            # we can fill in more info about this node
            rva, name = maps.ava_to_rva(procmap, self.ava)
            if not name is None:
                self.rva = rva
                self.obj = name

        self._description = self._get_description()

    def _get_description(self):
        if isinstance(self.rva, int):
            return "%s+%#x" % (os.path.basename(self.obj), self.rva)
        return "%#x" % self.ava

    def __repr__(self):
        return "<CFGNode %s>" % self._description

    def __str__(self):
        return "<CFGNode %s>" % self._description

    def __hash__(self):
        return adler32(self._description.encode('utf8'))

    def __eq__(self, other):
        return self._description == other._description

    def __ne__(self, other):
        return not self == other

def parse_ptxed(input, graph=None, maps=None):
    """Reads a ptxed disassembly and yields a CFG.

    Keyword Arguments:
    input -- Either a filepath or an already opened file. If filepath
    extension is '.gz', it will be treated as a gzip file. Opened
    files must have a readlines() method. If the caller provides an
    already opened file, they must close it.
    graph -- A NetworkX DiGraph to update. If None, a new graph is
    created
    maps -- Use the maps list from maps.read_maps(), if provided, to
    attach additional metadata to nodes, such as relative virtual
    addresses (RVA). This is required if graph is updated using several
    different traces to get a sensible result.

    Returns:
    A CFG as a NetworkX DiGraph
    """
    if isinstance(input, str):
        if input.endswith('.gz'):
            input = gzip.open(input, 'rt')
            needs_close = True
        else:
            input = open(input, 'r')
            needs_close = True
    else:
        # caller provided open file, they should close it
        needs_close = False

    if graph is None:
        graph = nx.DiGraph()

    prev_node = None
    is_bb_start = False
    is_func_start = False

    for line in input.readlines():
        line = line.rstrip()  # remove newline character

        if line == '[disabled]':
            # tracing turned off, cannot assume next node
            # is linked to prior
            prev_node = None
            is_bb_start = False
            is_func_start = False
        else:
            instr = PTXED_INSTR.match(line)
            if not instr is None:
                # disassembled instruction
                v_addr = int(instr.group(1), 16)
                mnemonic = instr.group(2)

                # if this is the start of a basic block, update graph
                if is_bb_start:
                    curr_node = CFGNode(v_addr, is_func_start, maps)
                    graph.add_node(curr_node)
                    if not prev_node is None:
                        graph.add_edge(prev_node, curr_node)

                    prev_node = curr_node
                    is_bb_start = False
                    is_func_start = False

                if mnemonic in BRANCH_MNEMONICS:
                    # next address is the start of a basic block
                    is_bb_start = True
                elif mnemonic in CALL_MNEMONICS:
                    # next address starts basic block and function
                    is_bb_start = True
                    is_func_start = True
                elif mnemonic in SYSCALL_MNEMONICS:
                    pass  # TODO - Should we take special note of syscalls?
                elif mnemonic in BORING_MNEMONICS:
                    # nothing needs to be done
                    pass
                else:
                    log.warning("Unhandled mnemonic: %s" % mnemonic)

    if needs_close:
        input.close()

    return graph

def main():
    parser = OptionParser(usage='Usage: %prog [options] 1.ptxed ...')
    parser.add_option('-l', '--logging', action='store', type='int', default=20,
            help='Log level [10-50] (default: 20 - Info)')

    options, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)

    # init stdout logging
    log.setLevel(options.logging)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)7s | %(asctime)-15s | %(message)s'))
    log.addHandler(handler)

    graph = nx.DiGraph()
    for filepath in args:
        map_fp = os.path.join(os.path.dirname(filepath), 'maps')
        if not os.path.isfile(map_fp):
            log.warning("No map file found for: %s" % map_fp)
            map = None
        else:
            map = maps.read_maps(map_fp)
        log.info("Parsing: %s" % filepath)
        graph = parse_ptxed(filepath, graph, map)

    ofd, ofilepath = tempfile.mkstemp('.dot')
    os.close(ofd)

    log.info("Saving graph to: %s" % ofilepath)
    write_dot(graph, ofilepath)

if __name__ == "__main__":
    main()
