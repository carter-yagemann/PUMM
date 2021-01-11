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

import networkx as nx
from networkx.drawing.nx_pydot import write_dot
import pyvex

import maps

log = logging.getLogger(name=__name__)

PTXED_INSTR = re.compile('([0-9a-f]+) ((?:[0-9-a-f]{2} )+) +([a-z ]+)')

BRANCH_MNEMONICS = {
    'jb', 'jbe', 'jl', 'jle', 'jmp', 'jmpq', 'jnb', 'jnbe', 'jnl', 'jnle', 'jns',
    'jnz', 'jo', 'jp', 'js', 'jz', 'retq', 'bnd jmp', 'bnd retq'
}

CALL_MNEMONICS = {
    'callq', 'bnd callq'
}

SYSCALL_MNEMONICS = {
    'syscall', 'sysenter'
}

BORING_MNEMONICS = {
    'adc', 'add', 'addl', 'addq', 'addw', 'and', 'andb' 'andl' 'andq', 'andw',
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
    'xsavec', 'andl', 'data', 'andq', 'andb', 'leaveq', 'rep stosqq'
}

class CFGNode(object):

    def __init__(self, ava, procmap, size):
        """Represents a basic block in an ASLR-agnostic manner.

        Keyword Arguments:
        ava -- Absolute virtual address of the start of the basic block.
        procmap -- Map from maps.read_maps().
        size -- Size of the basic block, in bytes.
        """
        if size < 1:
            raise ValueError("Invalid size: %d" % size)
        self.size = size
        self.rva, self.obj = maps.ava_to_rva(procmap, ava)

        if self.obj is None:
            raise ValueError("AVA %#x does not belong to any object" % ava)

        if self.rva in self.obj['reverse_plt']:
            self.plt_sym = self.obj['reverse_plt'][self.rva]
        else:
            self.plt_sym = None

        self.description = self._describe()

        # TODO - context sensitivity

        self.irsb = node2vex(self, procmap)
        # TODO - capstone too?

    def _describe(self):
        # start with object name, RVA, and size
        desc = "%s+%#x[%d]" % (os.path.basename(self.obj['name']), self.rva, self.size)

        # if PLT stub, append symbol name
        if isinstance(self.plt_sym, str):
            desc += " (PLT.%s)" % self.plt_sym

        return desc

    def __repr__(self):
        return "<CFGNode %s>" % self.description

    def __str__(self):
        return "<CFGNode %s>" % self.description

    def __hash__(self):
        return self.obj['obj_id'] ^ (self.rva << 1)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self == other

def parse_ptxed(input, procmap, graph=None):
    """Reads a ptxed disassembly and yields a CFG.

    Keyword Arguments:
    input -- File path to the ptxed disassembly, '.gz' extension will
    be treated as a gzip file.
    procmap -- Map from maps.read_maps().
    graph -- A NetworkX DiGraph to update. If None, a new graph is
    created

    Returns:
    A CFG as a NetworkX DiGraph
    """
    if input.endswith('.gz'):
        input = gzip.open(input, 'rt')
    else:
        input = open(input, 'r')

    if graph is None:
        graph = nx.DiGraph()

    curr_bb_start_addr = None
    entering_syscall = False
    prev_node = None

    for line in input.readlines():
        line = line.rstrip()  # remove newline character

        if line == '[disabled]':
            log.debug('PTXed: [disabled]')
            # tracing turned off, cannot assume next node
            # is linked to prior unless we entered a syscall
            if not entering_syscall:
                prev_node = None
            else:
                entering_syscall = False

        else:
            instr = PTXED_INSTR.match(line)
            if instr is None:
                # we skip anything else that isn't an instruction
                continue

            log.debug("PTXed: %s" % line)

            # disassembled instruction
            v_addr = int(instr.group(1), 16)
            instr_size = len(instr.group(2)) // 3
            mnemonic = instr.group(3).rstrip()

            if curr_bb_start_addr is None:
                # previous instruction completed a basic block, this is now
                # the start of a new one
                curr_bb_start_addr = v_addr

            if mnemonic in BRANCH_MNEMONICS | CALL_MNEMONICS | SYSCALL_MNEMONICS:
                # this will end the current basic block, next instruction
                # will be the start of a new one
                size = v_addr + instr_size - curr_bb_start_addr
                curr_node = CFGNode(curr_bb_start_addr, procmap, size)
                if not curr_node in graph:
                    graph.add_node(curr_node)
                if not prev_node is None:
                    graph.add_edge(prev_node, curr_node)

                log.debug("PTXed: [BB boundary]")
                prev_node = curr_node
                curr_bb_start_addr = None

                if mnemonic in SYSCALL_MNEMONICS:
                    # we're expecting PT to turn off because we're only tracing
                    # user space, do not disconnect the next node from prior
                    entering_syscall = True
                else:
                    entering_syscall = False

            elif mnemonic in BORING_MNEMONICS:
                # nothing needs to be done
                entering_syscall = False

            else:
                log.warning("Unhandled mnemonic, treating as boring: %s" % mnemonic)
                entering_syscall = False

    input.close()
    return graph

def node2vex(node, map):
    """Given a node and a map from maps.read_maps(), return a VEX IRSB representation
    of the node."""
    assert isinstance(node, CFGNode)

    # convert the node's RVA into an AVA within the CLE loader's memory space
    ld = node.obj['cle']
    name = node.obj['name']
    ld_obj = ld.find_object(name)
    if ld_obj is None:
        raise ValueError("Cannot find object with name: %s" % name)

    ava = ld_obj.mapped_base + node.rva

    code = ld.memory.load(ava, node.size)
    irsb = pyvex.lift(code, ava, ld_obj.arch)

    return irsb

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
            log.error("No map file found for: %s" % map_fp)
            sys.exit(1)
        procmap = maps.read_maps(map_fp)

        log.info("Parsing: %s" % filepath)
        graph = parse_ptxed(filepath, procmap, graph)

    ofd, ofilepath = tempfile.mkstemp('.dot')
    os.close(ofd)

    log.info("Saving graph to: %s" % ofilepath)
    write_dot(graph, ofilepath)

if __name__ == "__main__":
    main()
