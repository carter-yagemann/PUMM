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

import base64
import gzip
import logging
from optparse import OptionParser
import os
import re
import signal
import sys
import tempfile
from traceback import format_exc
import warnings

# we don't draw so we don't import matplotlib, supress warning
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from graph_tool.all import Graph
    from graph_tool.topology import shortest_path
import numpy as np

import maps

log = logging.getLogger(name=__name__)

PTXED_INSTR = re.compile('([0-9a-f]+) ((?:[0-9-a-f]{2} )+) +([a-z ]+)')

BRANCH_MNEMONICS = {
    'jb', 'jbe', 'jl', 'jle', 'jmp', 'jmpq', 'jnb', 'jnbe', 'jnl', 'jnle',
    'jns', 'jnz', 'jo', 'jp', 'js', 'jz', 'bnd jmp', 'loop', 'jno', 'jnp',
    'jnae', 'jc', 'jae', 'jnc', 'jna', 'ja', 'jnge', 'jge', 'jng', 'jg', 'jpe',
    'jpo', 'jcxz', 'jecxz'
}

CALL_MNEMONICS = {
    'callq', 'bnd callq'
}

RET_MNEMONICS = {
    'retq', 'bnd retq'
}

SYSCALL_MNEMONICS = {
    'syscall', 'sysenter'
}

BORING_MNEMONICS = {
    'adc', 'add', 'addl', 'addq', 'addw', 'and', 'andb' 'andl' 'andq', 'andw',
    'bsf', 'bsr', 'bswap', 'bt', 'btc', 'bts', 'cdqe', 'cmovb', 'cmovbe',
    'cmovbel', 'cmovbeq', 'cmovbew', 'cmovl', 'cmovle', 'cmovnb', 'cmovnbe',
    'cmovnbl', 'cmovnbq', 'cmovbew', 'cmovl', 'cmovle', 'cmovnb', 'cmovnbe',
    'cmovnbl', 'cmovnbq', 'cmovnle', 'cmovns', 'cmovnz', 'cmovs', 'cmovz',
    'cmovzl', 'cmovzq', 'cmp', 'cmpb', 'cmpl', 'cmpq', 'cmpw', 'cmpxchgl',
    'comisd', 'comisdq', 'cpuid', 'cqo', 'cvttsd2si', 'data16', 'decl', 'div',
    'divl', 'divq', 'idiv', 'imul', 'imull', 'imulq', 'leal', 'leaq', 'lock',
    'mfence', 'mov', 'movapd', 'movapsx', 'movb', 'movbel', 'movd', 'movdqa',
    'movdqax', 'movdqux', 'movhpdq', 'movl', 'movlpdq', 'movq', 'movsdq',
    'movsqq', 'movsx', 'movsxb', 'movsxd', 'movsxdl', 'movsxw', 'movupsx',
    'movw', 'movzx', 'movzxb', 'movzxw', 'mul', 'mulsdq', 'neg', 'nop', 'nopl',
    'nopw', 'not', 'or', 'orb', 'orl', 'orq', 'orw', 'pcmpeqb', 'pcmpeqbx',
    'pcmpeqd', 'pcmpistri', 'pcmpistrix', 'pminub', 'pminubx', 'pmovmskb',
    'popq', 'por', 'pshufb', 'pshufd', 'pslldq', 'psrldq', 'psubb', 'punpcklbw',
    'punpcklwd', 'pushq', 'pxor', 'rdtsc', 'rep', 'rol', 'ror', 'sar', 'sbb',
    'setb', 'setbe', 'setle', 'setnb', 'setnbe', 'setnle', 'setnz', 'setnzb',
    'seto', 'setz', 'setzb', 'shl', 'shr', 'sub', 'subb', 'subl', 'subq',
    'test', 'testb', 'testl', 'testq', 'tzcnt', 'ucomisdq', 'vmovd', 'vmovdl',
    'vmovdqax', 'vmovdqay', 'vmovdqux', 'vmovdquy', 'vmovq', 'vmovqq',
    'vpalignrx', 'vpand', 'vpandn', 'vpbroadcastb', 'vpcmpeqb', 'vpcmpeqbx',
    'vpcmpeqby', 'vpcmpgtb', 'vpcmpistri', 'vpminub', 'vpmovmskb', 'vpor',
    'vpslldq', 'vpsubb', 'vpxor', 'vzeroupper', 'xchg', 'xchgl', 'xgetbv',
    'xor', 'xorl', 'xorps', 'xorq', 'xrstor', 'xsavec', 'andl', 'data', 'andq',
    'andb', 'leaveq', 'rep stosqq', 'lock cmpxchgl', 'lock decl', 'setbb',
    'rep stosbb', 'setnl', 'cdq', 'cwd', 'movsbb', 'rep movsbb', 'xchgq',
    'xaddl', 'xaddq', 'cmpxchgq', 'adcq', 'addb', 'addsdq', 'cld', 'cmovnl',
    'cmovnlel', 'cmovnll', 'cvtsi', 'dec', 'movdl', 'movhpsq', 'movqq', 'mulq',
    'popfqq', 'punpcklqdq', 'pushfqq', 'pxorx', 'rep cmpsbb', 'rep movsdl',
    'rep movsqq', 'sbbq', 'setl', 'shll', 'testw', 'vptest', 'xorb', 'bsrq',
    'shld', 'fnstcww', 'cvttsd', 'subsd', 'cmovlel', 'subw', 'addpd', 'addsd',
    'andnpd', 'andpd', 'andpdx', 'andpsx', 'btr', 'cmovnzl', 'cmovnzq', 'cmpsd',
    'divsd', 'fcomi', 'fdiv', 'fildl', 'fildq', 'fldl', 'fmull', 'fstp',
    'fstpq', 'fxch', 'idivl', 'lock addl', 'lock addq', 'lock cmpxchgq',
    'lock subl', 'lock xaddl', 'lock xaddq', 'movapdx', 'movupdx', 'mulsd',
    'orpd', 'popcnt', 'psrad', 'punpckldq', 'punpckldqx', 'repne scasbb',
    'sqrtsd', 'subpd', 'subpdx', 'subsdq', 'ucomisd', 'vaddsd', 'vaddsdq',
    'vandnpd', 'vandpd', 'vandpdx', 'vcomisd', 'vcomisdq', 'vcvtsi', 'vfmadd',
    'vfmsub', 'vfnmadd', 'vmovapd', 'vmovsdq', 'vmulsd', 'vmulsdq', 'vorpd',
    'vstmxcsrl', 'vsubsd', 'vsubsdq', 'vucomisd', 'vxorpd', 'vxorpdx', 'xorpd',
    'cmovsq'
}

# change of flow
COF_MNEMONICS = (BRANCH_MNEMONICS | CALL_MNEMONICS
        | SYSCALL_MNEMONICS | RET_MNEMONICS)

CUSTOM_MEM_LIBS = ['libjemalloc.so']

# simple timeout handler
class AnalysisTimeout(Exception):
    pass

def timeout_handler(signum, frame):
    raise AnalysisTimeout("Timeout reached")

def start_timeout(timeout_str):
    timeout_str = timeout_str.lower()
    if timeout_str.endswith('s'):
        timeout = int(timeout_str[:-1])
    elif timeout_str.endswith('m'):
        timeout = int(timeout_str[:-1]) * 60
    elif timeout_str.endswith('h'):
        timeout = int(timeout_str[:-1]) * 60 * 60
    else:
        timeout = int(timeout_str)

    if timeout > 0:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)


class CFGNode(object):

    def __init__(self, ava, procmap, size, is_call, context=None):
        """Represents a basic block in an ASLR-agnostic manner.

        Keyword Arguments:
        ava -- Absolute virtual address of the start of the basic block.
        procmap -- Map from maps.read_maps().
        size -- Size of the basic block, in bytes.
        is_call -- Whether this CFGNode ends with a call instruction.
        context -- An optional CFGNode to serve as the context for this one.
        Two nodes with the same RVA + object, but different context are treated
        as different.
        """
        assert isinstance(context, CFGNode) or context is None
        if size < 1:
            raise ValueError("Invalid size: %d" % size)

        self.size = size
        self.ava = ava
        self.rva, self.obj = maps.ava_to_rva(procmap, ava)

        if self.obj is None:
            raise ValueError("AVA %#x does not belong to any object" % ava)

        if self.rva in self.obj['reverse_plt']:
            self.plt_sym = self.obj['reverse_plt'][self.rva]
        else:
            self.plt_sym = None

        self.context = context
        self.is_call = is_call
        # parse_ptxed will decide if is_head should be changed to True
        self.is_head = False
        self.description = self._describe()

        self.hash = self._calc_hash()

    def _describe(self):
        # start with object name, RVA, and size
        desc = "%s+%#x[%d]" % (os.path.basename(self.obj['name']),
                               self.rva, self.size)

        # if there's a context, include it
        if not self.context is None:
            desc += '[%04x]' % (hash(self.context) & 0xFFFF)

        # if PLT stub, append symbol name
        if isinstance(self.plt_sym, str):
            desc += " (PLT.%s)" % self.plt_sym

        return desc

    def _calc_hash(self):
        val = (self.obj['obj_id'] << 32) ^ self.rva
        if not self.context is None:
            val ^= (hash(self.context) << 64)
        return val

    def __repr__(self):
        return "<CFGNode %s>" % self.description

    def __str__(self):
        return "<CFGNode %s>" % self.description

    def __hash__(self):
        return self.hash

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self == other

def node2key(node):
    return "%s:%d" % (node.obj['name'], node.rva)

def add_node(graph, node):
    if has_node(graph, node):
        return

    v = graph.add_vertex()

    graph.gp.node2idx[node] = v

    key = node2key(node)
    if not key in graph.gp.rva2node:
        graph.gp.rva2node[key] = set()
    graph.gp.rva2node[key].add(node)

    graph.vp.node[v] = node

def add_edge(graph, src_node, dst_node):
    # perf: add_node checks has_node before adding
    add_node(graph, src_node)
    src_v = graph.gp.node2idx[src_node]

    add_node(graph, dst_node)
    dst_v = graph.gp.node2idx[dst_node]

    if not dst_v in graph.get_out_neighbors(src_v):
        graph.add_edge(src_v, dst_v)

def remove_edge(graph, src_node, dst_node):
    if not has_node(graph, src_node):
        return
    src_v = graph.gp.node2idx[src_node]

    if not has_node(graph, dst_node):
        return
    dst_v = graph.gp.node2idx[dst_node]

    graph.remove_edge(graph.edge(src_v, dst_v))

def has_node(graph, node):
    return node in graph.gp.node2idx

def has_edge(graph, src, dst):
    if not has_node(graph, src):
        return False
    src_v = graph.gp.node2idx[src]

    if not has_node(graph, dst):
        return False
    dst_v = graph.gp.node2idx[dst]

    if dst_v in graph.get_out_neighbors(src_v):
        return True

    return False

def has_path(graph, src_idx, dst_idx):
    return len(shortest_path(graph, src_idx, dst_idx)[0]) > 0

def get_existing_node(graph, node):
    # raises KeyError if node does not exist in the graph, this can be avoided
    # by calling has_node first and checking its return value
    idx = graph.gp.node2idx[node]
    return graph.vp.node[idx]

def successors(graph, node):
    if not has_node(graph, node):
        return set()

    v = graph.gp.node2idx[node]

    return set([graph.vp.node[w] for w in graph.get_out_neighbors(v)])

def predecessors(graph, node):
    if not has_node(graph, node):
        return set()

    v = graph.gp.node2idx[node]

    return set([graph.vp.node[w] for w in graph.get_in_neighbors(v)])

def rva_lookup(graph, obj_name, rva):
    """Look up an RVA + object name and return all nodes for that basic
    block."""
    key = "%s:%d" % (obj_name, rva)
    if key in graph.gp.rva2node:
        return graph.gp.rva2node[key]
    return set()

def rva_lookup_node(graph, node):
    """Lookup all nodes that correspond to the same basic block as node."""
    key = node2key(node)
    if key in graph.gp.rva2node:
        return graph.gp.rva2node[key]
    return set()

def parse_ptxed(input, procmap, graph=None, debug=False):
    """Reads a ptxed disassembly and yields a CFG.

    CFG has a function level context sensitivity of 1.

    Keyword Arguments:
    input -- File path to the ptxed disassembly, '.gz' extension will
    be treated as a gzip file.
    procmap -- Map from maps.read_maps().
    graph -- A directed graph to update. If None, a new graph is
    created

    Returns:
    A CFG as a directed graph
    """
    if input.endswith('.gz'):
        input = gzip.open(input, 'rt')
    else:
        input = open(input, 'r')

    # create graph if one wasn't provided, otherwise validate
    # recieved graph has required properties
    if graph is None:
        graph = Graph(directed=True)

    assert graph.is_directed() == True
    if not 'node2idx' in graph.graph_properties:
        graph.gp.node2idx = graph.new_graph_property("object")
        graph.gp.node2idx = dict()
    if not 'rva2node' in graph.graph_properties:
        graph.gp.rva2node = graph.new_graph_property("object")
        graph.gp.rva2node = dict()
    if not 'node' in graph.vertex_properties:
        graph.vp.node = graph.new_vertex_property("object")

    warned_mnemonics = set()
    curr_bb_start_addr = None
    resume_addr = None
    entering_syscall = False
    prev_node = None
    context = [None]

    for line in input.readlines():
        line = line.rstrip()  # remove newline character

        if line == '[disabled]':
            if debug: log.debug('PTXed: [disabled]')
            # tracing turned off, how should we handle the next instruction?
            if not entering_syscall and curr_bb_start_addr is None:
                # turned off at the end of a basic block, next instruction is
                # a new one, but we don't know if it's related to the prior, so
                # we won't create an edge
                prev_node = None
            elif not entering_syscall:
                # turned off in the middle of a basic block, note where it
                # should resume if it returns to this context, and we'll
                # check later whether it does
                #
                # note that if curr_bb_start_addr is not None, we have decoded
                # at least 1 instruction, so v_addr and instr_size are defined
                resume_addr = v_addr + instr_size
            else:
                # entered a syscall, don't know which context we'll return to
                #
                # note that for entering_syscall to be True, an instruction
                # must have been decoded so v_addr and instr_size are defined
                entering_syscall = False
                resume_addr = v_addr + instr_size

        else:
            instr = PTXED_INSTR.match(line)
            if instr is None:
                # we skip anything else that isn't an instruction
                continue

            if debug: log.debug("PTXed: %s" % line)

            # disassembled instruction
            v_addr = int(instr.group(1), 16)
            instr_size = len(instr.group(2)) // 3
            mnemonic = instr.group(3).rstrip()

            if not resume_addr is None:
                if v_addr != resume_addr:
                    # tracing previously disabled and we resumed somewhere
                    # else, treat this as the start of a new basic block and do
                    # not link it with an edge
                    log.warning("Tracing disabled and resumed somewhere else")
                    curr_bb_start_addr = None
                    prev_node = None

                resume_addr = None

            if curr_bb_start_addr is None:
                # previous instruction completed a basic block, this is now
                # the start of a new one
                curr_bb_start_addr = v_addr

            if mnemonic in COF_MNEMONICS:
                # this will end the current basic block, next instruction
                # will be the start of a new one
                size = v_addr + instr_size - curr_bb_start_addr
                is_call = mnemonic in CALL_MNEMONICS
                curr_node = CFGNode(curr_bb_start_addr, procmap, size, is_call,
                                    context[-1])

                if not prev_node is None:
                    if has_node(graph, curr_node) and not has_edge(graph,
                            prev_node, curr_node):
                        # we've returned to a node we've visited before, via a
                        # new edge, making it a backward edge, so the
                        # destination is the head of a loop
                        curr_node = get_existing_node(graph, curr_node)
                        curr_node.is_head = True
                    add_edge(graph, prev_node, curr_node)
                else:
                    add_node(graph, curr_node)

                if debug: log.debug("PTXed: [BB boundary]")
                prev_node = curr_node
                curr_bb_start_addr = None

                if mnemonic in SYSCALL_MNEMONICS:
                    # we're expecting PT to turn off because we're only tracing
                    # user space, do not disconnect the next node from prior
                    entering_syscall = True
                else:
                    entering_syscall = False

                # update context
                if mnemonic in CALL_MNEMONICS:
                    # call being made, push caller onto context stack
                    context.append(curr_node)
                elif mnemonic in RET_MNEMONICS and len(context) > 1:
                    # return, pop top caller from context stack
                    # (we never pop the final, None context)
                    context.pop()

                # branches and syscalls do not change context

            else:
                if (not mnemonic in BORING_MNEMONICS and
                        not mnemonic in warned_mnemonics):
                    log.warning("Unhandled mnemonic, treating as boring: "
                                "%s" % mnemonic)
                    warned_mnemonics.add(mnemonic)
                entering_syscall = False
                # extra paranoid check that next instruction follows the prior
                resume_addr = v_addr + instr_size

    input.close()
    return graph

def insert_plt_fakeret(graph):
    """Insert fake returns from PLT stubs and disconnect the real successors.

    This is intended for use in post-processing to create self-contained,
    per-object CFGs, which simplifies some types of analysis. For example, an
    algorithm analyzing the control flow of the main object may not care about
    how printf is implemented, just that the program called it. In otherwords,
    this analysis turns this:

    -------------    ------------                                -------------
    | caller BB | => | PLT stub | => ...external execution... => | return BB |
    -------------    ------------                                -------------

    into:

    -------------    ------------    -------------
    | caller BB | => | PLT stub | => | return BB |
    -------------    ------------    -------------

    The graph is modified directly, None is returned.
    """
    for v in graph.vertices():
        node = graph.vp.node[v]

        if node.plt_sym is None:
            # only modifying calls to imported functions
            continue

        succs = successors(graph, node)
        preds = predecessors(graph, node)

        # remove all successor edges
        for succ in succs:
            remove_edge(graph, node, succ)

        # for each calling predecessor, insert a fake return to its return
        # address
        for pred in preds:
            if not pred.is_call:
                continue

            ret_rva = pred.rva + pred.size
            val_nodes = rva_lookup(graph, pred.obj['name'], ret_rva)

            if len(val_nodes) > 0:
                ret_node = None
                for val_node in val_nodes:
                    if val_node.context == pred.context:
                        ret_node = val_node
                        break

                if ret_node is None:
                    log.warning("Cannot find return after %s with correct "
                    "context (return to RVA %#x)" % (pred, ret_rva))
                else:
                    add_edge(graph, node, ret_node)
                    # remove predecessor edges from external objects, including
                    # the real return
                    ret_preds = predecessors(graph, ret_node)
                    for ret_pred in ret_preds:
                        if ret_pred.obj['name'] != ret_node.obj['name']:
                            remove_edge(graph, ret_pred, ret_node)
            else:
                log.warning("Cannot find return after %s (return to RVA "
                            "%#x)" % (pred, ret_rva))

def should_skip_obj(name, filter_keywords):
    """Decides whether an object should be skipped based on the name
    and provided filters.

    Returns True if object should be skipped, otherwise False.
    """
    if name.startswith('['):
        # always skip pseudo-files
        return True

    if filter_keywords is None:
        # no keywords provided, apply a default filter
        obj_basename = os.path.basename(name)
        if obj_basename.startswith('libc-'):
            # skip libc
            return True
        if obj_basename.startswith('ld-'):
            # skip runtime loader
            return True

        # passed all filters, parse it
        return False

    else:
        # keywords were provided, see if any match
        for keyword in filter_keywords:
            if keyword in name:
                # keyword match, parse it
                return False

        # no keyword matches, skip it
        return True

    # should be unreachable
    assert False

def find_exec_units(graph, filter_keywords=None, timeout_str='0s'):
    """Find execution units in the graph.

    An execution unit (EU) is defined as an autonomous unit of work, consisting
    of a group of basic blocks with explicit entry and exit points. Entering an
    EU starts an instance, exiting ends it. Since EUs are autonomous, two
    different instances share no data dependencies and no use-after-free or
    double free bugs can occur between them (but can still occur within the
    same instance).

    Heuristically, EUs are often approximated by finding the outter most loop of
    the program, which is expected to iterate once per task the program
    performs, creating one EU instance per task. Assuming tasks are
    independent, this satisfies the EU definition.

    Not all programs are designed to perform a variable number of tasks. In such
    cases, it is fine to treat the entire program as a single EU which only ever
    spawns one instance.

    Each returned unit is a dictionary with the following keys:
    object -- Name of the object the unit was found in.
    filter -- The object's vertex filter
    head -- Node that marks the head of the unit.

    Returns:
    A list of execution units, see above for layout.
    """
    # Step 1: make per-object subgraphs
    skipped_objs = set()
    parsed_objs = set()
    obj2filter = dict()
    objheads = dict()

    for v in graph.vertices():
        node = graph.vp.node[v]
        obj_name = node.obj['name']

        if obj_name in skipped_objs:
            # already determined object should be skipped,
            # no need to check again
            continue
        elif obj_name in parsed_objs:
            # already determined object should be parsed,
            # no need to check again
            pass
        elif should_skip_obj(obj_name, filter_keywords):
            # object should be skipped,
            # mark so we don't have to recheck again
            skipped_objs.add(obj_name)
            continue
        else:
            # object should be parsed,
            # mark so we don't have to recheck again
            parsed_objs.add(obj_name)

        # record loop heads for future reference
        if not obj_name in objheads:
            objheads[obj_name] = set()

        if node.is_head:
            objheads[obj_name].add(v)

        # record node mask
        if not obj_name in obj2filter:
            obj2filter[obj_name] = graph.new_vertex_property("bool", val=0)

        obj2filter[obj_name][v] = 1

    if len(skipped_objs) > 0:
        log.warning("Skipped objects for EUP: %s" % ', '.join(skipped_objs))

    # Step 2: find all possible units of work
    units = list()

    for obj in obj2filter:
        heads = list(objheads[obj])
        heads.sort()
        log.info("Finding EUs in %s, starting from %d loop "
                 "heads" % (os.path.basename(obj), len(heads)))
        log.debug("Heads: %s" % ', '.join(
                [str(graph.vp.node[n]) for n in heads]))

        # restrict analysis to current object
        filter = obj2filter[obj]
        graph.set_vertex_filter(filter)

        # Step 2a: merge heads to find the outter-most ones
        #
        # We use a trick here, which is that node IDs are assigned sequentially,
        # meaning lower numbers occurred earlier in the traces and are therefore
        # more likely to be outter-most.
        if len(heads) < 1:
            log.warning("No heads, no partitions")
            continue

        merged = [heads[0]]
        try:
            # user may set a timeout for performing merges
            start_timeout(timeout_str)

            for v in heads[1:]:
                should_merge = False
                for h in merged:
                    if has_path(graph, h, v) and has_path(graph, v, h):
                        should_merge = True
                        break
                if not should_merge:
                    # v is a loop head that cannot be reached from any of the
                    # current merged heads, add it as a new merged head
                    merged.append(v)

            # we're done, cancel alarm if one was set
            signal.alarm(0)
        except AnalysisTimeout:
            log.warning("Reached timeout, proceeding with current results")

        # Step 2b: record execution units
        log.info("Found %d units" % len(merged))
        log.debug("Unit heads: %s" % ', '.join(
                [str(graph.vp.node[n]) for n in merged]))

        for v in merged:
            units.append({'object': obj,
                          'filter': filter,
                          'head': graph.vp.node[v]})

    graph.clear_filters()

    log.info("Total units found: %d" % len(units))
    return units

def find_release_sites(graph, units, max_distance=-1):
    """Find quarantine release sites based on a graph and the identified EUs.

    Adds a new key to each unit in units, 'safe_callers', which is a set of
    nodes that call into an instrumented function from a context where it is
    safe to release the quarantine list.

    At enforcement time, function context sensitivity will not be available,
    so the release sites have to be safe in any context.

    Returns:
    Number of safe callers found.
    """
    # functions in the instrumented library that can release the quarantine
    rel_funcs = ['malloc', 'calloc', 'realloc', 'reallocarray']
    # find all PLT stubs that call the instrumented functions
    plts_global = set()
    for v in graph.vertices():
        node = graph.vp.node[v]
        if node.plt_sym in rel_funcs:
            plts_global.add(node)

    num_units = len(units)
    units_with_releases = 0
    num_safe_callers = 0

    for unit in units:
        # object this unit belongs to
        unit_obj = unit['object']
        log.info("Analyzing: %s" % str(unit['head']))

        # get the PLTs for the object this unit belongs to
        unit_plts = set([plt for plt in plts_global if
                plt.obj['name'] == unit_obj])
        # get all callers in the object that call the object's PLTs
        unit_callers = set()
        for plt in unit_plts:
            for pred in predecessors(graph, plt):
                if pred.obj['name'] == unit_obj:
                    unit_callers.add(pred)

        log.debug("Number of PLTs:    %d" % len(unit_plts))
        log.debug("Number of callers: %d" % len(unit_callers))

        unit['safe_callers'] = set()

        # for each caller, can it be reached from the unit's head without going
        # through any other callers?
        for caller in unit_callers:

            # trivial case: unit head ends with a call to one of the PLTs
            if unit['head'] == caller:
                unit['safe_callers'].add(unit['head'])
                # if this happens, we don't need any additional safe callers
                # because this one will always occur at the start of each
                # EU instance
                break

            # normal case: do a path search
            # mask for current object
            filter = unit['filter'].copy()
            # also mask out every other caller
            for other in unit_callers:
                if other != caller:
                    filter[graph.gp.node2idx[other]] = 0

            # set filter and search for path
            graph.set_vertex_filter(filter)

            h_idx = graph.gp.node2idx[unit['head']]
            c_idx = graph.gp.node2idx[caller]
            spath_len = len(shortest_path(graph, h_idx, c_idx)[0])

            # is this the first allocation of the unit?
            if spath_len > 0 and (max_distance < 0 or
                                  spath_len <= max_distance):
                # then it marks the start of a new EU instance and previous
                # deallocations can be released from quarantine
                unit['safe_callers'].add(caller)

            # clear filter
            graph.clear_filters()

        # some bookkeeping for statistics
        unit_safe_callers = len(unit['safe_callers'])
        num_safe_callers += unit_safe_callers
        if unit_safe_callers > 0:
            units_with_releases += 1

    log.info("Found safe callers for %d of %d units" % (units_with_releases,
             num_units))
    assert units_with_releases <= num_units
    if units_with_releases < num_units:
        log.warning("Some units have no safe callers for releasing the "
                    "quarantine list")

    return num_safe_callers

def resolve_output_filepath(options, name):
    """Resolves where the generated profile should be stored.

    Keyword Arguments:
    options -- CLI arguments, parsed by OptionParser.
    name -- Name of the profile

    Returns:
    A string filepath if a suitable output can be resolved, otherwise None.
    """
    output_fp = options.output
    if output_fp is None:
        # user did not specify an output path, resolve a default location
        if sys.platform.startswith('linux'):
            output_fp = os.path.expanduser('~/.config/uaf-defense/%s' % name)
        else:
            log.error("User did not specify an output filepath and no default "
                      "exists for OS: %s" % sys.platform)
            return None

    # check if we're allowed to write to this output
    if os.path.exists(output_fp) and not os.path.isfile(output_fp):
        log.error("Output filepath for profile already exists and is not a "
                  "file")
        return None
    if os.path.isfile(output_fp) and not options.force:
        log.error("Output filepath for profile already exists, if you want to "
                  "overwrite it, re-run with -f.")
        return None

    # ensure directories exist for output filepath
    log.debug("Creating %s" % os.path.dirname(output_fp))
    output_dp = os.path.dirname(output_fp)
    if len(output_dp) > 0:
        os.makedirs(output_dp, exist_ok=True)

    return output_fp

def write_profile(profile_fp, units, maps):
    """Writes a profile to disk based on the data gathered on EUs.

    Assumes profile_fp has already been validated via
    resolve_output_filepath().
    """
    safe_callers = set()
    for unit in units:
        if not 'safe_callers' in unit:
            continue
        for caller in unit['safe_callers']:
            # record caller's return address, this is what'll appear on stack
            safe_callers.add("%s:%0x\n" % (caller.obj['name'],
                    caller.rva + caller.size))

    if len(safe_callers) < 1:
        # no safe callers, create an OTA profile by adding a nonexistent caller
        log.warning("Creating an OTA policy")
        main_obj = maps[0]['cle'].main_object
        safe_callers.add("%s:%0x\n" % (main_obj.binary,
                main_obj.max_addr - main_obj.min_addr))

    with open(profile_fp, 'w') as ofile:
        for caller in safe_callers:
            ofile.write(caller)

class NoMapsException(Exception):
    pass

def load_maps(trace_fp):
    """Given the path to a trace file, load its maps.

    Raises a NoMapsException exception if a maps file cannot be found.
    """
    map_fp = os.path.join(os.path.dirname(trace_fp), 'maps')
    if not os.path.isfile(map_fp):
        raise NoMapsException("No map file found for: %s" % map_fp)
    return maps.read_maps(map_fp)

def main():
    parser = OptionParser(usage='Usage: %prog [options] 1.ptxed[.gz] ...')
    parser.add_option('-l', '--logging', action='store', type='int',
            default=20, help='Log level [10-50] (default: 20 - Info)')
    parser.add_option('--debug-pt', action='store_true', default=False,
            help='Include PT debug messages in debug log (very verbose)')
    parser.add_option('-n', '--no-fakeret', action='store_true', default=False,
            help='Insert fake returns for calls to imported functions.')
    parser.add_option('-d', '--distance', action='store', type='int',
            default=-1, help='Limit max distance for safe caller search')
    parser.add_option('-o', '--output', action='store', type='str',
            default=None, help='Override output filepath for storing generated'
            ' profile')
    parser.add_option('-f', '--force', action='store_true', default=False,
            help='Overwrite output filepath if it already exists')
    parser.add_option('-p', '--partition', action='store', type='str',
            default=None, help='A comma seperated list of substrings denoting'
            ' which objects should be partitioned')
    parser.add_option('-t', '--timeout', action='store', type='str',
            default='0', help='Set timeout for cycle detection, supports '
            'suffixes s, m, and h, timeout is per-object (default: no '
            'timeout)')

    options, args = parser.parse_args()

    if isinstance(options.partition, str):
        options.partition = options.partition.split(',')

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)

    # init stdout logging
    log.setLevel(options.logging)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)7s | %(asctime)-15s '
            '| %(message)s'))
    log.addHandler(handler)

    # init graph and procmap, specify which positional args are traces
    graph = Graph(directed=True)
    procmap = load_maps(args[0])
    traces = args

    # validate profile output path is feasible
    main_obj = procmap[0]['cle'].main_object
    profile_fp = resolve_output_filepath(options,
            base64.b64encode(main_obj.binary.encode('utf8')).decode('ascii'))
    if profile_fp is None:
        log.error("Cannot resolve filepath to store generated profile")
        sys.exit(1)

    # parse PT traces into graph
    for filepath in traces:
        procmap = load_maps(filepath)

        # warn if the traced program appears to be using a custom memory
        # manager, protection requires an instrumented implementation
        for bin_obj in procmap:
            try:
                libbase = os.path.basename(bin_obj['name'])
            except TypeError:
                continue

            for mem_name in CUSTOM_MEM_LIBS:
                if libbase.startswith(mem_name):
                    log.warn("Program appears to use custom memory manager:"
                             " %s" % libbase)
                    break

        log.info("Parsing: %s" % filepath)
        try:
            graph = parse_ptxed(filepath, procmap, graph, options.debug_pt)
        except KeyboardInterrupt as ex:
            raise ex
        except:
            log.error("Failed to parse trace: %s" % format_exc())

    if not options.no_fakeret:
        log.info("Inserting fake returns")
        insert_plt_fakeret(graph)

    log.info("Number of nodes: %d" % graph.num_vertices())
    log.info("Number of edges: %d" % graph.num_edges())

    log.info("Starting execution unit partitioning")
    units = find_exec_units(graph, options.partition, options.timeout)

    if len(units) < 1:
        log.error("No execution units found, nothing to partition")
        num_rels = 0
    else:
        log.info("Searching for quarantine release sites")
        num_rels = find_release_sites(graph, units, options.distance)

    if num_rels < 1:
        log.warning("No sites found, profile will be OTA")

    log.info("Writing profile to: %s" % profile_fp)
    write_profile(profile_fp, units, procmap)

if __name__ == "__main__":
    main()
