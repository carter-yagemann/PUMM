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
    'jnz', 'jo', 'jp', 'js', 'jz', 'bnd jmp'
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
    'xsavec', 'andl', 'data', 'andq', 'andb', 'leaveq', 'rep stosqq', 'lock cmpxchgl',
    'lock decl', 'setbb'
}

# change of flow
COF_MNEMONICS = BRANCH_MNEMONICS | CALL_MNEMONICS | SYSCALL_MNEMONICS | RET_MNEMONICS

CUSTOM_MEM_LIBS = ['libjemalloc.so']

class CFGNode(object):

    def __init__(self, ava, procmap, size, context=None):
        """Represents a basic block in an ASLR-agnostic manner.

        Keyword Arguments:
        ava -- Absolute virtual address of the start of the basic block.
        procmap -- Map from maps.read_maps().
        size -- Size of the basic block, in bytes.
        context -- An optional CFGNode to serve as the context for this one. Two
        nodes with the same RVA + object, but different context are treated as
        different.
        """
        assert isinstance(context, (NoneType, CFGNode))
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
        self.irsb = node2vex(self, procmap)

        self.description = self._describe()

    def _describe(self):
        # start with object name, RVA, and size
        desc = "%s+%#x[%d]" % (os.path.basename(self.obj['name']), self.rva, self.size)

        # if there's a context, include it
        if not self.context is None:
            desc += '[%04x]' % (hash(self.context) & 0xFFFF)

        # if PLT stub, append symbol name
        if isinstance(self.plt_sym, str):
            desc += " (PLT.%s)" % self.plt_sym

        return desc

    def __repr__(self):
        return "<CFGNode %s>" % self.description

    def __str__(self):
        return "<CFGNode %s>" % self.description

    def __hash__(self):
        val = (self.obj['obj_id'] << 32) ^ self.rva
        if not self.context is None:
            val ^= (hash(self.context) << 64)
        return val

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not self == other

def index_graph_rvas(graph):
    """Returns a dictionary for faster lookup of nodes based on a RVA and object name"""
    rva2node = dict()

    for node in graph.nodes:
        key = "%s:%d" % (node.obj['name'], node.rva)
        if not key in rva2node:
            # due to context sensitivity, a basic block can have multiple nodes
            rva2node[key] = set()
        rva2node[key].add(node)

    return rva2node

def rva_lookup(index, obj_name, rva):
    """Look up an RVA + object name in an index created by index_graph_rvas() and
    return all nodes for that basic block."""
    key = "%s:%d" % (obj_name, rva)
    if key in index:
        return index[key]
    return set()

def rva_lookup_node(index, node):
    """Lookup all nodes in index that correspond to the same basic block as node.

    Index is created by index_graph_rvas().
    """
    key = "%s:%d" % (node.obj['name'], node.rva)
    if key in index:
        return index[key]
    return set()

def parse_ptxed(input, procmap, graph=None):
    """Reads a ptxed disassembly and yields a CFG.

    CFG has a function level context sensitivity of 1.

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
    context = [None]

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

            if mnemonic in COF_MNEMONICS:
                # this will end the current basic block, next instruction
                # will be the start of a new one
                size = v_addr + instr_size - curr_bb_start_addr
                curr_node = CFGNode(curr_bb_start_addr, procmap, size, context[-1])
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

                # update context
                if mnemonic in CALL_MNEMONICS:
                    # call being made, push caller onto context stack
                    context.append(curr_node)
                elif mnemonic in RET_MNEMONICS and len(context) > 1:
                    # return, pop top caller from context stack
                    # (we never pop the final, None context)
                    context.pop()

                # branches and syscalls do not change context

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

def insert_plt_fakeret(graph):
    """Insert fake returns from PLT stubs and disconnect the real successors.

    This is intended for use in post-processing to create self-contained, per-object
    CFGs, which simplifies some types of analysis. For example, an algorithm analyzing
    the control flow of the main object may not care about how printf is implemented,
    just that the program called it. In otherwords, this analysis turns this:

    -------------    ------------     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     -------------
    | caller BB | => | PLT stub | => { dynamic symbol resolving, etc. } => | return BB |
    -------------    ------------     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     -------------

    into:

    -------------    ------------    -------------
    | caller BB | => | PLT stub | => | return BB |
    -------------    ------------    -------------

    The graph is modified directly, nothing is returned.
    """
    # create a dictionary so we can lookup nodes faster based on object name + RVA
    rva2node = index_graph_rvas(graph)

    for node in graph.nodes:
        if node.plt_sym is None:
            # only modifying calls to imported functions
            continue

        succs = list(graph.successors(node))
        preds = list(graph.predecessors(node))

        # remove all successor edges
        graph.remove_edges_from([(node, succ) for succ in succs])

        # for each calling predecessor, insert a fake return to its return address
        for pred in preds:
            if pred.irsb.jumpkind != 'Ijk_Call':
                continue

            ret_rva = pred.rva + pred.size
            val_nodes = rva_lookup(rva2node, pred.obj['name'], ret_rva)

            if len(val_nodes) > 0:
                ret_node = None
                for val_node in val_nodes:
                    if val_node.context == pred.context:
                        ret_node = val_node
                        break

                if ret_node is None:
                    log.warning("Cannot find return after %s with correct context "
                                "(return to RVA %#x)" % (pred, ret_rva))
                else:
                    graph.add_edge(node, ret_node)
                    # remove predecessor edges from external objects, including the real return
                    ret_preds = list(graph.predecessors(ret_node))
                    for ret_pred in ret_preds:
                        if ret_pred.obj['name'] != ret_node.obj['name']:
                            graph.remove_edge(ret_pred, ret_node)
            else:
                log.warning("Cannot find return after %s (return to RVA %#x)" % (pred, ret_rva))

def find_exec_units(graph):
    """Find execution units in the graph.

    An execution unit (EU) is defined as an autonomous unit of work, consisting of a group of
    basic blocks with explicit entry and exit points. Entering an EU starts an instance,
    exiting ends it. Since EUs are autonomous, two different instances share no data
    dependencies.

    Each returned unit is a dictionary with the following keys:
    object -- Name of the object the unit was found in.
    entries -- Nodes within the unit that can be the start of an instance.
    exits -- Nodes within the unit that could lead outside, thereby ending an instance.
    nodes -- All the nodes in the execution unit.

    Returns:
    A list of execution units, see above for layout.
    """
    # Step 1: make per-object subgraphs
    skipped_objs = set()
    obj2nodes = dict()

    for node in graph.nodes:
        obj_name = node.obj['name']
        if obj_name.startswith('['):
            skipped_objs.add(obj_name)
            continue  # pseudo-file

        obj_basename = os.path.basename(obj_name)
        if obj_basename.startswith('libc-'):
            skipped_objs.add(obj_basename)
            continue  # we don't care about libc
        if obj_basename.startswith('ld-'):
            skipped_objs.add(obj_basename)
            continue  # we don't care about ld

        if not obj_name in obj2nodes:
            obj2nodes[obj_name] = set()

        obj2nodes[obj_name].add(node)

    if len(skipped_objs) > 0:
        log.warning("Skipped objects for EUP: %s" % ', '.join(skipped_objs))

    subgraphs = dict()
    for obj in obj2nodes:
        subgraphs[obj] = nx.subgraph(graph, obj2nodes[obj])

    # Step 2: find all possible units of work
    units = list()

    for obj in subgraphs:
        # Step 2a: find all simple cycles
        log.info("Finding cycles for: %s" % os.path.basename(obj))
        sub = subgraphs[obj]
        simples = nx.simple_cycles(sub)

        # Step 2b: merge together simple cycles that share any nodes in common
        simple_nodes = set()
        for cycle in simples:
            for node in cycle:
                simple_nodes.add(node)

        merged_cycs = list(nx.connected_components(nx.to_undirected(
                           nx.subgraph(sub, simple_nodes))))

        log.info("Found %d cycles in %s" % (len(merged_cycs), os.path.basename(obj)))

        # Step 2c: identify which nodes are entries and exits
        #
        # Note: When we say entry/exit node, we mean the first/last node *within* the
        # execution unit that could start/end an instance. E.g., an exit node can be a branching
        # basic block where one edge leads to another iteration of a loop (continuing the
        # instance) and the other leads to a block outside the unit, thereby ending it.
        for cycle in merged_cycs:
            entries = set()
            exits = set()

            for node in cycle:
                if not node.plt_sym is None:
                    # PLT stubs cannot be entries or exits
                    continue

                for pred in sub.predecessors(node):
                    if not pred in cycle:
                        entries.add(node)
                        break
                for succ in sub.successors(node):
                    if not succ in cycle:
                        exits.add(node)
                        break

            if len(entries) > 0 and len(exits) > 0:
                log.debug("Found cycle in %s with %d nodes, %d entries, %d exits" % (
                          os.path.basename(obj), len(cycle), len(entries), len(exits)))
                units.append({'object': obj, 'entries': entries, 'exits': exits,
                              'nodes': cycle})
            elif len(entries) < 1:
                log.warning("Skipped possible unit with no entries")
            elif len(exits) < 1:
                log.warning("Skipped possible unit with no exits")

    log.info("Total units found: %d" % len(units))
    return units

def find_release_sites(graph, units):
    """Find quarantine release sites based on a graph and the identified EUs.

    Adds a new key to each unit in units, 'safe_callers', which is a set of nodes
    that call into an instrumented function from a context where it is safe to
    release the quarantine list.

    Returns the number of safe callers found.
    """
    # At enforcement time, function context sensitivity will not be available,
    # so the release sites have to be safe in any context. To help with this
    # check, we build a dictionary to map every address to all its nodes.
    rva2node = index_graph_rvas(graph)

    # functions in the instrumented library that can release the quarantine list
    rel_funcs = ['free']
    # find all PLT stubs that call the instrumented functions
    plts_global = set()
    for node in graph.nodes:
        if node.plt_sym in rel_funcs:
            plts_global.add(node)

    # build per-object sets of all nodes belonging to basic blocks that are in a unit
    obj2ublocks = dict()
    for unit in units:
        unit_obj = unit['object']
        if not unit_obj in obj2ublocks:
            obj2ublocks[unit_obj] = set()
        for unit_node in unit['nodes']:
            obj2ublocks[unit_obj] |= rva_lookup_node(rva2node, unit_node)

    num_units = len(units)
    units_with_releases = 0
    num_safe_callers = 0

    for unit in units:
        # object this unit belongs to
        unit_obj = unit['object']
        # get the PLTs for the object this unit belongs to
        unit_plts = set([plt for plt in plts_global if plt.obj['name'] == unit_obj])
        # all nodes corresponding to basic blocks associated with units in this object
        obj_unit_blocks = obj2ublocks[unit_obj]

        # for each PLT, if there's a caller basic block that is not in an execution
        # unit under any context, this is a safe context to release the quarantine list
        unit['safe_callers'] = set()
        for plt in unit_plts:
            for pred in graph.predecessors(plt):
                if not pred in obj_unit_blocks:
                    unit['safe_callers'].add(pred)

        unit_safe_callers = len(unit['safe_callers'])
        num_safe_callers += unit_safe_callers
        if unit_safe_callers > 0:
            units_with_releases += 1

    log.info("Found safe callers for %d of %d units" % (units_with_releases, num_units))
    assert units_with_releases <= num_units
    if units_with_releases < num_units:
        log.warning("Some units have no safe callers for releasing the quarantine list")

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
        log.error("Output filepath for profile already exists and is not a file")
        return None
    if os.path.isfile(output_fp) and not options.force:
        log.error("Output filepath for profile already exists, if you want to "
                  "overwrite it, re-run with -f.")
        return None

    # ensure directories exist for output filepath
    log.debug("Creating %s" % os.path.dirname(output_fp))
    os.makedirs(os.path.dirname(output_fp), exist_ok=True)

    return output_fp

def write_profile(profile_fp, units):
    """Writes a profile to disk based on the data gathered on EUs.

    Assumes profile_fp has already been validated via resolve_output_filepath().
    """
    safe_callers = set()
    for unit in units:
        if not 'safe_callers' in unit:
            log.warning("Unit is missing safe callers set")
            continue
        safe_callers |= unit['safe_callers']

    with open(profile_fp, 'w') as ofile:
        for caller in safe_callers:
            # record caller's return address, this is what'll appear on stack
            ofile.write("%s:%0x\n" % (caller.obj['name'], caller.rva + caller.size))

def main():
    parser = OptionParser(usage='Usage: %prog [options] 1.ptxed ...')
    parser.add_option('-n', '--no-fakeret', action='store_true', default=False,
            help='Insert fake returns for calls to imported functions.')
    parser.add_option('-d', '--dot', action='store_true', default=False,
            help='Save CFG graph as dot file')
    parser.add_option('-l', '--logging', action='store', type='int', default=20,
            help='Log level [10-50] (default: 20 - Info)')
    parser.add_option('-o', '--output', action='store', type='str', default=None,
            help='Override output filepath for storing generated profile')
    parser.add_option('-f', '--force', action='store_true', default=False,
            help='Overwrite output filepath if it already exists')

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

        # warn if the traced program appears to be using a custom memory manager,
        # protection requires an instrumented implementation
        for bin_obj in procmap:
            try:
                libbase = os.path.basename(bin_obj['name'])
            except:
                continue

            for mem_name in CUSTOM_MEM_LIBS:
                if libbase.startswith(mem_name):
                    log.warn("Program appears to use custom memory manager: %s" % libbase)
                    break

        log.info("Parsing: %s" % filepath)
        graph = parse_ptxed(filepath, procmap, graph)

    # Sadly, this is the earliest point where we can resolve the output filepath for
    # the profile we're going to generate because we want to name it based on the
    # main object and we don't know its name until we've parsed a trace.
    main_obj = procmap[0]['cle'].main_object
    profile_fp = resolve_output_filepath(options, main_obj.binary_basename)
    if profile_fp is None:
        log.error("Cannot resolve filepath to store generated profile")
        sys.exit(1)

    if not options.no_fakeret:
        log.info("Inserting fake returns")
        insert_plt_fakeret(graph)

    if options.dot:
        ofd, ofilepath = tempfile.mkstemp('.dot')
        os.close(ofd)

        log.info("Saving graph to: %s" % ofilepath)
        write_dot(graph, ofilepath)

    log.info("Number of nodes: %d" % graph.number_of_nodes())
    log.info("Number of edges: %d" % graph.number_of_edges())

    log.info("Starting execution unit partitioning")
    units = find_exec_units(graph)
    if len(units) < 1:
        log.error("No execution units found, nothing to partition")
        return

    log.info("Searching for quarantine release sites")
    num_rels = find_release_sites(graph, units)

    if num_rels < 1:
        log.warning("No sites found, no profile will be generated")
    else:
        log.info("Writing profile to: %s" % profile_fp)
        write_profile(profile_fp, units)

if __name__ == "__main__":
    main()
