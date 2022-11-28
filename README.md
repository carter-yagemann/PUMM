# Setup

Tested on Debian Buster x86-64, Python 3.7, CPU must support Intel PT for tracing.

1. Install `cmake`, `elf.h`, `gawk`, and `perf`:

```
sudo apt install build-essential cmake libc6-dev gawk linux-perf
```

2. Run `./scripts/build.sh` from the root directory of this repository.

3. Install [Graph-Tool](https://git.skewed.de/count0/graph-tool/-/wikis/installation-instructions).

4. Install additional Python modules:

```
pip install -Ur ./src/analysis/requirements.txt
```

5. Ensure `perf` supports Intel PT:

```
$ perf list | grep intel_pt
  intel_pt//                                         [Kernel PMU event]
```

# Usage

We will use `$REPO` to denote the root directory of this repository.

1. Record at least 1 trace:

```
$ cd $(mktemp -d)
$ $REPO/scripts/trace.sh /bin/ls
perf.data
[ perf record: Woken up 1 times to write data ]
[ perf record: Captured and wrote 0.031 MB perf.data ]
```

2. Disassemble the trace:

**Note:** Disassembly may take a long time and traces may be very large.

```
$REPO/scripts/ptxed.sh
```

3. Run the analysis:

**Note:** Multiple traces of the same program can be merged together by passing
all their `*.ptxed.gz` files to `analysis.py`.

```
$ $REPO/src/analysis/analysis.py $(find -name "*.ptxed.gz" -type f)
   INFO | 2021-07-09 13:16:34,509 | Parsing: ./1.ptxed.gz
   INFO | 2021-07-09 13:16:39,138 | Inserting fake returns
   INFO | 2021-07-09 13:16:39,160 | Number of nodes: 9282
   INFO | 2021-07-09 13:16:39,160 | Number of edges: 9815
   INFO | 2021-07-09 13:16:39,160 | Starting execution unit partitioning
WARNING | 2021-07-09 13:16:39,171 | Skipped objects for EUP: /usr/lib/x86_64-linux-gnu/ld-2.31.so, /usr/lib/x86_64-linux-gnu/libc-2.31.so
   INFO | 2021-07-09 13:16:39,171 | Finding EUs in libpthread-2.31.so, starting from 2 loop heads
   INFO | 2021-07-09 13:16:39,172 | Found 2 units
   INFO | 2021-07-09 13:16:39,172 | Finding EUs in libdl-2.31.so, starting from 0 loop heads
WARNING | 2021-07-09 13:16:39,172 | No heads, no partitions
   INFO | 2021-07-09 13:16:39,172 | Finding EUs in libpcre2-8.so.0.10.1, starting from 0 loop heads
WARNING | 2021-07-09 13:16:39,172 | No heads, no partitions
   INFO | 2021-07-09 13:16:39,172 | Finding EUs in libselinux.so.1, starting from 2 loop heads
   INFO | 2021-07-09 13:16:39,172 | Found 2 units
   INFO | 2021-07-09 13:16:39,172 | Finding EUs in ls, starting from 9 loop heads
   INFO | 2021-07-09 13:16:39,180 | Found 2 units
   INFO | 2021-07-09 13:16:39,181 | Total units found: 6
   INFO | 2021-07-09 13:16:39,181 | Searching for quarantine release sites
   INFO | 2021-07-09 13:16:39,191 | Analyzing: <CFGNode libpthread-2.31.so+0xe2cc[11][4a9d]>
   INFO | 2021-07-09 13:16:39,191 | Analyzing: <CFGNode libpthread-2.31.so+0xe2cc[11][5ada]>
   INFO | 2021-07-09 13:16:39,191 | Analyzing: <CFGNode libselinux.so.1+0xf231[16][f5b4]>
   INFO | 2021-07-09 13:16:39,191 | Analyzing: <CFGNode libselinux.so.1+0x7e5c[13][f292]>
   INFO | 2021-07-09 13:16:39,191 | Analyzing: <CFGNode ls+0x40a0[6][2bde] (PLT.__errno_location)>
   INFO | 2021-07-09 13:16:39,195 | Analyzing: <CFGNode ls+0x140cd[22][4bc6]>
   INFO | 2021-07-09 13:16:39,199 | Found safe callers for 2 of 6 units
WARNING | 2021-07-09 13:16:39,199 | Some units have no safe callers for releasing the quarantine list
   INFO | 2021-07-09 13:16:39,199 | Writing profile to: /home/carter/.config/uaf-defense/L3Vzci9iaW4vbHM=
```

4. Use the generated profile with the analyzed program:

```
$REPO/scripts/hook.sh /bin/ls
```

# Profiles

Profiles are written into `$HOME/.config/uaf-defense`. They are currently
*not portable* and *do not check for file modifications*, so if you move or
update an executable or library, the profile must be regenerated.

# Publications

* Carter Yagemann, Simon P. Chung, Brendan Saltaformaggio, Wenke Lee.
  [*PUMM: Preventing Use-After-Free Using Execution Unit Partitioning.*](https://www.usenix.org/conference/usenixsecurity23/presentation/yagemann)
  Appeared in the 32nd USENIX Security Symposium (USENIX’23).
  Anaheim, California. August 9-11, 2023.
