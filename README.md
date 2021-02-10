# Setup

Tested on Debian Buster, CPU must support Intel PT for tracing.

*Note: We recommend using a Python virtual environment to simplify module
installation and [PyPy](https://www.pypy.org/) for better performance.*

1. Install `cmake`, `elf.h`, `gawk`, and `perf`:

```
sudo apt install build-essential cmake libc6-dev gawk linux-perf
```

2. Run `./scripts/build.sh` from the root directory of this repository.

3. Install required Python modules:

```
pip install -Ur ./src/analysis/requirements.txt
```

4. Ensure `perf` supports Intel PT:

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

*Note: Disassembly may take a long time and traces may be very large.*

```
$REPO/scripts/ptxed.sh
```

3. Run the analysis:

*Note: Multiple traces of the same program can be merged together by passing
all their `*.ptxed.gz` files to `analysis.py`.*

```
$ $REPO/src/analysis/analysis.py $(find -name "*.ptxed.gz" -type f)
   INFO | 2021-01-13 15:17:57,388 | Parsing: ./5.ptxed.gz
   INFO | 2021-01-13 15:18:01,905 | Inserting fake returns
   INFO | 2021-01-13 15:18:01,910 | Number of nodes: 3558
   INFO | 2021-01-13 15:18:01,914 | Number of edges: 4284
   INFO | 2021-01-13 15:18:01,914 | Starting execution unit partitioning
WARNING | 2021-01-13 15:18:01,921 | Skipped objects for EUP: ld-2.28.so, libc-2.28.so
   INFO | 2021-01-13 15:18:01,922 | Finding cycles for: libpthread-2.28.so
   INFO | 2021-01-13 15:18:01,928 | Found 4 cycles in libpthread-2.28.so
WARNING | 2021-01-13 15:18:01,928 | Skipped possible unit with no entries
   INFO | 2021-01-13 15:18:01,929 | Finding cycles for: libdl-2.28.so
   INFO | 2021-01-13 15:18:01,930 | Found 0 cycles in libdl-2.28.so
   INFO | 2021-01-13 15:18:01,930 | Finding cycles for: libpcre.so.3.13.3
   INFO | 2021-01-13 15:18:01,930 | Found 0 cycles in libpcre.so.3.13.3
   INFO | 2021-01-13 15:18:01,931 | Finding cycles for: libselinux.so.1
   INFO | 2021-01-13 15:18:01,940 | Found 3 cycles in libselinux.so.1
WARNING | 2021-01-13 15:18:01,940 | Skipped possible unit with no entries
WARNING | 2021-01-13 15:18:01,940 | Skipped possible unit with no entries
   INFO | 2021-01-13 15:18:01,940 | Finding cycles for: ls
   INFO | 2021-01-13 15:18:02,240 | Found 3 cycles in ls
WARNING | 2021-01-13 15:18:02,240 | Skipped possible unit with no entries
WARNING | 2021-01-13 15:18:02,240 | Skipped possible unit with no entries
   INFO | 2021-01-13 15:18:02,242 | Total units found: 5
```
