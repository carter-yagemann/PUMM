# Setup

Tested on Debian Buster, CPU must support Intel PT for tracing.

1. Install `cmake`, `elf.h`, and `perf`:

```
sudo apt install build-essential cmake libc6-dev linux-perf
```

2. Run `./src/build.sh` from the root directory of this repository.

3. Install required Python modules:

```
pip install -Ur ./src/analysis/requirements.txt
```

4. Ensure `perf` supports Intel PT:

```
$ perf list | grep intel_pt
  intel_pt//                                         [Kernel PMU event]
```
