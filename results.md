# Benchmark results

Last run on main: commit [eaffdd8](https://github.com/scionproto-contrib/csnet/commit/eaffdd8e3a73841b9ea233c93a7d5501337e68be), [workflow run](https://github.com/scionproto-contrib/csnet/actions/runs/46019361180).

Each round sends a packet over loopback and receives it. The overhead is the time that csnet
adds to a plain UDP socket, see [Running the Benchmarks](https://github.com/scionproto-contrib/csnet#running-the-benchmarks).

| Size | csnet | UDP | Overhead |
|---:|---:|---:|---:|
| 64 B | 6046 ns | 5101 ns | +19% |
| 512 B | 6031 ns | 5155 ns | +17% |
| 1400 B | 6296 ns | 5178 ns | +22% |
