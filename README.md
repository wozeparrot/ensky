# ensky: a flexible wireguard mesher

ensky is a [NixOS](https://nixos.org/)-integrated WireGuard mesh propagator. Requiring only a single known node it is able to bootstrap a mesh network of WireGuard peers. It is designed to be flexible and extensible, allowing for a variety of use cases, not just a mesh network.

ensky was born from the requirement of supporting a hybrid static hub-and-spoke and dynamic mesh network. Inspired by the automeshers that already exist but were either too complex or not flexible enough.

Written in [zig](https://ziglang.org) with zero heap allocations.

## Usage

Preferred usage is via the NixOS module in (flake.nix)[flake.nix]. But it is also possible to use it standalone by manually writing the configuration JSON with the format specific in [main.zig](src/main.zig).

The gossip port must be open and the same on all machines that run ensky.

Requires [zig](https://ziglang.org) master to build.

## LICENSE

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
