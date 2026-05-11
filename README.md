# Scorpi

Scorpi is a platform for creating and running reproducible Linux and Windows VM
environments from a scriptable CLI. It is built on the
[`scorpi-hv`](https://github.com/macos-fuse-t/scorpi-hv) hypervisor runtime and
provides managed VM templates, guest-agent command execution, host/guest file
sharing, port forwarding, snapshots, and disposable starts.

The user experience is Docker-like: create environments from named templates,
start and stop them quickly, run commands inside them, attach files and ports,
and discard temporary VMs when you are done.

Project site: [fuse-t.org/scorpi](https://fuse-t.org/scorpi)

Documentation: [fuse-t.org/scorpi/docs](https://fuse-t.org/scorpi/docs)

## Install

Install Scorpi with Homebrew:

```sh
brew install macos-fuse-t/homebrew-cask/scorpi
```

## Quick Start

```sh
scorpi status
scorpi template list
scorpi create dev --template ubuntu
scorpi start dev
scorpi run dev -- uname -a
```

## Related Repositories

- Scorpi hypervisor: [macos-fuse-t/scorpi-hv](https://github.com/macos-fuse-t/scorpi-hv)
- Scorpi documentation: [fuse-t.org/scorpi/docs](https://fuse-t.org/scorpi/docs)
