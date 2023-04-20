nfstop
======

[nfswatch](https://nfswatch.sourceforge.io/) is an indispensable diagnostic tool for heavily used NFS servers. Unfortunately, it only supports NFSv3 and is blind to all NFSv4 traffic. For several years we've been looking for a NFSv4-capable replacement in order to be able to diagnose IO issues on our file servers. After several failed attempts we finally discovered the [nfs tapset](https://sourceware.org/systemtap/man/tapset::nfs.3stap.html) for [systemtap](https://sourceware.org/systemtap/) that readily provides the data needed for an in-depth inspection of an NFS server. nfstop consists of a python script that launches a systemtap probe which outputs a JSON that python then parses and displays.

### Requirements

On Debian, you'll need `systemtap linux-headers-generic linux-image-amd64-dbg python3-rich`. On Ubuntu, it's `linux-image-$(uname -r)-dbgsym`, see [here](https://wiki.ubuntu.com/Kernel/Systemtap#Where_to_get_debug_symbols_for_kernel_X.3F).

### Usage

Just run `./nfstop.py`. It'll take some seconds to compile and insmod the systemtap module. Currently there are two command line parameters: `--seconds` to set the update interval and `--lines` to determine how many hosts/users are shown in each category.
