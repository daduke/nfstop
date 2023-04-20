nfstop
======

[nfswatch](https://nfswatch.sourceforge.io/) is an indispensable diagnostic tool for heavily used NFS servers. Unfortunately, it only supports NFSv3 and is blind to all NFSv4 traffic. For several years we've been looking for a NFSv4-capable replacement in order to be able to diagnose IO issues on our file servers. After several failed attempts we finally discovered the [https://sourceware.org/systemtap/man/tapset::nfs.3stap.html](nfs tapset) for [systemtap](https://sourceware.org/systemtap/) that readily provides the data needed for an in-depth inspection of an NFS server. nfstop consists of a python script that launches a systemtap probe which outputs a JSON that python then parses and displays.

