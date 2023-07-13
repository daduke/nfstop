#!/usr/bin/env python3

# nfstop via systemtap, supports both NFSv3 and v4
# derived from nfsdtop.stp (systemtap examples)
# (c) 2023 Christian Herzog <daduke@daduke.org>
#
# needs systemtap linux-headers-generic linux-image-amd64-dbg python3-rich

# TODO
# show protocol version?
# ebpf engine?

import json
import socket
import re
import pwd
import subprocess
import argparse
import stat
import signal
import sys
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", "-s", help="update interval", default="2")
    parser.add_argument("--lines", "-l", help="number of data points per category", default="10")
    args = parser.parse_args()

    stp_file = Path("nfstop-temp.stp")
    with open(stp_file, "w") as f:
        f.write(systemtap(args.seconds, args.lines))
    stp_file.chmod(stp_file.stat().st_mode | stat.S_IEXEC)

    myself = socket.gethostname()
    console = Console()
    console.clear(home=True)
    with Live(console=console) as live_table:
        for line in execute([f"./{str(stp_file)}"]):
            data = json.loads(line)

            now = datetime.now().strftime("%H:%M:%S")
            t = Table(box=box.MINIMAL, expand=True, title='nfstop on '+myself+', '+now, title_style="bold", title_justify="right")
            t.add_column("read", ratio=1)
            t.add_column("write", ratio=1)

            read_table = halftable()
            write_table = halftable()
            t.add_row(read_table, write_table)

            addrow(read_table, "total", "reads", "MiB/s", "bold")
            addrow(read_table, "", "", "", "underline")

            total_ops_r = int(data["total"]["read"][0]["reads"])
            total_bw_r = int(data["total"]["read"][0]["bw"])
            addrow(read_table, "", str(total_ops_r), str(total_bw_r), "")
            addrow(read_table, "", "", "", "")
            addrow(read_table, "", "", "", "")

            total_ops_w = int(data["total"]["write"][0]["writes"])
            total_bw_w = int(data["total"]["write"][0]["bw"])
            addrow(write_table, "total", "writes", "MiB/s", "bold")
            addrow(write_table, "", "", "", "underline")
            addrow(write_table, "", str(total_ops_w), str(total_bw_w), "")
            addrow(write_table, "", "", "", "")
            addrow(write_table, "", "", "", "")

            # top hosts
            addrow(read_table, "top hosts", "reads", "MiB/s", "bold")
            addrow(read_table, "", "", "", "underline")
            host_ops_r = 0
            host_bw_r = 0
            for host in data["by_ip"]["read"]:
                hostname = lookup(host["ip"])
                ops = host["reads"]
                bw = host["bw"]
                addrow(read_table, hostname, ops, bw, "")
                host_ops_r += int(ops)
                host_bw_r += int(bw)
            if total_ops_r != host_ops_r:
                addrow(read_table, "others", str(total_ops_r - host_ops_r), str(total_bw_r - host_bw_r), "italic")
            for n in range(len(data["by_ip"]["read"]), int(args.lines) + 2):
                addrow(read_table, "", "", "", "")

            addrow(write_table, "top hosts", "writes", "MiB/s", "bold")
            addrow(write_table, "", "", "", "underline")
            host_ops_w = 0
            host_bw_w = 0
            for host in data["by_ip"]["write"]:
                hostname = lookup(host["ip"])
                ops = host["writes"]
                bw = host["bw"]
                addrow(write_table, hostname, ops, bw, "")
                host_ops_w += int(ops)
                host_bw_w += int(bw)
            if total_ops_w != host_ops_w:
                addrow(write_table, "others", str(total_ops_w - host_ops_w), str(total_bw_w - host_bw_w), "italic")
            for n in range(len(data["by_ip"]["write"]), int(args.lines) + 2):
                addrow(write_table, "", "", "", "")

            # top uids
            addrow(read_table, "top users", "reads", "MiB/s", "bold")
            addrow(read_table, "", "", "", "underline")
            user_ops_r = 0
            user_bw_r = 0
            for user in data["by_uid"]["read"]:
                name = uname(user["uid"])
                ops = user["reads"]
                bw = user["bw"]
                addrow(read_table, name, ops, bw, "")
                user_ops_r += int(ops)
                user_bw_r += int(bw)
            if total_ops_r != user_ops_r:
                addrow(read_table, "others", str(total_ops_r - user_ops_r), str(total_bw_r - user_bw_r), "italic")

            addrow(write_table, "top users", "writes", "MiB/s", "bold")
            addrow(write_table, "", "", "", "underline")
            user_ops_w = 0
            user_bw_w = 0
            for user in data["by_uid"]["write"]:
                name = uname(user["uid"])
                ops = user["writes"]
                bw = user["bw"]
                addrow(write_table, name, ops, bw, "")
                user_ops_w += int(ops)
                user_bw_w += int(bw)
            if total_ops_w != user_ops_w:
                addrow(write_table, "others", str(total_ops_w - user_ops_w), str(total_bw_w - user_bw_w), "italic")

            live_table.update(t)


def execute(cmd):
    signal.signal(signal.SIGINT, signal_handler)
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)


def signal_handler(sig, frame):
    sys.exit(0)


def halftable():
    t = Table(box=box.SIMPLE_HEAD, expand=True, show_header=False)
    t.add_column("", ratio=2)
    t.add_column("", justify="right", ratio=1)
    t.add_column("", justify="right", ratio=1)

    return t


def addrow(table, col1, col2, col3, style):
    table.add_row(col1, col2, col3, style=style)


def lookup(ip):
    ip = re.sub(r":\d+$", "", ip)  # strip port
    name, alias, addresslist = socket.gethostbyaddr(ip)
    if name:
        tld, domain, *sub_domains, hostname = name.split(".")[::-1]
        return hostname
    else:
        return ip


def uname(uid):
    uname = pwd.getpwuid(int(uid))
    if uname:
        return uname.pw_name
    else:
        return uid


def systemtap(seconds, lines):
    script = r"""#!/usr/bin/env stap

# nfsd global counters
global nfsd_reads
global nfsd_writes

# nfsd client tables
global nfsd_read_clients
global nfsd_write_clients

# nfsd uid tables
global nfsd_write_uids
global nfsd_read_uids


probe nfsd.proc.read {
    uid_s = sprintf("%d", uid)
    nfsd_reads <<< size
    nfsd_read_clients[client_ip] <<< size
    nfsd_read_uids[uid_s] <<< size
}

probe nfsd.proc.write {
    uid_s = sprintf("%d", uid)
    nfsd_writes <<< size
    nfsd_write_clients[client_ip] <<< size
    nfsd_write_uids[uid_s] <<< size
}

probe timer.sec(SECONDS) {
    print("{")

    # total
    print("\"total\": {\"write\": [")
    printf("{\"writes\": \"%d\",\"bw\": \"%d\"}",
        @count(nfsd_writes),
        (@sum(nfsd_writes) >> 20)/SECONDS)
    print("],\"read\": [")
    printf("{\"reads\": \"%d\",\"bw\": \"%d\"}",
        @count(nfsd_reads),
        (@sum(nfsd_reads) >> 20)/SECONDS)
    print("]},")

    # by ip
    print("\"by_ip\": {\"write\": [")
    delimiter = "";
    foreach (ip in nfsd_write_clients- limit LINES) {
        printf("%s{\"ip\": \"%s\",\"writes\": \"%d\",\"bw\": \"%d\"}",
            delimiter,
            ip,
            @count(nfsd_write_clients[ip]),
            (@sum(nfsd_write_clients[ip]) >> 20)/SECONDS)
        delimiter = ",";
    }
    print("],\"read\": [")
    delimiter = "";
    foreach (ip in nfsd_read_clients- limit LINES) {
        printf("%s{\"ip\": \"%s\",\"reads\": \"%d\",\"bw\": \"%d\"}",
            delimiter,
            ip,
            @count(nfsd_read_clients[ip]),
            (@sum(nfsd_read_clients[ip]) >> 20)/SECONDS)
        delimiter = ",";
    }
    print("]},")

    # by uid
    print("\"by_uid\": {\"write\": [")
    delimiter = "";
    foreach (uid in nfsd_write_uids- limit LINES) {
        printf("%s{\"uid\": \"%s\",\"writes\": \"%d\",\"bw\": \"%d\"}",
            delimiter,
            uid,
            @count(nfsd_write_uids[uid]),
            (@sum(nfsd_write_uids[uid]) >> 20)/SECONDS)
        delimiter = ",";
    }
    print("],\"read\": [")
    delimiter = "";
    foreach (uid in nfsd_read_uids- limit LINES) {
        printf("%s{\"uid\": \"%s\",\"reads\": \"%d\",\"bw\": \"%d\"}",
            delimiter,
            uid,
            @count(nfsd_read_uids[uid]),
            (@sum(nfsd_read_uids[uid]) >> 20)/SECONDS)
        delimiter = ",";
    }
    print("]}")
    print("}\n")

    delete nfsd_reads
    delete nfsd_writes
    delete nfsd_read_clients
    delete nfsd_read_uids
    delete nfsd_write_clients
    delete nfsd_write_uids
}
"""
    script = script.replace("SECONDS", seconds)
    script = script.replace("LINES", lines)

    return script


if __name__ == "__main__":
    main()
