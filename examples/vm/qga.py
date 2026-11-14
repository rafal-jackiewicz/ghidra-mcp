#!/usr/bin/env python3
# Copyright 2026 Rafał Jackiewicz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A small client for the QEMU guest agent: run programs and copy files in a guest that
has no network at all.

    qga.py [--socket PATH] info
    qga.py [--socket PATH] exec PROGRAM [ARGS...]      run a program, print its output
    qga.py [--socket PATH] ps 'POWERSHELL COMMAND'     run a PowerShell command (Windows guests)
    qga.py [--socket PATH] put LOCAL GUEST_PATH        copy a file into the guest
    qga.py [--socket PATH] get GUEST_PATH LOCAL        copy a file out of the guest

The script must run on the machine where QEMU runs, because the agent is reached through a
Unix socket there (see windows-vm.sh). From another machine, call it through ssh:

    ssh vmhost 'python3 qga.py exec "C:\\Legacy\\ferryman.exe" audit "C:\\Legacy\\evening.ledger"'

The agent serves one client at a time. Every operation here opens the socket briefly and
closes it again; a long-running program is polled with a fresh connection each time, so
other users of the same agent are not locked out. Commands run as SYSTEM (Windows) or root
(Linux) in the guest: this is an administration channel, treat it as one.
"""
import argparse
import base64
import json
import os
import random
import socket
import sys
import time

CHUNK = 48 * 1024


class Agent:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.settimeout(60)
        self.s.connect(path)
        self.buf = b""
        # The agent may still hold replies meant for an earlier client. guest-sync-delimited
        # makes it answer with a number we chose; everything before that answer is discarded.
        token = random.randrange(1, 2**31)
        self.s.sendall(b"\xff" + json.dumps({"execute": "guest-sync-delimited",
                                             "arguments": {"id": token}}).encode() + b"\n")
        while self._read().get("return") != token:
            pass

    def _read(self):
        while b"\n" not in self.buf:
            data = self.s.recv(65536)
            if not data:
                raise RuntimeError("the guest agent closed the connection")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.lstrip(b"\xff") or b"{}")

    def call(self, command, **arguments):
        self.s.sendall(json.dumps({"execute": command, "arguments": arguments}).encode() + b"\n")
        reply = self._read()
        if "error" in reply:
            raise RuntimeError(f"{command}: {reply['error'].get('desc', reply)}")
        return reply["return"]

    def close(self):
        self.s.close()


def run(path, program, args, timeout):
    agent = Agent(path)
    pid = agent.call("guest-exec", path=program, arg=args, **{"capture-output": True})["pid"]
    agent.close()
    started, wait = time.time(), 0.3
    while True:
        time.sleep(wait)
        wait = min(wait * 1.5, 3.0)
        agent = Agent(path)
        status = agent.call("guest-exec-status", pid=pid)
        agent.close()
        if status["exited"]:
            break
        if time.time() - started > timeout:
            sys.exit(f"qga: still running after {timeout} s (pid {pid} in the guest)")
    sys.stdout.buffer.write(base64.b64decode(status.get("out-data", "")))
    sys.stdout.flush()
    sys.stderr.buffer.write(base64.b64decode(status.get("err-data", "")))
    code = status.get("exitcode", 1)
    return code if 0 <= code < 256 else 1


def put(path, local, guest):
    agent = Agent(path)
    handle = agent.call("guest-file-open", path=guest, mode="wb")
    with open(local, "rb") as f:
        while chunk := f.read(CHUNK):
            agent.call("guest-file-write", handle=handle, **{"buf-b64": base64.b64encode(chunk).decode()})
    agent.call("guest-file-close", handle=handle)
    agent.close()


def get(path, guest, local):
    agent = Agent(path)
    handle = agent.call("guest-file-open", path=guest, mode="rb")
    with open(local, "wb") as f:
        while True:
            part = agent.call("guest-file-read", handle=handle, count=CHUNK)
            f.write(base64.b64decode(part["buf-b64"]))
            if part["eof"]:
                break
    agent.call("guest-file-close", handle=handle)
    agent.close()


def info(path):
    agent = Agent(path)
    os_info = agent.call("guest-get-osinfo")
    about = agent.call("guest-info")
    enabled = {c["name"] for c in about["supported_commands"] if c["enabled"]}
    agent.close()
    print(f"guest:  {os_info.get('pretty-name')} ({os_info.get('machine')})")
    print(f"agent:  {about['version']}")
    print(f"exec:   {'yes' if 'guest-exec' in enabled else 'no'}")
    print(f"files:  {'yes' if 'guest-file-open' in enabled else 'no'}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket", default=os.environ.get("QGA_SOCK", "./qga.sock"),
                    help="the agent's Unix socket (default: $QGA_SOCK, else ./qga.sock)")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds to wait for exec/ps (default 1800)")
    ap.add_argument("operation", choices=["info", "exec", "ps", "put", "get"])
    ap.add_argument("args", nargs=argparse.REMAINDER)
    opt = ap.parse_args()
    try:
        if opt.operation == "info":
            info(opt.socket)
        elif opt.operation == "exec":
            return run(opt.socket, opt.args[0], opt.args[1:], opt.timeout)
        elif opt.operation == "ps":
            return run(opt.socket, "powershell.exe",
                       ["-NoProfile", "-NonInteractive", "-Command", opt.args[0]], opt.timeout)
        elif opt.operation == "put":
            put(opt.socket, opt.args[0], opt.args[1])
        elif opt.operation == "get":
            get(opt.socket, opt.args[0], opt.args[1])
    except (OSError, RuntimeError, IndexError) as e:
        sys.exit(f"qga: {e if not isinstance(e, IndexError) else 'missing argument; see --help'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
