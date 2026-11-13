#!/bin/sh
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

# Starts a Windows guest under QEMU/KVM for testing legacy binaries.
#
#   windows-vm.sh install WINDOWS.iso [VIRTIO-WIN.iso]   first boot, with the installation media
#   windows-vm.sh run                                    isolated: no network card at all
#   windows-vm.sh run-net                                with user-mode networking (guest sees the
#                                                        host as 10.0.2.2; host port 2222 -> guest 22)
#
# The guest is reached in three ways, all local to this machine:
#   screen       VNC on 127.0.0.1:5905           vncviewer 127.0.0.1:5905
#   guest agent  Unix socket ./qga.sock          ./qga.py info
#   QEMU control Unix socket ./qmp.sock          screenshots, snapshots, power
#
# Create the disk once:   qemu-img create -f qcow2 win10.qcow2 64G
#
# The machine type, firmware and disk controller below are those of the VM on which the
# Windows tests of the book were run; the script as a whole is a template and was not itself
# used to install that machine.
set -e
cd "$(dirname "$0")"
DISK=${DISK:-win10.qcow2}
OVMF=${OVMF:-/usr/share/OVMF/OVMF_CODE_4M.fd}

MEDIA=""
NET="-nic none"
case "$1" in
    install)
        [ -n "$2" ] || { echo "usage: $0 install WINDOWS.iso [VIRTIO-WIN.iso]" >&2; exit 2; }
        MEDIA="-drive file=$2,media=cdrom,readonly=on"
        [ -n "$3" ] && MEDIA="$MEDIA -drive file=$3,media=cdrom,readonly=on"
        ;;
    run) ;;
    run-net) NET="-nic user,model=e1000,hostfwd=tcp:127.0.0.1:2222-:22" ;;
    *) sed -n '18,24p' "$0" >&2; exit 2 ;;
esac
# UEFI variables are per machine: keep a private, writable copy next to the disk.
[ -f OVMF_VARS.fd ] || cp "${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}" OVMF_VARS.fd

exec qemu-system-x86_64 -name win10-lab \
    -machine q35,accel=kvm -cpu host -smp 4 -m 8192 -rtc base=localtime \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -device ich9-ahci,id=ahci \
    -drive file="$DISK",if=none,id=disk0,format=qcow2 \
    -device ide-hd,drive=disk0,bus=ahci.0,bootindex=1 \
    $MEDIA $NET \
    -device virtio-serial-pci,id=vser0 \
    -chardev socket,id=qga0,path=qga.sock,server=on,wait=off \
    -device virtserialport,bus=vser0.0,chardev=qga0,name=org.qemu.guest_agent.0 \
    -usb -device usb-tablet -vga std \
    -display none -vnc 127.0.0.1:5 \
    -qmp unix:qmp.sock,server=on,wait=off \
    -pidfile qemu.pid -daemonize
