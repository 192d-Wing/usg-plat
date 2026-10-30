#!/usr/bin/env python3
# Attach one queue to the multiqueue TUN and print every IPv4 packet received.
import fcntl, os, struct, sys, select, time
TUNSETIFF = 0x400454ca
IFF_TUN, IFF_NO_PI, IFF_MULTI_QUEUE = 0x0001, 0x1000, 0x0100
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", sys.argv[1].encode(), IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE))
end = time.time() + float(sys.argv[2])
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        p = os.read(fd, 65535)
        if p[0] >> 4 == 4:
            print("TUN-RX v4 src=%s dst=%s len=%d" % (".".join(map(str, p[12:16])), ".".join(map(str, p[16:20])), len(p)), flush=True)
