from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    port_src = 6666
    result = []
    verb_conf = conf.verb
    conf.verb = 0
    
    # SYN scan
    for i in range(1,1025):
        syn_scan_recv = sr1(IP(dst = ip_addr)/TCP(dport = i, flags = "S"), timeout=10)
        if(syn_scan_recv.haslayer(TCP)):
            if(syn_scan_recv.getlayer(TCP).flags == 0x12) :
                p = sendp(IP(dst = ip_addr)/TCP(dport = i, flags = "R"))
                result.append(ip_addr+","+str(i))

    for r in result:
        print(r)
		

