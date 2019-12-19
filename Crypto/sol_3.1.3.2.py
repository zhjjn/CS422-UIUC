import sys,math

input_file = sys.argv[1]
output_file = sys.argv[2]

with open(input_file) as f:
    input_string = f.read().strip()

def WHA(inStr):
    input_dec = ['0'* (8-len(bin(ord(c))[2:]))+bin(ord(c))[2:] for c in inStr]
    outHash = 0
    
    for byte in input_dec:
        byte = int(byte,2)
        intermediate_value = ((byte ^ 0xcc) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xaa) << 8) | (byte ^ 0x55)
        outHash = (outHash & 0x3fffffff) + (intermediate_value & 0x3fffffff)

    return hex(outHash)

f = open(output_file,'w')
f.write(WHA(input_string)[2:])
f.close()