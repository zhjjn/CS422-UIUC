import sys, math

ciphertext_file = sys.argv[1]
key_file = sys.argv[2]
modulo_file = sys.argv[3]
output_file = sys.argv[4]

with open(ciphertext_file) as f:
    ciphertext = int(f.read().strip(), 16)

with open(key_file) as f:
    key = int(f.read().strip(), 16)

with open(modulo_file) as f:
    modulo = int(f.read().strip(), 16)


c = 1
for i in range(1, key+1):
    c = (c * ciphertext) % modulo

print 'message:', c, 'hex:', hex(c)[2:].rstrip('L')

f = open(output_file,"w")
f.write(hex(c)[2:].rstrip('L'))
f.close()