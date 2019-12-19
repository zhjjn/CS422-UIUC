import hashlib
import sys


original_file = sys.argv[1]
perturbed_file = sys.argv[2]
output_file = sys.argv[3]

with open(original_file) as f:
    original_string = f.read().strip()

with open(perturbed_file) as f:
    perturbed_string = f.read().strip()

original_hash = hashlib.sha256()
perturbed_hash = hashlib.sha256()
original_hash.update(original_string.encode('utf-8'))
perturbed_hash.update(perturbed_string.encode('utf-8'))

original_value = bin(int(original_hash.hexdigest(),16))[2:]
original_value = '00'+original_value
perturbed_value = bin(int(perturbed_hash.hexdigest(),16))[2:]

print "Original: "+original_value+" length: ",len(original_value)
print "Perturbed: "+perturbed_value+" length: ",len(perturbed_value)

num = 0

for digit1,digit2 in zip(original_value,perturbed_value):
    if digit1 != digit2:
        num += 1

f = open(output_file,"w")
f.write(hex(num)[2:])
f.close()