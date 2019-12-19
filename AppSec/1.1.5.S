.global _main
.section .text

_main:

push	%ebp
mov	%esp,%ebp

mov	$11,%eax
push	$0x0068732f
push	$0x6e69622f
mov	%esp,%ebx
push	$0
mov	%esp,%ecx
mov 	$0,%edx
mov	$0,%esi
mov	$0,%edi

int	$0x80

leave
ret
