.section .text.shared,"ax",@progbits
.globl shared_symbol
.type shared_symbol,@function
shared_symbol:
	ret
.size shared_symbol, .-shared_symbol

.section .rodata,"a",@progbits
.balign 8
table:
	.quad shared_symbol + 0x10
	.long shared_symbol + 0x20 - .
	.balign 8
	.quad 0
.size table, .-table
