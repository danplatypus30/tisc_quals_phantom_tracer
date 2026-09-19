from pwn import *

elf = ELF('./phantom_tracer')
libc = ELF('./libc.so')
context.binary = elf

def start():
    #if args.GDB: return gdb.debug(elf.path, gdbscript='b *main+565\nc')
    return process(elf.path)

io = start()

def add(size):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'Strength:', str(size).encode())

def edit(idx, data):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'Index:', str(idx).encode())
    io.sendafter(b'Pattern:', data)

def delete(idx):
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'Index:', str(idx).encode())

def view(idx, size):
    io.sendlineafter(b'>', b'4')
    io.sendlineafter(b'Index:', str(idx).encode())
    io.recvuntil(b'recovered:\n')
    return io.recvn(size)



io.interactive()