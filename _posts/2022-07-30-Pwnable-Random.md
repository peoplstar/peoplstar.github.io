---
layout: post
title: [pwnable.kr] Random
subtitle: Random 문제 풀이
categories: Pwnable
tags: [Pwnable, BOF, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181879900-5f962cb3-24fb-45c9-85eb-96ec857bb601.png" width = 400>
</p>

프로그래밍에서 랜던한 값을 사용하는 법을 가르쳐 주신답니다.

열심히 풀어보도록 하죠!

```C
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}
```

이게 다라고?... 어제 리버싱 풀면서 XOR 관련해서 풀었었는데 쉬울 것으로 예상된다.

* **random** 변수는 `rand()`를 통해 랜덤 값을 받고 **key** 변수는 `scanf`를 통해 입력 값을 받는다. 

* 이 둘의 XOR 연산('^')으로 **0xdeadbeef**가 나와야 한다.

## 문제 풀이

* Main 함수의 어셈블리

```armasm
0x00000000004005f4 <+0>:     push   rbp
0x00000000004005f5 <+1>:     mov    rbp,rsp
0x00000000004005f8 <+4>:     sub    rsp,0x10
0x00000000004005fc <+8>:     mov    eax,0x0
0x0000000000400601 <+13>:    call   0x400500 <rand@plt>
0x0000000000400606 <+18>:    mov    DWORD PTR [rbp-0x4],eax
0x0000000000400609 <+21>:    mov    DWORD PTR [rbp-0x8],0x0
0x0000000000400610 <+28>:    mov    eax,0x400760
0x0000000000400615 <+33>:    lea    rdx,[rbp-0x8]
0x0000000000400619 <+37>:    mov    rsi,rdx
0x000000000040061c <+40>:    mov    rdi,rax
0x000000000040061f <+43>:    mov    eax,0x0
0x0000000000400624 <+48>:    call   0x4004f0 <__isoc99_scanf@plt>
0x0000000000400629 <+53>:    mov    eax,DWORD PTR [rbp-0x8]
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181887892-0a70ba4c-b109-41e4-8383-4bf0745de1b4.png" width = 320>
</p>

* **<main+18> : rbp-0x4**에 `random = rand()`값이 들어가고, **<main+53> : rbp-0x8**에 `scanf()`로 key 값이 들어간다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181892583-5629548a-3772-494d-bba6-3e1abf98d329.png" width = 480>
</p>

* 예시로, scanf를 **1111**을 넣고 확인해보겠습니다.

* 16진수 0x00000457은 10진수로 **1111**, 그 다음 **0x6b8b4567**은 Random 값인데 몇 번을 다시 시작해도 같은 값이 나온다. (<u>그 이유는 마지막에 따로 설명하겠습니다!</u>)


```armasm
0x000000000040062c <+56>:    xor    eax,DWORD PTR [rbp-0x4]
0x000000000040062f <+59>:    cmp    eax,0xdeadbeef
0x0000000000400634 <+64>:    jne    0x400656 <main+98>
0x0000000000400636 <+66>:    mov    edi,0x400763
0x000000000040063b <+71>:    call   0x4004c0 <puts@plt>
0x0000000000400640 <+76>:    mov    edi,0x400769
0x0000000000400645 <+81>:    mov    eax,0x0
0x000000000040064a <+86>:    call   0x4004d0 <system@plt>
0x000000000040064f <+91>:    mov    eax,0x0
0x0000000000400654 <+96>:    jmp    0x400665 <main+113>
0x0000000000400656 <+98>:    mov    edi,0x400778
0x000000000040065b <+103>:   call   0x4004c0 <puts@plt>
0x0000000000400660 <+108>:   mov    eax,0x0
0x0000000000400665 <+113>:   leave
0x0000000000400666 <+114>:   ret
```
* **<main+56>**을 통해 Key와 Random 값을 XOR 하여 **0xdeadbeef**가 아니면 `<main+98>`로 jump하여 `printf("Wrong, maybe you should try 2^32 cases.\n");`를 실행한다.

```C
if( (key ^ random) == 0xdeadbeef )
```

* ​XOR은 **결합법칙이(associative)** 성립한다.​ 즉, $(x (+) y) (+) z = x (+) (y (+) z)$ 이다.

* XOR은 **교환법칙이(commutative)** 성립한다. 즉, $x (+) y = y (+) x$ 이다.

* XOR은 결국 같은 비트를 연산 두번하면 XOR이 사라진다는 것이다. 그렇기에 `key = random ^ 0xdeadbeef` 가 된다.

```Python
>>> print(int((0x6b8b4567) ^ (0xdeadbeef)))
3039230856
```

### 스크립트

```Python
from pwn import *

rand = 0x6b8b4567
dead = 0xdeadbeef

key = str(rand ^ dead)

s = ssh('random', 'pwnable.kr', port=2222, password='guest')
p = s.process('/home/random/random')

p.sendline(key)

p.interactive()
```

* 위에서 사용했던 `print` 기반으로 payload를 작성

## rand() 취약점

rand() 함수는 [0, RAND_MAX] 범위(0과 RAND_MAX 포함)에서 정수 형태의 의사-난수(pseudo-random number)를 만든다. RAND_MAX 는 rand() 가 만드는 난수의 최대값으로, C 라이브러리에 따라 다르다. 다만, 최소 크기는 0x7FFF(=32767, 15비트)로 보장된다. 결국 해당 범위 내에서의 난수 한 가지 값을 가져오는 것이다.

srand() 함수는 rand 함수로 생성되는 난수는 일정한데, srand를 이용 시간 값을 매개로 초기화하면 일정하지 않고 불규칙적인 난수가 생성된다.
저렇게 하면 매번 같은 값이 생성되기 때문이다. 진짜 랜덤값을 얻고자 한다면 srand(time(NULL))을 써야한다.

seed 값을 설정하고 rand() 함수를 호출하면 0~0x7fff 사이의 값이 랜덤으로 리턴된다.

srand() 함수에 seed 값을 주면 전달 된 seed 값을 기준으로 정해진 알고리즘에 따라 0~0x7fff 사이의 랜덤 값 리스트를 생성하게 된다.

그 후 rand() 함수를 호출하면 랜덤 값 리스트에서 값을 순서대로 하나씩 꺼내 리턴한다.