---
layout: post
title: 시스템 해킹
subtitle: 메모리 & 어셈블리
categories: etc
tags: [System, Memory]
---

`I'll share the link  i heard in the youtube lecture `

- ### Link : [Youtube](https://www.youtube.com/watch?v=PsXXjNL_ogc&list=PLRx0vPvlEmdAXwJnNtKIVeC27UmwljRYA&index=4)

## 어셈블리어 

```ARM Assembly
; helloworld.s
section  .data
        msg db "hello world"

section .text
        global_start

_start:
        mov rax, 1
        mov rdi, 1
        mov rsi, msg
        mov rdx, 12
        syscall
        mov rax, 60
        mov rdi, 0
        syscall
```

**어셈블리어**란, 우리가 흔히 사용하고 있는 C, C++, python 등 고급 코드를 실행하기 위해 컴파일을 하게 되는데 그때 컴파일러를 통해 생성되는 코드이다. 이 코드는 기계 즉, CPU가 이해할 수 있는 형태로 번역되는 것이다.

* 위 어셈블리어를 실행하기 위해서 LINUX에서는 `nasm -f elf64 -o helloworld.o helloworld.s` 를 통해 'hellworld.o' 라는 목적 코드로 변형시키면 실행 프로그램이 생성된다.

### 반복문

```ARM Assembly
section .data
        msg db "A"

section .text
        global _start

_start:
        mov rax, 1
        mov rdi, 1
        mov rsi, msg
        mov rdx, 1
        mov r10, 1

again:
        cmp r10, 100
        je done
        syscall
        mov rax, 1
        inc r10
        jmp again

done:
        mov rax, 60
        mov rdi, 0
        syscall
```

반복문에서는 잘 쓰이지 않는 **r10**의 레지스터 값을 이용하는데 cmp 함수를 통해 r10이 100이 되면 `je done` 위 두 변수의 값이 동일할 경우 `done`이란 함수로 가도록 하고 그렇지 않다면 `rax = 1` 이므로 `syscall` 할 때 A가 출력되게 한다. 

**`rax`는 함수 실행 후 그 함수의 결과가 rax에 담기기 때문에** 다시 `rax, 1`로 출력할 수 있게 한다.


`inc r10`는 `++r10`과 같은 의미를 가지고 있다.  

### Echo Program 

**에코 프로그램**이란, 자신이 입력할 문자열을 그대로 출력해주는 프로그램이다. 아래의 소스 중 `xor rax, rax` = `mov rax, 0` 와 같은 의미를 나타내고 

`sub rsp, 64`를 통해 RSP를 64만큼 뺀다는 것은 스택에서 **RSP** 위로 64만큼의 공간을 확보한다는 의미하게 된다. 

위 언급한 마이크로소프트 사이트에서 레지스터 아키텍쳐 표를 보면, `rax = 0` 일 때 rdi는 디스크를 읽게 되고 `rax = 1` 일때 rdi는 디스크를 쓰게 된다.

```ARM Assembly
section .text
        global _start

_start:
        xor rax, rax
        mov rbx, rax
        mov rcx, rax
        mov rdx, rax

        sub rsp, 64
        mov rdi, 0
        mov rsi, rsp
        mov rdx, 63

        syscall ; 디스크를 읽어오는 과정

        mov rax, 1
        mov rdi, 1
        mov rsi, rsp
        mov rdx, 63

        syscall ; 디스크를 쓰는 과정

        mov rax, 60

        syscall ; 프로그램 종료
``` 

`nasm -f elf64 -o echo.o echo.s` 를 통해 목적 코드로 변경하고 `ld -o echo echo.o`로 목적 코드를 실행프로그램으로 만들어 준다.

### 피라미드

```ARM Assembly
section .data
        STAR db '*'
        EMPTY db 0x0a ;줄바꿈
section .text
        global _start

_start:
        mov rax, 1 ; WRITE 시스템콜
        mov rdi, 1 ; 기본 출력 모드
        mov rdx, 1 ; 출력 길이 설정 (한글자 출력)
        mov r10, 0 ; 반복문의 인덱스 역할
        mov r9, [rsp + 16] ; 현재 입력이 된 문자열을 찾는다. 

        cmp r9, 0 ; 입력이 없는 경우 r9에는 0이 담긴다.
        je _done ; 실행종료 프로그램 호출

        mov cl, [r9] ; r9의 가장 앞 한 바이트만 cl에 저장
        movzx r9, cl ; 문자형태의 cl를 r9에 저장
        sub r9, 0x30 ; 인덱스

        mov r8, r9
        xor r9, r9 ; 초기화
        call _syscall ; 새로운 syscall의 함수

_small:
        cmp r10, r9
        je _up
        mov rsi, STAR ; 별 출력
        syscall
        mov rax, 1 ; WRITE 시스템콜 설정
        inc r10 
        jmp _small ; 다시 출력
_up:
        cmp r9, r8 ; i == n인 경우
        je _down
        mov rsi, EMPTY ; 줄바꿈 출력
        syscall 
        mov rax, 1 ; WRTIE 시스템 콜 설정
        mov r10, 0
        add r9, 1
        jmp _small

_down:
        cmp r9, 0
        je _done;
        mov rsi, EMPTY 
        syscall
        mov rax, 1
        mov r10, 0
        sub r9, 1
        jmp _big

_big:
        cmp r10, r9
        je _down
        mov rsi, STAR
        syscall
        mov rax, 1
        inc r10
        jmp _big

_done:
        mov rax, 60
        mov rdi, 0
        syscall

_syscall:
        syscall
        ret
               
```

## 레지스터 

64비트 환경에서 컴퓨터는 시스템 구조, 레지스터를 어떻게 불러오는지에 대해 MICROSOFT사에서 자세히 설명해두었다. 

어셈블리어에서 이용하는 레지스터의 이름과 메모리는 어떻게 되는지 자세히 알고싶으면 확인해보길 바랍니다. [MICROSOFT](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture)

* **rax** : 가장 중요한 레지스터 중 하나, 시스템 콜의 실질적인 번호, 함수의 결과가 담기는 곳

* **rbx** : 베이스 레지스터, 메모리 주소를 지정해주는 곳

* **rcx** : 카운터 레지스터, 반복문에 주로 사용

* **rdx** : 데이터 레지스터, 연산수행    

  * __위 4개의 레지스터를 통틀어 데이터 레지스터라 칭함.__

* **rsi** : 메모리를 이동하거나 비교할 때 출발지 주소

* **rdi** : 메모리를 이동하거나 비교할 때 목적지 주소

* **rbp** : 함수의 파라미터나 변수의 주소

* **rsp** : 스택에 대한 삽입 및 삭제 명령에 의해서 변경되는 top의 주소   

Syscall 같은 경우는 Google에 __64bit system call table__ 을 검색하면 자세히 설명되어있다.
 
## 메모리
 
<p align="center">
        <img src="https://user-images.githubusercontent.com/78135526/147747144-f2fedaab-9729-4f26-8e74-24c060363a5a.png"  width="200" height="300"/>
</p>

* (사진은 운영체제 32bit 기준의 메모리이다. 64bit의 메모리 크기는 2^64-1이다)

영역 | 내용
---- | ---- 
STACK | 선입선출의 개념(FIFO), 함수 및 함수 지역변수 등 호출할 때마다 정보가 쌓인다.  
HEAP | 동적으로 할당되는 변수, C언어의 malloc()함수과 같은 것으로 할당 할 때 저장되는 공간이다. 
BSS | 프로그램에서 사용될 변수들이 실제로 위치하는 영역, 초기화하지 않은 변수다. 
DATA | 초기화가 이루어진 변수이고, 위 어셈블리어 코드중 `section .data`가 이 영역이다.  
TEXT | 우리가 작성한 소스 코드, 시스템이 알아들을 수 있는 실질적인 명령어이고, 컴파일러가 만들어 놓은 기계어 코드이고, 위 어셈블리어 코드 중 `global_start`로부터 `_start:`의 코드가 하나씩 들어가게 된다. 

<p align="center">
        <img src="https://user-images.githubusercontent.com/78135526/147747405-b417dee3-f354-4d45-a07e-dfee606d9b15.png">
</p>

* 리눅스는 기본적으로 프로그램을 실행할 때 스택영역에 다양한 취약점에 대해 기본적인 방어체계 마련하는데 이러한 것을 다 끈 상태로 컴파일을 하도록 만들어주는 명령어이다.

* `stack-boundary=4`를 통해 64bit 운영체제 버전으로 컴파일할 수 있게한다. sum.c의 파일을 sum.a의 어셈블리어 코드로 바꿔줄 수 있게 한다.

<p align="center">
        <img src="https://user-images.githubusercontent.com/78135526/147747139-0beed467-d799-41c9-96a4-7e53972ee4fd.png"  width="250" height="300"> 
</p>
   
C언어는 main함수부터 실행하기 되는데 main함수를 불러오게 되면 가장 아래에 RET(return address)가 생성되는데, 특정한 함수가 끝나면 돌아갈 위치를 저장한다. 

return address를 해커가 임의로 변경하여 공격하는 것이 버퍼오버플로우 등이 있다.

**RBP**란, 스택이 시작하는 베이스 포인터를 뜻하는데, RBP 바로 위부터 데이터에 대한 것이 스택에 쌓이는 것을 알려준다.    
   
### 디버깅

`apt-get install strace`로 툴을 다운받아준다. 디버깅을 하기 위해서 strace 로 시스템콜과 관련한 내용을 살펴보도록 도와주는 도구, 어떠한 프로그램이 있을 때 그것과 유사한 프로그램 만들 때도 사용하는 유용한 도구이다. `strace -ifx ./echo`를 통해 디버깅 과정을 알 수 있다.

<p align="center">
        <img src="https://user-images.githubusercontent.com/78135526/147747409-ecb79500-d919-4738-bc95-93a899986b0e.png">
</p>
   
더욱 구체적이고 좋은 디버깅 툴을 이용할 것인데 이 도구는 깃허브에서 제공한다. `git clone https://github.com/pwndbg/pwndbg` 을 입력하여 pwndbg를 다운받는다. 디버깅할 폴더로 이동하여 `gdb 해당파일이름`을 통해 디버깅을 하게 된다. 

Breaking point를 `break * _start`와 같이 지정해 `run`으로 실행하고, `ni`라는 명령어로 한줄씩 **next instruction** 한다.
   
### 쉘 코드

명령 Shell을 실행 시켜 해킹을 당하는 서버 컴퓨터를 제어하도록 하는 코드로, 특정한 소프트웨어의 버퍼오버플로우 같은 취약점 등을 이용한 쉘 코드를 이용할 수 있다. 

**루트 권한으로 실행된다면 장악할 수 있다. ex) 명령 프롬프트**

```C
#include <stdio.h>
#include <string.h>

char shell[] =  "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

void main() {
        printf("length : %d bytes\n", strlen(shell));
        (*(void( *)()) shell)();
        return 0;
}
```

기본적으로 최신의 OS는 프로그램 컴파일시 스택 프로텍터 같은 것으로 프로그램이 실행될 때 마다 디렉터리나 파일등의 메모리 주소 등이 계속 변화하기에 실습과정에서는 이러한 보호기법을 모두 끄고 할 것이다.

`gcc --fno-stack-protector -mpreferred-stack-boundary=4 -z execstack shell.c -o shell` 이렇게 만들어진 쉘 프로그램은 `chmod 4775 shell`로 해당 프로그램을 실행하면 루트권한을 얻을 수 있게 한다. 

일반적인 유저권한으로 해당 프로그램을 실행하면 루트권한을 획득해 모든 작업을 할 수 있게 된다.