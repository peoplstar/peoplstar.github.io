---
layout: post
title: Pwnable | pwnable.kr 2번 Collision
subtitle: Collision 문제 풀이
categories: Pwnable
tags: [Pwnable, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179390573-f5c4d1b4-48e6-486a-b906-1a4d6bd3cb8b.png" width = 400>
</p>
 
아빠가 MD5 해시에 대해서 말해줬다네요. 문제는 일단 해시 관련인 거 같으므로 접속부터 해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179390648-f4ad5f0c-5ed2-48f6-8baa-f93f5107411e.png" width = 420>
</p>

* 이번에도 flag를 보면 읽을 권한이 없다. **col.c** 파일을 분석해보고, ROOT 권한을 탈취하여 flag를 읽어야 할 것으로 예상된다.

```C
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

## 문제 풀이

```C
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
```

* 해시코드가 `0x21DD09EC`라는 것을 명시해줬다.

```C
if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
```

* 인자로 넣은 값을 `check_password()`함수를 통해서 해시코드 값과 같은지 비교하여 flag를 읽어주는 것으로 확인했다.

* `check_password()` 함수가 인자를 어떻게 변경시키는지 확인해보고, 로직대로 인자를 넣어주면 해결될 것이다.

```C
if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
}
```

* **인자의 값을 총 20byte로 명시 되어 있음을 잊지말자**

```C
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
```

위 함수를 보면 인자로 받은 파라미터를 **int**로 형변환한다.

파라미터를 총 5번 res에 더해서 res 값과 **hasscode**와 비교하는 것이다.

* 파라미터로 전달 받은 p를 int형 포인터 ip로 받았는데 해당 값을 더하는데 형이 **int** 라는 것은 **4byte**씩 더한다는 것을 알 수 있다.

* 5번 더 해서 Hashcode 값이 나오려면 4번은 **0x6c5cec8**, 마지막 한번은 0x6c5cec8에서 0x04 더한 값 **0x6c5cecc**여야 한다는 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179392104-e04e4e44-8366-4be1-aed3-83355b06acfd.png" width = 300>
</p>

그림으로 설명하면 아래와 같게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179392339-42e16a9e-e3df-4a5a-a78c-a6e335cf9f6c.png">
</p>

* 따라서, 아래의 코드를 입력할 시 flag가 생성된다.
```
./col `python -c 'print "\xc8\xce\xc5\x06"*4 + "\xcc\xce\xc5\x06"'` 
```

### 스크립트

```Python
from pwn import *
p = ssh("col","pwnable.kr",2222,"guest")
path = "/home/col/col"
argv = "\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xC8\xCE\xC5\x06\xCC\xCE\xC5\x06"
payload = [path,argv]
s = p.run(payload)
s.interactive()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179392484-b5e93d91-cd77-462c-a33d-ca8fd5e71024.png" width = 400>
</p>

## Endian

분명 값은 0x06C5CEC8인데 \xc8\xce\xc5\x06와 같이 순서를 반대로 하는 이유에 대해 알아본다.

Endian은 **Big endian**과 **Little endian**으로 나뉜다.   

- Big endian   
  - 빅 엔디안 방식은 낮은 주소에 데이터의 높은 바이트(MSB, Most Significant Bit)부터 저장하는 방식입니다.<br>따라서 메모리에 저장된 순서 그대로 읽을 수 있으며, 이해하기가 쉽다는 장점을 가지고 있습니다.<br>SPARC을 포함한 대부분의 RISC CPU 계열에서는 이 방식으로 데이터를 저장합니다.   

- Little endian
  - 리틀 엔디안 방식은 낮은 주소에 데이터의 낮은 바이트(LSB, Least Significant Bit)부터 저장하는 방식입니다.<br>이 방식은 평소 우리가 숫자를 사용하는 선형 방식과는 반대로 거꾸로 읽어야 합니다.<br>대부분의 인텔 CPU 계열에서는 이 방식으로 데이터를 저장합니다.

* 서버와 워크스테이션을 목적으로 사용하는 PC가 아닌 이상 대부분의 PC는 Little endian 기반이기에 낮은 바이트부터 저장할 수 있게 해야한다. 
    
    
출처 : [TCPschool](https://tcpschool.com/c/c_refer_endian)