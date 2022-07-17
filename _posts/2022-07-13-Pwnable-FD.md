---
layout: post
title: Pwnable | pwnable.kr 1번 FD
subtitle: FD 문제 풀이
categories: Pwnable
tags: [Pwnable, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/178695660-0a014bc2-aa84-491e-bb99-3f3f7d3ac3bf.png" width = 400>
</p>

**FD**를 클릭하시면 아래와 같이 나올텐데 리눅스 환경에서는 `ssh fd@pwnabler.kr -p 2222`로 접속하고 패스워드는 **guest**로 접속하시면 됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179387122-edf97741-8f33-4c74-9659-4e170ccfb462.png">
</p>

* 접속하면 위와 같은 내용이 나올 겁니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179387172-e0cce2c7-6a3b-4d97-af79-3da6300ffe2f.png" width = 420>
</p>

* flag를 보면 읽을 권한이 없다. **fd.c** 파일을 분석해보고, ROOT 권한을 탈취하여 flag를 읽어야 할 것으로 예상된다.

## 문제 풀이

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;
}
```

fd.c 파일의 내용이다. 프로그램을 실행할 때 인자가 있어야 본 루팅을 이행 할 것이다.

* 우리의 인자가 사용되는 부분은 `int fd = atoi( argv[1] ) - 0x1234;` , `len = read(fd, buf, 32);`이 두 부분이다.

* 그리고 우리가 읽어야 할 flag를 실행해주는 코드는 `if(!strcmp("LETMEWIN\n", buf)`에 있다.

우선 **read()**는 인자가 사용되는 fd가 들어므로 read()함수를 알아보자.

```C
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t nbytes);
```

**read()**함수의 원형이다.

* **int fd**
  * 읽을 파일의 파일 디스크립터

* __void *buf__
  * 읽어드린 데이터를 저장할 버퍼

* __size_t nbytes__
  * 읽어들일 데이터의 최대 길이 (buf의 길이보다 길어선 안됨)

번호  | 설명 | 파일스트림 |
:---: | :---:| :----------:|
0    | 표준 입력 |  stdin
1    | 표준 출력 |  stdout
2    | 표준 에러 |  stderr

우리가 buf에 LETMEWIN이라는 값을 넣기 위해서는 **read()**가 **표준 입력**이 되어야 하므로 `int fd = atoi( argv[1] ) - 0x1234;`에서 fd가 0이 되야 한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179387791-b3cbaa66-847e-46e4-ae48-278c9ffadd1d.png" width = 350>
</p>

* 0x1234를 10진수로 변환하면 **4660**이란 숫자가 나온다. `./fd 4660`으로 실행해보면 flag 값이 나온다. 이렇게 파일 디스크립터를 알아봤다 !

