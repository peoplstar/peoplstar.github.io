---
layout: post
title: Pwnable | pwnable.kr 4번 FLAG
subtitle: Flag 문제 풀이
categories: Pwnable
tags: [Pwnable, malloc, pwnable.kr, Pentest]
---

**본 문제는 pwnable.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

문제는 <a href = "https://pwnable.kr/play.php">pwnable.kr</a>를 들어가시면 확인할 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180634262-3a2d3025-2e35-471b-a839-64ea773e8ff8.png" width = 400>
</p>

아빠가 Packing된 선물은 가져왔다는데 열어보랍니다 !

이번에 리버싱 과정이라는데 어떤 의미일지 확인해보겠습니다!

`wget` 명령어로 각 파일을 다운 받고 flag를 실행해보려합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180634320-270e4a88-32cb-4aaa-8aa5-a440411c0db1.png" width = 400>
</p>

malloc() 함수와 strcpy()함수로 플래그를 가져온다는 데 pwndbg로 확인해보겠습니다.

## 문제 풀이

### **Main 함수의 어셈블리**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180634746-4eb5dc31-4880-4bb3-907b-dd24e4600112.png" width = 500>
</p>

Main을 가져오지 못했다? `file flag`를 해본다.

```
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

분명 ELF 파일인데 왜 안되는거지? `checksec flag`로 무슨 보호 기법이 사용 되어 있는지 확인해본다.

### **Checksec Flag**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180634832-d50315b5-03d1-436a-9e0f-9af908f9f45f.png" width = 400>
</p>

모든 보호 기법이 해제되어있고, 처음보는 UPX로 패킹 되어 있다고 한다.

UPX가 무엇인지 부터 확인해야 할 것으로 보인다.

#### **UPX 패킹**

UPX(Ultimate Packer for eXecutables)는 여러 운영체제에서 수많은 파일 포맷을 지원하는 오픈 소스 실행 파일 압축 프로그램이다. GNU 일반 공중 사용 허가서를 통해 공개된 자유 소프트웨어이다. 압축, 압축 해제의 기능을 모두 담당한다. 

패킹은 파일의 크기를 줄이기 위해 압축하는 것을 말한다. 파일의 코드를 숨기기 위해 패킹을 하기도 한다. _UPX는 패킹 도구 중 하나다._

```
apt install upx
upx -d flag
```

* 이 UPX 패키지를 설치하여 UPX 언패킹을 진행해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180635307-a70ee0d2-ba3b-4c48-8089-4dc05d3276b2.png" width = 500>
</p>

* 언패킹이 성공적으로 되었고, 파일의 크기가 증가한 것을 볼 수 있다. 다시 pwndbg를 이용해서 disassemble 해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180635360-a80e38f8-7bb6-4a3f-af43-4ee917727ee1.png">
</p>

* 결과가 제대로 나오는 것 같으므로, 이제 하나씩 진행해보면서 알아보려 한다.

* 보이는 것으로는 `puts(), malloc(), call 0x400320`가 보인다. 

#### **puts(), malloc()**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180635421-a85878bf-d7c0-4aae-864d-435d88a69c8a.png" width = 450>
</p>

* `mov edi, 0x496658` 이후 call을 이용해서 맨 처음 ./flag 했던 값이 나오는 것을 알 수 있다. 즉, **0x496658에는 해당 문자열이 담겨 있는 것을 알 수 있다.**

* `mov edi, 0x64` 이후 malloc() 함수를 호출 하는 것으로 보아 **malloc(0x64)**로 진행되는 것이다.

#### **After**

1. `[rbp-8]`에 rax가 가진 값을 넣는다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180636064-95fb1b27-5b06-466c-9be2-4882b633bdaf.png" width = 240>
</p>

2. `rdx`에 `[rip+0x2c0ee5]`값을 넣는다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180636127-eb84e4b3-0d73-4feb-bbe5-d11a6ab5060f.png" width = 460>
</p>

> ?... rdx에 FLAG 같은 값을 넣었다? 일단 이것이 FLAG 값이라고 점 찍어두어야 할 것 같다.

3. `rsi`에 `rdx`값을 넣고, `rdi`에 `rax`값을 넣는다.

> 그렇다면 rsi에는 위 FLAG 같은 값이 들어가고 rdi에는 1번의 값이 들어 갈 것이다. 이후 CALL까지 진행하면 RAX에도 FLAG 값이 들어가는 것으로 보니 **0x400320**가 strcpy()이다.

### 후기

어쩌다가 FLAG 값을 찾은거 같은데 아무리 생각해도 이게 무슨 풀이인지 모르겠다.

단순 UPX 패킹을 알려주기 위한 문제인지 확신이 서질 않는다.

따라서, 다른 사람의 풀이를 보면서 더 들여다 보면서 공부해야 할 것 같아서 다른 분의 풀이를 <a href = "https://marcokhan.tistory.com/224#recentComments">링크</a>로 남기겠습니다!