---
layout: post
title: Reversing | reversing.kr 3번 Easy Unpack
subtitle: Easy Unpack 문제 풀이
categories: reversing.kr
tags: [Reversing, reversing.kr, Assembly]
---

**본 문제는 reversing.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

### Easy_UnpackMe.exe

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182014197-3662b339-e5ec-42cc-8fe7-7a72fea4c925.png" width = 250>
</p>

파일을 실행하면 아무것도 나오지 않는다. 도대체 무엇을 하는 프로그램일지도 예상이 안되고, `Az`를 통해 문자열의 위치를 알 수도 없다.

### Readme.txt

```
ReversingKr UnpackMe

Find the OEP

ex) 00401000
```

OEP? OEP란 Original Entry Point를 말한다. 패킹된 파일을 실행할 때 자동적으로 시스템 내부에서 언패킹을 한다. 

언패킹이 끝나면 복구한 원본코드를 동작시켜야 하는데 이 원본코드의 Entry Point를 OEP라고 한다. 

**즉, 우리는 실질적은 Entry Point를 찾아야 할 것으로 예상되고, 그거에 대한 주소가 Flag가 될 것 같다 !**

## 문제 풀이

`F9`를 눌러 시 프로그램 실행을 하면 EP가 나오게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182014339-9a69a3e8-b227-421e-88ed-942b7139493a.png" width = 700>
</p>

* 보면 `push ebp`와 같은 스택 프레임의 베이스 포인터를 PUSH 하는 명령은 보이지 않는다.

* 해당 프로그램이 패킹되어 시작 위치 및 데이터가 암호화(?) 되어 있다는 것 같다.

프로그램을 계속해서 한 줄씩 실행하면서 하다 보면 아래처럼 Loop를 통해 ECX 값이 복호화가 진행되는 것을 확인 할 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182014442-3583b587-fde8-46f8-8c2d-460514338b06.png" width = 500>
</p>

* 이런 경우 루프 다음 구문에 중단점을 걸어 중단점까지 실행을 통해 건너 뛸 수 있다. 이 방법으로 계속해서 넘어가보자.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182014730-d6183908-a4f8-4049-a1e1-0dcc19a84274.png" width = 400>
</p>

* `jmp easy_unpackme.401150` 구문을 넘어가면 아래와 같은 위치로 이동한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182014784-499af4e1-936b-436b-8c1d-0aa60c40ee4a.png" width = 400>
</p>

* 이렇게 우리가 원하는 OEP에 도달했다.

> 다른 문제들 보단 쉬웠지만, 뭔가 이게 이렇게 푸는게 맞나 싶을 정도의 문제였다.