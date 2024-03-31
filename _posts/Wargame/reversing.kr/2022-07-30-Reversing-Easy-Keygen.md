---
layout: post
title: Reversing | reversing.kr 2번 Easy Keygen
subtitle: Easy Keygen 문제 풀이
categories: reversing.kr
tags: [Reversing, reversing.kr, Assembly]
---

**본 문제는 reversing.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

Reversing.kr의 두번째 문제 Easy Keygen을 풀어보려한다.

이번에는 실행 파일과 텍스트 파일이 들어있다.

텍스트 파일의 내용을 확인해보고, 파일을 실행해보자.

## 문제 내용

### Keygen.exe

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181714348-57cdaf9e-5a51-4b5b-bf64-2146f27d2906.png" width = 250>
</p>

파일을 실행하면 Name과 Serial을 입력하는게 나온다. 이렇게 보면 옳은 Name과 Serial을 찾아야 할 것 같은 느낌이 들 것이다.

Readme.txt 파일을 읽어보면서 다른 내용이 있는지 확인해본다.

### Readme.txt

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181714025-6fb31a39-3b00-4acd-84be-31256572312d.png" width = 350>
</p>

Serial이 **5B134977135E7D13**인 Name을 찾아라?

그렇다면, Name에 어떠한 규칙에 의해 저 Serial을 찾는 것으로 예상된다.

## 문제 풀이

이번에도 어김없이 상단에 `Az` 아이콘을 통해 참조할 수 있는 문자열이 있는지 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181714917-3f0718f3-bbcb-4bb4-a541-dddc81b5a976.png" width = 400>
</p>


**Correct와 Wrong !!** 문자열이 있는 것으로 보아 Correct를 확인하면 될 것 같다.

`F9`[프로그램 실행] 이후, `Ctrl + K` [이전 참조]를 통해 제일 처음 참조하는 곳 및 제일 윗 부분을 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181715372-56eda540-0112-40a7-8dfb-4562da4b0343.png" width = 400>
</p>

* `[esp+10], [esp+20], [esp+30]`에 각각 **10, 20, 30**의 값을 넣는 것을 알 수 있고, `easy keygen.4011B9`는 **Input Name :**을 출력하는 함수 호출임을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181718795-f766a4e8-6c51-4015-9801-0b255a829842.png" width = 260>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181719392-8e154daa-8144-4d78-a670-ec552d304dd0.png" width = 380>
</p>

* `call esay keygen.4011B9`를 통해 실질적인 Name을 입력 받고, 그 값을 `ss:[esp+18]`에 저장하는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181720203-a753e98a-8343-463c-b75a-4e5674b4e5a9.png" width = 280>
</p>

1. `ss:[esp+esi+C]`는 맨 처음에 삽입된 10, 20, 30이 값이 1byte씩 나열되어있고, `ss:[esp+ebp+10`에는 우리가 입력한 **ABCD**가 1byte씩 나열되어있다.
2. 해당 값 '10', 'A'을 XOR하여 ECX에 저장한다.
3. ECX에 저장된 값을 `call easy keygen.401150`까지 해서 **[esp+74+10]**위치에 저장한다('51').
4. 루프를 반복하게 되는데 이번엔 '20', 'B'를 XOR에 저장하게 되는데 10, 20, 30, 10, 20...XOR를 반복하게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181723799-7c2de5e9-3b5e-466d-8328-81b65310800e.png" width = 390>
</p>

XOR 기준 | (기준) 2진수 | 입력 값 | (입력) 2진수| 결과 값|
:-----: |:------------:| :-----:|:-----------:|:-----:|
10      |  0001 0000  |   A    |  0100 0001  | 0101 0001|
20      |  0010 0000  |   B    |  0100 0010  | 0101 0010|
30      |  0011 0000  |   C    |  0100 0011  | 0111 0011|
10      |  0001 0000  |   D    |  0100 0100  | 0101 0100|


_그렇다면 **5B134977135E7D13**은 각각 XOR해서 만들어진 값이라는 것을 알 수 있다._

* 5B, 13, 49, 77, 13, 5E, 7D, 13 각각 XOR해서 만들어진 값이라면 총 8글자라는게 완성된다.

* XOR 하는 방식을 위 예시로 보여드렸으니 답을 입력했을 때의 결과를 보여드리겠습니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/181726479-4e4f2fef-8c58-4b3e-bffb-0798013382fb.png" width = 350>
</p>

* 찾아보니 저처럼 노가다로 푸는게 아니라 스크립트를 작성하여 푸시는 분들도 있길래 저도 한번 해보려고 합니다!

### 스크립트 작성

```Python
xor_value = [0x10, 0x20, 0x30]
serial = "5B134977135E7D13"
index = j = 0

for i in range(int((len(serial))/2)):
    print(bytes.fromhex((hex(int(serial[index:index+2], 16) ^ xor_value[j])).split("0x")[1]).decode('utf-8'), end = ' ')
    index += 2
    j += 1
    if j > 2:
        j = 0
```

* 해당 파일의 링크는 제 [Github](https://github.com/peoplstar/peoplstar.github.io/blob/main/assets/python/Easy_Keygen.py)링크에 있습니다!