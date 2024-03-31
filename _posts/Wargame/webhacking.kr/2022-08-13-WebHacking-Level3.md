---
layout: post
title: Webhacking.kr | Level 3
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184473884-01bc3b85-b959-4526-abd6-0caea30108d6.jpg" width = 420>
</p>

들어가면 이러한 것이 나오는데 소스코드를 봐도 이거를 제외하고는 아무것도 없다. 그래서 노노그램이라는 퍼즐게임을 일단 풀어봤다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184474025-0ced3b5a-0e70-4a11-b8fd-28dbf8ee6d9f.jpg" width = 340>
</p>

클리어 했다면서 로그를 위해 이름을 찍으라는데 입력해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184474083-215cc804-9192-411d-aa40-af352d19fb79.jpg" width = 340>
</p>

입력하면 이름과 수상한 답, 그리고 공인 IP가 찍힌다.

## 문제 풀이

URL을 보면 이상한 파라미터들이 난무해있다.

```
https://webhacking.kr/challenge/web-03/index.php?
_1=1&_2=0&_3=1&_4=0&_5=1&_6=0&_7=0&_8=0&_9=0&
_10=0&_11=0&_12=1&_13=1&_14=1&_15=0&_16=0&
_17=1&_18=0&_19=1&_20=0&_21=1&_22=1&_23=1&
_24=1&_25=1&_answer=1010100000011100101011111
```

수상한 파라미터라 마지막 파라미터인 `_answer=` 맨 뒤에 1을 덮붙여서 실행하면 아래와 같은 화면이 출력된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184474216-4cd3b563-eea2-4969-b27a-800b09bbc3c6.jpg" width = 170>
</p>

No...? 뒤에 _answer가 2진수라 10진수로 변환해서 입력해봤다.

* 1010100000011100101011111 = 22034783

그래도 No !

_answer 파라미터에 `'OR 1=1--`를 변형해도 다른게 없어서 Burp Suite로 잡아봤다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184474639-dee2f67b-86cc-4d7e-b646-ece7ec9e19d5.jpg" width = 350>
</p>

answer 값이 정해진게 아니라 변경이 가능하다? 그렇다면 answer 값을 옳게 만들면 되는 것으로 보여서 `OR 1=1-- ` 를 해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184474982-e9fae022-2c5e-4831-b12f-5a12542eabb9.jpg" width = 260>
</p>

...? 이게 풀린다고? 분명 레벨 2에서는 더욱 복잡하고 힘들었는데 이렇게 풀리니 조금 어이가 없습니다...

그런데 `'OR 1=1--(공백)` 띄어쓰기가 없으면 **query error!**가 뜹니다 !