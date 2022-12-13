---
layout: post
title: [Webhacking.kr] Level 19
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/201305763-90e1d65b-61ae-4a64-9fe0-36def1d3ec99.jpg" width = 240> 
</p>

id는 default로 `admin`으로 되어 있으며 그대로 제출하면, **you are not admin** 문구와 함께 GET 방식으로 `?id=admin`이 넘어간다.

## 문제 풀이

`id`를 임의로 변경하여 다시 제출해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204970482-dc61066d-e640-49eb-a60f-03b391484df7.jpg" width = 360> 
</p>

hella 'id'와 함께 로그아웃 버튼이 생기며 URL에는 기존 URL과 다를게 없다.

이렇게 어느 한 값을 넣고 URL의 변동 없이 변화하는 것을 보고, 쿠키에 다른 값이 생기는 지 확인해보니 아래와 같았다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204970671-d0047a2c-5552-4a57-8d68-6f86055733c4.jpg" width = 360> 
</p>

원래 없던 `userid`라는 쿠키가 생긴 것을 알 수 있는데, 해당 값을 통해서 admin인지 아닌지를 확인할 것으로 예상된다.

해당 쿠키를 지우고 또 다시 같은 값(**aaaa**)으로 했을 때, userid는 같은 값을 나왔다. 여기서 판단한 점으로는 해당 쿠키 생성 시 userid의 문자열 기반으로 암호화하여 부여한 것으로 보인다.

쿠키 값 마지막 바이트를 보면 `%3D`로 되어있는디 디코딩하면 `=`의 값이다. 이것은 인코딩 시 패딩을 위해 집어넣는 **base64 encoding**의 특징이다. 해당 값을 복호화해서 확인해보겠습니다.

```
0cc175b9c0f1b6a831c399e2697726610cc175b9c0f1b6a831c399e2697726610cc175b9c0f1b6a831c399e2697726610cc175b9c0f1b6a831c399e269772661
```

해당 값을 자세히 보면 `0cc175b9c0f1b6a831c399e269772661`라는 값이 4번 반복되는 것을 알 수 있는데, 결국 해당 문자열이 `aaaa`라는 것을 유추할 수 있다.

id에 `a, d, m, i, n`을 하나씩 넣어 해당 값을 출력하여 모두 연결하여 쿠키 변조를 하면 해결될 것으로 보인다.

* **a : 0cc175b9c0f1b6a831c399e269772661**

* **d : 8277e0910d750195b448797616e091ad**

* **m : 6f8f57715090da2632453988d9a1501b**

* **i : 865c0c0b4ab0e063e5caa3387c1a8741**

* **n : 7b8b965ad4bca0e41ab51de7b31363a1**

이 모든 문자열을 합쳐서 base64 인코딩하고, 해당 값을 쿠키에 넣고 새로고침해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/204973904-1a3d99ac-71a3-4359-b53d-840707c6d04a.jpg" width = 420> 
</p>

쿠키가 **[현재 시간 + 입력 값]**을 기준으로 하는 것이 아닌 이렇게 고정된 값을 통해서 제공하게 된다면 쿠키 변조를 이용하여 타인의 권한을 사용할 수 있게 된다.