---
layout: post
title: Webhacking.kr | Level 15
subtitle: Webhacking CTF Problem Solving
categories: Webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196607794-bc483cee-3dc0-49e1-a253-378da339e671.jpg" width = 360> 
</p>

Level 15를 들어가기 위해서 클릭하면 Alert창과 함께 처음 화면으로 리다이렉트된다.

## 문제 풀이

Alert가 뜬다는 것은 <script>alert("Access_Denied")</script>가 맨 처음에 포함되어 있을 것을 예상된다.

Chrome에서는 [디버거 - **자바스크립트 사용 중지**]를 지원한다.

`Alert`는 자바스크립트이기에 사용 중지한다면 해당 스크립트를 진행하지 않을 것이다. 그렇다면 본 링크로 이동이 가능할 것으로 보인다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196608305-8c207b75-88c4-4d4c-adef-a3e8291a16be.jpg" width = 360> 
</p>

**자바스크립트 사용 중지**를 체크하고 새로고침하면 주소창에 아래 사진처럼 나올 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196608437-cf527689-c917-43a4-aa28-173efc1add66.jpg" width = 360> 
</p>

**자바스크립트 계속 차단**을 체크하고 다시 Level 15로 들어가본다.

들어가면 아무것도 보이지 않는 하얀 화면일텐데 소스 코드를 보면 아래와 같다.

```javascript
<script>
  alert("Access_Denied");
  location.href='/';
  document.write("<a href=?getFlag>[Get Flag]</a>");
</script>
```

`document.write`를 보면 **?getFlag** `<a>` 태그를 통해 이동하고 Get Flag 즉, flag를 얻을 수 있을 것으로 보인다.

따라서, 현재 URL에서 **?getFlag**를 추가하면 해결되는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196609437-08b87f11-6d81-4340-9658-9150699b9d17.jpg" width = 360> 
</p>