---
layout: post
title: Webhacking.kr | Level 10
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188061273-869d2385-c6c9-4d2c-a0ec-1bc19cc028c1.jpg">
</p>

무슨 경주장 같은 이상한 페이지가 나오는데 O 이거를 Goal 라인을 넘겨야 하나 싶기도 하고...? 그 어느 것도 보이지 않아서 소스코드를 보기로 했습니다.

## 소스 코드

```javascript
<a id = "hackme"
style = "position:relative;left:0;top:0"
onclick = "this.style.left=parseInt(this.style.left,10)+1+'px';if(this.style.left=='1600px')this.href='?go='+this.style.left"
onmouseover = "this.innerHTML='yOu'"
onmouseout = "this.innerHTML='O'" > O 
</a>
```

이 코드는 **O**의 코드다. 애초에 해당 Element 자체가 **hackme**라 되어 있으니 중점은 이것으로 잡겠습니다.

`onmouseover` 하면 변한다고 하기에 확인해봤습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188061798-53d44ff4-9f35-4d89-9ff4-ad9bd19f26b6.jpg" width = 180>
</p>

onclick 부분에서 무슨 링크로 변하는거 처럼 보이는게 있어서 보겠습니다.

```javascript
// hackme's onclick
if(this.style.left=='1600px')this.href='?go='+this.style.left"
```

hackme의 위치가 1600px에 위치하면 `href`로 ?go parameter로 **1600px**을 넘겨서 이동한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188062335-fbabf0dd-43a3-4069-bcc9-935c2351007e.jpg" width = 600>
</p>

F12로 개발자 도구를 열어 left를 1599px까지 변경하고 O를 직접 클릭하여 1600px로 만들면 href가 활성화되어 링크로 접속하게 되는데 접속하면 바로 풀리게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188062795-dde4620c-6888-49c8-a1c9-d0ab50ddb8d0.jpg" width = 380>
</p>

이렇게 될 수 있는 이유는 JavaScript를 포함한 HTML, CSS는 **Client-Side**로 서버에 요청을 하는 것이 아닌 클라이언트 단 즉, 앞단에서 일을 처리하기에 가능한 것이다. **Server-Side**로는 PHP, ASP 등이 있지만 Client-Side를 사용하는 이유로는 서버의 과부화, 리소스를 줄이기 위해서 사용하는 것이라 볼 수 있다.