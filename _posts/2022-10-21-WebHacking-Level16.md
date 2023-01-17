---
layout: post
title: Webhacking.kr | Level 16
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212843300-fd7395be-dba7-411d-b536-a79b876ac335.png" width = 360> 
</p>

해당 문제를 들어가면 **\***가 표기되어 있고, 그 어떠한 것도 볼 수가 없다.
소스코드를 보며 어떤 식의 문제인지 파악해보겠습니다.

## 문제 풀이

```html
<body bgcolor="black" onload="kk(1,1)" onkeypress="mv(event.keyCode)">
<font color="silver" id="c"></font>
<font color="yellow" size="100" style="position:relative" id="star">*</font>

```

모든 내용은 `<body>` 태그에 묶여 있고 `onkeypress`로 키가 눌리면 `mv`라는 함수를 실행 시키는 것을 볼 수 있다.

```javascript
<script> 
document.body.innerHTML+="<font color=yellow id=aa style=position:relative;left:0;top:0>*</font>";
function mv(cd){
  kk(star.style.left-50,star.style.top-50);
  if(cd==100) star.style.left=parseInt(star.style.left+0,10)+50+"px";
  if(cd==97) star.style.left=parseInt(star.style.left+0,10)-50+"px";
  if(cd==119) star.style.top=parseInt(star.style.top+0,10)-50+"px";
  if(cd==115) star.style.top=parseInt(star.style.top+0,10)+50+"px";
  if(cd==124) location.href=String.fromCharCode(cd)+".php"; // do it!
}
function kk(x,y){
  rndc=Math.floor(Math.random()*9000000);
  document.body.innerHTML+="<font color=#"+rndc+" id=aa style=position:relative;left:"+x+";top:"+y+" onmouseover=this.innerHTML=''>*</font>";
}
</script>
```

`onkeypress`로 사용자가 누른 키 값 별로 **\***의 style을 정의하고 `document.body.innerHTML`을 통해 *을 추가하는 것을 알 수 있다.

```javascript
if(cd==124) location.href=String.fromCharCode(cd)+".php"; // do it!
```

**do it!**과 함께 해당 키 값이 124라면 그 키 값에 해당 Char로 변환하고 String 형변환하여 **.php**를 붙이는 값으로 넘어 가는 것을 알 수 있다.

해당 키 값은 구글에 치면 나옵니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/197110767-29275b2c-d4ed-4940-93a3-491de15f3fc0.jpg" width = 360> 
</p>

KeyCode에 대한 [참고](https://blog.outsider.ne.kr/322)링크 입니다.

`|`에 대한 값이 124이므로 Shift + \를 누른다면 바로 해결되는 것을 알 수 있다.