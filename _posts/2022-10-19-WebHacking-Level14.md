---
layout: post
title: Webhacking.kr | Level 13
subtitle: Webhacking CTF Problem Solving
categories: Webhacking
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196601493-6463e5ad-a105-4afa-9e1d-fe0d9a7f13a2.jpg" width = 240> 
</p>

초기 화면에는 어떠한 것도 없고 값을 전송하는 것만 있다. 따라서, 소스를 열어서 무슨 기능인지 파악해야한다.

```javascript
<form name="pw">
    <input type="text" name="input_pwd">
    <input type="button" value="check" onclick="ck()">
</form>

<script>
    function ck(){
        var ul=document.URL;
        ul=ul.indexOf(".kr");
        ul=ul*30;
        if(ul==pw.input_pwd.value) { 
            location.href="?"+ul*pw.input_pwd.value; 
        }
        else { alert("Wrong"); }
    }
</script>
```

## 문제 풀이

`ck()`함수는 보면 '.kr'의 인덱스를 30번 곱한 값을 `ul` 변수에 넣고 form에 해당 값을 넣으면 어떠한 링크로 이동하는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196602557-8f2e9807-76eb-4c8e-ac46-6ed6864fb60b.jpg" width = 240> 
</p>

ul의 값이 540인 것을 [개발자 도구 - 콘솔]을 통해서 쉽게 구할 수 있다.

이 값을 넣어보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/196602679-ebb82e0a-5dae-4971-a71a-6694a9860c9a.jpg" width = 400> 
</p>

URL의 이동은 되었지만, 소스코드도 동일하고 다른 점이 없다.

`location.href="?"+ul*pw.input_pwd.value;` 이 부분을 잘 보면 **?**이후 ul값과 우리가 입력한 값을 곱한 링크 즉, `/js-1/?num`과 같이 이동해야 할 텐데 input_pwd 변수가 붙어 있다.

ul의 값은 540이고, 우리가 입력한 값이 540이어야 해당 링크를 이동하는 것이였으므로 `pw.input_pwd.value` 값도 540일 것이다.

이 두 값을 곱하면 **291600**이 나오는데 input_pwd GET URL이 아닌 `?`이후 **291600**을 넣어보면 풀린다.

어떠한 문제로 인해서 제대로 된 링크 연결이 안되었는지 확인해보고 있지만, 아직까진 찾질 못했다.