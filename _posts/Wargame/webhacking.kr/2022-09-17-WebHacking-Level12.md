---
layout: post
title: Webhacking.kr | Level 12
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

접속 시 **javascript challenge**라는 문구만 있기에 개발자 도구를 이용하여 JavaScript 구문이 어떻게 되어 있는지 확인해보겠습니다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190841929-4409352e-8c43-4a17-a2d7-6c7c33116b2c.jpg" width = 400> 
</p>

Webhacking Level 5와 유사해보입니다. 보기 어려우니 이전에 사용했던 [beautifier](https://beautifier.io/)를 이용해서 확인해보겠습니다.

```javascript
ﾟωﾟﾉ = /｀ｍ´）ﾉ ~┻━┻   / /*´∇｀*/ ['_'];
o = (ﾟｰﾟ) = _ = 3;
c = (ﾟΘﾟ) = (ﾟｰﾟ) - (ﾟｰﾟ);
(ﾟДﾟ) = (ﾟΘﾟ) = (o ^ _ ^ o) / (o ^ _ ^ o);
(ﾟДﾟ) = {
    ﾟΘﾟ: '_',
    ﾟωﾟﾉ: ((ﾟωﾟﾉ == 3) + '_')[ﾟΘﾟ],
    ﾟｰﾟﾉ: (ﾟωﾟﾉ + '_')[o ^ _ ^ o - (ﾟΘﾟ)],
    ﾟДﾟﾉ: ((ﾟｰﾟ == 3) + '_')[ﾟｰﾟ]
};
(ﾟДﾟ)[ﾟΘﾟ] = ((ﾟωﾟﾉ == 3) + '_')[c ^ _ ^ o];
(ﾟДﾟ)['c'] = ((ﾟДﾟ) + '_')[(ﾟｰﾟ) + (ﾟｰﾟ) - (ﾟΘﾟ)];
(ﾟДﾟ)['o'] = ((ﾟДﾟ) + '_')[ﾟΘﾟ];
(ﾟoﾟ) = (ﾟДﾟ)['c'] + (ﾟДﾟ)['o'] + (ﾟωﾟﾉ + '_')[ﾟΘﾟ] + ((ﾟωﾟﾉ == 3) + '_')[ﾟｰﾟ] + ((ﾟДﾟ) + '_')[(ﾟｰﾟ) + (ﾟｰﾟ)] + ((ﾟｰﾟ == 3) + '_')[ﾟΘﾟ] + ((ﾟｰﾟ == 3) + '_')[(ﾟｰﾟ) - (ﾟΘﾟ)] + (ﾟДﾟ)['c'] + ((ﾟДﾟ) + '_')[(ﾟｰﾟ) + (ﾟｰﾟ)] + (ﾟДﾟ)['o'] + ((ﾟｰﾟ == 3) + '_')[ﾟΘﾟ];
(ﾟДﾟ)['_'] = (o ^ _ ^ o)[ﾟoﾟ][ﾟoﾟ];
(ﾟεﾟ) = ((ﾟｰﾟ == 3) + '_')[ﾟΘﾟ] + (ﾟДﾟ).ﾟДﾟﾉ + ((ﾟДﾟ) + '_')[(ﾟｰﾟ) + (ﾟｰﾟ)] + ((ﾟｰﾟ == 3) + '_')[o ^ _ ^ o - ﾟΘﾟ] + ((ﾟｰﾟ == 3) + '_')[ﾟΘﾟ] + (ﾟωﾟﾉ + '_')[ﾟΘﾟ];
(ﾟｰﾟ) += (ﾟΘﾟ);
(ﾟДﾟ)[ﾟεﾟ] = '\\';
(ﾟДﾟ).ﾟΘﾟﾉ = (ﾟДﾟ + ﾟｰﾟ)[o ^ _ ^ o - (ﾟΘﾟ)];
(oﾟｰﾟo) = (ﾟωﾟﾉ + '_')[c ^ _ ^ o];
(ﾟДﾟ)[ﾟoﾟ] = '\"';
```

이렇게 선언문이 나옵니다. 하지만 이후의 값이 제대로 나오지 않은 것인지 마지막이 **...**으로 처리되어 있습니다. 너무 많은 값이 나와서 전체 구문을 제공하지 않은 것인지 BurpSuite로 다시 가져와보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842092-c6a78310-5726-4561-8289-8ea9e8ff0322.jpg" width = 400> 
</p>

확실하게 기존 Chrome 개발자 도구에서 본 자바스크립트 끝 구문 **...**과는 다르게 `('_');`로 다른 것을 알 수 있다. Chrome에서 제공하는 콘솔을 이용하여 Level 5과 비슷하게 풀이를 진행하겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842171-147d963b-4335-421a-8513-99c432099a16.jpg" width = 400> 
</p>

이렇게 21번째까지 선언문일 것으로 예측하고 21번까지 콘솔 입력 후 22번째줄을 마지막에 해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842287-e39fe608-da5d-4965-85bf-141ebd6799c6.jpg" width = 400> 
</p>

**undefined**로 에러가 발생했다. 하지만 제일 마지막을 보면 `('_');` 이 문구는 선언문에서 제공되지 않았다. 그렇다면 이거 왜 있는지 모르겠지만, 일단 지우고 진행해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842356-400e34de-56cf-4d2f-905b-f39a266332f0.jpg" width = 400> 
</p>

결과 값은 이렇게 나왔다. 이 부분을 더블 클릭하게 되면 모든 내용이 나오는데 아래와 같다.

```javascript
(function anonymous(
) {
var enco='';
var enco2=126;
var enco3=33;
var ck=document.URL.substr(document.URL.indexOf('='));
for(i=1;i<122;i++){
  enco=enco+String.fromCharCode(i,0);
}
function enco_(x){
  return enco.charCodeAt(x);
}
if(ck=="="+String.fromCharCode(enco_(240))+String.fromCharCode(enco_(220))+String.fromCharCode(enco_(232))+String.fromCharCode(enco_(192))+String.fromCharCode(enco_(226))+String.fromCharCode(enco_(200))+String.fromCharCode(enco_(204))+String.fromCharCode(enco_(222-2))+String.fromCharCode(enco_(198))+"~~~~~~"+String.fromCharCode(enco2)+String.fromCharCode(enco3)){
  location.href="./"+ck.replace("=","")+".php";
}
})
```

이 함수를 보면 해당 URL에서 **=**를 기준으로 나누고 아스키코드로 변환하여 합쳐진 문자열이 나누어진 `ck`와 같으면 해결될 것으로 보인다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842524-0e179137-1454-447f-9960-c9a0e59f14fb.jpg" width = 400> 
</p>

* **=youaregod~~~~~~~!**

해당 문자열을 URL에 **?=**을 함께 입력해서 확인해보겠습니다.

* **?**를 붙인 이유로는 URL의 `/` 이후에 바로 **=**를 넣어서 입력하게 된다면 해당 디렉토리 인덱싱을 통해 없는 파일을 불러온다고 하게 될 것이다. 따라서 **?=**로 붙여서 GET 방식으로 보내어 디렉토리 인덱싱으로 넘어가지 않게 하는 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/190842844-a017e7d8-2292-4882-8885-ee85fdcc281b.jpg" width = 400> 
</p>

자바스크립트 마지막 구분을 통해 .php String이 붙어서 해당 php 파일을 읽어와 문제가 해결하는 것을 알 수 있다.