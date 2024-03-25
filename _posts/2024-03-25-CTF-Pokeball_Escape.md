---
layout: post
title: UMDCTF 2023 | Pokeball Escape 
subtitle: UMDCTF 2023 Moblie
categories: CTF
tags: [Programming]
---

**해당 CTF는 직접 참여한 것이 아닌 Writeup이 제공 되어 이후에도 문제를 풀이할 수 있게 되었습니다.**

**공식 링크는 아래에 첨부되어있고, 해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 분석

You are stuck in a Pokeball, break out!

Hint: I do not mean exit the app

Download File: [pokeball_escape.apk](https://jaedyno15.github.io/ctf_writeup/assets/challenges/pokeball_escape.apk)

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3e1324ed-227d-4135-83d7-cb428af7907e" width = 450>
</p>

앱 실행 시 일정 시간동안 **!! CONDITIONS NOT MET TO ESCAPE** Toast 메세지가 발생하고 있다.

해당 앱은 **JEB**을 통해 확인해보록 하겠습니다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/3defd9e1-0a75-4e1b-8e88-201f72f9f883">
</p>

`newGame()` 함수를 보면 ` if(Intrinsics.areEqual(this.systemInfo(), "Devon Corporation"))`를 통해 **system.Info()**가 **Devon Corporation**면 `imageView.setImageBitmap(BitmapFactory.decodeFile(v2.getOutputFile().getAbsolutePath()));` 함수를 통해 어떠한 이미지 파일을 비트맵으로 보여주고 있다.

하지만 **system.Info()**가 **Devon Corporation**가 아니라면 `Toast.makeText(((Context)this), "!! CONDITIONS NOT MET TO ESCAPE !!", 0).show();`를 통해 처음 실행한 화면을 보여주게 된다.

해당 함수에 대해서 Frida를 이용한 값을 변경하기엔 `void` 리턴 타입이라 리턴 값 변경도 어려울 것으로 판단하며 앱 변조로 해결하고자 한다.

### Smail Manipulation

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/266338fc-2ef9-4be4-9229-b0d79db8f9c8">
</p>

`newGame()` 함수의 Smali 코드를 보면 `if-eqz` 분기를 통해 **system.Info()**가 **Devon Corporation**를 비교하여 해당 플래그 값을 기준으로 Toast 메세지를 보여주거나 새로운 비트맵 이미지를 보여주는 것으로 되어 있다.

현재 해당 값을 `v0`와 같지 않기에 Toast 메세지가 나오므로 `if-eqz`가 아닌 `if-nez`로 변경한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/760b5d6e-d008-4d1c-ab97-3e0a79aca417">
</p>

또한 해당 앱은 `System.loadLibrary("pokeballescape");`를 통해 외부 라이브러리를 사용하고 있기에 앱 업데이트 시에 .so 파일을 복사하는 것을 방지해서 앱 업데이트 시에 용량이 적어지는 이점을 얻기 위해 **False** 설정 되어 Install 하려고 하면 `Failed to extract native libraries` 에러가 발생하기에 이 값을 **true**로 변경하여 리사이닝 이후 설치하면 정상 실행된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/75494a0a-6f7d-4636-aa57-771376f57971">
</p>

실행하게 되면 **system.Info()**가 **Devon Corporation**가 아니어도 내부 분기로 이동하게 되기에 이 처럼 플래그가 등록된 비트맵 이미지가 보이게 되며 해결이 가능하다.