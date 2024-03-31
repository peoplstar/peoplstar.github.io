---
layout: post
title: Android rooting guide
subtitle: Android rooting
categories: AOS
tags: [Docker, vscode, wsl]
---

안드로이드 앱 모의해킹을 하기 위해 Nox를 사용할 계획이였지만, Nox도 wsl를 이용한 가상화를 사용하기에 이미 Docker를 위한 **wsl**를 사용 중이라 충돌이 일어나게 된다.

따라서, 별도의 공기계를 구입하여 안드로이드 앱 모의해킹을 하려 한다. 이를 위해서는 루팅이라는 작업을 해야 한다.

## 루팅 

**Root**는 트리의 일부일뿐만 아니라 사용자가 시스템을 완전히 제어 할 수 있는 권한 (일종의 관리 계정)을 제공하는 유닉스 시스템 계정의 전통적인 이름을 의미합니다. 

Android의 운영 체제는 Linux 코어를 기반으로 하며 **root**라는 사용자(관리자)가 있으며 모든 파일에 무제한으로 액세스 할 수 있으며 수정과 관련된 모든 작업을 수행 할 수 있습니다.

**루팅을 하게되면 금융앱 사용불가, 삼성페이 영원히 사용불가이며, 각종 보안 취약점에 놓일수도 있으니 사용하지 않는 공기계나 서브폰으로 시도하세요. 또한 공장초기화가 진행되어 데이터가 모두 날라갑니다**

## 부트로더 해제

부트로더 해제를 하지 않을 시 OEM 잠금해제를 하더라도 다운로드 모드에서는 해제 되지 않은 것으로 되어 있다.

따라서, 다운로드 모드로 접근하게 되면 아래와 같이 경고 문구가 나오는데 부트로더 해제 관련은 **디바이스 잠금 해제 모드**로 볼륨 상 키를 길게 누르면 부트로더가 해제된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210131966-627d159c-6fd1-43e9-a4c9-9150ad9e28d5.png" width = 180>
</p>

### 다운로드 모드 접근

* **홈버튼이 있는 기기** : 전원 + 홈 버튼 + 볼륨 하

* **홈버튼이 없고 빅스비버튼이 있는 기기** : 전원 + 빅스비 + 볼륨 하

* **홈버튼이 없고 빅스비버튼이 없는 기기** : 전원 + 볼륨 상 + 볼륨 하

* **One Ui 3.0 이상** : USB 연결 상태로 볼륨 하 + 볼륨 상

## 개발자 모드

**설정 > 휴대전화 정보 > 소프트웨어 정보 > 빌드번호 연타**

빌드번호를 연타하게 되면 개발자 옵션이 활성화 되었다는 Toast 메세지가 나오게 된다.(저는 이미 활성화 시켰기 때문에 다른 Toast 메세지가 뜨는 겁니다!)

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209950724-dc11cbbe-b13f-4b16-9544-859d49f2bd40.png" width = 180>
</p>

메세지가 뜨고 나서 다시 설정으로 들어가보면 마지막 부분에 **개발자 옵션**이 나오게 된다. 해당 옵션으로 들어가서 **OEM 잠금해제**와 **USB 디버깅 옵션**을 활성화 해줘야한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209951118-2fa4695f-4570-4be9-a646-5436137c5ef6.png" width = 180>
</p>

**odin을 통해 이미 펌웨어를 건드리는 경우 OEM 잠금해제가 없을 수 있다. 이런 경우 아래 링크를 통해 따라하면 됩니다!**

* [가래들공방](http://john-home.iptime.org:8085/xe/index.php?mid=board_ZoED57&document_srl=18091)

## Frija

루팅 과정에서 사소한 잘못으로 인한 벽돌현상(무한 부팅)이 발생하게 된다. 이를 방지하고, 자신의 버전에 맞는 **TWRP**를 삽입를 올려야 하기에 이를 사용하게 된다.

`Frija`라는 툴을 이용하여 기종에 맞는 순정 펌웨어를 받게 된다.

[https://github.com/SlackingVeteran/frija/releases/download/v1.4.4/Frija-v1.4.4.zip](https://github.com/SlackingVeteran/frija/releases/download/v1.4.4/Frija-v1.4.4.zip)

클릭하시면 바로 다운받아집니다. 파일을 다운받은후 압축을 푼 뒤, `Frija.exe`파일을 실행시켜주세요.

실행 시 아래와 같은 경고창과 꺼지는 경우가 있는데 

```
Please make sure microsoft visual c++ 2008 redistributable package (x86) 
and microsoft visual c++ 2010 redistributable package (x86)
```

이러한 경고창이 뜬다면 아래의 링크를 통해서 버전에 맞게 다운받으시면 됩니다. 위 경고창에서 버전만 다르게 나온다면 구글에 검색하면 마이크로소프트에서 제공하는 파일 받으시면 됩니다!

[microsoft visual c++ 2008 redistributable package (x86)](https://www.microsoft.com/ko-kr/download/details.aspx?id=26368)

[microsoft visual c++ 2010 redistributable package (x86)](https://www.microsoft.com/ko-kr/download/details.aspx?id=26999)

`Frija.exe`파일을 실행하게 되면 아래와 같은 창이 나온다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209953489-2d31e5e1-f431-422b-a4c6-8d30b3084fd6.png" width = 480>
</p>

* **Model** : 설정 > 휴대전화 정보 > 모델번호

* **CSC** : 통신사 코드, 모델번호 뒷 자리에 따라 알 수 있다.
  
  * **KT**: KTC, 뒷 자리 K일 경우

  * **SKT** : SKC, 뒷 자리 S일 경우
  
  * **U+** : LUC, 뒷 자리 L일 경우

  * **자급제** : KOO, 뒷 자리 N일 경우

이에 맞게 **Check Update**를 클릭하여 파일을 다운로드 받으면 됩니다.

## odin

> **이 과정은 순정 펌웨어일 경우 하지 않으셔도 무방합니다.**

https://www.osamsung.com/kr/ 공식 페이지에서 `odin` 프로그램을 다운로드 받고, `Frija`를 통해 받은 **BL, AP, CP, CSC** 파일을 아래와 같이 odin을 통해 세팅을 한다. 

이 과정은 Frija를 통해 받은 순정 펌웨어를 올리는 과정입니다.

**_(해당 버전은 odin 3.12 버전으로 set Patition 부분에서 멈추는 현상이 있기에 [odin 3.14.4](https://odin-samsung.com/category/odin3)을 이용했습니다.)_**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209961769-2ec6368b-30f2-4817-9b22-015e6e2bb392.png" width = 480>
</p>

잘못된 파일이 들어가지 않았는지 확인을 해보시길 바랍니다. 

> 반드시, 휴대폰에 적용되어 있는 모든 계정을 삭제하고 하시길 바랍니다.

이후, USB 포트를 연결한 상태로 전원을 끄고, **볼륨 하 + 볼륨 상**을 동시에 누르고 있으면 Continue에 해당하는 문구대로 하면 아래처럼 **다운로드 모드**로 들어가게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209964274-1289305e-7849-46d4-83d6-0ca92fc97d7f.png" width = 250>
</p>

이 상태가 되었다면 다시 odin으로 가서 `Start` 버튼을 누르고 기다리면 완료 odin에는 **PASS!** 문구가 나오며 스마트폰은 자동으로 공장 초기화가 이루어져 있을 것이다.

그게 아닌 리커버리 모드로 들어가게 되는 경우 볼륨 키와 전원 키를 이용하여 **Wipe data/factory reset**을 통해 공장 초기화를 해주시면 됩니다.

## Magisk

`Magisk`는 공식 깃허브에서 모든 버전을 쉽게 구할 수 있다. 최선버전의 `.apk`파일을 다운 받으시면 됩니다.

[https://github.com/topjohnwu/Magisk/releases?page=1](https://github.com/topjohnwu/Magisk/releases?page=1)

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209956092-ce6c4c23-abaf-4256-8b05-ebb20dc144fa.png" width = 420>
</p>

다운로드 받은 .apk 파일을 단말기에 넣으면 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209959441-ae770f6b-4977-4dda-ae5a-3dad58c1cbfa.png" width = 420>
</p>

스마트폰으로 돌아가 **내 파일 > APK 설치 파일**을 들어가면 우리가 넣은 `Magisk.apk` 파일이 보일텐데 설치를 마치면 된다.

### Magisk에서 펌웨어 루팅

우리는 순정 펌웨어를 올리기 위해 odin에서 사용한 파일을 다시 활용하겠습니다.

```
AP_XXXXXXXXXX_YYYYYYYYY_ZZZZZZZZZ_REV00_user_low_ship_meta_OS11.tar.md5
```

AP에 적용한 파일명을 변경하게 되는데 `.tar.md5`에서 `md5`를 삭제한 `~~~~OS11.tar` 형태로 만든 이후 단말기로 복사한다.

단말기로 돌아가 Magisk 어플을 키고 아래와 같이 설치 버튼을 클릭합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125683-49158db6-0297-4a2f-84c7-655da895fb7f.png" width = 280>
</p>

리커버리 모드 체크하고 다음 버튼을 누릅니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125684-a2841d8f-0265-43ab-8ffa-13ab1b09d228.png" width = 280>
</p>

다음 버튼을 누르면 설치 방법에서 **파일 선택 및 패치**를 누릅니다.

누르면 어떤 파일을 선택할 지 탐색기가 나오는데 왼쪽 상단 네비게이션 드로어 버튼을 누르면 목록이 있는데 **내 파일**로 이동합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125686-3f139d28-4c2f-496b-85a5-f9654fda0696.png" width = 280>
</p>

내 파일에서 아까 넣어둔 `AP.xxx.tar` 파일의 디렉토리로 이동해서 클릭하고 설치 클릭합니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125687-5c040f7d-264d-44cc-b679-fd4daa1bf566.png" width = 280>
</p>

기다리면 펌웨어의 플래싱 과정을 보여주고 완료된 파일의 위치를 보여주는데 PC로 다시 빼오면 됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125689-96f96507-b521-4602-8ad0-d3d3c002a465.png" width = 280>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210125940-eb53213e-5933-400a-8fb2-8727e2ab8fe1.png" width = 400>
</p>

## 펌웨어 마운트

단말기를 다시 **다운로드 모드**로 진입시키고, odin을 켜 AP에 추출한 파일을 넣고 **Options > Auto Reboot**를 해제한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210126281-b2c0e9d4-498d-4a5f-9952-5c4f99a743ac.png" width = 560>
</p>

`Start`을 누르고 기다리면 완료가 되어도 **Auto Reboot**를 껏기에 계속 다운로드 모드에 남게 되는데 **볼륨 하 + 전원 키**를 통해 재부팅을 한다.

이후 단말기를 킬 **볼륨 상 + 전원 키**를 통한 부팅을 해야 루팅된 OS로 부팅이 된다.

**볼륨 상 + 전원 키**를 너무 길게 누르면 리커버리 모드로 가기에 3초~5초만 유지해야 한다. (부팅 화면이 나올 때 바로 때면 된다.)

부팅을 했을 때 루팅이 안되어 있다고 하면 재부팅하면서 위 동작을 반복하면 된다. 루팅된 상태로 부팅을 할 경우 설치한 Magisk가 알아서 쉘 권한 등 대부분 작업을 해준다.

**adb**를 통해 아래와 같은 결과가 나오면 마무리 되었다고 볼 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/210132414-41dc81f7-630b-4766-8b17-6094aca2a347.png" width = 560>
</p>

## 참고 

   * [효튜의 세상](https://hyotwo.tistory.com/130#4.%203.%20Magisk%EC%97%90%EC%84%9C%20%ED%8E%8C%EC%9B%A8%EC%96%B4%20%EB%A3%A8%ED%8C%85)

   * [마빅의 IT블로그](https://hwsw00.tistory.com/entry/%EA%B0%A4%EB%9F%AD%EC%8B%9C-%EC%98%A4%EB%94%98-%ED%8E%8C%EC%9B%A8%EC%96%B4-%EC%82%AC%EC%9A%A9-%EA%B0%80%EC%9D%B4%EB%93%9C)

   * [RS잡동사니](https://xellos-8090.tistory.com/41)

   * [sboot.bin.lz4 멈춤](https://www.youtube.com/watch?v=u9asipBFrl0)

