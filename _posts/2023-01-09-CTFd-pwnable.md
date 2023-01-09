---
layout: post
title: CTFd 환경 구축
subtitle: 환경 구축 및 pwnable 문제
categories: etc
tags: [CTFd, docker]
---

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/211243360-8f3b342d-f991-4be6-a909-92c74f161ec8.png" width = 340>
</p>

CTF(Capture The Flag) 대회를 해보면서 교내 동아리에서 신입 부원 및 동아리의 적극적인 활동을 위해 교내용 CTF를 구축하기로 하였다.

이에 CTFd라는 오픈소스 프레임워크를 이용하였다. 사용하면서 웹 문제의 경우 단순히 `apache`를 이용해 간단히 포트포워딩이 가능했지만, pwnable 문제의 경우 `nc(netcat)`를 이용하는 것이 대다수이기에 어려움을 겪었다.

`apache`에 대한 내용은 아래 링크를 통해 설명해두었으니 확인해주시면 되겠습니다.

* [peoplstar's Note](https://peoplstar.github.io/etc/2023/01/03/Apache2.html)

CTFd와 pwnable nc 구축 모두 `docker`를 사용하기에 설치부터 진행하겠습니다.

## CTFd Install

* docker 설치

```
curl -fsSL https://get.docker.com/ | sudo sh
```

* docker-compose 설치

이는 pwnable 문제 하나 당 도커 컨테이너가 존재하게 되는데, 이를 한번에 관리해주는 툴이다.

```
sudo curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
```

저의 환경은 AWS ubuntu 20.04 환경에서 진행했습니다. **CTFd**는 Git에서 간단히 clone해 사용이 가능하기에 linux 환경에서 진행하는 것을 추천드리겠습니다.

만들어진 환경에서 아래의 명령어를 하나씩 입력하시면 됩니다.

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get dist-upgrade
curl -fsSL http://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
sudo apt-get update
apt-cache policy docker-ce
sudo apt install docker-ce
git clone https://github.com/CTFd/CTFd.git
cd CTFd
vi docker-compose.yml
```

마지막 `vi docker-compose.yml` 명령어를 입력하면 아래와 같이 버전부터 서비스 모든 내용이 있습니다. 구축한 CTFd를 접속한 포트는 default로 **8000**을 부여하였지만, ports 부분을 통해서 변경이 가능하고, `SECRET_KEY`에 자신만의 키를 입력하고 저장하면 됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/211245202-cfbf2d71-363a-4786-a829-b39ea91e5ca9.png" width = 340>
</p>

실행을 위해서 `docker-compose`를 설치하고 아래의 명령어를 입력하고

```
sudo apt install docker-compose
sudo docker-compose up -d
sudo docker-compose start
```

도커를 실행한 환경(Host)의 `https://IP:8000/`를 들어가면 아래와 같이 기본 세팅이 가능하게 된다. 이렇게 기본적인 CTFd 환경 구축은 끝이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/211245532-664e20e3-63a0-45d8-a135-bbcfc6eb5569.png" width = 340>
</p>

## pwnable nc 구축

pwnable을 위해서는 CTFd 프레임워크처럼 Docker를 사용해야한다. 따라서, 위에서 설명한 `docker`와 `docker-compose` 설치를 기본적으로 수행해야한다. (이미 한 번 했다면 다음으로 넘어가면 된다.)

`docker-compose`를 이용해 한 번에 관리하기에 기본적인 파일 구조는 아래와 같다. 따라 하실때 아래와 같이 파일 구조를 구성하면 됩니다.

```
.pwnable/
├── docker-compose.yml // Only One 
├── bbof
│   ├── Dockerfile
│   ├── bbof
│   ├── bbof.c
│   ├── flag
│   └── settings
│       ├── bbof.xinetd
│       └── start.sh
├── mgame
│   ├── Dockerfile
│   ├── flag
│   ├── mgame
│   ├── mgame3.c
│   └── settings
│       ├── mgame.xinetd
│       └── start.sh
└── printer
    ├── Dockerfile
    ├── flag
    ├── printer
    ├── printer.c
    ├── printer.py
    └── settings
        ├── printer.xinetd
        └── start.sh
```

즉 하나의 `docker-compose.yml`에 포너블 문제에 대한 디렉토리가 존재하면 된다.

이후 각 디렉토리에 문제에 대한 `Dockerfile`과 flag, 문제파일, `settings(inetd, start.sh)`이 존재하게 된다.

### start.sh

```
#!/bin/bash
/etc/init.d/xinetd restart
/bin/bash
sleep infinity
```

`nc` 접속을 위해 설정해준 `xinetd`를 재시작하게 해주는 배치 스크립트 파일로 변경 사항 없이 동일하게 진행하면 된다.

### Dockerfile

문제 하나당 하나의 Dockerfile이 존재한다고 생각하면 이해하기 쉽습니다.

맨 처음에 해당 문제를 어떤 환경에서 가능하기 할 것인지 `FROM ubuntu:version`으로 원하는 버전을 입력하면 됩니다.

* `RUN useradd -m -d /home/bbof bbof -s /bin/bash` : `nc`로 접근하였을 때 어떤 권한 즉, 어떠한 유저로 접근하게 할 것인지 유저 생성 및 디렉토리 생성

* `ADD ./bbof /home/bbof/bbof` : ADD `<HOST> <Docker>` 왼쪽이 실제 존재하는 문제 파일, 오른쪽이 왼쪽의 파일을 어디에 배치할 것인지 추가

각 문제에 대해 유저를 바꾸지 않는다면 **shell** 획득 시 다른 문제의 flag를 읽을 것이 가능하기에 문제 별 유저를 다 명시해줬습니다.

이렇게 아래의 **bbof**를 사용자가 원하는 내용으로만 바꾸게 된다면 쉽게 이용이 가능하다.

```
FROM ubuntu:18.04

RUN apt-get update

# 32bit
#RUN apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386

RUN apt-get install -y xinetd netcat

RUN useradd -m -d /home/bbof bbof -s /bin/bash

RUN chown -R root:bbof /home/bbof
RUN chmod 750 /home/bbof

ADD ./bbof /home/bbof/bbof 
ADD ./flag /home/bbof/flag

RUN chown root:bbof /home/bbof/flag
RUN chown bbof:bbof /home/bbof/bbof
RUN chmod 440 /home/bbof/flag

CMD ["/usr/sbin/xinetd","-dontfork"]

ADD ./settings/bbof.xinetd /etc/xinetd.d/bbof
ADD ./settings/start.sh /start.sh
```

### prob.xinetd

```
service bbof
{
    disable = no
    flags = REUSE
    socket_type = stream
    protocol = tcp
    user = bbof
    wait = no
    server = /home/bbof/bbof
    type = UNLISTED
    port = 8080
}
```

* **service** : 해당 문제에 대한 내용으로 문제 파일명과 동일하게 하면 구분이 쉽다.

* **user** : 해당 문제 접근하는 사용자

* **server** : `nc` 접근 시 실행시켜줄 바이너리(문제 파일)

### docker-compose.yml

위에서 각 문제별 Docker에 대한 설정 파일을 만들어주고, 한 번에 관리해준 `docker-compose`를 만들어 실행하면 된다.

아래와 같이 `build` 시 어느 디렉토리에서 할 것인지, 해당 context에서 `Dockerfile`이 어디에 존재하는지 명시하고, 각 문제가 어떠한 포트를 이용할 것인지 `ports`로 잡아주면된다.


```
version: '3'

services:
    bbof:
        build:
            context: ./bbof/
            dockerfile: ./Dockerfile
        ports:
            - "30001:8080"
        command:
            - /start.sh
    
    mgame:
        build:
            context: ./mgame/
            dockerfile: ./Dockerfile
        ports:
            - "30002:8080"
        command:
            - /start.sh

    printer:
        build:
            context: ./printer/
            dockerfile: ./Dockerfile
        ports:
            - "30003:8080"
        command:
            - /start.sh
```

이후 `docker-compose.yml` 파일이 있는 디렉토리로 이동하여 아래의 명령어를 이용하면 실행이 된다.

* `docker-compose up -d` : 실행

* `docker-compose down` : 종료

* `docker-compose up -d --build` : 도커 파일 등 변경 시 재시작

```
root@ip-172-11-1-111:/home/ubuntu# docker ps
CONTAINER ID   IMAGE             COMMAND                  CREATED             STATUS             PORTS                                         NAMES
7f697da942a4   pwnable_printer   "/start.sh"              About an hour ago   Up About an hour   0.0.0.0:30003->8080/tcp, :::30003->8080/tcp   pwnable_printer_1
d5038d725173   pwnable_mgame     "/start.sh"              2 days ago          Up 2 days          0.0.0.0:30002->8080/tcp, :::30002->8080/tcp   pwnable_mgame_1
b0636a4b6f7b   pwnable_bbof      "/start.sh"              3 days ago          Up 2 days          0.0.0.0:30001->8080/tcp, :::30001->8080/tcp   pwnable_bbof_1
0e482d146ccb   ctfd_ctfd         "/opt/CTFd/docker-en…"   4 days ago          Up 2 days          0.0.0.0:8000->8000/tcp, :::8000->8000/tcp     ctfd_ctfd_1
852d34cde82f   mariadb:10.4.12   "docker-entrypoint.s…"   4 days ago          Up 2 days                                                        ctfd_db_1
086eaa1012e8   redis:4           "docker-entrypoint.s…"   4 days ago          Up 2 days                                                        ctfd_cache_1
```

`docker ps` 명령어를 입력하면 이처럼 실행 중인 도커 컨테이너의 목록을 보여주게 되는데 CTFd를 사용하고 있는 **8000** 포트, 포너블을 이용하고 있는 **30001 ~ 30003** 포트가 보여지게 된다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/211247710-8b276e5e-e777-40bf-abd4-51da22322c4c.png" width = 550>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/211247827-ab763e82-69ce-48e6-91fd-d90d4719655c.png" width = 550>
</p>
