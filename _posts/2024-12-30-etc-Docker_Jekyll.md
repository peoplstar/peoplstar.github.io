---
layout: post
title: Docker를 활용한 Jekyll 로컬 테스트
subtitle: Jekyll Dockerfile
categories: etc
tags: [Docker, vscode, wsl]
---

Jekyll을 이용한 Gitblog 작성 이후 커스텀하면서 여러 모듈을 직접 설치하여 Host PC가 더럽혀지는게 싫은 나머지 Docker를 이용한 Jekyll Local을 올려본다.

_(내 PC는 소중하니까)_

로컬 테스트하니 위한 Docker가 우선 필요하지만 설치하지 않으신 분은 이 [링크](https://peoplstar.github.io/etc/2022/12/02/etc-Docker.html#h-wsl-2)를 통해 설치하고 오면 됩니다.




## WSL 2

- WSL를 간단하게 표현하자면 MS(마이크로소프트)에서 제공하는 Windows에서 리눅스 커널을 사용할 수 있게 해주는 기술이다.

**Powershell**을 관리자 권한 **(시작 메뉴 > PowerShell > 관리자 권한으로 실행)**으로 열고 다음 명령을 입력한다.

```
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```
 
* **Linux 커널 업데이트 패키지 다운로드**

  * [x64 머신용 최신 WSL2 Linux 커널 업데이트 패키지]("https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi")

WSL 버전을 1에서 2로 업데이트하기 위함과 최신 패키지 다운로드 및 설치를 위한 과정이다.

* WSL 2를 기본 설정

```
wsl --set-default-version 2
```

## Docker Desktop

* 다음 경로로 접속하여 Docker Desktop on Windows 설치를 위한 설치 파일을 다운로드 [Docker Download Link](https://www.docker.com/get-started/)

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205291653-27fcb06e-1b50-4392-8f20-7611f5b1babc.png" width = 550>
</p>

설치 완료 후 옵션 버튼을 클릭하면 위와 같은 화면이 나오게 되는데 **General** - **User the WSL 2 based engine**을 체크하도록 합니다.(기본적으로 체크 되어 있지만 혹시 모르니 확인해보시길 바랍니다.)

## Visual Code Extension

**Visual Code** 를 설치하고 아래와 같이 확장 프로그램을 설치해주시면 됩니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205292743-1c0bf652-4583-4c4f-90b2-27f033960618.png" width = 400>
</p>

이후 현재 디렉토리에 Dockerfile을 생성하고 사용할 버전을 맞춰 만들면 됩니다.

## Dockerfile

원래대로면 `apt-get install vim git gcc ..-y` 하나로 묶어서 사용하지만 필자의 환경에서는 Time out으로 이상하게 실패했기에 다 따로 진행했습니다.

주로 사용하는 디버거로는 `pwndbg`이지만, 설치의 `./setup.sh`를 집어 넣는 방법을 찾지 못해서 실패했지만, 추후 넣어서 수정할 계획입니다.

또한, 기본으로 `zsh`을 사용하려고 하는데 어떻게 해줘야 할 지 아직 감이 안잡힌다...그래서 시작할 때 마다 `zsh`를 입력하고 시작하는 상황이 발생하고 있다.

### Ubuntu 16.04

```
FROM ubuntu:16.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN sed -i 's@archive.ubuntu.com@kr.archive.ubuntu.com@g' /etc/apt/sources.list

WORKDIR /root

RUN apt-get update 
RUN apt-get install -y netcat
RUN apt-get install libssl-dev -y
RUN apt-get install vim -y
RUN apt-get install git -y
RUN apt-get install gcc -y
RUN apt-get install ssh -y
RUN apt-get install curl -y
RUN apt-get install wget -y
RUN apt-get install gdb -y
RUN apt-get install sudo -y
RUN apt-get install zsh -y
RUN apt-get install python3 -y 
RUN apt-get install libffi-dev -y
RUN apt-get install build-essential -y
RUN apt-get install python3-pip -y
RUN apt-get install libc6-i386 -y
RUN apt-get install libc6-dbg -y
RUN apt-get install gcc-multilib -y
RUN apt-get install make -y

RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get install libc6:i386 -y

RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install -U pip==20.3.4
RUN pip3 install -U pwntools
RUN pip3 install capstone ropper
RUN pip3 install ropgadget
RUN apt-get install libcapstone-dev -y

RUN wget https://github.com/hugsy/gef/archive/refs/tags/2020.03.tar.gz
RUN tar -xzvf 2020.03.tar.gz
RUN echo source ~/gef-2020.03/gef.py >> ~/.gdbinit
RUN echo set disassembly-flavor att >> ~/.gdbinit

RUN apt-get install ruby-full -y
RUN apt-get install ruby-dev -y
RUN gem install one_gadget -v 1.7.3
RUN apt-get install patchelf -y

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
RUN mkdir -p "$HOME/.zsh"
RUN git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
RUN echo "fpath+=("$HOME/.zsh/pure")\nautoload -U promptinit; promptinit\nprompt pure" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
RUN echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

CMD ["zsh"]
SHELL ["/usr/bin/zsh", "-ec"]
```

### Ubuntu 18.04

```
FROM ubuntu:18.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN sed -i 's@archive.ubuntu.com@kr.archive.ubuntu.com@g' /etc/apt/sources.list

WORKDIR /root

RUN apt-get upgrade
RUN apt-get update
RUN apt-get install -y netcat
RUN apt-get update 
RUN apt-get install -y netcat
RUN apt-get install libssl-dev -y
RUN apt-get install vim -y
RUN apt-get install git -y
RUN apt-get install gcc -y
RUN apt-get install ssh -y
RUN apt-get install curl -y
RUN apt-get install wget -y
RUN apt-get install gdb -y
RUN apt-get install sudo -y
RUN apt-get install zsh -y
RUN apt-get install python3 -y 
RUN apt-get install libffi-dev -y
RUN apt-get install build-essential -y
RUN apt-get install python3-pip -y
RUN apt-get install libc6-i386 -y
RUN apt-get install libc6-dbg -y
RUN apt-get install gcc-multilib -y
RUN apt-get install make -y

RUN python3 -m pip install --upgrade pip
RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install pwntools
RUN pip3 install ropgadget
RUN apt-get install libcapstone-dev -y

RUN git clone https://github.com/hugsy/gef ./gef
RUN echo source ~/gef/gef.py >> ~/.gdbinit
RUN echo set disassembly-flavor att >> ~/.gdbinit

RUN apt-get install ruby-full -y
RUN gem install one_gadget seccomp-tools
RUN apt-get install patchelf -y

RUN git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
RUN echo 'source ~/powerlevel10k/powerlevel10k.zsh-theme' >>! ~/.zshrc

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
RUN mkdir -p "$HOME/.zsh"
RUN git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
RUN echo "fpath+=("$HOME/.zsh/pure")\nautoload -U promptinit; promptinit\nprompt pure" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
RUN echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

CMD ["zsh"]
SHELL ["/usr/bin/zsh", "-ec"]
```

### Ubuntu 20.04

```
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN sed -i 's@archive.ubuntu.com@kr.archive.ubuntu.com@g' /etc/apt/sources.list

WORKDIR /root

RUN apt-get upgrade
RUN apt-get update
RUN apt-get install -y netcat
RUN apt-get update 
RUN apt-get install -y netcat
RUN apt-get install libssl-dev -y
RUN apt-get install vim -y
RUN apt-get install git -y
RUN apt-get install gcc -y
RUN apt-get install ssh -y
RUN apt-get install curl -y
RUN apt-get install wget -y
RUN apt-get install gdb -y
RUN apt-get install sudo -y
RUN apt-get install zsh -y
RUN apt-get install python3 -y 
RUN apt-get install libffi-dev -y
RUN apt-get install build-essential -y
RUN apt-get install python3-pip -y
RUN apt-get install libc6-i386 -y
RUN apt-get install libc6-dbg -y
RUN apt-get install gcc-multilib -y
RUN apt-get install make -y

RUN python3 -m pip install --upgrade pip
RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install pwntools
RUN pip3 install ropgadget
RUN apt-get install libcapstone-dev -y

RUN git clone https://github.com/hugsy/gef ./gef
RUN echo source ~/gef/gef.py >> ~/.gdbinit
RUN echo set disassembly-flavor att >> ~/.gdbinit

RUN apt-get install ruby-full -y
RUN gem install one_gadget seccomp-tools
RUN apt-get install patchelf -y

RUN git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
RUN echo 'source ~/powerlevel10k/powerlevel10k.zsh-theme' >>! ~/.zshrc

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
RUN mkdir -p "$HOME/.zsh"
RUN git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
RUN echo "fpath+=("$HOME/.zsh/pure")\nautoload -U promptinit; promptinit\nprompt pure" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
RUN echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

CMD ["zsh"]
SHELL ["/usr/bin/zsh", "-ec"]
```

### Ubuntu 21.10

```
FROM ubuntu:21.10

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN sed -i 's@archive.ubuntu.com@kr.archive.ubuntu.com@g' /etc/apt/sources.list

WORKDIR /root

RUN apt-get upgrade
RUN sed -i -r 's/([a-z]{2}.)?archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
RUN sed -i -r 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

RUN apt-get update
RUN apt-get install -y netcat
RUN apt-get install libssl-dev -y
RUN apt-get install vim -y
RUN apt-get install git -y
RUN apt-get install gcc -y
RUN apt-get install ssh -y
RUN apt-get install curl -y
RUN apt-get install wget -y
RUN apt-get install gdb -y
RUN apt-get install sudo -y
RUN apt-get install zsh -y
RUN apt-get install python3 -y 
RUN apt-get install libffi-dev -y
RUN apt-get install build-essential -y
RUN apt-get install python3-pip -y
RUN apt-get install libc6-i386 -y
RUN apt-get install libc6-dbg -y
RUN apt-get install gcc-multilib -y
RUN apt-get install make -y

RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get install libc6:i386 -y

RUN python3 -m pip install --upgrade pip
RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install pwntools
RUN pip3 install ropgadget
RUN apt-get install libcapstone-dev -y

RUN git clone https://github.com/hugsy/gef ./gef
RUN echo source ~/gef/gef.py >> ~/.gdbinit
RUN echo set disassembly-flavor att >> ~/.gdbinit

RUN apt-get install ruby-full -y
RUN gem install one_gadget seccomp-tools
RUN apt-get install patchelf -y

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
RUN mkdir -p "$HOME/.zsh"
RUN git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
RUN echo "fpath+=("$HOME/.zsh/pure")\nautoload -U promptinit; promptinit\nprompt pure" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
RUN echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

CMD ["zsh"]
SHELL ["/usr/bin/zsh", "-ec"]
```

### Ubuntu 22.04

```
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN sed -i 's@archive.ubuntu.com@kr.archive.ubuntu.com@g' /etc/apt/sources.list

WORKDIR /root

RUN apt update && apt install -y netcat

RUN apt-get update 
RUN apt-get install -y netcat
RUN apt-get install libssl-dev -y
RUN apt-get install vim -y
RUN apt-get install git -y
RUN apt-get install gcc -y
RUN apt-get install ssh -y
RUN apt-get install curl -y
RUN apt-get install wget -y
RUN apt-get install gdb -y
RUN apt-get install sudo -y
RUN apt-get install zsh -y
RUN apt-get install python3 -y 
RUN apt-get install libffi-dev -y
RUN apt-get install build-essential -y
RUN apt-get install python3-pip -y
RUN apt-get install libc6-i386 -y
RUN apt-get install libc6-dbg -y
RUN apt-get install gcc-multilib -y
RUN apt-get install make -y

RUN dpkg --add-architecture i386
RUN apt update
RUN apt install libc6:i386 -y

RUN python3 -m pip install --upgrade pip
RUN pip3 install unicorn
RUN pip3 install keystone-engine
RUN pip3 install pwntools
RUN pip3 install ropgadget
RUN apt install libcapstone-dev -y

RUN git clone https://github.com/hugsy/gef ./gef
RUN echo source ~/gef/gef.py >> ~/.gdbinit
RUN echo set disable-randomization off >> ~/.gdbinit
RUN apt install file -y
RUN echo set disassembly-flavor att >> ~/.gdbinit

RUN apt install ruby-full -y
RUN gem install one_gadget seccomp-tools
RUN apt install patchelf -y


RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true
RUN mkdir -p "$HOME/.zsh"
RUN git clone https://github.com/sindresorhus/pure.git "$HOME/.zsh/pure"
RUN echo "fpath+=("$HOME/.zsh/pure")\nautoload -U promptinit; promptinit\nprompt pure" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
RUN echo "source ./zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

CMD ["zsh"]
SHELL ["/usr/bin/zsh", "-ec"]
```


## Vscode & Docker 연동

First. **터미널을 통해(Ctrl + j) 생성한 dockerfile이 있는 디렉토리로 이동한 후 아래의 코드를 입력하면 image bulid를 할 수 있다.**

```
docker build -t 이름:태그 -f dockerfile명 .
```

* 맨 뒤 **.**는 필수로 적어주셔야 합니다. 또한 태그는 없어도 되므로 `docker build -t 이름 -f dockerfile명 .`로 끝낼 수 있습니다.

Second. **위 코드로 만들어진 image를 실행하면 된다.**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205293988-ee3f31dc-e686-47e3-bd0f-9cea4a2a9eee.png" width = 420>
</p>

```
docker run -itd 이름
```

Third. **생성된 container를 vscode에서 docker를 들어가고, 우리가 만든 이름에 우클릭 - Start - 다시 우클릭 - Attach Shell로 실행할 수 있다.**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205294572-1725e3d4-cb52-4c1a-9e1b-6ef5f408b654.png" width = 320>
</p>

Fourth. **위 방법을 사용하지 않을 경우 계속 bash로 실행이 되게 된다. 따라서, 아래의 방법을 이용해서 사용하는게 명령어를 익히기도 편하다.** 

Container의 이름은 **Docker Desktop - Container** 에서 해당 컨테이너를 복사하여 편하게 입력할 수 있습니다.
```
docker exec -it containers's name zsh
```

**참고자료**

* [https://wyv3rn.tistory.com/233](https://wyv3rn.tistory.com/233)

* [https://wyv3rn.tistory.com/165](https://wyv3rn.tistory.com/165)

* [https://89douner.tistory.com/123](https://89douner.tistory.com/123)


