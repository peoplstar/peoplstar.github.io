---
layout: post
title: Docker & vscode Enviroment
subtitle: Docker & vscode
categories: Environment
tags: [Docker, vscode, wsl]
---

CTF 대회 참여하면서 pwnable 역할을 맡고 대회 문제를 풀다 보면 환경 문제로 실행 조차 못하는 문제에 들이 닥치기 쉽다.

필자 또한, 문제 실행 조차 안돼서 접근조차 못한 경우가 많다. 또한, 익스플로잇 환경 조차 다르게 되어 다시 짜야 하는 경우가 발생했는데, 이번 기회를 통해 Docker 환경을 갖추고 편하게 접근하려고 한다.

Window 경우 **Docker Desktop**을 설치를 할 때, WSL 2를 활용하게 된다. WSL 2 부터 차근차근 설치해보도록 하겠습니다.

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

# essential packages
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc git python3 python3-pip ruby ruby-full sudo tmux vim wget zsh netcat gdb binutils-multiarch libssl-dev libffi-dev build-essential libc6-i386 libc6-dbg gcc-multilib make libc6:i386 libncurses5:i386 libstdc++6:i386 python3 python3-dev python3-setuptools socat dh-autoreconf && \
    apt-get upgrade -y &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

# essential python packages
RUN pip3 install --upgrade pip setuptools
RUN pip3 install unicorn keystone-engine ROPgadget capstone angr pwntools

RUN gem install one_gadget && \
    gem install seccomp-tools -v 1.5.0

# install patchelf
WORKDIR /root
RUN apt install -y dh-autoreconf
RUN git clone https://github.com/NixOS/patchelf
WORKDIR /root/patchelf
RUN git checkout 0.17.2
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN sudo make install
WORKDIR /

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "$HOME/.zsh"
RUN echo "LS_COLORS='rs=0:di=01;32:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=01;33:ow=01;97:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';" >> ~/.zshrc && \
    echo "export LS_COLORS" >> ~/.zshrc

RUN git clone https://github.com/dracula/zsh.git
RUN ln -s /root/zsh/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting && \
    echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

RUN echo "syntax on\\nfiletype indent plugin on\\nlet python_version_2=1\\nlet python_highlight_all=1\\nset tabstop=8\\nset softtabstop=4\\nset autoindent\nset nu" >> ~/.vimrc

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    git checkout 2023.03.19 && \
    ./setup.sh 

RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/cache/* && \
    rm -rf /var/lib/log/*

RUN useradd -m -s /bin/zsh user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN cp -r /root/.zsh /home/user/.zsh && \
    cp /root/.zshrc /home/user/.zshrc && \
    cp -r /root/.oh-my-zsh /home/user/.oh-my-zsh && \
    cp /root/.gdbinit /home/user/.gdbinit

RUN chown -R user:user /home/user/.zsh /home/user/.zshrc /home/user/.oh-my-zsh /home/user/.gdbinit

RUN chsh -s /bin/zsh root

USER user
```

### Ubuntu 18.04

```
FROM ubuntu:18.04

# essential packages
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc git python3 python3-pip ruby ruby-full sudo tmux vim wget zsh netcat gdb binutils-multiarch libssl-dev libffi-dev build-essential libc6-i386 libc6-dbg gcc-multilib make libc6:i386 libncurses5:i386 libstdc++6:i386 python3 python3-dev python3-setuptools socat dh-autoreconf && \
    apt-get upgrade -y &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

# essential python packages
RUN pip3 install --upgrade pip setuptools
RUN pip3 install unicorn keystone-engine ROPgadget capstone angr pwntools

RUN gem install one_gadget && \
    gem install seccomp-tools -v 1.5.0

# install patchelf
WORKDIR /root
RUN apt install -y dh-autoreconf
RUN git clone https://github.com/NixOS/patchelf
WORKDIR /root/patchelf
RUN git checkout 0.17.2
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN sudo make install
WORKDIR /

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "$HOME/.zsh"
RUN echo "LS_COLORS='rs=0:di=01;32:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=01;33:ow=01;97:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';" >> ~/.zshrc && \
    echo "export LS_COLORS" >> ~/.zshrc

RUN git clone https://github.com/dracula/zsh.git
RUN ln -s /root/zsh/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting && \
    echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

RUN echo "syntax on\\nfiletype indent plugin on\\nlet python_version_2=1\\nlet python_highlight_all=1\\nset tabstop=8\\nset softtabstop=4\\nset autoindent\nset nu" >> ~/.vimrc

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    git checkout 2023.03.19 && \
    ./setup.sh 

RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/cache/* && \
    rm -rf /var/lib/log/*

RUN useradd -m -s /bin/zsh user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN cp -r /root/.zsh /home/user/.zsh && \
    cp /root/.zshrc /home/user/.zshrc && \
    cp -r /root/.oh-my-zsh /home/user/.oh-my-zsh && \
    cp /root/.gdbinit /home/user/.gdbinit

RUN chown -R user:user /home/user/.zsh /home/user/.zshrc /home/user/.oh-my-zsh /home/user/.gdbinit

RUN chsh -s /bin/zsh root

USER user
```

### Ubuntu 20.04

```
FROM ubuntu:20.04

# essential packages
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc git python3 python3-pip ruby ruby-full sudo tmux vim wget zsh netcat gdb binutils-multiarch libssl-dev libffi-dev build-essential libc6-i386 libc6-dbg gcc-multilib make libc6:i386 libncurses5:i386 libstdc++6:i386 python3 python3-dev python3-setuptools socat dh-autoreconf && \
    apt-get upgrade -y &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

# essential python packages
RUN pip3 install --upgrade pip setuptools
RUN pip3 install unicorn keystone-engine ROPgadget capstone angr pwntools

RUN gem install one_gadget && \
    gem install seccomp-tools -v 1.5.0

# install patchelf
WORKDIR /root
RUN apt install -y dh-autoreconf
RUN git clone https://github.com/NixOS/patchelf
WORKDIR /root/patchelf
RUN git checkout 0.17.2
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN sudo make install
WORKDIR /

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "$HOME/.zsh"
RUN echo "LS_COLORS='rs=0:di=01;32:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=01;33:ow=01;97:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';" >> ~/.zshrc && \
    echo "export LS_COLORS" >> ~/.zshrc

RUN git clone https://github.com/dracula/zsh.git
RUN ln -s /root/zsh/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting && \
    echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

RUN echo "syntax on\\nfiletype indent plugin on\\nlet python_version_2=1\\nlet python_highlight_all=1\\nset tabstop=8\\nset softtabstop=4\\nset autoindent\nset nu" >> ~/.vimrc

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    git checkout 2023.03.19 && \
    ./setup.sh 

RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/cache/* && \
    rm -rf /var/lib/log/*

RUN useradd -m -s /bin/zsh user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN cp -r /root/.zsh /home/user/.zsh && \
    cp /root/.zshrc /home/user/.zshrc && \
    cp -r /root/.oh-my-zsh /home/user/.oh-my-zsh && \
    cp /root/.gdbinit /home/user/.gdbinit

RUN chown -R user:user /home/user/.zsh /home/user/.zshrc /home/user/.oh-my-zsh /home/user/.gdbinit

RUN chsh -s /bin/zsh root

USER user
```

### Ubuntu 21.10

```
FROM ubuntu:21.10

# essential packages
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc git python3 python3-pip ruby ruby-full sudo tmux vim wget zsh netcat gdb binutils-multiarch libssl-dev libffi-dev build-essential libc6-i386 libc6-dbg gcc-multilib make libc6:i386 libncurses5:i386 libstdc++6:i386 python3 python3-dev python3-setuptools socat dh-autoreconf && \
    apt-get upgrade -y &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

# essential python packages
RUN pip3 install --upgrade pip setuptools
RUN pip3 install unicorn keystone-engine ROPgadget capstone angr pwntools

RUN gem install one_gadget && \
    gem install seccomp-tools -v 1.5.0

# install patchelf
WORKDIR /root
RUN apt install -y dh-autoreconf
RUN git clone https://github.com/NixOS/patchelf
WORKDIR /root/patchelf
RUN git checkout 0.17.2
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN sudo make install
WORKDIR /

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "$HOME/.zsh"
RUN echo "LS_COLORS='rs=0:di=01;32:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=01;33:ow=01;97:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';" >> ~/.zshrc && \
    echo "export LS_COLORS" >> ~/.zshrc

RUN git clone https://github.com/dracula/zsh.git
RUN ln -s /root/zsh/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting && \
    echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

RUN echo "syntax on\\nfiletype indent plugin on\\nlet python_version_2=1\\nlet python_highlight_all=1\\nset tabstop=8\\nset softtabstop=4\\nset autoindent\nset nu" >> ~/.vimrc

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    git checkout 2023.03.19 && \
    ./setup.sh 

RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/cache/* && \
    rm -rf /var/lib/log/*

RUN useradd -m -s /bin/zsh user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN cp -r /root/.zsh /home/user/.zsh && \
    cp /root/.zshrc /home/user/.zshrc && \
    cp -r /root/.oh-my-zsh /home/user/.oh-my-zsh && \
    cp /root/.gdbinit /home/user/.gdbinit

RUN chown -R user:user /home/user/.zsh /home/user/.zshrc /home/user/.oh-my-zsh /home/user/.gdbinit

RUN chsh -s /bin/zsh root

USER user
```

### Ubuntu 22.04

```
FROM ubuntu:22.04

# essential packages
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y gcc git python3 python3-pip ruby ruby-full sudo tmux vim wget zsh netcat gdb binutils-multiarch libssl-dev libffi-dev build-essential libc6-i386 libc6-dbg gcc-multilib make libc6:i386 libncurses5:i386 libstdc++6:i386 python3 python3-dev python3-setuptools socat dh-autoreconf && \
    apt-get upgrade -y &&\
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* 

# essential python packages
RUN pip3 install --upgrade pip setuptools
RUN pip3 install unicorn keystone-engine ROPgadget capstone angr pwntools

RUN gem install one_gadget && \
    gem install seccomp-tools -v 1.5.0

# install patchelf
WORKDIR /root
RUN apt install -y dh-autoreconf
RUN git clone https://github.com/NixOS/patchelf
WORKDIR /root/patchelf
RUN git checkout 0.17.2
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make check
RUN sudo make install
WORKDIR /

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "$HOME/.zsh"
RUN echo "LS_COLORS='rs=0:di=01;32:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=01;33:ow=01;97:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:';" >> ~/.zshrc && \
    echo "export LS_COLORS" >> ~/.zshrc

RUN git clone https://github.com/dracula/zsh.git
RUN ln -s /root/zsh/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme

RUN git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ~/.zsh/zsh-syntax-highlighting && \
    echo "source ~/.zsh/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> ~/.zshrc

RUN git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
RUN echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh" >> ~/.zshrc
RUN echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=111'" >> ~/.zshrc

RUN echo "syntax on\\nfiletype indent plugin on\\nlet python_version_2=1\\nlet python_highlight_all=1\\nset tabstop=8\\nset softtabstop=4\\nset autoindent\nset nu" >> ~/.vimrc

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    git checkout 2023.03.19 && \
    ./setup.sh 

RUN apt-get clean && \
    apt-get autoclean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/cache/* && \
    rm -rf /var/lib/log/*

RUN useradd -m -s /bin/zsh user && \
    echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN cp -r /root/.zsh /home/user/.zsh && \
    cp /root/.zshrc /home/user/.zshrc && \
    cp -r /root/.oh-my-zsh /home/user/.oh-my-zsh && \
    cp /root/.gdbinit /home/user/.gdbinit

RUN chown -R user:user /home/user/.zsh /home/user/.zshrc /home/user/.oh-my-zsh /home/user/.gdbinit

RUN chsh -s /bin/zsh root

USER user
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


