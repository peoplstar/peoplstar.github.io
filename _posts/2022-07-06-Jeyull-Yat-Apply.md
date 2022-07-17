---
layout: post
title: GitBlog 만들기
subtitle: Jekyll Yat 테마 적용
categories: Git_Blog
tags: [Git_Blog, Jekyll, Yat]
---

안녕하세요 :).

저는 모든 내용을 Github에 올렸는데 그것 쫌 아닌거 같아서...

이렇게 GitHub 블로그를 만들면서 정리해보려합니다!

혼자 해보면서 몇 번을 지웠다가 생성했다가 했는지 모르겠네요 :(

설치부터 시작하겠습니다.

## Ruby 설치

GitBlog의 테마는 jekyll 테마를 사용하고, 이를 수정 및 관리를 하기 위해서는 Ruby 개발 환경을 세팅 해야 합니다!

아래 링크를 통해 루비를 다운 받고 설치 하시면 됩니다.

<a href = "https://rubyinstaller.org/downloads/"> 루비 설치 홈페이지로 바로 가고 싶다면?</a>

<p align="center">
<img src="https://user-images.githubusercontent.com/78135526/179343341-a9180e87-7134-4c3b-a7e4-2bafb21076c2.png" width = 250>
</p>


설치 하실 때 Default로 되어 있는 대로 하시면 됩니다:)

저는 그냥 최신 버전으로 받았습니다!!

이후 터미널 창에서 `ruby -v` 하시면 아래 처럼 나오시면 설치 완료입니다.

<p align="center">
<img src="https://user-images.githubusercontent.com/78135526/177484836-078e15f6-c0f4-4dd9-803c-881f3ace54cc.png" width = 250>
</p>

## Git Repository 생성 

### **1. 새로운 Repository를 만든다.**

<p align="center">
<img src="https://user-images.githubusercontent.com/78135526/177480801-e2e4184c-dfed-48f6-9528-630b9aaa316e.png" width = 400>
</p>

New 버튼을 통해서 만드시면 됩니다.

### **2. Reopsitory 이름을 명시한다.**

<p align="center">
<img src="https://user-images.githubusercontent.com/78135526/177481201-f3d42660-3119-4d8e-b9be-1613b093aa7a.png"/>
</p>

New 버튼 누르고 나면 위와 같이 나올텐데 **Owner는 절대 건들지 마시고,** Repository name에 **"username.github.io"** 작성 하시면 됩니다!

저의 username은 peoplstar 이기에 Repository name은 peoplstar.github.io가 되겠습니다!

그리고 해당 Github는 모두가 볼 수 있도록 해야 GitBlog도 제대로 작동 하기에 **Public**으로 설정 하고, **Add a README FILE**을 체크하고 Create하시면 되겠습니다!

### **3. My Repository Clone**

우리는 계속된 개발 환경을 위해서 우리가 만든 Repository를 Clone 해올 것이다. 경로는 자신이 주로 사용하는 경로에 Clone 하면 된다. **Git Bash, CMD** 어떤거로 해도 상관 없다.

<p align="center">
<img src="https://user-images.githubusercontent.com/78135526/179344466-7e433104-e989-4d6e-b03a-d750e70b55a6.png"/>
</p>

* 자신의 Repositoy에서 Clone의 URL을 복사해서 위 명령어로 하면 된다.

## 테마 설치 및 적용

Jekyll 테마는 찾아보면 진짜 엄청 많습니다...

진짜 뭘 골라야 할지도 모를 수준으로 많습니다 예쁘다고 생각하시는거 아무거나 고르시면 됩니다 :)

[jamstackthemes.dev](https://jamstackthemes.dev)

[jekyllthemes.org](http://jekyllthemes.org)

[jekyllthemes.io](https://jekyllthemes.io)

[jekyll-themes.com](https://jekyll-themes.com)

저는 [Jekyll Yat](https://github.com/jeffreytse/jekyll-theme-yat)테마를 선택 했습니다!

### **1. 테마 설치**

해당 테마의 GitHub에 들어가셔서 아래와 처럼 **Download Zip**으로 설치 하시면 됩니다.

![Download](https://user-images.githubusercontent.com/78135526/177485724-8c0a1ae8-318c-47eb-b11c-53156c5fd19e.png)

> **왜 Clone으로 안하냐는 분이 계실까봐 말씀드립니다!**

Clone을 하게 되면 해당 배포자의 Git log까지 모두 가져오게 되고 우리는 만들어진 Repository가 상대의 Git으로 덮여지기에 Download Zip으로 진행합니다!

### **2. 기본 세팅**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179347494-650537d3-d5fd-47db-93d9-da5ba206e524.png" width = 200>
</p>

윈도우 검색에서 "Start Command Prompt with Ruby"를 실행하고, 아래 명령어를 순차적으로 입력한다.
`gem install jekyll bundler` <br> 
`bundle install` <br>
`chcp 65501` <br>

### **3. 테마 적용**

다운받은 파일을 압축 해제하고, 자신의 Repository에 모두 덮어 씌우시면 됩니다!

디렉토리 내에 `_config.yml` 파일이 있을 겁니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/177489025-bce86550-45e6-4da1-8afa-1d7807569a41.png" width = 300>
</p>

해당 내용 사용자 별로 변경하시고,

다음 `_data` 폴더 밑 `defaults.yml` 파일을 보겠습니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/177489390-c20ed11b-0547-4099-bfd2-414927860fdb.png" width = 500>
</p>

위 내용은 config.yml에서 default로 설정 된 내용을 여기서 변경하면 바로 적용 됩니다!! 이것 또한 마음대로 변경하시면 됩니다!!!

그리고 터미널으로 해당 디렉토리로 이동하시고, 아래와 같이 하시면 됩니다.

`bundle add webrick` <br>
`bundle exec jekyll serve`
* 하면 로컬에서 즉, http://127.0.0.1:4000으로 확인 가능하다.

`git add .` 로 Staged에 올리고<br>
`git commit -m "Commit Message"` , 로 Local Repository에 올리고<br>
`git push` 를 통해 Remote Repository 즉, Github에 올리시면 됩니다.

적용 되는데에는 시간이 조금 걸립니다! 진행 과정을 알기 위해서는 브라우저에서 해당 Repository로 이동하시고 **Action**으로 이동하시면 진행 과정을 볼 수 있습니다!

이후 `"username".github.io`로 이동하시면 적용이 된 것을 볼 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/177490213-dafa47ec-43e2-4c51-b817-aaaaa247fcfa.png">
</p>

그리고 새로운 내용을 쓰고 싶으신 분은 `_posts` 폴더에서 `.md`형식인 마크다운 파일을 만드시면 바로 적용 됩니다!

이 폴더 내에 있는거 삭제 하지 마시고, 안에 내용 보시면서 적용하시면 편하실거에요!! 

여러분들은 저처럼 여러번 삭제하고 그런일은 없도록 하시구 화이팅입니다. :>

### **안되시는 분들을 위하여**

