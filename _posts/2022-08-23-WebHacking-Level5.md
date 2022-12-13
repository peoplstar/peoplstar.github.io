---
layout: post
title: [Webhacking.kr] Level 5
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186066119-be9ad795-d44c-4f0d-83d2-5c6086830953.jpg" width = 360>
</p>

접속하면 위 처럼 로그인과 회원가입에 대한 버튼이 있다. 우선 로그인을 들어가보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186066264-56fd4096-ca72-4235-9d44-13a632ea6cda.jpg" width = 360>
</p>

로그인할 수 있는 부분이 있다. 아무거나 대입해보면 **Wrong Password**가 안내를 해준다. SQLi를 해보면 될 것으로 예상되고, 회원가입으로 가보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186066480-f3b217cb-8132-420e-9ba6-386ad7f0eb12.jpg" width = 360>
</p>

...? 누르자 마자 접근 불가라는 Alert가 나온다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186066721-bae7338f-8c3a-4ddf-bf19-24bd556b9b91.jpg" width = 520>
</p>

해당 Join 버튼은 무조건 접근 불가라는 Alert를 띄우는 Script가 되어 있다. 또한, **move** 함수를 보면 현재 디렉토리에서 **mem/**을 거친 `login.php`를 가져온다. 여기서 **디렉토리 인덱싱**이 있을 것으로 예상해보고 문제 풀이를 해보겠습니다.

## 문제풀이

맨 처음 로그인 화면에서 SQLi를 시작해봤는데 제 머릿속에서 나올 수 있는 모든 인젝션을 진행했는데도 아무런 발전이 없었다. 그렇다면 로그인 부분에서는 SQLi 대응 방안이 구축되어 있을거라 생각하고 두번째 **디렉토리  인덱싱**으로 의심된 부분을 확인해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186067673-8de47f44-4349-4d59-bad8-3242a3e58636.jpg" width = 360>
</p>

우리가 접근하지 못했던 **join.php**와 SQLi을 실패한 **login.php**가 보인다. 이렇게 디렉토리 인덱싱을 통해 숨겨져 있거나 접근이 불가한 곳을 접근할 수 있다. **join.php**를 접근하여 문제를 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186067852-f0a01cce-59a4-4dd3-87c8-d4fb2f99abfd.jpg" width = 360>
</p>

느닷없이 **bye**라는 말과 함께 아무것도 보이지 않는 페이지가 나온다. 소스코드를 보고 확인해보겠습니다.

`<script></script>` 부분을 보면 코드가 있다. 보기가 어렵게 되어 있으니 예쁘게 변환해주는 [링크](https://beautifier.io/)를 첨부하겠습니다.

```javascript
if (eval(lIIIIIIIIIIIIIIIIIIl).indexOf(lIllIllIllIllIllIllIllIllIllIl) == -1) {
    alert('bye');
    throw "stop";
}
if (eval(llll + lllllllllllllll + lll + lllllllllllllllllllll + lllllllllllll + lllll + llllllllllllll + llllllllllllllllllll + li + 'U' + 'R' + 'L').indexOf(lllllllllllll + lllllllllllllll + llll + lllll + '=' + I) == -1) {
    alert('access_denied');
    throw "stop";
} else {
    document.write('<font size=2 color=white>Join</font><p>');
    document.write('.<p>.<p>.<p>.<p>.<p>');
    document.write('<form method=post action=' + llllllllll + lllllllllllllll + lllllllll + llllllllllllll + li + llllllllllllllll + llllllll + llllllllllllllll +
        '>');
    document.write('<table border=1><tr><td><font color=gray>id</font></td><td><input type=text name=' + lllllllll + llll + ' maxlength=20></td></tr>');
    document.write('<tr><td><font color=gray>pass</font></td><td><input type=text name=' + llllllllllllllll + lllllllllllllllllllllll + '></td></tr>');
    document.write('<tr align=center><td colspan=2><input type=submit></td></tr></form></table>');
}
```

해당 스크립트 구문 위에는 모두 난독화를 위해 만들어진 변수들이 선언 되어있다. 저는 이 난독화를 Python의 `replace`를 이용해서 하려고 했지만, 실패했습니다...따라서 `replace`가 아닌 난독화로 된 부분이 변수처럼 되어 있으니 똑같이 변수로 변경시켜서 print해보겠습니다.

### 난독화 해제

아래는 난독화 해제한 코드입니다. 변수 선언은 자바스크립트 변수부분은 하나의 String으로 가져와 replace로 수정했습니다.

```python
l = 'a'
ll = 'b'
lll = 'c'
llll = 'd'
lllll = 'e'
llllll = 'f'
lllllll = 'g'
llllllll = 'h'
lllllllll = 'i'
llllllllll = 'j'
lllllllllll = 'k'
llllllllllll = 'l'
lllllllllllll = 'm'
llllllllllllll = 'n'
lllllllllllllll = 'o'
llllllllllllllll = 'p'
lllllllllllllllll = 'q'
llllllllllllllllll = 'r'
lllllllllllllllllll = 's'
llllllllllllllllllll = 't'
lllllllllllllllllllll = 'u'
llllllllllllllllllllll = 'v'
lllllllllllllllllllllll = 'w'
llllllllllllllllllllllll = 'x'
lllllllllllllllllllllllll = 'y'
llllllllllllllllllllllllll = 'z'
I = '1'
II = '2'
III = '3'
IIII = '4'
IIIII = '5'
IIIIII = '6'
IIIIIII = '7'
IIIIIIII = '8'
IIIIIIIII = '9'
IIIIIIIIII = '0'
li = '.'
ii = '<'
iii = '>'
lIllIllIllIllIllIllIllIllIllIl = lllllllllllllll + llllllllllll + llll + llllllllllllllllllllllllll + lllllllllllllll + lllllllllllll + ll + lllllllll + lllll
lIIIIIIIIIIIIIIIIIIl = llll + lllllllllllllll + lll + lllllllllllllllllllll + lllllllllllll + lllll + llllllllllllll + llllllllllllllllllll + li + lll + lllllllllllllll + lllllllllllllll + lllllllllll + lllllllll + lllll

print(f"if (eval({lIIIIIIIIIIIIIIIIIIl}).indexOf({lIllIllIllIllIllIllIllIllIllIl}) == -1)")
print("{")
print("    alert('bye');")
print("    throw 'stop';")
print("}")
print(f"if (eval({llll}{lllllllllllllll}{lll}{lllllllllllllllllllll}{lllllllllllll}{lllll}{llllllllllllll}{llllllllllllllllllll}{li}'U''R''L').indexOf({lllllllllllll}{lllllllllllllll}{llll}{lllll}'='{I}) == -1)")
print("{")
print("    alert('access_denied');")
print("    throw 'stop';")
print("} else")
print("{")
print("    document.write('<font size=2 color=white>Join</font><p>');")
print("    document.write('.<p>.<p>.<p>.<p>.<p>');")
print(f"    document.write('<form method=post action='{llllllllll}{lllllllllllllll}{lllllllll}{llllllllllllll}{li}{llllllllllllllll}{llllllll}{llllllllllllllll}'>');")
print(f"    document.write('<table border=1><tr><td><font color=gray>id</font></td><td><input type=text name='{lllllllll}{llll}' maxlength=20></td></tr>');")
print(f"    document.write('<tr><td><font color=gray>pass</font></td><td><input type=text name='{llllllllllllllll}{lllllllllllllllllllllll}'></td></tr>');")
print("    document.write('<tr align=center><td colspan=2><input type=submit></td></tr></form></table>');")
print("}")
```

이렇게 Python을 이용해서 변수 지정으로 난독화를 해제하고 하나씩 뜯어보겠습니다.

```javascript
if (eval(document.cookie).indexOf(oldzombie) == -1)
{
    alert('bye');
    throw 'stop';
}
```

* document.cookie : User의 쿠키에 **'oldzombie'**가 없다면 저희가 `mem/join.php`에 들어갔을 때 나왔던 Bye Alert가 뜨는 것을 알 수 있습니다.

```javascript
if (eval(document.'U''R''L').indexOf(mode'='1) == -1)
{
    alert('access_denied');
    throw 'stop';
}
```

* document.URL : 현재 URL에 `mode=1`이 없다면 **access_denied**가 나오는 것이다.

```javascript
else
{
    document.write('<font size=2 color=white>Join</font><p>');
    document.write('.<p>.<p>.<p>.<p>.<p>');
    document.write('<form method=post action='join.php'>');
    document.write('<table border=1><tr><td><font color=gray>id</font></td><td><input type=text name='id' maxlength=20></td></tr>');
    document.write('<tr><td><font color=gray>pass</font></td><td><input type=text name='pw'></td></tr>');
    document.write('<tr align=center><td colspan=2><input type=submit></td></tr></form></table>');
}
```

위 두 조건을 만족한다면 **join.php**를 통해 id와 pw값을 POST 방식으로 전달하는 것이다. 

### 쿠키 및 URL

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186070981-6e8ef7d4-1cda-40f8-8d4b-e97554db67b5.jpg" width = 520>
</p>

크롬의 확장 프로그램은 **Edit this Cookie**를 이용해서 **oldzombie**라는 쿠키를 아래 3개를 체크하고 만들고 다시 `mem/join.php`를 들어가면 Bye가 아닌 Access_denied Alert가 뜬다. 

이제 `mode=1`를 URL에 집어넣어야한다. 하지만 그냥 집어넣으면 존재하지 않는 디렉토리 접근이라 할 것이다. 여기서 GET 메소드와 같이 **?**를 다시 붙여서 접속을 시도한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186071528-746d4649-8f2e-4489-8221-77f278a7a812.jpg" width = 280>
</p>

* https://webhacking.kr/challenge/web-05/mem/**join.php?mode=1**

접속하면 id와 pw를 입력할 수 있는 폼이 생긴다. 전 단순히 test/test로 제출하고 다시 로그인가서 test/test로 로그인을 시도했습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186072293-3722a366-a5b6-413f-84ac-e74c134bfa21.jpg" width = 280>
</p>

test 계정은 반가운데 무조건 **admin** 계정을 이용해야한다니 다시 admin으로 join 해보려고 했는데 admin은 이미 존재한다고 하네요?

불충분한 인증처럼 중간에서 admin 회원가입 패킷을 잡아서 변조하려했지만 방법을 찾을 수 없었습니다. 

이에 대해서 어떤 방법이 있을지 찾아볼 결과 이런게 있더라구요? 알아두시면 용이하실거 같아서 링크를 걸어드리겠습니다! (https://techblog.woowahan.com/2559/)

결국에는 **admin** 앞에 공백을 추가하여 중복 ID가 가능한 거였습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/186074474-8916f538-da1d-421f-b1fa-47dae3c3c500.jpg" width = 360>
</p>