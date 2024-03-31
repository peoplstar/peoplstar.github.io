---
layout: post
title: Reversing | reversing.kr 1번 Easy Crack
subtitle: Easy Crack 문제 풀이
categories: Reversing
tags: [Reversing, reversing.kr, Assembly]
---

**본 문제는 reversing.kr를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

필자는 CTF에서 리버싱을 맡게 되어 이번에 처음 입문하게 되었습니다. 리버싱에 대해 무지하지만 CTF 문제 풀이를 하면서 하면 어느정도 되지 않을까라는 생각에 맨 땅에 헤딩하듯이 시작했습니다.

아주 기초적인 어셈블리어를 독학하고, 이렇게 시작하게 되어서 많이 불안하지만 모두가 할 수 있다는 것을 이렇게 말씀드리고 싶습니다.

디버깅 프로그램은 수도 없이 많지만 저는 **x64dbg**를 이용했습니다. 해당 프로그램이 더 우수하다? 이런거는 첫 입문이라 모르지만 눈에 보여서 이것으로 실습을 진행했습니다.

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/179394104-d1fda79b-3e54-4277-afff-4cac8046a291.png" width = 350>
</p>

Easy Crack.exe 파일에 'ABCDEFG'를 입력하고 확인했을 때 Incorrect Password가 나온다.

해당 프로그램에서 원하는 값을 입력해야 풀릴 것으로 예상되고, 리버싱을 통해서 해당 값을 추측해야 할 것 같다.

따라서, x32dbg를 통해서 값을 검사하는 메소드에 Breakpoint를 걸고 확인해보겠다.

## 문제 풀이

상단에 `Az` 아이콘을 통해 **Incorrect Password, Congratulation !!** 문자열이 어디에 있는지 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180590731-59d52454-2874-4278-97d0-1e3341e933ab.png">
</p>

* 옳은 값에서는 'Congratulation !!' 나오는 것을 확인할 수 있다.

`F9`[프로그램 실행] 이후, `Ctrl + K` [이전 참조]를 통해 제일 처음 참조하는 곳을 확인해본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180590816-06c55ef3-f39f-4039-bd65-377a18b5c65c.png">
</p>

* `call dword ptr ds:[&GetDlgItemTextA]`를 통해서 우리가 입력한 값을 받는 것을 확인 할 수 있다.

* 그렇다면, 위 시스템 콜 이후 값을 비교하여 옳은 값을 체크 할 것으로 예상이 된다.

* `call dword ptr ds:[&GetDlgItemTextA]` 밑 `jne easy_crackme.401135`를 보자

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180590915-0293d1de-ae60-47e7-9a1c-9b874c173aaf.png">
</p>

_해당 어셈블리 우클릭 > G로 그래프화 시켜서 볼 수 있다._

* **401135**는 우리가 ABCDEFG를 입력했을 때 패스워드가 틀렸다고 메시지를 띄운 것으로 보면, **cmp**를 통해서 여기로는 들어오면 안된다는 것을 알 수 있다.

* **401135**와 call 사이의 cmp byte ptr ss:[esp+5], 61를 확인해보겠다. 이 위치에 `F2`[Break Point 설정]하고 확인해본다. 

**61**은 아스키 코드로 'a'이고, 이 값과 byte 단위로 esp+5의 값을 비교한다는 것인데 esp+5의 값을 확인한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180591115-3fd3e6d9-fc31-4d9e-8922-4002f46a2511.png" width = 140>
</p>

**_오른쪽 상단을 보면 레지스터의 값을 모두 볼 수 있다._**

왼쪽 하단 메모리쪽에서 **Ctrl+G[표현식]** 단축키를 통해 ESP+5의 값을 입력하여 따라가본다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180591194-8fbabd32-f582-4bb5-8136-3ab7254ff1d3.png">
</p>

_우리가 입력한 값을 확인할 수 있다._

* 우리가 입력한 `ABCDEFG`가 있지만 ESP+5는 'B'이다.

* 즉, 두번째 값이 'a'인지를 확인하는 것이므로 패스워드의 두번째 값은 **a**인게 확정이 되었다.

**Password : \_ a \_ \_ \_ \_ \_ (_몇 글자인지는 모른다_)**

_1a2345를 대입해보고 레지스터를 확인해본다._

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180591369-90025238-549c-4ef7-885b-0cbc910d90c9.png">
</p>

* 우리가 건너 뛰어야 할 **401135**이다. 하지만, 위 `cmp` 구문을 통해 두번째 값이 같으므로 `ZF`가 1이 되었음을 알 수 있다.

* `ZF`란, 제로 플러그로 해당 구문 연산 결과 값이 0면 1로 설정된다. **즉, CMP가 참이면 1, TEST가 참이면 1이란 것이다.**

* `jne`는 jump if not equal으로, `jnz`와 동일한 역할이다. not equal, not zero는 `ZF`로 체크하고 ZF 값이 0이면 jump하지만 이 값이 1이므로, **401135**으로 빠지지 않는다.

두번째 값을 알았으므로, 그 다음 구문을 확인해본다.

필자는 여기 부분에서 2일정도는 삽질을 했다. 아무리 봐도 어느 부분에서 어떻게 체크가 되는지 아무리 봐도 몰랐다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180591952-42052506-dc15-4ef7-bef2-6b9828193fd4.png">
</p>

* [ESP+A]에서 4byte에 해당되는 주소를 ecx에 넣고, eax의 값을 TEST해서 **401135**를 한다? 이전에 있는 함수를 들어가서 확인해봐야 왜 eax로 체크를 하는지 알 수 있을 것 같다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180592232-942c099a-f4fc-4eef-8299-3cd9f1d0b8f5.png">
</p>

* `lea ecx, dword ptr ss:[esp+A]` : esp+A의 위치에서 4byte에 해당되는 주소는 ecx에 넣는것을 의미한다. `F7`[다음단계로 진행]으로 넘어가면서 값을 확인해보면 위 처럼 ecx에 값이 들어가있는 것을 알 수 있다.

_의문의 `call 401150`를 확인해본다._

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180592350-e87db5fa-f0b4-4aec-a441-bbdace74ab23.png" width = 250>
</p> 

* 해당 명령어를 메모리에서 확인해보면 **5A FA 19 00**인데 Little Endian 이므로 **0019FA5A**이다. 

* 이는 또 다른 메모리 값을 가져와서 edi에 넣는 것인데 오른쪽 하단 스택 영역을 확인해보면 세번째 글자부터인 '2345'를 넣는 것을 확인 할 수 있다.

* 7줄 밑에 `mov esi, dword ptr ss:[esp+C]`가 있다. `[esp+C]` 주소에 **5y**라는 값을 대입하는 함수가 존재한다. **즉, esi에 '5y'값을 넣는 것이다.**<br> esi 값을 Ctrl+G로 확인해보면 5y값이 있을 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180592834-82977642-1cc5-43e5-9c34-914b98568d59.png" width = 380>
</p> 

* `al(eax)`에 '5y'값을 넣고, 우리의 입력 값의 세번째부터(345)를 비교한다. 비교한 값을 통해 `ja`로 가게 되면 **eax값이 FFFFFFFF**되고, RET 이후 `TEST eax,eax`로 실패 함수로 빠진다. **결국 세번째부터의 값이 5y가 되어야 한다는 것이다.**

**Password : \_ a 5 y \_ \_ \_ \_ \_**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180593198-7971e1ef-2983-4d12-8810-e4674378d6de.png" width = 380>
</p>

* 이번엔 '1a5y234'를 대입해서 확인해본다.

* esi에 'R3versing' 값이 들어갔다. 결국엔 이 값을 다시 비교하는 것으로 예상된다.

* eax에 들어간 값 1byte('2')를 dl에, esi에 들어간 값 1byte('R')을 cmp한다. <br> 이후에 계속 한 글자씩 비교하고, 해당 비교 값이 False면 실패함수로 빠지는 것을 보면 R3versing이 이후 값임을 알 수 있다.

**Password : \_ a 5 y R 3 v e r s i n g**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/180593398-93f8bd1e-2ae6-4cd3-a666-cae6323b19e8.png" width = 450>
</p>

* 우리는 두번째 값이 **[esp+5]**임을 맨 처음에 알았다. 갑자기 **[esp+4]**값을 비교한다? 맨 처음 값이 결국 'E'라는 것이다. 그리고 우리가 원하는 **Congratulation !!**이 있다. 패스워드는 결국 **Ea5yR3versing**이라는 것이다.

> **Password : E a 5 y R 3 v e r s i n g**

이렇게 reversing.kr의 첫 문제를 2일동안 풀어봤다. 리버싱을 이렇게 입문해보니 삽질만 죽어라 한 거 같은데 덕분에 어셈블리에 대한 이해도와 갈피가 어느 정도 잡힌거 같아서 다행이다.

