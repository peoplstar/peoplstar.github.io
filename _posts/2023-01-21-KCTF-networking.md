---
layout: post
title: KnightCTF 2023 | Networking
subtitle: 2023 KnightCTF Write up
categories: CTF
tags: [Packet]
---

**The most awaited international CTF from Bangladesh!**

**KnightCTF 2023 is a jeopardy CTF competition for Cyber ​​Security professionals and students or those who are interested in security.**

**There will be challenges in various categories like PWN, Reversing, Web, Cryptography etc.**

**Tons as well as tons of thankfulness along with an appreciation for all of our sponsors who made this event possible.**


## 문제 분석

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215248115-ccbb01a6-01f7-43d8-a5e8-be45539c0eeb.png" width = 400>
</p>

비즈네르경이 꿈에서 패킷 캡쳐 내용을 보냈는데 거기에는 성공에 대한 Key 즉, 플래그가 담겨 있다 합니다.

패킷 파일을 들여다 보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215248208-cccdd8ba-1d00-4e8a-8c66-056309339b65.png" width = 600>
</p>

**ICMP** 프로토콜이며 Request는 모두 `Type 8 ping`을 반복적으로 전송하고 있습니다. 

Data를 포함하여 보내고 있는데 값을 보면 모두 1byte씩 보내고 있습니다. 

ICMP 프로토콜에 대한 Data를 모두 조합하면 `a25pZ2h0Cg==`입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215248528-4ac9a471-99b2-4449-8b24-8fef4f5bf5ad.png" width = 600>
</p>

이후에는 DNS를 이용하여 query를 보내고 있는데 URL의 첫 값을 계속 바꿔가면서 DNS Query를 보내는 것을 알 수 있습니다.

DNS Query에서 첫 값을 모두 조합하면 `VVBCTHtvMV9tcjNhX2VuMF9oazNfaTBofQ==`입니다.

일단 base64 인코딩된 값임을 알 수 있고 디코딩해봐야 알 것으로 보입니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215248608-b272c82d-3a54-4a6b-b2e2-45346471bb28.png" width = 400>
</p>

첫 값은 knight로 나오는 것을 보니 맞는거 같은데 두번째 값은 형태는 맞는데 값이 다른 것으로 보여 **카이사르(시저) 암호**로 유추했습니다.(_단순 치환 암호_)

규칙을 찾아보며 확인해봤지만 알 수 없었다. 이후 문제의 힌트가 있을 것으로 예상되어 보낸 이의 이름을 찾아보면 아래와 같은 내용이 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215248682-5a7425f0-c2fc-4f9a-9650-c0fd6100f15b.png" width = 250>
</p>

두번째 디코딩한 값은 비즈네르 암호화가 되어 있는 것으로 예상되어 해당 암호 값을 복호화 해보면 아래와 같다.

복호화를 위해서는 Key가 필요하는데 첫번째 base64 디코딩 값 **knight**를 넣으니 FLAG가 나오는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215249033-4ba730de-e38b-48d0-8dd8-cd731a83f3a0.png" width = 450>
</p>
