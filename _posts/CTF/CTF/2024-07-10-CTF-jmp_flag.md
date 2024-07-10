---
layout: post
title: DUCTF | jmp flag write-up
subtitle: Downunder CTF web
categories: CTF
tags: [CTF, Web]
---

## 문제 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/51f44014-19a4-4bf8-b18f-875db908517d" width = 450>
</p>

```
저는 모든 보안 코딩 방법을 배웠습니다. 저는 메모리 안전 언어와 군사급 암호화만 사용합니다. 당연히 제 금고에 침입할 수 없겠죠.
```

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/caf7be7a-5092-4d42-9e8e-b2ea1a1e2675" width = 850>
</p>

```C
  v0 = _rust_alloc(60LL, 1LL);
  v1 = (const void *)v0;
  *(_OWORD *)v0 = xmmword_4A000;
  *(_OWORD *)(v0 + 16) = xmmword_4A010;
  *(_OWORD *)(v0 + 32) = xmmword_4A020;
  *(_QWORD *)(v0 + 48) = 0x6179CBE7049F1890LL;
  *(_DWORD *)(v0 + 56) = 0x385BD95C;
```

`v1` 변수에 초기 값을 할당하고 있는 것을 알 수 있다. `xmmword_4A000` `xmmword_4A010` `xmmword_4A020`의 값을 확인해보면 다음과 같다.

```bash
.rodata:000000000004A000 xmmword_4A000   xmmword 65E74F390F161629CD3071C33256A6FAh
.rodata:000000000004A010 xmmword_4A010   xmmword 0ADF63090ED7FF4C81247EACCDB05FA2Eh
.rodata:000000000004A020 xmmword_4A020   xmmword 8EA036FE9AB32E3BD1B5CFA2A750B1ABh
```

44번 라인을 확인해보면 `aes::autodetect::aes_intrinsics::STORAGE::hc946fe15683ce26b`와 같이 AES 암호화를 사용하는 것으로 확인된다. 문제에서 제공해준 키워드 군사급 암호화란 [https://new.atsit.in/1491/#google_vignette](https://new.atsit.in/1491/#google_vignette)에서 말하는것과 같이 **AES** 또는 더 구체적으로 **AES-256**을 의미합니다.

```bash
_$LT$aes..ni..Aes256Enc$u20$as$u20$crypto_common..KeyInit$GT$::new::hf32da104863c2ae4(src, &unk_4A074);
```

66번 라인을 통해서 AES 관련 초기 Key값이 무엇인지 `&unk_4A074`를 통해 `95 87 E8 E7 DE C0 3C 28 A2 8C A1 F7 35 27 23 81 6C 21 6E 10 71 4A 62 0B 9E 36 78 93 38 96 90 CF` 인 것을 알 수 있다.

```bash
_$LT$Alg$u20$as$u20$aead..Aead$GT$::encrypt::h3e32796c24d9a97c(&v25, v31, &unk_4A068, v7, v18);
```

199번 라인에서 `&unk_4A068` 값 `FF 06 72 45 C6 AE 7B 9F C1 36 D4 8E`을 통해 최종적으로 AES 암호화를 진행하는 것을 알 수 있다.

```C
  if ( v27 == 60 && !bcmp(v1, s2, 0x3CuLL) )
  {
    if ( v22 )
      _rust_dealloc(v23, v22, 1LL);
    src[0] = (__int64)&off_5A150;
    src[1] = 1LL;
    src[2] = 8LL;
    *(_OWORD *)&src[3] = 0LL;
    std::io::stdio::_print::h8f9e07feda690a3d(src);
  }
```

204번 라인 `v27`의 값이 60이며 `v1`, `s2`를 60자리만큼 비교하여 참일 경우 `&off_5A150`를 출력하는데 이 내용은 **Congratulations, you have opened the vault**로 즉 초기에 나온 값들과 Key, Nonce를 조합하여 AES Decrypt하면 해결될 것으로 보인다.

그렇다면 여태 확인한 값을 통해서 복호화를 진행하게 되면 플래그를 얻을 수 있을 것이다.

```python
from Crypto.Cipher import AES

nonce = bytes.fromhex('FF 06 72 45 C6 AE 7B 9F C1 36 D4 8E')
key = bytes.fromhex('95 87 E8 E7 DE C0 3C 28 A2 8C A1 F7 35 27 23 81 6C 21 6E 10 71 4A 62 0B 9E 36 78 93 38 96 90 CF')
ct = bytes.fromhex('65E74F390F161629CD3071C33256A6FA')[::-1]
ct += bytes.fromhex('ADF63090ED7FF4C81247EACCDB05FA2E')[::-1]
ct += bytes.fromhex('8EA036FE9AB32E3BD1B5CFA2A750B1AB')[::-1]
ct += bytes.fromhex('6179CBE7049F1890')[::-1]
ct += bytes.fromhex('385BD95C')[::-1]

aes = AES.new(key, mode=AES.MODE_GCM, nonce=nonce)
flag = aes.decrypt(ct)
print(flag)
```

**b'DUCTF{enCrypTi0n_I5_NoT_Th3_S@me_as_H@sh1ng}\x19s}\xa0|A\x19Q\x95\x0e\xd0\xf9\xc3z\xe9\xff'**