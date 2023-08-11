---
layout: post
title: Reversing | Dreamhack rev-basic-5
subtitle: rev-basic-5 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b06e7e45-fe12-48e5-99b9-1dd73f6b1a38" width = 550>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_1400011C0("Input : ", argv, envp);
  sub_140001220("%256s", v4);
  if ( (unsigned int)sub_140001000(v4) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
}
```

입력 값을 256자를 받으며 해당 `v4[256]` 배열에 저장한다.

해당 값이 `sub_140001000(v4)` 함수를 통해 return 값이 1이면 해결된다.

### sub_140001000(v4)

```C
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x18; ++i )
  {
    if ( *(unsigned __int8 *)(a1 + i + 1) + *(unsigned __int8 *)(a1 + i) != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```

`i = 0` 이라 가정했을 때, `a1[0 + 1] + a1[1]` = `byte[0]` 이란 소리가 된다.
i는 총 0x18byte로 24번 반복하며 `byte_14003000`의 개수 또한 24개이다.

i는 총 23까지 반복하게 되므로 `a1[23 + 1] + a1[23]` = `byte[23]`로 마무리 된다.
이를 점진적으로 나아가면 아래와 같은 그림이 나오게 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/70d55b1a-3696-4468-9e31-b772bff13270" width = 550>
</p>

연쇄적으로 결과가 나오기에 하나의 값이 정해지면 결과까지 나오게 되는데 알고 있는 정보는 `byte`의 값이다.

`b[23]`의 값은 `a[23]`과 `a[24]`의 덧셈이지만 `a[24]`가 0이라면 `b[23] = a[23]`이 되며, `a[22] = b[22] - a[23]`으로 **a[22]** 값마저 구할 수 있게 된다.

```python
data = '''
0ADh, 0D8h, 0CBh, 0CBh, 9Dh, 97h, 0CBh, 0C4h, 92h
0A1h, 0D2h, 0D7h, 0D2h, 0D6h, 0A8h, 0A5h, 0DCh, 0C7h
0ADh, 0A3h, 0A1h, 98h, 4Ch, 0
'''

lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))
tmp = 0
rst = ''

for i in range(len(lst_3000)):
    tmp = int(lst_3000[-1 - i], 16) - tmp
    rst += chr(tmp)

print(rst[::-1])
```