---
layout: post
title: Reversing | Dreamhack rev-basic-9
subtitle: rev-basic-9 문제 풀이
categories: dreamhack.io
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/e66d0393-c91a-4abc-89b5-b85c299e578e" width = 550>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_1400012E0("Input : ", argv, envp);
  sub_140001340("%256s", v4);
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
_BOOL8 __fastcall sub_140001000(const char *a1)
{
  int i; // [rsp+20h] [rbp-18h]
  int v3; // [rsp+24h] [rbp-14h]

  v3 = strlen(a1);
  if ( (v3 + 1) % 8 )
    return 0i64;
  for ( i = 0; i < v3 + 1; i += 8 )
    sub_1400010A0(&a1[i]);
  return memcmp(a1, &unk_140004000, 0x19ui64) == 0;
}
```

```C
  if ( (v3 + 1) % 8 )
    return 0i64;
```

일단 입력 값의 길이는 `if`문에 **0**값이 들어가야 하므로 **7의 배수**가 된다.

```C
  for ( i = 0; i < v3 + 1; i += 8 )
    sub_1400010A0(&a1[i]);
  return memcmp(a1, &unk_140004000, 0x19ui64) == 0;
```

`sub_1400010A0` 함수 인자를 `a1[i]`의 값으로 사용하며 인덱스는 8씩 커지면서 반복하게 된다.

해당 함수를 마치고 나서 `a1`과 `unk_140004000` 값을 비교한다.

### sub_1400010A0(v4)

```C
__int64 __fastcall sub_1400010A0(unsigned __int8 *a1)
{
  __int64 result; // rax
  unsigned __int8 v2; // [rsp+0h] [rbp-48h]
  int j; // [rsp+4h] [rbp-44h]
  int i; // [rsp+8h] [rbp-40h]
  char v5[16]; // [rsp+10h] [rbp-38h] BYREF

  strcpy(v5, "I_am_KEY");
  result = *a1;
  v2 = *a1;
  for ( i = 0; i < 16; ++i )
  {
    for ( j = 0; j < 8; ++j )
    {
      v2 = __ROR1__(a1[((_BYTE)j + 1) & 7] + byte_140004020[(unsigned __int8)v5[j] ^ v2], 5);
      a1[((_BYTE)j + 1) & 7] = v2;
    }
    result = (unsigned int)(i + 1);
  }
  return result;
}
```

해당 알고리즘은 단순히 `v5`라는 KEY를 이용하여 `XOR 연산, ROR 연산, 대입`을 진행하기에 대칭키라 볼 수 있다.

따라서, 역연산이 가능하다는 것을 이용해 식은 변환해본다.

`v2 = ROR(a1[(j+1) & 7] + byte[v5[j] ^ xor v2], 5)`

`a1[(j+1) * 7] + byte[v5[j] ^ v2] = ROL(v2, 5)`

`a1[(j+1) * 7] = ROL(v2, 5) - byte[v5[j] ^ v2]`

`a1[((_BYTE)j + 1) & 7] = v2`

`v2 = a1[((_BYTE)j + 1) & 7]`

인덱스에 따라 값을 변형하므로 인덱스도 순서를 반대로 하여 연산하여야 한다. 

간단히 하면 아래와 같다.

```C
for ( i = 0; i < v3 + 1; i += 8 ) {
  sub_1400010A0(&a1[i]);
  for ( i = 16; i > 0; --i )
  {
    for ( j = 8; j > 0; --j )
    {
      v2 = a1[((_BYTE)j + 1) & 7];
      a1[(j+1) * 7] = ROL(v2, 5) - byte[v5[j] ^ v2];
    }
  }
}
```

이를 기반으로 익스플로잇을 작성하고 실행하면 FLAG를 획득할 수 있다.

```python
def rol(x, n):
	shiftBit = x << n
	shiftBit &= 255
	carryBit = x >> 8 - n
	result = shiftBit | carryBit
	return result & 0xff

v5 = 'I_am_KEY'.encode()

data_4000 = '''
7Eh, 7Dh, 9A, 8B, 25h, 2Dh, D5, 3Dh,
3, 2Bh, 38h, 98, 27h, 9F, 4Fh, BC,
2Ah, 79h, 0, 7Dh, C4, 2Ah, 4Fh, 58h, 0
'''

data_4020 = '''
63h, 7Ch, 77h, 7Bh, 0F2h, 6Bh, 6Fh, 0C5h, 30h, 1, 67h
2Bh, 0FEh, 0D7h, 0ABh, 76h, 0CAh, 82h, 0C9h, 7Dh, 0FAh
59h, 47h, 0F0h, 0ADh, 0D4h, 0A2h, 0AFh, 9Ch, 0A4h, 72h
0C0h, 0B7h, 0FDh, 93h, 26h, 36h, 3Fh, 0F7h, 0CCh, 34h
0A5h, 0E5h, 0F1h, 71h, 0D8h, 31h, 15h, 4, 0C7h, 23h
0C3h, 18h, 96h, 5, 9Ah, 7, 12h, 80h, 0E2h, 0EBh, 27h
0B2h, 75h, 9, 83h, 2Ch, 1Ah, 1Bh, 6Eh, 5Ah, 0A0h, 52h
3Bh, 0D6h, 0B3h, 29h, 0E3h, 2Fh, 84h, 53h, 0D1h, 0
0EDh, 20h, 0FCh, 0B1h, 5Bh, 6Ah, 0CBh, 0BEh, 39h, 4Ah
4Ch, 58h, 0CFh, 0D0h, 0EFh, 0AAh, 0FBh, 43h, 4Dh, 33h
85h, 45h, 0F9h, 2, 7Fh, 50h, 3Ch, 9Fh, 0A8h, 51h, 0A3h
40h, 8Fh, 92h, 9Dh, 38h, 0F5h, 0BCh, 0B6h, 0DAh, 21h
10h, 0FFh, 0F3h, 0D2h, 0CDh, 0Ch, 13h, 0ECh, 5Fh, 97h
44h, 17h, 0C4h, 0A7h, 7Eh, 3Dh, 64h, 5Dh, 19h, 73h
60h, 81h, 4Fh, 0DCh, 22h, 2Ah, 90h, 88h, 46h, 0EEh
0B8h, 14h, 0DEh, 5Eh, 0Bh, 0DBh, 0E0h, 32h, 3Ah, 0Ah
49h, 6, 24h, 5Ch, 0C2h, 0D3h, 0ACh, 62h, 91h, 95h, 0E4h
79h, 0E7h, 0C8h, 37h, 6Dh, 8Dh, 0D5h, 4Eh, 0A9h, 6Ch
56h, 0F4h, 0EAh, 65h, 7Ah, 0AEh, 8, 0BAh, 78h, 25h
2Eh, 1Ch, 0A6h, 0B4h, 0C6h, 0E8h, 0DDh, 74h, 1Fh, 4Bh
0BDh, 8Bh, 8Ah, 70h, 3Eh, 0B5h, 66h, 48h, 3, 0F6h, 0Eh
61h, 35h, 57h, 0B9h, 86h, 0C1h, 1Dh, 9Eh, 0E1h, 0F8h
98h, 11h, 69h, 0D9h, 8Eh, 94h, 9Bh, 1Eh, 87h, 0E9h
0CEh, 55h, 28h, 0DFh, 8Ch, 0A1h, 89h, 0Dh, 0BFh, 0E6h
42h, 68h, 41h, 99h, 2Dh, 0Fh, 0B0h, 54h, 0BBh, 16h
'''

unk_4000 = [int(val, 16) for val in data_4000.replace('h', '').replace(',', '').replace('\n', ' ').split() if val]
byte_4020 = [int(val, 16) for val in data_4020.replace('h', '').replace(',', '').replace('\n', ' ').split() if val]

for x in range(0, 17, 8):
    a1 = unk_4000[x:x+8]
    for i in range(16):
        for j in range(7, -1, -1):
            idx = (j + 1) & 7
            v2 = a1[idx] & 0xff
            a1[idx] = (rol(v2, 5) - byte_4020[v5[j] ^ a1[j & 7]]) & 0xff

    for i in a1:
        print(chr(i), end = '')
```