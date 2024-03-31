---
layout: post
title: Reversing | Dreamhack rev-basic-4
subtitle: rev-basic-4 문제 풀이
categories: Reversing
tags: [Reversing, dreamhack, Assembly]
---

**본 문제는 dreamhack.io를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/227758114-8ca66238-7bb5-4bff-96be-cbad77a272b8.png" width = 550>
</p>

해당 프로그램을 통해 문자열 입력을 받아 옳은 입력 값임을 증명해야한다. 바이너리 분석을 위해 IDA를 사용하겠습니다.

### 분석

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[256]; // [rsp+20h] [rbp-118h] BYREF

  memset(v4, 0, sizeof(v4));
  sub_1400011B0("Input : ", argv, envp);
  sub_140001210("%256s", v4);
  if ( (unsigned int)sub_140001000(v4) )
    puts("Correct");
  else
    puts("Wrong");
  return 0;
```

입력 값을 256자를 받으며 해당 `v4[256]` 배열에 저장한다.

해당 값이 `sub_140001000(v4)` 함수를 통해 return 값이 1이면 해결된다.

### sub_140001000(v4)

```C
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x1C; ++i )
  {
    if ( ((unsigned __int8)(16 * *(_BYTE *)(a1 + i)) | ((int)*(unsigned __int8 *)(a1 + i) >> 4)) != byte_140003000[i] )
      return 0i64;
  }
  return 1i64;
}
```

이전 문제와 달리 **XOR** 연산이 아닌 `*|* `연산을 수행하는데 이는 역연산에 대한 규칙이 존재하지 않는다.

따라서, 입력 값에 대해서 모든 경우는 확인해봐야 하는 Brute-force가 적합할 것으로 보인다.

비트 연산이 존재하고, 이는 `Shift` 연산 시 사라지는 비트가 앞과 뒤에 붙는지 아닌지를 확인하기 위해 더욱 자세히 확인해볼 필요가 있다.

```armasm
.text:000000014000101A loc_14000101A:                          ; CODE XREF: sub_140001000+10↑j
.text:000000014000101A                 movsxd  rax, [rsp+18h+var_18]
.text:000000014000101E                 cmp     rax, 1Ch
.text:0000000140001022                 jnb     short loc_140001065

.text:0000000140001024                 movsxd  rax, [rsp+18h+var_18]
.text:0000000140001028                 mov     rcx, [rsp+18h+arg_0]
.text:000000014000102D                 movzx   eax, byte ptr [rcx+rax]
.text:0000000140001031                 sar     eax, 4 // MSB bit 유지
.text:0000000140001034                 movsxd  rcx, [rsp+18h+var_18]
.text:0000000140001038                 mov     rdx, [rsp+18h+arg_0]
.text:000000014000103D                 movzx   ecx, byte ptr [rdx+rcx]
.text:0000000140001041                 shl     ecx, 4
.text:0000000140001044                 and     ecx, 0F0h
.text:000000014000104A                 or      eax, ecx
.text:000000014000104C                 movsxd  rcx, [rsp+18h+var_18]
.text:0000000140001050                 lea     rdx, byte_140003000
.text:0000000140001057                 movzx   ecx, byte ptr [rdx+rcx]
.text:000000014000105B                 cmp     eax, ecx
.text:000000014000105D                 jz      short loc_140001063
.text:000000014000105F ; 7:       return 0i64;
.text:000000014000105F                 xor     eax, eax
.text:0000000140001061                 jmp     short loc_14000106A
```

중요 연산만 확인하게 된다면 네가지가 존재한다.

* `.text:0000000140001031                 sar     eax, 4` : 입력 값을 오른쪽으로 4칸 밀기

  * 만약 **41**이라는 값이라면 **4** 앞 한자리만 남게 된다.

* `.text:0000000140001041                 shl     ecx, 4` : 입력 값을 왼쪽으로 4칸 밀기

* `.text:0000000140001044                 and     ecx, 0F0h` : 위 연산 값과 `and F0` 연산

  * 만약 **41**이라는 값이라면 `shl 4`로 인해 **410**이 되고, `and`로 인해 **10**만 남는다.

* `.text:000000014000104A                 or      eax, ecx` : 두 연산 값을 `OR` 연산

  * `1031`의 연산 **4**와 `1044`의 연산 **10**을 합쳐 **14**가 된다.

**즉 입력 값 앞 4비트, 뒤 4비트의 순서가 바뀌게 된다는 것이다. 이 값을 이용해 기존 데이터의 값을 비교하게 된다.**

#### 비트 수 변경하는 Exploit

```python
data = '''
24h, 27h, 13h, C6h, C6h, 13h, 16h, E6h, 47h, F5h
26h, 96h, 47h, F5h, 46h, 27h, 13h, 26h, 26h, C6h
56h, F5h, C3h, C3h, F5h, E3h, E3h
'''

lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))
rst = []
val = []

for i in lst_3000:
    tmp0 = i[0]
    tmp1 = i[1]
    mv = tmp1 + tmp0
    rst.append(mv)

for i in rst:
    val.append(chr(int(i, 16)))

print(''.join(val))
```

#### 기존 연산에 초점을 둔 Exploit

```python
data = '''
24h, 27h, 13h, C6h, C6h, 13h, 16h, E6h, 47h, F5h
26h, 96h, 47h, F5h, 46h, 27h, 13h, 26h, 26h, C6h
56h, F5h, C3h, C3h, F5h, E3h, E3h
'''

lst_3000 = list(filter(None, data.replace('h', '').replace(',', '').replace('\n', ' ').split(' ')))
rst = ''

for i in range(0, len(a1)):
    print(chr(16 * a1[i] & 0xF0 | a1[i] >> 4), end='')

print(rst)
```