---
layout: post
title: Unity | 모바일 게임 해킹
subtitle: Unity로 제작된 모바일 게임 해킹 방법법
categories: AOS
tags: [Android, frida, Unity]
---

# 서론

한국콘텐츠진흥원에서 게임 이용자의 게임 분야별 이용률 조사에 따라 모바일 게임 비율이 84.6퍼를 하는 것을 알 수 있다. 이 문서에서는 많은 비율을 차지하고 있는 모바일 게임 중 **Unity**로 개발된 모바일 게임에 대해서 모의해킹 진행을 진행하게 된다면 어떻게 분석하고 악의적인 조작이 어떻게 이루어질 수 있나 확인하도록 하겠습니다.

<p align="center">
<img src ="https://github.com/user-attachments/assets/49818990-dabf-476f-b60c-6bd23898d288" width = 700>
</p>

# Unity

Unity 엔진 내부는 C++로 제작되어 있으며 유저(Client)단 코드만 **C#**을 이용해서 작성하게 된다. **Unity** 런타임 하는 방식은 두 가지로 **mono, il2cpp**가 존재하는데, 두 방식에서 가장 큰 차이점으로는 AOT(**A**head-**O**f-**T**ime) 컴파일 방식을 사용하냐 JIT(**J**ust-**I**n-**T**ime) 컴파일 방식을 사용하는지 차이가 있습니다.

* **AOT 컴파일** : 프로그램에서 코드가 실행되는 시점에 기계어로 번역되는 컴파일 기법

* **JIT 컴파일** : 런타임 시 수행해야 할 작업량을 줄이기 위해 미리 빌드 타임에서 모든 내용을 컴파일 해놓는 기법
 
개발하는데에 있어서 해당 게임에 대한 리소스가 많으냐, 고성능의 게임을 다루게 되느냐 등 게임의 환경에 따라 두 방식을 모두 사용하기에 어느 한 방식을 더욱 많이 사용한다고 보기 어렵다. 또한 다양한 플랫폼에서 사용하는가, 빌드 시간을 단축하며 빌드 속도를 향상하는가, 메모리 사용량을 줄이고 실행 속도를 높이는가에 따라 두 방식으로 나누어지게 된다.

따라서 두 방식에 대한 내용을 모두 이해하고 두 방식으로 컴파일하는 경우 어떻게 차이가 나는지 확인해보며 분석 방법에 대해 말씀드리겠습니다.

## mono

<p align="center">
<img src ="https://github.com/user-attachments/assets/47122b5a-ade6-4126-90c2-f9754c739613" width = 700>
</p>

**mono**란 `Just-In-Time` 컴파일 기술을 이용해 런타임에 코드를 컴파일한다. **mono**의 경우 `.Net Framework`를 대응하기 위해 만들어진 것이며 크로스 플랫폼은 지원에 대응하는 C# 런타임 방식이다. C#으로 구성된 코드가 C# 컴파일러를 거쳐 IL 코드로 변환된다. 

이후 해당 코드가 Mono 런타임에서 실행되는데 메모리 관리, 가비지 콜렉터, 쓰레드 같은 기능이 있는 가상머신을 제공한다. 또한 **JIT** 컴파일 방식을 사용한다 하였는데 이는 Mono 런타임 시점에 코드를 컴파일하게 된다. 

Mono의 경우 생성된 IL 코드를 DLL 파일에 아주 쉽게 디컴파일이 가능하다. 해당 파일은 APK 내에 `assets\bin\Data\Managed\Assembly-CSharp.dll` 파
일을 확인할 수 있다. 해당 파일에는 Client 작성된 코드가 IL 코드로 변환되어 해당 DLL 파일에 저장되어 있다.

## il2cpp

<p align="center">
<img src ="https://github.com/user-attachments/assets/1bf00472-e5f8-4972-96e3-621b55e302ca" width = 700>
</p>

**il2cpp**란 `Ahead-Of-Time` 컴파일 기술을 이용해 런타임에 코드를 컴파일한다. 이 방식은 IL 코드를 사용할 수 있는 플랫폼(.NET Framework, Mono)보다 C++를 지원하는 플랫폼이 더 많기 때문에 다양한 플랫폼을 지원할 수 있다.

il2cpp 방식으로 빌드를 하게 되면 mono와 달리 IL 코드를 C++ Native Code로 변환한다. 이는 `libil2cpp.so` 파일을 생성하게 되며 여러 플랫폼에서 해당 라이브러리를 참조하여 실행하게 된다.

il2cpp의 경우 생성된 IL 코드가 APK 파일 내에 `assets\bin\Data\Managed\Metadata\global-metadata.dat`의 내용을 토대로 `libil2cpp.so` 파일을 특정 도구를 통해 분석할 수 있다.

il2cpp 방식은 **Bytecode Striping**이라는 것을 적용하는데 이는 사용하지 않거나 도달할 수 없는 코드를 제거하여 최종 빌드 크기를 줄이게 된다. 


두 런타임 방식의 차이점을 정리하자면 아래와 같은 테이블이 나오게 된다.

||Mono|IL2CPP|
|:--:|:--:|:--:|
|   컴파일러      |    JIT     |    AOT    |
|     속도       |     느림    |     빠름   |
|     보안       |    약함     |    비교적 강함    |
|     메모리 사용량   |     많음    |    적음    |
|    빌드 속도   |     빠름    |    느림    |
| 빌드 파일 크기 |    적음     |    많음    |



## IL 코드

`IL 코드`란 Intermediate Language로 중간 언어를 의미하고 C#으로 작성된 코드를 `ilasm.exe`를 통해 컴파일하고 나면 CPU와 OS에 독립적인 기계어 코드가 생성되는데 이 코드를 IL 코드라 한다. 

`IL` 는 .NET의 중간 단계의 언어로 특정 하드웨어나 운영체제에 중속되지 않으며, .NET의 어셈블리 코드(파일)이라 볼 수 있다.

<p align="center">
<img src ="https://github.com/user-attachments/assets/221b4926-1c6f-40df-ba24-e8ccb205fc76" width = 700>
</p>


```C#
using System;

struct Point
{
    ​​​​public int x;
    ​​​​public int y;
}

class Program
{
    static void Main(string[] args)
    ​​​​{
        ​​​​​​​​Point pt1;
        ​​​​​​​​Point pt2 = new Point();
    ​​​​}
}
```

`Point` 구조체와 Main 함수에서 `pt1`, `pt2`를 선언하며 `pt2`는 초기화까지 한 C#의 코드이다. 아래는 기존 C# 코드의 IL 코드로 어떠한 차이가 생기는지 비교해본다.

<p align="center">
<img src ="https://github.com/user-attachments/assets/d621bef1-ffeb-4fb8-aad1-4e05769feecf" width = 700>
</p>

C#의 코드가 IL 코드로 변환되었을 때 모습으로 `valuetype`이 Point이며 `V_0`, `V_1` 지역 변수를 만든 것을 볼 수 있다. `​​​​​​​​Point pt2 = new Point();`에 해당하는 코드로는 `IL_0001:  ldloca.s   V_1    ​​​​IL_0003:  initobj    Point`와 매칭이 가능하다.

local 변수인 V_1를 load하여 `initobj Point`로 해당 객체로의 초기화를 진행하는 것을 알 수 있다.

## 모바일 게임 분석 

<p align="center">
<img src ="https://github.com/user-attachments/assets/a5fe66e8-0016-41dc-b086-d2e98395a0bc" width = 700>
</p>

Mono 와 il2cpp 두 방식 모두 [dnSpy](https://github.com/dnSpy/dnSpy) 프로그램을 이용합니다. Mono의 경우 별도의 파일 추출 방법이 필요한 것이 아닌 `assets\bin\Data\Managed\Assembly-CSharp.dll` 해당 파일을 **dnSpy**로 열어 수정, 위/변조를 통해 간단히 진행할 수 있고 본질적으로 분석하는 방법은 동일하기에 추가 작업이 필요한 il2cpp 방식만을 분석하며 설명하도록 하겠습니다.

앞서 설명한 것과 같이 Mono 방식은 `assets\bin\Data\Managed\Assembly-CSharp.dll` 파일 하나를 추출하여 **dnSpy** 프로그램을 통해 디컴파일하면 Client 작동 코드는 모두 확인이 가능합니다.

다만 Mono와 달린 il2cpp 방식은 해당 어플리케이션의 실질적인 정보를 담고 있는 파일 `lib\libil2cpp.so`와 어플리케이션 내의 메타데이터를 가지고 있는 `assets\bin\Data\Managed\Metadata\global-metadata.dat` 두 파일을 조합하며 생성되는 `Assembly-CSharp.dll`를 **dnSpy**로 분석이 가능하다.

`Il2CppDumper.exe` 파일을 실행 시 아래 두 차례를 따르면 된다.

    1. Dump에 사용될 libil2cpp.so 로드

    2. Dump에 사용될 lobal-metadata.dat 로드

<p align="center">
<img src ="https://github.com/user-attachments/assets/b585bf25-78e7-4e05-bd3d-da8f33eca15d" width = 700>
</p>

위 과정이 정상적으로 종료 되면 **DummyDll** 이라는 폴더가 생성되는데 해당 폴더에 `Assembly-CSharp.dll` 파일이 생성된 것을 알 수 있다.

<p align="center">
<img src ="https://github.com/user-attachments/assets/f7702e38-e1c0-403d-a780-181d879e0d2e" width = 700>
</p>

dnSpy 프로그램을 통해 해당 파일을 열게 되면 모든 소스 코드가 정상적으로 디컴파일 되는 것을 확인할 수 있다. 하지만 해당 파일은 Dump를 통해 임의로 생성된 파일이기에 Frida를 통해 직접적인 메모리 값을 변경하기 위해서는 실제로 참조하고 있는 라이브러리인 `libil2cpp.so` 파일 또한 분석을 진행해야된다.

<p align="center">
<img src ="https://github.com/user-attachments/assets/2948bf0c-e691-4df0-a5de-c53ffc36da61" width = 700>
</p>

게임 재화 관련 값을 변조하기 위해 함수명에 대해 찾아 본 결과 `SpendCoins` 라는 함수를 확인할 수 있다. 이 때 파일이 메모리에 로딩 되었을 때의 상대 주소 값을 의미하는 `RVA` 값을 확인할 수 있다. 이 값을 토대로 IDA에서 확인해보면 SpendCoins 라는 함수를 확인해볼 수 있다.

```C
__int64 __fastcall sub_18DA4AC(_DWORD *a1, int a2, __int64 a3, __int64 a4, __int64 a5, char a6)
{
  int v12; // w8
  __int64 v13; // x19
  __int64 v14; // x0
  __int64 v15; // x19
  __int64 v16; // x0
  unsigned __int64 v18; // t2
  unsigned int v19; // w27
  unsigned int v20; // w25
  unsigned int v21; // w26
  int v22; // [xsp+8h] [xbp-58h] BYREF
  int v23; // [xsp+Ch] [xbp-54h] BYREF
```

dnSpy에서 확인한 Offset을 통해 IDA로 확인해보면 인자의 갯수가 동일한 것을 알 수 있다. 그렇다면 코인을 사용하였을 때 해당 값이 어떻게 작동하는지 해당 변수를 찾아 다닐 수 있다.

```C
  if ( (unsigned int)(v18 >> 2) >= 0x28F5C29 )
  {
    if ( !*((_DWORD *)off_3941388 + 56) )
      j_il2cpp_runtime_class_init_0(off_3941388);
    nullsub_13(qword_397E888, 0LL, (float)a2);
    if ( !*((_DWORD *)off_393E408 + 56) )
      j_il2cpp_runtime_class_init_0(off_393E408);
    sub_33C95D4(qword_3988638, 0LL);
    v12 = a1[41];
  }
  v19 = a1[39];
  v20 = v12 - a2; // Here
  v21 = a1[40] + a2;
  a1[40] = v21;
  a1[41] = v12 - a2;
  if ( !*((_DWORD *)off_3942A20 + 56) )
    j_il2cpp_runtime_class_init_0(off_3942A20);
  sub_18B89FC(v20, v19, v21, (unsigned int)a2, 0LL);
  if ( (a6 & 1) != 0 )
    sub_18DA3C0(a1);
  if ( a3 )
  ...
```

`a1[39]`을 받아와 `a2`와의 차이를 구하고 있는 것으로 보아 `a1[39]`는 현재 코인의 개수, `a2`는 사용하고자 하는 코인의 개수를 의미하는 것으로 보이며 코인을 사용했을 때 저 값이 나오는지 확인하기 위한 Frida 코드를 작성한다.

```javascript
console.log(colors.green, "[+] ", name, colors.reset);      
Interceptor.attach(il2cpp.add(offset), {
    onEnter: function (args) {
        let reg = this.context;
        console.log(colors.green, " └─[*] reg.x8 : ", JSON.stringify(reg.x8, 0, 2));
        console.log(colors.green, " └─[*] reg.x19 : ", JSON.stringify(reg.x19, 0, 2));
    },
    onLeave: function (retval) { // boolean
    }
});
```

게임 코인 사용 시 사용되는 모든 레지스터의 값을 확인 할 수 있다. 여기서 봐야할 레지스터로는 `a1[39]`를 사용하고 있는 `v12`의 **x8**, 사용하고자 하는 코인의 개수를 뜻하는 `a2`의 **x19**임을 IDA에서 확인할 수 있다. 

<p align="center">
<img src ="https://github.com/user-attachments/assets/a88e7946-a57b-4dc1-a02d-abe541217624" width = 700>
</p>

```
SUB W25, W8, W19
```

<p align="center">
<img src ="https://github.com/user-attachments/assets/e5adb13c-bce7-47fa-9083-44bfbb318ea7" width = 500>
</p>

**x19**의 값은 상자를 열기 위한 가격 100 코인(0x64), **x8**의 값은 현재 가지고 있는 1024 코인(0x400)임을 알 수 있다.

그렇다면 해당 메소드에 진입했을 때에 코인의 값을 변조한다면 원하는 메모리에 접근이 가능할 것이다.

```javascript
function SpendCoins(il2cpp, offset, name) {
    console.log(colors.green, "[+] ", name, colors.reset);      
    Interceptor.attach(il2cpp.add(offset), {
        onEnter: function (args) {
            let reg = this.context;
           
            reg.x8 = 0x1000000; // currentCoin 현재 사용중인 코인 값을 sizeup
            reg.x19 = 0x0; // spendCoin

            console.log(colors.green, " └─[*] reg.x8 : ", JSON.stringify(reg.x8, 0, 2));
            console.log(colors.green, " └─[*] reg.x19 : ", JSON.stringify(reg.x19, 0, 2));

        },
        onLeave: function (retval) { // boolean
        }
    });
}
```

<p align="center">
<img src ="https://github.com/user-attachments/assets/0786802d-380a-40da-b0d5-58145048885c" width = 500>
</p>

이러한 방법으로 Unity il2cpp 방식에 대한 분석 및 메모리 변조가 가능하다는 것을 알 수 있다.

## Reference

* [https://docs.unity3d.com/Manual/Mono.html](https://docs.unity3d.com/Manual/Mono.html)

* [https://docs.unity3d.com/Manual/IL2CPP.html](https://docs.unity3d.com/Manual/IL2CPP.html)

* [https://www.kocca.kr/kocca/koccanews/reportview.do?nttNo=565&menuNo=204767](https://www.kocca.kr/kocca/koccanews/reportview.do?nttNo=565&menuNo=204767)

* [https://www.youtube.com/watch?v=v7hYmNujfXM](https://www.youtube.com/watch?v=v7hYmNujfXM)

* [https://learn.microsoft.com/ko-kr/dotnet/framework/tools/ilasm-exe-il-assembler](https://learn.microsoft.com/ko-kr/dotnet/framework/tools/ilasm-exe-il-assembler)

* [https://mplnsr.wordpress.com/2011/02/21/switching-clr-versions-in-iis/](https://mplnsr.wordpress.com/2011/02/21/switching-clr-versions-in-iis/)

* [https://github.com/Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper)

