---
layout: post
title: MCH2022CTF | MySimpleLogin 
subtitle: MCH2022CTF Moblie
categories: CTF
tags: [Programming]
---

**해당 CTF는 직접 참여한 것이 아닌 Writeup이 제공 되어 이후에도 문제를 풀이할 수 있게 되었습니다.**

**공식 링크는 아래에 첨부되어있고, 해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/7f315159-3ed3-4a49-bb66-f64a6a42e1b8" width = 850>
</p>

안전한 안드로이드 어플리케이션을 제작하였는데 플래그를 찾을 수 있겠냐?

실행시 패스워드 입력할 수 있는 `EditText`가 존재한다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/49e9c04e-be50-42df-afc5-58c9be8a3fd8" width = 450>
</p>

```java
public class MainActivity extends ActionBarActivity {
    private Button btnOK;
    private EditText edtPassword;
    private TextView lblPassword;

    // Detected as a lambda impl.
    public void checkPassword() {
        String i = this.edtPassword.getText().toString();
        String s = this.getResources().getString(0x7F0A0015);  // string:OO0O00OOO00O0O "S3kuritY!"
        String h = this.getResources().getString(0x7F0A0016);  // string:OO0O00OOO00OOO "7f03e614c9f1c1a0561f87f33d83e599"
        String f = this.getResources().getString(0x7F0A0014);  // string:OO0O0O0OO00OOO "Wrong Password! Try Again!"
        String w = this.getResources().getString(0x7F0A0017);  // string:OO0O0OOOO00OOO ">49s?#kjllw>ijvnra;;i>=kuki`ta;`iirj9::xtm;<rij%"
        if(this.l(String.valueOf(s) + i).equals(h)) {
            this.showError(w);
            return;
        }

        this.showFlag(f);
    }
}
```

* `checkPassword` : 입력한 값에 대해서 `l` 메소드를 통해서 문자열 `h`와 같은지를 비교한다

```java
public String r(String arg2, String arg3) {
    return arg2.replace(arg3, "");
}

public void showError(String arg4) {
    this.lblPassword.setText(this.x(this.r(this.r(this.r(this.r(this.r(this.r(this.r(arg4, "r"), "s"), "t"), "u"), "v"), "w"), "x"), "X"));
}

public String x(String s, String k) {
    StringBuilder sb = new StringBuilder();
    int i;
    for(i = 0; i < s.length(); ++i) {
        sb.append(((char)(s.charAt(i) ^ k.charAt(i % k.length()))));
    }

    return sb.toString();
}
```

* `showError(w)` : `lblPassword`를 통해 플래그

    * 해당 연산을 진행하면 플래그가 나오는 것을 알 수 있다.

기존 Writeup 또한 위 방법을 사용했지만 더욱 쉬운 방법을 사용하고자 한다.

```java
if(MainActivity.this.l(String.valueOf(s) + i).equals(h)) {
    MainActivity.this.showError(w);
    return;
}

MainActivity.this.showFlag(f);
```

현재 일치하지 않기에 `IF` 분기를 통해서 `MainActivity.this.showFlag(f);` **"Wrong Password! Try Again!"**를 출력하고 있다.

해당 코드를 Smali로 보면 아래와 같다.

```smali
0000009E  if-eqz              v5, :AA
:A2
000000A2  invoke-virtual      MainActivity->showError(String)V, p0, v4
:A8
000000A8  return-void
:AA
000000AA  invoke-virtual      MainActivity->showFlag(String)V, p0, v0
```

`if-eqz` 분기를 반대인 `if-nez` 로 변경하게 된다면 `showError`를 통해 플래그를 출력할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/fee606a4-bfb7-41a4-90ce-0de95ba35255" width = 450>
</p>