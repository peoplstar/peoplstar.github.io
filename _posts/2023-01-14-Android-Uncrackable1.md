---
layout: post
title: Android | Uncrackable Lv 1
subtitle: Frida Android Rooting Detection Bypass, Uncrackable1
categories: Android
tags: [Android, frida, rooting]
---

**본 내용은 프리다(Frida)를 이용한 안드로이드 앱 모의해킹 서적을 통해 습득한 내용입니다.**

## 루팅 탐지 우회

루팅 탐지 우회에서 진단할 APK 파일은 **OWASP**에서 배포한 `UnCrackable-Level1.apk` 파일이다.

의도적으로 취약하게 만든 파일로 진단 공부할 때 용이하게 이용된다.

* [OWASP UnCrackable-Level1.apk](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes/Android/Level_01)

파일을 다운받고 CMD를 다운로드 받은 경로로 이동한다.

```
C:\Users\users>adb install UnCrackable-Level1.apk
Performing Streamed Install
Success
```

`adb` 명령어를 통해 단말기에 다운받은 파일을 install 해주고 **Success**가 나오면 단말기에는 정상적으로 다운이 된 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212458981-eba968d1-2653-49cb-b726-97d421e56488.png" width = 440>
</p>

해당 파일을 실행시키면 아래와 같이 **Root detected!** 다이얼로그가 나오고 **OK** 버튼을 누르면 프로세스가 종료되는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212459032-0dd26acc-5978-4ff6-b4ac-aedd5ed6b435.png" width = 200>
</p>

Frida를 이용하려면 진단할 APK 파일이 어떤 클래스에서 탐지를 하는지 파악해야 하기에 이전에 설치한 `jadx`를 이용해 디컴파일을 한다.

## 루팅 탐지 코드 분석

**소스코드 > sg.vantagepoint > uncrackable1 > MainActivity**를 보면 `onCreate`함수가 있는데 모바일에서는 `MainActivity > onCreate`가 제일 실행되는 Main이라 볼 수 있다.

```java
@Override // android.app.Activity
protected void onCreate(Bundle bundle) {
    if (c.a() || c.b() || c.c()) {
        a("Root detected!");
    }
    if (b.a(getApplicationContext())) {
        a("App is debuggable!");
    }
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
}
```

* **c.a()**

```java
public static boolean a() {
    for (String str : System.getenv("PATH").split(":")) {
        if (new File(str, "su").exists()) {
            return true;
        }
    }
    return false;
}
```

환경변수 **PATH**를 가져오는데 루팅하면 `su`라는 바이너리 파일이 생성되기에 **PATH**에 `su`가 있으면 루팅되어 있음을 감지한다.

* **c.b()**

```java
public static boolean b() {
    String str = Build.TAGS;
    return str != null && str.contains("test-keys");
}
```

Bulid.TAGS의 값을 가져오는데 기본 값으로는 **release-keys**로 되어 있지만 루팅하게 되면 해당 값이 **test-keys**로 변경되기에 이를 감지하는 것이다.

* **c.c()**

```java
public static boolean c() {
    for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
        if (new File(str).exists()) {
            return true;
        }
    }
    return false;
}
```

`str`은 루팅 시 사용되는 apk와 파일을 기반으로 루팅을 감지하는 것이다.

**C** 객체의 `a(), b(), c()` 셋 중 하나라도 해당된다면 위 처럼 루팅을 감지하는 것으로 되어 있습니다. 

```java
if (c.a() || c.b() || c.c()) {
    a("Root detected!");
}

private void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.1
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}
```

`a()`함수를 보면 커스텀 다이얼로그를 출력하게 되는데 **OK** 버튼을 누르면 `System.exit(0);`을 통해 프로그램을 종료시키는 것을 알 수 있다.

`if`문의 모든 값을 false로 바꾸는 것보단 `System.exit(0)`를 후킹하여 종료되지 않게 하는게 편할 것을 예상됩니다.

우선, 단말기에서 **frida-server**를 실행시키고 아래의 둘 중 하나의 후킹 스크립트를 작성해 우회가 가능하다.

### Hooking

* **exit() hook**

```java
console.log("[+] System Hooking");
Java.perform(function() {
    var hook = Java.use("java.lang.System");
    hook.exit.implementation = function () {
        console.log("[+] Hooking System exit");
    }
});
```

* **return value hook**

```java
console.log("[+] System Hooking");
Java.perform(function() {
    var hook = Java.use("sg.vantagepoint.a.c");
    hook.a.implementation = function () {
        console.log("[+] Hooking a()");
        return false;
    }
    hook.b.implementation = function () {
        console.log("[+] Hooking b()");
        return false;
    }
    hook.c.implementation = function () {
        console.log("[+] Hooking c()");
        return false;
    }
});
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212460860-eb0156ce-30fa-404c-bd2d-e0bd1576b2d3.png" width = 480>
</p>

## Verify

이후 OK 버튼을 클릭하면 꺼지지 않고 대기 중인 것을 알 수 있다. 그리고 **EditText**가 보이는 데 **VERIFY** 버튼을 클릭하면 아래처럼 다이얼로그가 나온다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212460925-ed5048e4-f7a4-45ce-af6b-605d2d77af1a.png" width = 200>
</p>

## Verify 코드 분석

```java
public void verify(View view) {
    String str;
    String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
    AlertDialog create = new AlertDialog.Builder(this).create();
    if (a.a(obj)) {
        create.setTitle("Success!");
        str = "This is the correct secret.";
    } else {
        create.setTitle("Nope...");
        str = "That's not it. Try again.";
    }
    create.setMessage(str);
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.2
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            dialogInterface.dismiss();
        }
    });
    create.show();
}
```

`a.a(obj)`가 True면 넘어갈 수 있을 것으로 보인다. obj는 우리가 EditText에 입력한 값이 됩니다.

### a.a()

```java
public static boolean a(String str) {
    byte[] bArr;
    byte[] bArr2 = new byte[0];
    try {
        bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArr = bArr2;
    }
    return str.equals(new String(bArr));
}
```

`b()` 메소드를 통한 `8d127684cbc37c17616d806cf50473cc` 반환 값과 `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=`를 base64로 디코딩한 값을 `sg.vatagepoint.a.a.a()` 호출하여 나온 값을 **bArr**에 저장한다. 

이 값을 우리의 입력한 값과 비교하여 참인지 거짓인지 return 한다.

### sg.vatagepoint.a.a.a()

```java
public class a {
    public static byte[] a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        return cipher.doFinal(bArr2);
    }
}
```

암호화와 패딩 방식등을 명시하고 **AES** 방식으로 decrypt하는 함수다.

**bArr**와 우리의 입력 값을 비교하기에 bArr가 무엇인지 스크립트를 짜면 된다.

### Hooking

```java
// Secret String.js
console.log("[+] Secret String");
Java.perform(function() {
    var secret = Java.use("sg.vantagepoint.a.a");
    secret.a.implementation = function(arg1, arg2) {
        console.log("[+] Hooking sg.vatagepoint.a.a");    
        var retval = this.a(arg1, arg2);
        var secret_str = "";

        for (var i = 0; i < retval.length; i++) {
            secret_str += String.fromCharCode(retval[i]);
        }
        console.log("[+] Secret String :", secret_str);
        return retval;
    }
});
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212468697-e514e022-b464-4fec-b8c9-c4e0bb41dea3.png" width = 440>
</p>

Secret String을 단말기에서 EditText에 넣고 **Verify** 버튼을 누르면 성공했다는 다이얼로그가 출력된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/212468824-96c3b14a-b08d-44ef-b142-599b72e374b3.png" width = 200>
</p>