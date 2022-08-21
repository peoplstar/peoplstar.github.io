---
layout: post
title: Webhacking.kr | Level 2
subtitle: Webhacking CTF Problem Solving
categories: Webhacking
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184475330-ec6bbd68-75a7-4335-bece-4f69640d1941.jpg" width = 420>
</p>

패스워드를 입력하는 Textarea가 있다. 아무 값을 입력하고 제출하면 Alert창도 없이 새로고침 되면서 위 String이 변경된다. 위에는 암호화가 되어 있는듯한(?) 문자열이 있다. 소스 보기란이 있으니 소스를 본다. 

## 소스 보기

```php
<?php
  sleep(1); // anti brute force
  if((isset($_SESSION['chall4'])) && ($_POST['key'] == $_SESSION['chall4'])) solve(4);
  $hash = rand(10000000,99999999)."salt_for_you";
  $_SESSION['chall4'] = $hash;
  for($i=0;$i<500;$i++) $hash = sha1($hash);
?>

<tr>
  <td colspan=3 style=background:silver;color:green;>
    <b><?=$hash?></b>
  </td>
</tr>
```

필요 없어 보이는 부분 제외하고 보니 세션 변수 'chall4'가 존재하면서 POST 방식으로 보낸 우리의 Password(**key**)와 세션 변수 'chall4' 값이 같으면 해결된다고 한다. 그리고 패스워드 위 암호화 된 것은 **$hash**임을 소스코드를 보면 알 수 있다.

`$hash`는 10,000,000과 99,999,999의 랜덤 값에 "salt_for_you"를 붙인 String 값으로 500번의 SHA1 암호화 방식을 거친 것이 최종적인 `$hash($_SESSION['chall4'])`가 된다.

**초기 $hash 값을 500번 SHA 암호화한 값이 $_SESSION['chall4']이 될 것이다.**

SHA1 암호화는 단방향 암호화이지만, 복호화가 가능한 것으로 알려져 있다. 하지만, 500번의 복호화 과정을 거치면 나오는 것이겠지만 위에서 준 소스코드를 보면 암호화를 위한 초기값이 무엇인지를 말해준 것으로 보아 모든 조합 즉, 레인보우 테이블을 작성하라는 것으로 보인다.

하지만, 9천만개의 테이블을 모두 만드는 것은 너무나도 오래걸려서 도중에 취소하고 현재까지 구성된 테이블의 값이 페이지에 있는지를 수작업으로 새로고침하면서 찾아봤다.

또한, 저 긴 해시 값을 전부 넣는 것은 용량을 너무 많이 차지할 것으로 예상되어서 앞에서 부터 8글자만 넣는 것으로 했다.

```python
import hashlib
from multiprocessing import Process, Queue

default = '1f67b9dd7d04365512a7884d772af794fc46062b'

def search(start, end, result):
    with open('./hashtable', 'w') as f:
        for i in range(start, end):
            passwd = str(i) + 'salt_for_you'
            for j in range(500):
                passwd = hashlib.sha1(passwd.encode()).hexdigest()
            if passwd == default:
                print('FIND FLAG : ' + str(i) + 'salt_for_you')
                break
            dict_hash = {str(i)+'salt_for_you' : passwd[:8]}
            f.write(str(dict_hash)+'\n')

if __name__ == '__main__':
    START, END = 10000000, 100000000
    result = Queue()
    thd1 = Process(target = search, args = (START, END // 2, result))
    thd2 = Process(target = search, args = (END // 2, END, result))

    thd1.start()
    thd2.start()
    thd1.join()
    thd2.join()
```

저는 맨처음에는 멀티프로세스를 사용하지 않고 단일로 사용했지만, 찾아보니 멀티프로세스를 활용해서 시간을 단축하는 방법이 있어서 [참고](https://blog.limelee.xyz/entry/Webhackingkrold-4%EB%B2%88)한 링크를 돌려드립니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/185779343-5f33ee8b-df0f-462e-82e2-83290f8c1195.jpg" width = 420>
</p>

해당 값을 입력하면 아래처럼 문제를 풀었다고 알려줍니다!

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/185779324-b1871155-76fe-4f90-be21-98bee354a92c.jpg" width = 420>
</p>