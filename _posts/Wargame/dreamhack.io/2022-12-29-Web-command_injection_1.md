---
layout: post
title: Dreamhack | Command Injection 1
subtitle: Dreamhack Command Injection 1
categories: dreamhack.io
tags: [Pentest, Web]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209776185-0eb21102-fb06-4ad8-9a66-c24cd0320bbb.png" width = 500> 
</p>

해당 커리큘럼은 **Command Injection**으로 기존 제공하는 서비스에 임의의 Command를 삽입하는 공격이다.


## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209776737-bc485d56-6596-46be-9143-8f56ff91f005.png" width = 360> 
</p>

처음 접속했을 때의 화면으로 **Welcome this is ping playground!**를 출력하며 육안으로 들어갈 수 있는 곳은 `Ping` 하나로 보인다. 해당 페이지로 이동해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209776878-a8612807-d52a-4196-ac71-5fb2689bad6d.png" width = 360> 
</p>

Host 입력란이 나오고 Ping을 보낼 수 있을 것으로 보인다. Hint로 되어 있는 8.8.8.8으로 Ping을 보내보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209776988-d01e8801-49db-4f2e-8276-3b348bd33e56.png" width = 360> 
</p>

```python
@APP.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 "{host}"'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')
```

우리가 입력한 Host에 `ping -c 3 "host"`와 같은 방식으로 ping을 보내는 것을 알 수 있다.

`;` 명령 구분자를 이용하여 추가로 명렁어를 삽입하겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209780325-073bc038-329b-433c-ad85-2a9b4ac63fce.png" width = 360> 
</p>

하지만, `;` 문자를 넣으면 아래와 같은 경고문자가 출력된다. 이에 해당 경고문은 Client-Side라 생각하고, 개발자 도구를 통해 해당 form에 있는 `pattern="[A-Za-z0-9.]{5,20}"` 패턴 탐지를 지우고 값을 대입하여 필터링을 우회하도록 합니다.

필터링 역할을 하는 pattern을 **8.8.8.8; ls** 대입하면 아래의 문구가 나온다.

```
an error occurred while executing the command. -> ping -c 3 "8.8.8.8;ls"
```

자세히 보면 `"` 더블 쿼테이션 정상적이지 않다.

```python
cmd = f'ping -c 3 "{host}"'
```

코드에서도 입력 값을 더블 쿼테이션으로 묶고 있기 때문에 이를 활용해서 값을 넣으면 된다. **8.8.8.8";ls "** 대입하면 아래와 같은 결과가 나온다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209781690-4eae687c-0f89-4528-9d25-39306562b0ec.png" width = 360> 
</p>

이렇게 `ls` 명령어까지 되는 것을 확인했고, FLAG는 `flag.py`내에 있다고 하니 확인해보겠습니다.

`8.8.8.8";"cat flay.py` 했을 때 계속 에러가 발생했기에 전체 문자열 필터링이거나, 공백 필터링이 있을 거라 예상했다.

생각해보니 `cat`는 명령어로써 더블 쿼테이션으로 묶으면 문자열로 인식하기에 문제가 생겼을 것으로 예상했기에 `8.8.8.8";cat "flag.py`로 전송하니 해결되었다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/209784715-1daf8778-ce87-4d54-bb93-b4d13478091e.png" width = 360> 
</p>