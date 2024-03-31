---
layout: post
title: Dreamhack | File Download 1
subtitle: Dreamhack File Download 1
categories: Web
tags: [Pentest, Web]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215312594-288ba997-07d5-488f-bec3-eba4c9221aad.png" width = 500> 
</p>

해당 커리큘럼은 **File Vulnerability**으로 파일을 업로드하거나 다운로드할 때 발생되는 취약점에 대해서 나옵니다.

문제에서 다운로드 취약점임을 밝혔고 `flag.py` 파일을 다운로드 받으면 FLAG를 알 수 있다고 했습니다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215312644-b08d34ed-07b1-4f16-b9dc-7ea4bf230ca9.png" width = 360> 
</p>

우리의 메모를 업로드 하라고 했습니다. **Upload My Memo**를 통해 업로드 하면 어떠한 일이 벌어지는지 확인해보겠습니다.

### UPLOAD PAGE

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215312732-2e1b3c98-41bf-4966-8fb4-981c073cc3f4.png" width = 360> 
</p>

파일명을 `hello`라 하고 안에 내용을 **test**라 했을 때 아무 이상없이 우리의 메모가 업로드되는 것을 알 수 있습니다.

이후 루트 URL로 접근하게 되면 우리가 입력한 파일명이 보이고 접근하면 우리가 입력한 Content를 볼 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215312799-eab654cb-db44-4a64-b9e4-abdd659fdc62.png" width = 360> 
</p>

### app.py

제공해주는 `app.py` 파일을 살펴보면 우리 업로드할 파일을 클릭 했을 때 나타나는 `/read` 접근이 있다는 것을 알 수 있다.

```python
@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)
```

GET 메소드를 통해 매개변수 `name`을 통해 받은 것이 `filename`인 것을 알 수 있다.

결국, 우리가 업로드 했던 메모 파일을 다운로드 받으면서 값을 불러오는 것을 알 수 있으므로, 다운로드 받을 때 파일명을 달리 하면 FLAG를 받아 올 수 있을 것으로 보인다.

`flag.py`를 읽어 오라 했기에 `http://host3.dreamhack.games:23362/read?name=flag.py` 처럼 입력을 하면 **flag.py does not exist. :(** 존재하지 않다고 나온다.

어떠한 필터링도 없고 `flag.py`의 경로가 어딘지 모르기에 `../`를 붙여 상위 디렉토리 이동으로 확인해보고자 한다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215313610-2a6601b4-9e16-4b61-b498-5fab2c50bfcf.png" width = 360> 
</p>

이렇게 해서 다운로드 취약점을 이용한 FLAG를 읽을 수 있었다.