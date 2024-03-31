---
layout: post
title: Dreamhack | Image Storage
subtitle: Dreamhack Image Storage
categories: dreamhack.io
tags: [Pentest, Web]
---

**본 문제는 Dreamhack을 통해서 풀어 보실 수 있습니다.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 내용

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215260166-1268129d-0c30-417a-bcf3-4dcb99269e98.png" width = 500> 
</p>

해당 커리큘럼은 **File Vulnerability**으로 파일을 업로드하거나 다운로드할 때 발생되는 취약점에 대해서 나옵니다.

## 문제 풀이

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215260566-2ba7920c-fe75-47c0-b721-a5acf78b7f76.png" width = 360> 
</p>

메인 페이지는 이미지를 업로드하고 이미지 파일을 공유해보라는 글만 존재한다.

일단 업로드가 가능하다는 것에서 웹 쉘을 업로드하여 플래그를 읽으면 될 것으로 예상된다.

### UPLOAD PAGE

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215262157-444e8e9e-8616-4fc3-a4f3-76a5eb30a05b.png" width = 360> 
</p>

파일을 받아와 업로드가 가능하다. 현재는 확장자 `jpg`인 이미지 파일을 업로드하였을 때 `./uploads/` 경로에 업로드되는 것을 알 수 있다.

테스트용으로 `php` 확장자 파일을 업로드했을 때 확장자 필터링을 하지 않아 쉽게 올릴 수 있을 것으로 보인다.

```php
<?php
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES)) {
      $directory = './uploads/';
      $file = $_FILES["file"];
      $error = $file["error"];
      $name = $file["name"];
      $tmp_name = $file["tmp_name"];
     
      if ( $error > 0 ) {
        echo "Error: " . $error . "<br>";
      }else {
        if (file_exists($directory . $name)) {
          echo $name . " already exists. ";
        }else {
          if(move_uploaded_file($tmp_name, $directory . $name)){
            echo "Stored in: " . $directory . $name;
          }
        }
      }
    }else {
        echo "Error !";
    }
    die();
  }
?>
```

소스 파일을 보면 이미 존재하는지만 검사하기에 쉽게 업로드가 가능하다.

### LIST PAGE

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215262329-de16112a-feae-4251-9764-bd5bdd2f32d5.png" width = 360> 
</p>

URL은 `list.php`로 되어 있고 들어가면 우리가 업로드한 이미지 파일이 있다.

해당 소스를 확인해보면 디렉토리는 현재에서 `uploads/` 이며, 해당 디렉토리를 조회할 때 `.., ., index.html`가 해당 하는 것은 제외하고 목록을 보여주는 것으로 되어있다.

```php
<?php
    $directory = './uploads/';
    $scanned_directory = array_diff(scandir($directory), array('..', '.', 'index.html'));
    foreach ($scanned_directory as $key => $value) {
        echo "<li><a href='{$directory}{$value}'>".$value."</a></li><br/>";
    }
?> 
```

### 익스플로잇

**Window Defender** 때문에 코드를 올리지는 못한다. `system($_GET['cmd'])`; 를 php 태그로 감싸고 업로드 이후 GET 메소드를 통해 명령어를 전달하면 아래처럼 웹 쉘이 제대로 적용된 것이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/215262934-4e1e33ed-e877-4ea7-8feb-6ae8379e8fff.png" width = 460> 
</p>

이와 같은 방식으로 `/flag.txt`를 불러오면 FLAG를 찾을 수 있을 것이다.