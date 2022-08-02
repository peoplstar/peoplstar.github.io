---
layout: post
title: Theory | TTPs
subtitle: TTPs이란 무엇일까?
categories: Theory
tags: [Theory, Pentest]
---

## TTPs

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182317711-492f0678-5d34-453e-87a1-058918ffbeee.png" width = 450>
</p>

TTPs는 전술(Tactics), 기술(Techniques), 절차(Procedures)의 약어로 정수 값이나 스트링 값으로 편할할 수 없는 위협원들의 행위 자체를 의미한다.

이게 무슨 소리냐 하면, 보안 전문가들이 위협 행위자들의 공격을 행동, 프로세스, 전량 등을 분석 및 설명하는데 사용하며, 대응책 개발에 활용하는 것이다.(정보보호 컨설팅에서는 이 TTPs를 접목하여 보다 현실적인 위험 대응방안 수립이 가능한다.)

**모의해킹을 공부할 때 기술을 보이는 대로 마구잡이로 공부하는 것이 아니라, TTPs를 기반으로 공부하는 것이 좋다.**

### TTPs 목록

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182318739-752ba6aa-28b8-4bb1-98a3-4f9e379d8981.png" width = 650>
</p>

[MITRE](https://attack.mitre.org/matrices/enterprise/#)에 접속하면 실제 TTPs의 목록들을 확인할 수 있습니다.

Matrix For Enterprise(22/05/02 기준)으로 전략(Tactics) 14개, 전술(Techniques) 222개가 존재한다.

### TTPs 화제

TTPs 전략 전술은 약 3년전부터 주목받기 시작했고, 우리나라 또한 현 시점에서 크게 관심사로 두고 있다. 그렇다면 왜 주목을 받게 되었는가?

IoC(Indicator of compromise, 악성 IP나 악성 도메인 등 단순지표) 기반의 방어체계는 매우 유용하지만, 공격자는 단순 지표와 관련된 공격 인프라를 쉽게 확보하고 버린다.

공격자가 구체적으로 공격을 어떻게 할지는 매번 변한다. 하지만, TTP를 쉽게 확보하거나 버릴수 없다. 타깃이 정해진 공격자는 타깃의 방어 환경을 무력화하기 위해 많은 시간을 들여서 TTP를 학습하고 연습하기에 확보된 TTP를 지속 활용할 수 있는 대상들이 새로운 타깃이 된다.

**공격자의 TTP는 언제나 벙어 환경의 특성과 맞물려 있다. 즉, 공격자가 쉽게 포기 할 수 없는 전략을 역이용하여 방어한다는 셈이다.**

**각각에 있는 공격에 대한 전술과 전략을 확인하자 주 목적, 모든 공격을 하기 위한 전략은 거의 변하질 않는다.**

DB를 탈취하기 위해서 이전에 해야 할 접근 및 침투에 대한 공격이 있다. 내부망을 침투하기 위한 **전략 Initial Access**중에서 **전술 Exploit Public-Facing Application(외부에 알려진 어플리케이션을 통한 침투)**를 사용한다.

### MITRE ATT&CK TTPs 예시

[MITRE](https://attack.mitre.org/matrices/enterprise/#)에 전략과 전술에 대한 개념과 관계가 시각화 되어 있다.

정보 수집은 **Reconnaissance**란으로, 향후 공격을 계획하는데 사용할 수 있는 정보를 수집하기 위한 정찰 활동이다. 해당 전략에는 Active Scanning이 있다. 그렇다면 반대 개념인 Passive Scanning도 있을텐데 이것은 다른 항목에 함께 있다. 두 개의 차이점을 보자.

#### Active & Passive

두 스캐닝에 대한 가장 큰 차이점이라면 **상대 피해자 시스템에서 로그가 남는가 남지 않는가**가 가장 큰 차이다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182383656-f0fdf178-2ea9-4976-890f-a6a4ffe60148.png" width = 550>
</p>

* Active
  * 예시
    * `whatweb –v [URL]`
    * 해당 도메인이 무엇을 사용하고 있는지 스캔한다. `-v` 옵션은 자세한 출력으로 해당 플러그인에 대한 설명이 포함합니다.
    * ex) PHP, Apache, WordPress 등 버전까지 기술

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/182391792-c88a9f0e-cf7b-4ef2-9b1a-2e99172c3189.png" width = 450>
</p>

* Passive
  * 예시
    * `fierce –dns [URL]`
      * DNS 서버를 통해 질의하기 때문에 직접적으로 로그를 남기지 않는 특징이 있다.
      * 해당 도메인이 어떠한 DNS를 사용하고 있는지에 대한 정보를 출력한다.
  * Passive Scanning이 없는 이유
    * [MITRE](https://attack.mitre.org/matrices/enterprise/#)에서 **Reconnaissance** 안에 **Gather Victim Network Information** 항목에서 Sub-techniques을 보면 **[T1590.002 - DNS]**가 있다.

### TTPs 관점

TTPs는 전략과 전술은 있지만, 어떠한 방식을 썼냐에 따라 달라진다. 한 전술을 사용함에 있어서 어떠한 방식을 추구하냐에 따라 달라진다.

예시를 들어보면 스케쥴링 서비스를 이용해서 악성코드를 올린다.

이것을 일정한 주기로 실행 시키는 목적이라면 **Persistence**

일정 주기가 아닌 몇시 몇분 몇초에 딱 한번 실행을 요구하는거라면 **Execution**

**즉, 이렇게 공격자가 행하고 하는 목표가 무엇인지에 따라 공격이 달라진다는 것이다.**