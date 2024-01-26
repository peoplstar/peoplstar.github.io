---
layout: post
title: iOS DVIA-v2 | Excessive Permissions
subtitle: 불필요한 권한 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/cf4ffb0d-63fd-4166-9911-4b7706d553ee">
</p>

**불필요한 권한 취약점**이란 앱에서 사용하지도 않는 불필요한 권한 사용 시 이를 통한 피해 사례가 발생할 수 있기에 과도한 권한 사용을 지양하는 것이다. 정상적인 앱뿐만 아니라 악성 앱도 이러한 스마트폰 기능에 접근할 수 있기 때문이다. 

가령 악성 앱에 카메라 기능을 허용한다면 사용자의 사생활을 감시하는 용도로 쓰일 수 있고, 주소록 접근 권한을 허용한다면 이를 탈취해 지인을 가장한 보이스피싱이나 스미싱에 악용될 수도 있다. 이 때문에 **사용자는 앱 설치 시 각 앱이 적절한 권한을 요구하는지 확인하고, 지나치게 많은 권한을 요구한다면 해당 앱을 사용하지 않는 것이 좋다.**

간단한 예를 들면 웹툰 감상을 위해 설치한 앱이 별다른 설명 없이 위치정보나 생체정보(지문, 홍채 등)를 요구한다면 이를 의심해봐야 한다. 실제로 과거 기승을 부렸던 ‘몸캠피싱’이 이러한 접근 권한을 악용한 사례 중 하나다. 

몸캠피싱은 해커가 피해자에게 음란한 화상채팅을 할 것처럼 속여 개인정보 탈취 기능이 있는 악성 앱을 설치하도록 유도하는 것에서 시작한다. 이를 설치할 경우 해커는 피해자 지인의 연락처를 확보하고, 피해자의 치부를 지인에게 알리겠다고 협박한다. 만약 사용자가 악성 앱에 주소록 접근 권한 등을 허용하지 않았다면 일어나지 않을 보안사고다.

## Permission List

* `Bluetooth`

<div align='center'>

|항목|내용|
| :--:   | :--:  |
|  **NSBluetoothAlwaysUsageDescription**  |   앱이 블루투스에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |

 

* `Calendar and reminders`

<div align='center'>

| 항목 | 내용 |
| :--:   | :--:  |
|  **NSCalendarsFullAccessUsageDescription**  |   앱에서 캘린더 데이터 읽기 및 쓰기 액세스 권한을 요청하는 이유를 알려주는 메시지 |
| **NSCalendarsWriteOnlyAccessUsageDescription** | 앱에서 캘린더 이벤트 생성을 위한 액세스 권한을 요청하는 이유를 알려주는 메시지 |
| **NSRemindersFullAccessUsageDescription** | 앱에서 미리 알림 데이터를 읽고 쓰기 위한 액세스 권한을 요청하는 이유를 알려주는 메시지 |

 

* `Camera and Microphone`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSCameraUsageDescription**  |   앱이 디바이스의 카메라에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |
| **NSMicrophoneUsageDescription** | 앱이 디바이스의 마이크에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |

 

 

* `Contacts`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSContactsUsageDescription**  |   앱이 사용자의 연락처에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |

 

* `Face ID`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSFaceIDUsageDescription**  |   앱에서 Face ID로 인증 기능을 요청하는 이유를 사용자에게 알려주는 메시지 |

 

* `Files and folders`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSDesktopFolderUsageDescription**  |   앱이 사용자의 데스크톱 폴더에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |
| **NSDocumentsFolderUsageDescription** | 앱이 사용자의 문서 폴더에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |
| **NSDownloadsFolderUsageDescription** | 앱이 사용자의 다운로드 폴더에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |
| **NSNetworkVolumesUsageDescription** | 앱이 네트워크 볼륨의 파일에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |
| **NSRemovableVolumesUsageDescription** | 앱이 이동식 볼륨의 파일에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |
| **NSFileProviderDomainUsageDescription** | 앱이 파일 제공업체가 관리하는 파일에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |

 

* `Game center`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSGKFriendListUsageDescription**  |   앱이 게임 센터 친구 목록에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |

 

* `Health`

<div align='center'>

|항목|내용|
| :--:   | :--:  |
|  **NSHealthClinicalHealthRecordsShareUsageDescription**  | 앱에서 임상 기록 읽기 권한을 요청한 이유를 설명하는 사용자에게 보내는 메시지 |
| **NSHealthShareUsageDescription** | 앱이 HealthKit 스토어에서 샘플을 읽을 수 있는 권한을 요청한 이유를 설명하는 사용자에게 보내는 메시지 |
| **NSHealthUpdateUsageDescription** | 앱이 HealthKit 스토어에 샘플을 저장할 수 있는 권한을 요청한 이유를 설명하는 사용자에게 보내는 메시지 |
| **NSHealthRequiredReadAuthorizationTypeIdentifiers** | 앱이 읽기 권한을 얻어야 하는 임상 기록 데이터 유형 |

 

* `Home`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
|  **NSHomeKitUsageDescription**  | 앱이 사용자의 홈키트 구성 데이터에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |

 

* `Location`

<div align='center'>

| 항목 | 내용 |
| :--:   | :--:  |
|  **NSLocationAlwaysAndWhenInUseUsageDescription**  | 앱이 항상 사용자의 위치 정보에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |
| **NSLocationUsageDescription** | 앱이 사용자의 위치 정보에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |
| **NSLocationWhenInUseUsageDescription** | 앱이 포그라운드에서 실행되는 동안 앱이 사용자의 위치 정보에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |
| **NSLocationTemporaryUsageDescriptionDictionary** | 앱이 사용자 위치에 대한 임시 액세스를 요청하는 이유를 설명하는 메시지 |
| **NSWidgetWantsLocation** | 위젯이 사용자의 위치 정보를 사용하는지 여부를 나타내는 Boolean 값 |
| **NSLocationDefaultAccuracyReduced** | 앱이 기본적으로 위치 정확도 감소를 요청할지 여부를 나타내는 Boolean 값 |

 

* `Game center`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
| **NSGKFriendListUsageDescription** | 앱이 게임 센터 친구 목록에 액세스해야 하는 이유를 사용자에게 알려주는 메시지 |

 

* `MediaPlayer`

<div align='center'>

| 항목 |  내용 |
| :--:   | :--:  |
| **NSAppleMusicUsageDescription** | 앱이 사용자의 미디어 라이브러리에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |

 

* `Motion`

<div align='center'>

| 항목 | 내용 |
| :--:   | :--:  |
| **NSMotionUsageDescription** | 앱이 디바이스의 모션 데이터에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지 |
| **NSFallDetectionUsageDescription** | 낙상 감지 이벤트 데이터에 대한 앱의 액세스 권한 요청을 설명하는 사용자에게 보내는 메시지 |

 

이를 제외한 Networking, NFC, Photos, Scripting, Security, Sensors, Siri 등이 있으니 하단 [References](#reference)를 참고하면 되겠습니다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Excessive Permissions**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/56c2b250-016a-49e9-995e-b304f5e36b62" width = 450>
</p>

`CAMERA PERMISSION`을 클릭하는 경우 해당 앱에서 카메라 접근을 허용할 것인지에 대한 Alert가 발생하게 되고 허용하게 되면 아래의 뷰로 넘어가게 된다.

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/bcb2227c-a8a2-4876-bf50-fa1998b7b027" width = 450>
</p>

이 처럼 앱의 권한을 허용하는 것만으로 카메라를 이용한 사진 촬영이 가능하며 이는 추가 작업으로 사진을 공격자에게 전송하여 화제가 된 몸캠피싱의 피해가 발생할 수도 있다.

```zsh
iPhone:~ root# ps -ef | grep /var
  501 21317 1 0 25Nov23 ??      0:00.00 /private/var/containers/Bundle/Application/8411C0F6-C6FD-4E28-B433-9AE9DBB942E7/Maps.app/PlugIns...
  501 26740 1 0 Tue10AM ??      0:00.00 /private/var/containers/Bundle/Application/6992157D-46FC-40D8-857A-18296FA8C989/TestFlight.app/F...
  501 33953 1 0 10:40AM ??      0:06.35 /var/containers/Bundle/Application/EF3E1F84-4D8C-4315-8DCF-D89A055E77EC/DVIA-v2.app/DVIA-v2
   0  34044 1 0 10:46AM ttys001 0:00.00 grep /var
```

`ps -ef | grep /var`를 통해 현재 실행 중인 앱의 위치를 파악하여 권한 관련 Plist 파일을 확인해본다.(`/var/containers/Bundle/Application/EF3E1F84-4D8C-4315-8DCF-D89A055E77EC/DVIA-v2.app/`)

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/b4161bc5-5b04-44c5-aedf-791cf12699ef">
</p>

`WinSCP` 프로그램을 통해 해당 경로로 이동한 결과 `Info.plist`파일이 존재하였고 이를 확인해보면

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/a80a6c9c-3984-4e77-8bd2-dd7a37869c06">
</p>

 앱이 디바이스의 카메라에 대한 액세스를 요청하는 이유를 사용자에게 알려주는 메시지인 **NSCameraUsageDescription**의 권한 할당이 되어 있는 것을 확인할 수 있다.

## 대응 방안

* 해당 앱에서 반드시 필요한 권한인지 확인 후 불필요하거나 과도한 권한일 경우 삭제

* 구글 플레이나 원스토어 등 정상적인 앱 장터 이외의 경로에서 내려받은 APK 파일은 설치하지 않는 것을 지양

## Reference

* [https://m.boannews.com/html/detail.html?idx=91609](https://m.boannews.com/html/detail.html?idx=91609)

* [https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources](https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources)