---
layout: post
title: iOS DVIA-v2 | Side Channel Data Leakage (Screen Shot)
subtitle: 백그라운드 스냅샷 취약점
categories: iOS
tags: [iOS, Moblie]
---

## 취약점 개요

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/0ee28872-faff-43cf-863e-49e4bc3026ea">
</p>

**부채널 데이터 유출**은 사용되는 어플리케이션의 주 기능이 아닌 타 기능을 통해 데이터가 유출되는 취약점을 말한다. 의도하지 않은 데이터 유출은 개발자가 실수로 모바일 디바이스의 다른 앱이 쉽게 액세스할 수 있는 위치에 민감한 정보나 데이터를 저장할 때 발생한다. 

개발자의 코드가 사용자 또는 백엔드에서 제공한 민감한 정보를 처리할 때 이 과정에서 개발자가 알지 못하는 부작용으로 인해 해당 정보가 모바일 디바이스의 안전하지 않은 위치에 배치되어 디바이스의 다른 앱이 공개적으로 액세스할 수 있게 된다. 일반적으로 이러한 부작용은 기본 모바일 디바이스의 운영 체제(OS)에서 발생하며 공격자는 간단한 코드를 작성하여 민감한 정보가 저장된 위치에 액세스할 수 있다.

## 취약점 실습

* **실습 환경 : iOS 14.6, iPhone 8**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/210b2789-38c1-43b7-bbd8-6c9fb23d3396">
</p>

* **좌측 상단 메뉴 > Side Channel Data Leakage > App Screenshot**

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/aa711052-4ed9-479b-a449-5a6f9c2fbf94">
</p>

**This Security Question**에 중요정보라 가정한 임의의 문자를 입력하고 백그라운드로 돌릴 시 중요정보가 그대로 노출되고 있는 것을 알 수 있다.

iOS의 경우 백그라운드로 진입 시 해당 화면에 대한 스크린샷을 저장하여 해당 사진을 보여주게 된다. 즉 이 스냅샷 파일이 임시로 저장되고 해당 파일을 보여주게 되는데 저장 경로는 아래와 같다.

### Snapshot Path

`/var/mobile/Conatiners/Data/Application/[BundleID]/Library/SplashBoard/Snapshots/sceneID:[PackageName]-default/`

**[iOS 8 미만]**

- `/var/mobile/Application/[BundleID]/Library/Caches/Snapshots/[PackageName]/`

**[iOS 8 이상 13 미만]**

- `/var/mobile/Containers/Data/Application/[BundleID]/Library/Caches/Snapshots/[PackageName]/`

**[iOS 13 이상]**

- `/var/mobile/Conatiners/Data/Application/[BundleID]/Library/SplashBoard/Snapshots/sceneID:[PackageName]-default/`

<p align="center">
<img src ="https://github.com/peoplstar/peoplstar.github.io/assets/78135526/773c00e0-f8f0-40dc-93f1-a8ed7f2cd2cb" width = 450>
</p>

`Filza` 어플리케이션을 이용하여 직접 해당 경로로 이동하여 파일을 확인해보면 백그라운드에 대한 이미지 파일이 저장되어 있는 것을 알 수 있다.

해당 단말기에 피해자 몰래 원격이 되어 있거나 파일 접근 권한이 있는 경우 백그라운드 이미지를 통해 중요정보를 탈취할 수 있기에 아래의 대응 방안으로 정보 노출을 못 하게 대응해야한다.

## 대응 방안

어플리케이션을 백그라운드로 넘길 때 해당 View에서 중요한 정보를 담고 있다면 다른 View로 중요 정보를 가려야한다.

* `sceneDidBecomeActive` : 액티브 상태가 됐을 경우

* `sceneWillResignActive` : App Switcher 모드(홈 바 쓸어 올렸을 경우 또는 홈 버튼 모델 홈 버튼 두번 눌렀을 경우)

* `sceneWillEnterForeground` : 백그라운드 상태였다가 돌아왔을 경우

* `sceneDidEnterBackground` : 백그라운드 상태로 갔을 경우

**※ iOS13 미만의 경우 AppDelegate.swift에서 작업**

* `applicationDidBecomeActive`

* `applicationWillResignActive`

* `applicationWillEnterForeground`

* `applicationDidEnterBackground`

```swift
func callBackgroundImage(_ bShow: Bool) {
    
    let TAG_BG_IMG = -101

    let backgroundView = window?.rootViewController?.view.window?.viewWithTag(TAG_BG_IMG)

    if bShow {

        if backgroundView == nil {

            //Create View
            let bgView = UIView()
            bgView.frame = UIScreen.main.bounds
            bgView.tag = TAG_BG_IMG
            bgView.backgroundColor = .black

            let lbl = UILabel()
            lbl.frame = UIScreen.main.bounds
            lbl.textAlignment = .center
            lbl.font = UIFont.systemFont(ofSize: 30)
            lbl.textColor = .white
            lbl.numberOfLines = 0
            lbl.text = "Hide Imformation"
            bgView.addSubview(lbl)

            window?.rootViewController?.view.window?.addSubview(bgView)
        }
    } else {

        if let backgroundView = backgroundView {
            backgroundView.removeFromSuperview()
        }
    }
}

func sceneDidBecomeActive(_ scene: UIScene) {
    print("SceneDelegate - sceneDidBecomeActive 켜지기 전 2 (App Switcher 모드 였다가 돌아올 때)")
    callBackgroundImage(false)
}

func sceneWillResignActive(_ scene: UIScene) {
    print("SceneDelegate - sceneWillResignActive - 쓸어 올렸을 때, App Switcher 모드")
    callBackgroundImage(true)
}

func sceneWillEnterForeground(_ scene: UIScene) {
    print("SceneDelegate - sceneWillEnterForeground - 켜지기 전 1 (완전 백그라운드로 갔다 다시 돌아올 때) 백그라운드로 갔다가 바로 오면 여기 안탐. 백그라운드 1초 있다가 켜야 여기 탐")
    callBackgroundImage(false)
}

func sceneDidEnterBackground(_ scene: UIScene) {
    print("SceneDelegate - sceneDidEnterBackground - 백그라운드로 갔을 때, 홈 눌렀을 때")
    callBackgroundImage(true)
}
```

## Reference

* [https://gonslab.tistory.com/49](https://gonslab.tistory.com/49)