---
layout: post
title: TUCTF | Shell Maze
subtitle: 2022 TUCTF
categories: CTF
tags: [Programming]
---

**TUCTF is a jeopardy-style Capture the Flag (CTF) competition designed for all ranges of experience.**


**A jeopardy-style CTF is a CTF where you earn your team points for solving a challenge that's listed under a specific category with a specific point value.**

**The end goal of each challenge is usually to get a string of text called a flag that's usually in flag format.** 

**Our flag format looks something like this: TUCTF{3x4mpl3_fl4g}.**

**해답을 이해하며 생각을 해보면서 풀이 해보시길 바랍니다.**

## 문제 분석

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205563459-1cef5df8-9dd8-44c5-b118-29fff3325705.png" width = 400>
</p>

미로 전문가도 해당 미로를 탈출 할 수 없다고 하는데 결국 미로찾기에 대한 문제이다.

접속하여 보면 아래와 같다.

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205564123-e641b526-6332-4635-b1a9-f197fb0e1e96.png" width = 440>
</p>

현재의 위치는 `X`로 표기가 되고 갈 수 있는 길을 `O`로 되어 있는 것을 알 수 있다.

움직이는 방법으로는 `<, >, V` 세 가지 방법으로 움직일 수 있다.

* 현재 위치에서 바로 아래가 `O` 이라면 **Down**

* 무조건 그 다음 행을 보고 움직이는 것을 선택

```python
from pwn import *

p = remote('chals.tuctf.com', 30204)
ii = p.sendlineafter

x = 0
y = 0
# .rstrip(b'\n')

def move(j, next):
    global y
    for _ in range(j):
        if next == '>':
            y += 1
        if next == '<':
            y -= 1
        ii(': ', str(next))

def down(next):
    ii(': ', str(next))
    global x
    x += 1

def skip():
    p.recvuntil(b"Controls: `<` to move left, '>' to move right, and 'V' to move down.\n")

def maze_solve():
    global x
    global y

    while True:
        text = ''
        text = (p.recvuntil('M')).decode('utf-8')

        tmp = text.split('\n')
        row = 0
        x = 0
        y = 0

        while True:
            if 'M' in tmp[row] or 'ove:' in tmp[row]:
                break

            else:
                row += 1                    
                continue
        
        while x != row - 1:
            print(f'x = {x}, row = {row}')

            if x == row:
                if tmp[x][0] == 'O':
                    move(y, str('<'))
                else:
                    move(len(tmp[x]) - y, str('>'))

            elif 'O' == tmp[x+1][y]:
                down(str('V'))
            
            elif y < (tmp[x+1].find('O')):
                next_column = (tmp[x+1].find('O'))         
                move(next_column - y, str('>'))
                # print('right move')

            elif y > (tmp[x+1].find('O')):
                next_column = (tmp[x+1].rfind('O'))
                move(y - next_column, str('<'))
                # print('left move')

            try:
                not tmp[x+1]
            except IndexError:
                break

        next_column = (tmp[x].rfind('O'))         
        move(next_column - y, str('>'))
        # print('right move')

        if (x == (row - 1)) and (row == 60):
            print(p.recvuntil('\n'))
            p.interactive()
        else:
            p.recvuntil('Loading next level...\n\n')

    p.interactive()
    

if __name__ == '__main__':
    skip()
    maze_solve()
```

<p align="center">
<img src ="https://user-images.githubusercontent.com/78135526/205564693-de149e49-69e1-445c-b4f6-9893946bdd60.png" width = 400>
</p>