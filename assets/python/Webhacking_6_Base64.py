import base64

def replace_encode(str):
    str = str.replace("1", "!")
    str = str.replace("2", "@")
    str = str.replace("3", "$")
    str = str.replace("4", "^")
    str = str.replace("5", "&")
    str = str.replace("6", "*")
    str = str.replace("7", "(")
    str = str.replace("8", ")")
    return str

def replace_decode(str):
    str = str.replace("!", "1")
    str = str.replace("@", "2")
    str = str.replace("$", "3")
    str = str.replace("^", "4")
    str = str.replace("&", "5")
    str = str.replace("*", "6")
    str = str.replace("(", "7")
    str = str.replace(")", "8")
    return str

def account_encode(account):
    account = account.encode('utf-8')

    for i in range(20):
        account = base64.b64encode(account)

    account = account.decode('utf-8')
    account = replace_encode(account)
    return account

def account_decode(account):
    account = replace_decode(account)
    account = account.encode('utf-8')

    for i in range(20):
        account = base64.b64decode(account)

    account = account.decode('utf-8')
    return account

ID = "admin"
PW = "nimda"

id_encode = account_encode(ID)
pw_encode = account_encode(PW)
id_decode = account_decode(id_encode)
pw_decode = account_decode(pw_encode)
print('-------------------------[ID Encode]--------------------------')
print(id_encode)
print('-------------------------[ID Decode]--------------------------')
print(id_decode)
print('------------------------[PW Encode]---------------------------')
print(pw_encode)
print('------------------------[PW Decode]---------------------------')
print(pw_decode)
