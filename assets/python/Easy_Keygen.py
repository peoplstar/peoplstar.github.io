xor_value = [0x10, 0x20, 0x30]
serial = "5B134977135E7D13"
index = j = 0

for i in range(int((len(serial))/2)):
    print(bytes.fromhex((hex(int(serial[index:index+2], 16) ^ xor_value[j])).split("0x")[1]).decode('utf-8'), end = ' ')
    index += 2
    j += 1
    if j > 2:
        j = 0