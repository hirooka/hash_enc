import time
import random
import string
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def genetate_random_string(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k = n))

def hash(data, count):
    begin = time.perf_counter()
    for i in range(count):
        hash = hashlib.sha256(data).hexdigest()
    end = time.perf_counter()
    print('  Hash(SHA-256):    {}[ms]'.format((end - begin) * 1_000))

def decrypt(data, count):
    key = get_random_bytes(32)
    encrypter = AES.new(key, AES.MODE_EAX)
    nonce = encrypter.nonce
    encrypted, tag = encrypter.encrypt_and_digest(data)

    decrypter = AES.new(key, AES.MODE_EAX, nonce = nonce)
    begin = time.perf_counter()
    for i in range(count):
        decrypted = decrypter.decrypt(encrypted)
    end = time.perf_counter()
    print('  Decrypt(AES-256): {}[ms]'.format((end - begin) * 1_000))

def main():
    count = 1
    length = 100_000_000
    json = """\
{
    "id": 123456789,
    "addr": "02c2357f-d55d-4a9d-b52f-bd0c54fdd010",
    "addition": "あいうえお"

}"""
    data = json.encode('UTF-8')
    
    list = [100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000]
    for i in list:
        print('{} string, {} times calculation'.format('{:,}'.format(i), '{:,}'.format(count)))
        hash(genetate_random_string(i).encode('UTF-8'), count)
        decrypt(genetate_random_string(i).encode('UTF-8'), count)

if __name__ == '__main__':
    main()
