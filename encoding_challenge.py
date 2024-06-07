import pwn
from Crypto.Util.number import long_to_bytes
import json
import base64
import codecs
import sys


def json_recv():
    line = r.recvline()
    return json.loads(line.decode())


def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


def decrypts(encryption, ciphertext):
    if encryption == 'base64':
        plaintext = base64.b64decode(ciphertext.encode()).decode('utf-8')
    elif encryption == 'hex':
        plaintext = bytes.fromhex(ciphertext).decode('utf-8')
    elif encryption == 'rot13':
        plaintext = codecs.decode(ciphertext, 'rot13')
    elif encryption == 'bigint':
        plaintext = long_to_bytes(int(str(ciphertext), 16)).decode()
    elif encryption == 'utf-8':
        plaintext = ''.join([chr(word) for word in ciphertext])
    return plaintext


r = pwn.remote('socket.cryptohack.org', 13377, level='debug')
while True:
    received = json_recv()
    if 'flag' in received:
        print(received)
        sys.exit()

    to_send = {
        "decoded": decrypts(received['type'], received['encoded'])
    }
    json_send(to_send)
