# -*- coding: utf-8 -*-

# Python 3.4
# author: http://blog.dokenzy.com/
# date: 2015. 4. 8

# References
# http://www.imcore.net/encrypt-decrypt-aes256-c-objective-ios-iphone-ipad-php-java-android-perl-javascript/
# http://stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
# http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
# http://www.di-mgt.com.au/cryptopad.html
# https://github.com/dlitz/pycrypto

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
def unpad(s): return s[:-ord(s[len(s)-1:])]


def iv():
    """
    The initialization vector to use for encryption or decryption.
    It is ignored for MODE_ECB and MODE_CTR.
    """
    return chr(0) * 16


class AESCipher(object):
    """
    https://github.com/dlitz/pycrypto
    """

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        #self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, message):
        """
        It is assumed that you use Python 3.0+
        , so plaintext's type must be str type(== unicode).
        """
        message = message.encode()
        raw = pad(message)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        dec = cipher.decrypt(enc)
        return unpad(dec).decode('utf-8')


if __name__ == "__main__":
    key = (
        b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00")
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    message = '123456'
    _enc = 'peRMxuWD5nRijMGjlN7yiQ=='

    enc = AESCipher(key, iv).encrypt(message)
    dec = AESCipher(key, iv).decrypt(_enc)
    print(enc)
    print(_enc == enc)
    print(message == dec)
