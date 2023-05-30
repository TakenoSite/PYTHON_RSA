import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from util import UTIL

# OAEPパディングの実装
def padding(message, key_length):
    # メッセージのハッシュ値を計算
    hash_func = hashlib.md5()
    hash_func.update(message)
    hash_value = hash_func.digest()
    
    
    padding_length = key_length - len(message) - len(hash_value) - 2
    print(len(hash_value))

    if padding_length < 0:
        raise ValueError("Plaintext is too long.")

    padding = b'\x00' * padding_length
    padded_message = b'\x00' + hash_value + padding + b'\x01' + message
    
    return padded_message


def datablock(s:bytes, keys_len:int)->list:
    
    split_data_list = []
    lhash = 18 # md5 + 2
    lmax = keys_len - lhash
    
    while s:
        packet = s[:lmax]
        s = s[lmax:]
        
        split_data_list.append(packet)
        
     

    return  split_data_list


"""

# メッセージと鍵を用意
message = b'a'*90
key_length = 128

# OAEPパディングを適用
padded_message = padding(message, key_length)
# パディング後のメッセージを表示


print("Padded Message:", len(padded_message))
"""




def crypto():
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP

    # 公開鍵の生成
    key = RSA.generate(4096)
    public_key = key.publickey()

    # OAEPパディングと公開鍵暗号化の準備
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # メッセージの準備
    message = b't'*10
    # OAEPパディングと公開鍵暗号化を実行
    encrypted_message = cipher_rsa.encrypt(message)

    # 暗号化されたメッセージを表示
    print("Encrypted Message:",encrypted_message.hex(), len(encrypted_message.hex()))

crypto()
