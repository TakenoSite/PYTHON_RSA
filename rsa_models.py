from util import UTIL
from rsa_math import MATH
import base64

class RSA:
    def __init__(self, keys_len:int):
        self.math = MATH()
        self.util = UTIL()

        self.keys_len = keys_len // 8

    def padding(self, payloads:bytes, key_len:int):
        """
        padding is a very important element in encryption. 
        This padding is a very simple example.
        """
        hash_value = self.util.hash_md5(payloads)
         
        padding_length = key_len - len(payloads) - len(hash_value) - 2
        if padding_length < 0:
            raise ValueError("Plaintext is too long.")
        """
        The length of ciphertext per block is proportional 
        to the length of the key to be created.
        """

        padding = b'\x00' * (padding_length)
        padded_message = b'\x00' + hash_value + padding + b'\x01' + payloads
        c = self.util.bytes_to_long(padded_message)
        
        return c


    def rsa_generate_keys(self, bit_size:int)->dict:
        keys = {"pub":{"max":0, "e":0}, 
                "priv":{"max":0, "e":0},
                "prime1":0,
                "prime2":0 }
        
        p = 0
        q = 0
        
        e = (2 << 15) + 1  # 範囲設定 
        d = 0
        
        max_n = 0
        max_phi = 0
        
        if bit_size < 1024:
            raise ValueError("Select 1024bit or more")

        while not (p and q) or (p == q) or (self.math.gcd(max_phi, e) != 1):
            
            size_prime = bit_size // 2
            gen_prime = self.math.generate_prime(2, size_prime)
            
            p = gen_prime[0]
            q = gen_prime[1]

            max_n = p*q
            max_phi = (p - 1)*(q - 1)
             

        d = self.math.ext_euclid(max_phi, e)
        while d < 0:
            d = d + max_phi
        
        keys["pub"]     = {"max":max_n, "e":e}
        keys["priv"]    = {"max":max_n, "e":d}
        keys["prime1"]  = p
        keys["prime2"]  = q

        return keys


    def rsa_encrypt(self, msg:bytes, pub_key:dict)->list:
        encrypted = []
        # パディングする, to padding 
        pd = [self.padding(msg, self.keys_len)]
        for s in pd:
            #共通鍵で暗号化. Encryption with publik key
            encry = self.math.modular_exp(s, pub_key["e"], pub_key["max"])
            if encry == -1:
                return None

            encrypted.append(encry)
       
        return encrypted


    def rsa_decrypt(self, msg:list, priv_key:dict)->list:
        decrypted = []
        for s in msg:
            # プライベートキーで暗号文を復号化
            decrypt = self.math.modular_exp(s, priv_key["e"] , priv_key["max"])
            if decrypt == -1:
                return None

            #バイトに変換 
            dbytes = self.util.long_to_bytes(decrypt)
            
            #データをハッシュとペイロードに分割
            dhash = dbytes[:16].hex()
            dpayload = dbytes[16:]

            # ペイロードの実部を取得
            start_index = dpayload.split(b"\x01")
            if len(start_index) == 0:
                return None
            
            mpayloads = start_index[1]
            # ペイロードのハッシュを取得
            phash = self.util.hash_md5(mpayloads).hex()
            
            # ハッシュを比較して整合性チェック
            if phash != dhash:
                return None
            
            decrypted.append(mpayloads)

        return decrypted
    
    
    
    def certificate(self, doc:bytes, priv_key:dict)->dict:
        
        value = {
                "doc" : None,
                "certificate":None
                }
        
        to_long = self.util.bytes_to_long(doc)

        gen_proof = self.math.modular_exp(to_long, priv_key["e"], priv_key["max"])
        if gen_proof == -1:
            return None
        
        value["doc"] =  doc
        value["certificate"] = gen_proof

        return value
    
    
    def certificate_proof(self, c, pub_keys:dict):
        
        proof = self.math.modular_exp(c, pub_keys["e"], pub_keys["max"])
        if proof == -1:
            return None 

        return proof


#end
