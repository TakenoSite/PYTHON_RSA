from util import UTIL

import base64
import primes


class MATH:
    def __init__(self):
        pass 
    
    def modular_exp(self, a, b, n):
        res = 1
        while b != 0:
            if b & 1 != 0:
                res = (res * a) % n
            a = (a * a) % n
            b = b >> 1
            
        return res


    def modular_mult(self, a, b, mod):
        if a == 0:
            return 0

        product = a * b 
        if product / a == b:
            return product % mod 

        if a & 1:
            product = self.modular_mult((a>>1), b, mod)
            if (product << 1) > product:
                return (((product << 1) % mod) + b) % mod

        product = self.modular_mult((a >> 1), b, mod)
        if ((product << 1) > product):
            return (product << 1) % mod

        sum_n = 0
        while b > 0:
            if b & 1:
                sum_n = (sum_n + a) % mod
            a = (2 * a) % mod
            b >>= 1
        return sum_n


    def gcd(self, a, b):
        while a != 0:
            c = a
            a = b % a
            b = c 
        
        return b


    def ext_euclid(self, a, b):
        x = 0
        y = 1
        u = 1
        v = 0
        gcd = b 
        
        m = 0
        n = 0 
        q = 0 
        r = 0 

        while a != 0:            
            q   = gcd//a
            r   = gcd % a
            m   = x-u*q
            n   = y-v*q
            gcd = a
            a   = r
            x   = u 
            y   = v 
            u   = m 
            v   = n
            
            #print(q,r,m,n,gcd,a,x,y,u,v) # debug 
        #print("ExtEuclid : ", y) #debug 
        return  y

    def generate_prime(self, gen_len:int, bit_size:int)->list:
        big_primes_list = []
        
        for _ in range(gen_len):
            res = primes.generate_prime(bit_size)
            big_primes_list.append(res)

        return big_primes_list



class RSA:
    def __init__(self, keys_len:int):
        self.math = MATH()
        self.util = UTIL()

        self.keys_len = keys_len // 8


    def padding(self, payloads:bytes, key_len:int):
        hash_value = self.util.hash_md5(payloads)
         
        padding_length = key_len - len(payloads) - len(hash_value) - 2
        if padding_length < 0:
            raise ValueError("Plaintext is too long.")
        
        padding = b'\x00' * (padding_length)
        padded_message = b'\x00' + hash_value + padding + b'\x01' + payloads
        c = self.util.bytes_to_long(padded_message)

        return c
        


    def rsa_generate_keys(self, bit_size:int)->dict:
        keys = {"pub":{"max":0, "e":0}, 
                "priv":{"max":0, "e":0}}
        p = 0
        q = 0
        
        e = (2 << 16) + 1  # 範囲設定 
        d = 0
        
        max_n = 0
        max_phi = 0
        
        while not (p and q) or (p == q) or (self.math.gcd(max_phi, e) != 1):
            
            gen_prime = self.math.generate_prime(2, bit_size // 2)
            p = gen_prime[0]
            q = gen_prime[1]

            max_n = p*q
            max_phi = (p - 1)*(q - 1)
            #print("p : {} q : {} pq : {} max_phi : {}".format(p, q, max_n, max_phi))

            pass 

        d = self.math.ext_euclid(max_phi, e)

        while d < 0:
            d = d + max_phi
        
        keys["pub"] = {"max":max_n, "e":e}
        keys["priv"] = {"max":max_n, "e":d}
        return keys


    def rsa_encrypt(self, msg:bytes, pub_key:dict)->list:
        encrypted = []
        pd = [self.padding(msg, self.keys_len)]
         
        #print('\noriginal    encrypted') # debug 
        for s in pd:
            encry = self.math.modular_exp(s, pub_key["e"], pub_key["max"])
            if encry == -1:
                return None

            #print("{} -> {}".format(s, encry))
            encrypted.append(encry)
       
        return encrypted


    def rsa_decrypt(self, msg:list, priv_key:dict)->list:
        decrypted = []
        #print('\nencrypted    original')
        for s in msg:
            decrypt = self.math.modular_exp(s, priv_key["e"] , priv_key["max"])
            if decrypt == -1:
                return None
            #print("{} -> {}".format(s, decrypt)) #debug 

            
            dbytes = self.util.long_to_bytes(decrypt)
            
            dhash = dbytes[:16].hex()
            dpayload = dbytes[16:]

            # payload取り出し
            start_index = dpayload.split(b"\x01")
            if len(start_index) == 0:
                return None
            
            mpayloads = start_index[1]
            phash = self.util.hash_md5(mpayloads).hex()
            
            # hashを比較して整合性チェック
            if phash != dhash:
                return None
            
            decrypted.append(mpayloads)

        return decrypted
    

if __name__ == "__main__":
    #MAIN

    # 生成する鍵のながさ
    keysize = 1024 #bit 
    print("keys_length : {} bit".format(keysize))

    rsa = RSA(keysize)
   
    print("generate rsa keys ...")
    gen_key = rsa.rsa_generate_keys(bit_size=keysize) 
    print("Comp") 
    
    #共有鍵
    pub_key = gen_key["pub"]
    #秘密鍵
    priv_key = gen_key["priv"]
    
    priv_key_e = priv_key["e"]
    priv_key_max = priv_key["max"]
    
         
    
    #print("\npub_keys : {}\n\npriv_keys : {}".format(pub_key, priv_key))
    priv_key_bytes = "{} {}".format(UTIL().long_to_bytes(priv_key_e).hex(),
            UTIL().long_to_bytes(priv_key_max).hex())
    priv_key_base64 = base64.b64encode(priv_key_bytes.encode())

    # 平文
    msg = b"0"
    #msg = base64.b64encode(msg.encode()) 
    

    
    for i in range(1):        
        #暗号化する
        msg_encrypte = rsa.rsa_encrypt(msg, pub_key)
        

        encrypted_dec = msg_encrypte[0]
        encrypted_dec_len = len(list(str(msg_encrypte[0]))) 
        
        encrypted_bytes = UTIL().long_to_bytes(msg_encrypte[0]).hex()
        encrypted_bytes_len = len(list(str(encrypted_bytes)))
        
        print("\n----- encryp msg ------ \ndec : {} -> {} \n\nbytes : {} ->{} \n----------------------- "
                .format(msg_encrypte[0], len(list(str(msg_encrypte[0]))), UTIL().long_to_bytes(msg_encrypte[0]).hex(), encrypted_bytes_len)) 
                 
        
        #復号化する
        msg_decrypt = rsa.rsa_decrypt(msg_encrypte, priv_key)
        
        print("\n----- encryp msg ------ \n{}\n-----------------------"
                .format(msg_decrypt))

#end
