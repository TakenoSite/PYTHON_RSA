from rsa_models import RSA
from util import UTIL


# Will be a complete learning RSA
# Do not use in a production environment.
#
# When actually learning cryptography, 
# please determine the algorithm, padding, 
# etc. to be used under the guidance of a 
# security expert.


def print_bytes(key:bytes):
        key_len = util.long_len(key)
        k = 2
        for _ in range(key_len // 2):
            if k % 16 != 0:
                print(" ", key[k-2: k], end="")
            else:
                print(" ", key[k-2: k])
            k += 2
            
        print(f"length : {key_len}") 


def keyinfo(gen_key:dict):
    util = UTIL()
    
    pub_key = gen_key["pub"]
    priv_key = gen_key["priv"]
    exponent = pub_key["e"]

    prime_1 = gen_key["prime1"]
    prime_2 = gen_key["prime2"]

    priv_key_bytes = util.long_to_bytes(priv_key["e"]).hex()
    pub_key_bytes = util.long_to_bytes(pub_key["max"]).hex()
    

    prime_1_bytes = util.long_to_bytes(prime_1).hex()
    prime_2_bytes = util.long_to_bytes(prime_2).hex()

    print("private keys : ")
    print_bytes(priv_key_bytes)
    
    print("\npublic keys : ")
    print_bytes(pub_key_bytes)
    print(f"\nExponent : \n {exponent}")

    print("\nprime1 : ")
    print_bytes(prime_1_bytes) 
    
    print("\nprime2 : ")
    print_bytes(prime_2_bytes) 


if __name__ == "__main__":
    #MAIN
    util = UTIL()
    
    # 生成する鍵のながさ
    rsa_keys_size = 1024 #bit 
    print("[*] keys_lengt: {} bit".format(rsa_keys_size))

    rsa = RSA(rsa_keys_size)
   
    print("[*] generate rsa keys ...")
    gen_key = rsa.rsa_generate_keys(bit_size=rsa_keys_size) 
    #print(gen_key)

    #共有鍵
    pub_key = gen_key["pub"]
    #秘密鍵
    priv_key = gen_key["priv"]

    # SHOW KEY INFO ###########
       
    keyinfo(gen_key=gen_key)

    ###########################
  
    # 平文
    msg = b"ilove rsa!!"
     
    #暗号化する
    msg_encrypted = rsa.rsa_encrypt(msg, pub_key)
    
    
    encrypted_dec = msg_encrypted[0]
    encrypted_dec_len = util.long_len(msg_encrypted[0])
    encrypted_bytes = UTIL().long_to_bytes(msg_encrypted[0]).hex()
    encrypted_bytes_len = util.long_len(encrypted_bytes)
    print("\n----- encrypt msg ------ \ndec : {} -> {} bytes  \n\nbytes : {} ->{} bytes\n----------------------- "
            .format(encrypted_dec, encrypted_dec_len, encrypted_bytes, encrypted_bytes_len)) 
             
    #復号化する
    msg_decrypt = rsa.rsa_decrypt(msg_encrypted, priv_key)
    
    print("\n----- decrypt msg ------ \n{}\n-----------------------"
            .format(msg_decrypt))
    pass
