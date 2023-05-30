from rsa_models import RSA
from util import UTIL

if __name__ == "__main__":
    #MAIN
    util = UTIL()
    
    # 生成する鍵のながさ
    rsa_keys_size = 1024 #bit 
    print("keys_lengt2: {} bit".format(rsa_keys_size))

    rsa = RSA(rsa_keys_size)
   
    print("generate rsa keys ...")
    gen_key = rsa.rsa_generate_keys(bit_size=rsa_keys_size) 
    #print(gen_key)

    #共有鍵
    pub_key = gen_key["pub"]
    #秘密鍵
    priv_key = gen_key["priv"]
  
    # 平文
    msg = b"test"
     
    #暗号化する
    msg_encrypted = rsa.rsa_encrypt(msg, pub_key)
    
    encrypted_dec = msg_encrypted[0]
    encrypted_dec_len = util.long_len(msg_encrypted[0])
    encrypted_bytes = UTIL().long_to_bytes(msg_encrypted[0]).hex()
    encrypted_bytes_len = util.long_len(encrypted_bytes)
    
    print("\n----- encrypt msg ------ \ndec : {} -> {} \n\nbytes : {} ->{} \n----------------------- "
            .format(encrypted_dec, encrypted_dec_len, encrypted_bytes, encrypted_bytes_len)) 
             
    #復号化する
    msg_decrypt = rsa.rsa_decrypt(msg_encrypted, priv_key)
    
    print("\n----- decrypt msg ------ \n{}\n-----------------------"
            .format(msg_decrypt))
    pass
