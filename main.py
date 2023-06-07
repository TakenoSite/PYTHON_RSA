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
        key_len = len(key) // 2
        k = 2
        for _ in range(key_len ):
            if k % 32 != 0:
                print(" ", key[k-2: k], end="")
            else:
                print(" ", key[k-2: k])
            k += 2
            
        #print(f"\nlength : {key_len}") 


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
    print(f"{'-'*30}RSA KEYS{'-'*30}")
    print("private keys : ")
    print_bytes(priv_key_bytes)
    
    print("\npublic keys : ")
    print_bytes(pub_key_bytes)
    print(f"\nExponent : \n {exponent}")

    print("\nprime1 : ")
    print_bytes(prime_1_bytes) 
    
    print("\nprime2 : ")
    print_bytes(prime_2_bytes) 
    print(f"{'-'*70}\n\n")

if __name__ == "__main__":
    #MAIN
    util = UTIL()
    
    # 生成する鍵のながさ
    rsa_keys_size = 2 << 10 #bit.
    
    print("[*] keys_lengt: {} bit".format(rsa_keys_size))

    rsa = RSA(rsa_keys_size)
   
    print("[*] generate rsa keys ...")
    gen_key = rsa.rsa_generate_keys(bit_size=rsa_keys_size) 
    #print(gen_key)

    #共有鍵
    pub_key = gen_key["pub"]
    #秘密鍵
    priv_key = gen_key["priv"]

    #SHOW KEY INFO ###########
     
    keyinfo(gen_key=gen_key)
    
    ###########################
    
    #APPLICATION##############
    
    if True:
        # 文書 → 秘密鍵（署名生成）→ 署名値、署名値→ 公開鍵（署名検証）→ 文書
        document = b"ilove rsa !!"
        res = rsa.certificate(document ,priv_key)
        doc_certificate = res["certificate"]
        doc_certificate_hex = util.long_to_bytes(doc_certificate).hex()

        document_hash  =  (res["doc"]).hex()
        print("\ndocument : ")
        print_bytes(document_hash)

        print("\n\ncertificate  : ")
        print_bytes(doc_certificate_hex)    
         
        res = rsa.certificate_proof(res["certificate"], pub_key)
        print("\nproof document : ")
        proof = util.long_to_bytes(res).hex()
        print_bytes(proof)
        
    else:
        #平文 → 公開鍵（暗号化）→ 暗号文、暗号文→ 秘密鍵（復号）→ 平文
        msg = b"ilove rsa!!"
        
        #暗号化する
        encrypted = rsa.rsa_encrypt(msg, pub_key)
        to_hex = util.long_to_bytes(encrypted[0]).hex()
        print("encrypted : ") 
        print_bytes(to_hex)
                 
        decrypted = rsa.rsa_decrypt(encrypted, priv_key)
        print("\ndecrypted : ")
        print_bytes(decrypted[0].hex())
        print("\n", decrypted[0])
