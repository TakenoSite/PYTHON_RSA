from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# RSA公開鍵の読み込み
with open('public-key.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# 平文をバイト列に変換
plaintext = b't'*100

# RSA暗号化
ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(ciphertext)


# RSA秘密鍵の読み込み
with open('private-key.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # パスワードが設定されている場合は指定します
    )

# RSA復号化
decrypted_text = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(decrypted_text)





