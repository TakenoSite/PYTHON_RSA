# RAW_RSA

## how to run 

      python main.py
---------------------

mathライブラリなし　

計算詳細

RSA基本概念


[*] keys_lengt: 1024 bit
[*] generate rsa keys ...
private keys :
  01  7f  e8  a9  99  fc  95  27
  82  9a  fd  cb  ec  cf  9a  96
  03  06  e3  97  f6  94  5a  93
  11  77  94  1e  56  ec  cf  fc
  78  8d  82  8d  c6  3b  b7  be
  21  23  70  74  66  c9  bf  b6
  b1  7d  35  1b  83  f7  33  c7
  95  4f  1c  4a  3e  a3  ac  a6
  1a  8c  ac  3f  52  56  ab  29
  d5  93  36  6e  a2  c5  11  8c
  5a  56  35  0b  14  dc  dd  42
  27  cb  02  80  81  79  88  d3
  0b  28  bb  db  50  e0  22  c6
  27  ca  95  82  b4  43  2b  ef
  8e  0b  e9  46  70  27  fd  ef
  0b  89  51  52  43  01  ce  01
length : 256

public keys :
  a4  e7  28  2a  5f  6f  4f  12
  cb  d0  10  b7  3d  a6  66  10
  27  e7  5a  91  41  6c  bc  be
  ba  b1  a5  c3  74  77  cd  01
  f3  1b  1b  2e  ba  32  ac  9b
  02  64  55  d6  70  99  fc  c0
  f2  36  60  86  79  6f  91  84
  c3  4e  00  95  04  42  b3  74
  65  c7  71  6a  26  bd  4e  c8
  18  29  67  01  01  06  de  50
  cb  f1  73  8f  d9  c8  af  2d
  1a  0c  43  0e  45  28  09  12
  f2  20  56  b0  5d  42  9e  62
  4e  ab  5d  62  3f  d5  3e  49
  ed  92  2e  95  96  a9  8f  70
  df  d7  f2  be  4f  18  70  77
length : 256

Exponent :
 65537

prime1 :
  f2  fc  32  40  ed  8b  06  3f
  ce  b8  b1  46  dd  8a  96  ab
  40  48  10  86  ca  3c  a9  4c
  97  d5  14  c2  4e  33  19  9b
  ce  90  c0  52  6b  09  69  a6
  c5  b1  10  85  44  42  eb  71
  30  b1  db  9d  34  a7  4b  50
  d9  49  72  d9  56  6c  66  b7
length : 128

prime2 :
  ad  bc  4c  e8  8a  cf  b4  8e
  d7  98  39  3a  7b  3c  92  a2
  28  a1  10  03  16  71  57  0c
  ba  69  bd  1b  de  06  d8  e1
  ab  63  56  c6  6f  e1  bb  7a
  dc  d9  18  c4  2a  df  8d  cf
  4b  b5  a9  95  d5  cc  1b  4d
  c8  8c  69  bd  50  44  84  41
length : 128

----- encrypt msg ------
dec : 16806191103515128793931623024022241762093937578722578463886897425960672495025018765670899491016964304670663227652659173359758719769352429406311833696884367386367045172299225411817732898125783793937980886593772576767018142467234224263045590217273705465772831573989825912407067779992071616794838263574769676352 -> 308 bytes

bytes : 17eeccac18ba44d38d0bd842dfbe11f73c19be840f9a814bf5d94f39cd8f4e76a90fc5f6dce001a20acf8475881e53aa3913c7d0c917d8b062bbb8f91a65d576444683d0f77c82d24b7bac8e5c2d3c40ad057b30bb1c5dac5d42150dedbc96a7c9ff60190e195a4bd7355ffd1a4babac970bd8e54c9980c6aa606565ee73b040 ->256 bytes
-----------------------

----- decrypt msg ------
[b'ilove rsa!!']
-----------------------
