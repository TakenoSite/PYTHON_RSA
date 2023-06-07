# RAW_RSA

## how to run 

      python main.py
---------------------

mathライブラリなし　

計算詳細

RSA基本概念

## 文書 → 秘密鍵（署名生成）→ 署名値、署名値→ 公開鍵（署名検証）→ 文書 

            [*] keys_lengt: 1024 bit
            [*] generate rsa keys ...
            ------------------------------RSA KEYS------------------------------
            private keys :
              57  39  d2  6b  bd  3b  ca  fb  33  17  6c  b0  35  cb  32  b2
              9d  14  47  53  d4  f4  12  87  4e  64  e2  41  3c  52  dc  4f
              11  85  a8  10  98  b8  c9  4f  f6  d9  4a  9d  c1  fa  d4  67
              ce  34  3e  68  72  cd  dd  cb  81  17  52  80  41  e9  2b  93
              0b  27  62  b7  1b  2b  1b  0f  2c  f4  69  42  29  02  8b  2d
              0d  ff  96  78  1d  e1  ae  21  dc  ba  4c  56  32  ac  9f  6c
              e7  a0  34  79  c7  17  39  3c  0f  b1  d7  4a  1f  ae  72  d6
              25  bf  36  d6  68  31  0d  bc  19  ba  1c  0a  f3  f0  71  85
              length : 128

            public keys :
              6a  d3  2d  97  d5  84  51  88  1d  bf  ca  26  9e  29  75  a1
              49  9f  9b  4f  30  61  03  c3  0e  c7  40  7b  88  40  11  9d
              2a  05  33  f0  99  83  0b  8c  0e  fd  37  cf  1c  8e  cd  00
              86  3c  6c  63  12  0a  a1  f5  ce  14  4f  77  c6  ad  40  2e
              90  44  fd  ed  73  3f  a7  72  80  b3  23  16  d6  40  87  94
              1e  b7  7a  c1  73  07  a7  44  77  fd  7b  8d  95  8c  46  11
              ef  bf  fe  ed  9b  e1  5f  e7  57  5b  2b  68  fe  8c  73  cf
              81  82  a5  86  64  25  1d  ef  78  11  14  5b  ea  42  17  51
              length : 128

            Exponent :
             65537

            prime1 :
              b1  09  bf  5f  14  61  8e  aa  43  d6  5b  40  ec  17  4d  c7
              ed  6d  0f  c6  f3  b3  b1  cb  61  81  a1  10  d0  5c  7e  7e
              c1  e0  b1  b4  1c  9f  a6  f0  81  81  a6  75  64  d3  95  a0
              d5  ab  34  54  75  2e  b4  17  bb  bc  b5  35  fa  21  02  d7
              length : 64

            prime2 :
              9a  78  79  52  e4  a2  2e  ae  73  d9  b1  a8  d9  66  54  55
              f4  06  73  74  fb  76  0e  ef  5d  81  2c  3f  12  8c  35  62
              ee  f7  ec  7f  d3  b9  cb  e4  85  e1  fb  6b  7a  df  77  72
              0f  1d  71  23  b3  85  45  28  be  66  66  00  d1  e7  1a  17
              length : 64
            ----------------------------------------------------------------------



            document :
              69  6c  6f  76  65  20  72  73  61  20  21  21  length : 12


            certificate  :
              50  7f  1b  72  2c  53  0d  41  9d  e4  32  14  f3  b5  8e  a4
              0e  3c  49  e5  ac  56  da  2a  02  d8  d5  69  79  24  64  c4
              29  75  de  31  cc  65  42  d8  f6  59  1f  45  e9  12  42  90
              c1  20  47  0d  4b  fc  cc  29  d7  0e  c0  9c  59  cb  5c  d9
              45  39  9f  c6  cc  f7  98  8b  7c  4e  50  78  fc  34  d5  27
              db  17  e0  53  37  32  04  a0  4c  1d  6d  55  19  79  2c  af
              85  cd  f3  df  1a  29  1f  08  cd  40  f5  c7  e5  f8  e7  62
              19  bb  29  19  3d  1c  d4  a2  ed  57  f1  2a  6e  e8  ab  1b
              length : 128

            proof document :
              69  6c  6f  76  65  20  72  73  61  20  21  21  length : 12
              
              
   ------------------------------
   ##平文 → 公開鍵（暗号化）→ 暗号文、暗号文→ 秘密鍵（復号）→ 平文
   
            [*] keys_lengt: 1024 bit
            [*] generate rsa keys ...
            ------------------------------RSA KEYS------------------------------
            private keys :
              4d  27  c7  1b  81  93  18  d8  29  9b  2b  fa  b2  00  04  06
              b5  51  36  f4  d1  8c  6a  16  72  fc  c0  4a  03  ca  7b  e0
              14  2f  2f  b0  12  0e  70  de  1d  6c  f0  ca  94  02  2b  8d
              df  5c  16  42  41  f0  1b  b6  c9  91  c2  98  22  84  34  20
              85  71  22  3c  7c  3b  1d  6a  f9  9a  7f  09  56  6c  f2  96
              ad  2e  9c  95  a7  0e  b4  93  e2  09  d4  10  ea  8c  ec  9d
              cc  f3  60  fd  8e  78  a9  7d  03  28  ef  c1  0a  8a  9c  de
              a0  bb  12  60  d4  fe  f3  3a  eb  8b  42  a3  89  31  c7  41
              length : 128

            public keys :
              8d  af  eb  5d  50  9e  1d  ce  8c  f6  ea  68  50  4d  83  bf
              e8  c2  0d  b3  81  fd  19  71  51  1c  15  da  f5  2f  af  81
              68  09  35  a6  9a  d1  40  4e  25  d6  e6  0e  d7  0f  6f  0a
              ec  9e  14  fd  d2  1b  a4  b0  c9  9a  0d  f5  5c  e1  ce  1d
              1a  a5  2f  aa  ea  f7  7a  89  8b  11  7a  67  72  ff  da  4c
              f1  9e  b6  f7  56  55  10  97  ef  9a  77  e7  f5  1a  48  b9
              84  98  dc  b9  1d  f6  d7  09  02  ae  92  4c  18  46  84  e2
              b6  b5  c3  c7  48  c6  91  a2  55  ab  c1  e1  a6  85  3a  2f
              length : 128

            Exponent :
             65537

            prime1 :
              c8  f3  e3  d3  0f  b9  06  08  1e  9f  d1  4f  e7  15  86  81
              47  e1  92  33  ea  38  73  05  53  68  ca  5b  4d  b3  a0  91
              46  1c  01  bd  4c  27  d5  c3  2d  aa  06  02  a8  bc  89  f8
              61  52  da  97  f9  42  cf  f2  40  0d  91  50  f0  3a  eb  23
              length : 64

            prime2 :
              b4  7f  f2  47  c5  44  95  66  cd  ac  a6  23  45  83  c5  56
              40  a0  70  14  b6  65  4c  3c  e2  90  e5  31  c3  97  d7  c4
              aa  f0  72  30  8f  b6  62  f5  f9  79  05  6a  3e  81  42  fb
              cb  d1  c2  3f  ba  41  2f  db  22  06  c2  ad  e4  e8  3b  85
              length : 64
            ----------------------------------------------------------------------


            encrypted :
              1e  41  bd  9d  02  1b  16  8a  82  56  e3  95  15  98  f9  f2
              36  61  77  5c  b1  86  36  33  0a  6f  f0  41  f4  b1  0e  70
              32  4f  17  32  07  25  94  5f  44  2e  bf  b4  c2  1d  4d  7c
              a6  46  aa  0e  bd  73  82  44  43  24  1a  58  fa  5c  c3  58
              cb  bd  2f  a2  f1  42  76  07  26  22  01  2d  7a  60  30  4e
              e6  58  12  68  1a  89  0a  93  4e  82  8d  e0  15  d4  44  70
              5b  e7  95  13  d5  36  32  a8  cc  c4  70  6c  22  17  53  9b
              aa  9c  a2  24  e6  7a  25  26  3e  6e  28  a7  47  53  4a  82
              length : 128

            decrypted :
              69  6c  6f  76  65  20  72  73  61  21  21  length : 11

             b'ilove rsa!!'



      
