/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PKCS11T_2_3_H__
#define __PKCS11T_2_3_H__

#ifdef CRYPTOKI_VERSION_MAJOR

#undef CRYPTOKI_VERSION_MAJOR
#undef CRYPTOKI_VERSION_MINOR
#undef CRYPTOKI_VERSION_AMENDMENT

#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 30
#define CRYPTOKI_VERSION_AMENDMENT 0

#endif

#define CKK_SEED           0x00000026
#define CKK_MD5_HMAC       0x00000027
#define CKK_SHA_1_HMAC     0x00000028
#define CKK_RIPEMD128_HMAC 0x00000029
#define CKK_RIPEMD160_HMAC 0x0000002A
#define CKK_SHA256_HMAC    0x0000002B
#define CKK_SHA384_HMAC    0x0000002C
#define CKK_SHA512_HMAC    0x0000002D
#define CKK_SHA224_HMAC    0x0000002E
#define CKK_GOSTR3410      0x00000030
#define CKK_GOSTR3411      0x00000031
#define CKK_GOST28147      0x00000032

#define CKD_SHA224_KDF           0x00000005
#define CKD_SHA256_KDF           0x00000006
#define CKD_SHA384_KDF           0x00000007
#define CKD_SHA512_KDF           0x00000008
#define CKD_CPDIVERSIFY_KDF      0x00000009

#define CKM_SEED_KEY_GEN              0x00000650
#define CKM_SEED_ECB                  0x00000651
#define CKM_SEED_CBC                  0x00000652
#define CKM_SEED_MAC                  0x00000653
#define CKM_SEED_MAC_GENERAL          0x00000654
#define CKM_SEED_CBC_PAD              0x00000655
#define CKM_SEED_ECB_ENCRYPT_DATA     0x00000656
#define CKM_SEED_CBC_ENCRYPT_DATA     0x00000657
#define CKM_AES_GCM                   0x00001087
#define CKM_AES_CCM                   0x00001088
#define CKM_AES_OFB                   0x00002104
#define CKM_AES_CFB64                 0x00002105
#define CKM_AES_CFB8                  0x00002106
#define CKM_AES_CFB128                0x00002107
#define CKM_BLOWFISH_CBC_PAD          0x00001094
#define CKM_TWOFISH_CBC_PAD           0x00001095
#define CKM_AES_KEY_WRAP              0x00001090
#define CKM_AES_KEY_WRAP_PAD          0x00001091
#define CKM_RSA_PKCS_TPM_1_1          0x00004001
#define CKM_RSA_PKCS_OAEP_TPM_1_1     0x00004002
#define CKM_GOSTR3410_KEY_PAIR_GEN    0x00001200
#define CKM_GOSTR3410                 0x00001201
#define CKM_GOSTR3410_2012            0x00001208
#define CKM_GOSTR3410_WITH_GOSTR3411  0x00001202
#define CKM_GOSTR3410_KEY_WRAP        0x00001203
#define CKM_GOSTR3410_DERIVE          0x00001204
#define CKM_GOSTR3411                 0x00001210
#define CKM_GOSTR3411_2012            0x00001212
#define CKM_GOSTR3411_HMAC            0x00001211
#define CKM_GOST28147_KEY_GEN         0x00001220
#define CKM_GOST28147_ECB             0x00001221
#define CKM_GOST28147                 0x00001222
#define CKM_GOST28147_MAC             0x00001223
#define CKM_GOST28147_KEY_WRAP        0x00001224

#define CKA_GOSTR3410_PARAMS          0x00000250
#define CKA_GOSTR3411_PARAMS          0x00000251
#define CKA_GOST28147_PARAMS          0x00000252

#endif /* __PKCS11T_2_3_H__ */
