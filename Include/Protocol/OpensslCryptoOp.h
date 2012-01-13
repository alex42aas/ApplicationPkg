/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/** \file
 *  \brief OpenSSL some various direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#include <openssl/ssl.h>
#include <openssl/rc4.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_RC4) (
  RC4_KEY *key, 
  size_t len, 
  const unsigned char *indata, 
  unsigned char *outdata
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_RC4_SET_KEY) (
  RC4_KEY *key, 
  int len, 
  const unsigned char *data
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD4_INIT) (
  MD4_CTX *c
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD4_UPDATE) (
  MD4_CTX *c, 
  const void *data, 
  size_t len
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD4_FINAL) (
  unsigned char *md, 
  MD4_CTX *c
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD5_INIT) (
  MD5_CTX *c
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD5_UPDATE) (
  MD5_CTX *c, 
  const void *data, 
  size_t len
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_MD5_FINAL) (
  unsigned char *md, 
  MD5_CTX *c
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_SHA1_INIT) (
  SHA_CTX *c
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_SHA1_UPDATE) (
  SHA_CTX *c, 
  const void *data, 
  size_t len
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_SHA1_FINAL) (
  unsigned char *md, 
  SHA_CTX *c
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_HMAC_CTX_INIT) (
  HMAC_CTX *ctx
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_HMAC_CTX_CLEANUP) (
  HMAC_CTX *ctx
);

typedef
unsigned char *
(EFIAPI *OPENSSL_CRYPTO_HMAC) (
  const EVP_MD *evp_md, 
  const void *key, 
  int key_len, 
  const unsigned char *d, 
  size_t n, 
  unsigned char *md, 
  unsigned int *md_len
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_HMAC_INIT_EX) (
  HMAC_CTX *ctx, 
  const void *key, 
  int len, 
  const EVP_MD *md, 
  ENGINE *impl
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_HMAC_UPDATE) (
  HMAC_CTX *ctx, 
  const unsigned char *data, 
  size_t len
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_HMAC_FINAL) (
  HMAC_CTX *ctx, 
  unsigned char *md, 
  unsigned int *len
);

typedef
BN_CTX *
(EFIAPI *OPENSSL_CRYPTO_BN_CTX_NEW) (
  void
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_BN_CTX_FREE) (
  BN_CTX *c
);

typedef
BIGNUM *
(EFIAPI *OPENSSL_CRYPTO_BN_NEW) (
  void
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_BN_FREE) (
  BIGNUM *a
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_BN_INIT) (
  BIGNUM *a
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_BN_CLEAR_FREE) (
  BIGNUM *a
);

typedef
int
(EFIAPI *OPENSSL_CRYPTO_BN_SET_WORD) (
  BIGNUM *a,
  BN_ULONG w
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_BN_MOD_EXP) (
  BIGNUM *r, 
  const BIGNUM *a, 
  const BIGNUM *p, 
  const BIGNUM *m,
  BN_CTX *ctx
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_BN_NUM_BITS) (
  const BIGNUM *a
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_BN_NUM_BYTES) (
  const BIGNUM *a
);

typedef
BIGNUM *
(EFIAPI *OPENSSL_CRYPTO_BN_BIN2BN) (
  const unsigned char *s,
  int len,
  BIGNUM *ret
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_BN_BN2BIN) (
  const BIGNUM *a, 
  unsigned char *to
);

typedef
int
(EFIAPI *OPENSSL_CRYPTO_OBJ_CMP) (
  const ASN1_OBJECT *a,
  const ASN1_OBJECT *b
);

typedef
ASN1_OBJECT *
(EFIAPI *OPENSSL_CRYPTO_OBJ_NIB_2_OBJ) (
  int n
);

typedef
char *
(EFIAPI *OPENSSL_CRYPTO_ERR_ERROR_STRING) (
  unsigned long e,
  char *buf
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_ERR_STR_N) (
  unsigned long e,
  char *buf,
  size_t len
);

typedef
unsigned long
(EFIAPI *OPENSSL_CRYPTO_ERR_PEEK_ERROR) (
  void
);

typedef
unsigned long 
(EFIAPI *OPENSSL_CRYPTO_ERR_GET_ERROR) (
  void
);

typedef
unsigned long
(EFIAPI *OPENSSL_CRYPTO_ERR_GET_ERR_LINE) (
  const char **file,
  int *line
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_ERR_REMOVE_STATE) (
  unsigned long pid
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_ERR_FREE_STRINGS) (
  void
);

typedef
DH *
(EFIAPI *OPENSSL_CRYPTO_PEM_READ_BIO_DHPARAM) (
  BIO *bp,
  DH **x,
  pem_password_cb *cb,
  void *u
);

typedef
RSA *
(EFIAPI *OPENSSL_CRYPTO_PEM_READ_BIO_RSAPRIVATEKEY) (
  BIO *bp,
  RSA **x,
  pem_password_cb *cb,
  void *u
);

typedef
RSA *
(EFIAPI *OPENSSL_CRYPTO_RSA_GENERATE_KEY) (
  int bits,
  unsigned long e_value,
  void (*callback)(int,int,void *),
  void *cb_arg
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_RSA_GENERATE_KEY_EX) (
  RSA *rsa,
  int bits,
  BIGNUM *e_value,
  BN_GENCB *cb
);

typedef
RSA *
(EFIAPI *OPENSSL_CRYPTO_RSA_NEW) (
  void
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_RSA_FREE) (
  RSA *r
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_RSA_CHECK_KEY) (
  const RSA *key
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_GENERAL_NAMES_FREE) (
  STACK_OF(GENERAL_NAME) *alt
);

typedef
DH *
(EFIAPI *OPENSSL_CRYPTO_DH_GEN_PARAMETERS) (
  int prime_len,
  int generator,
  void (*callback)(int,int,void *),
  void *cb_arg
);

typedef
int
(EFIAPI *OPENSSL_CRYPTO_DH_SIZE) (
  const DH *dh
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_SET_LOCKING_CB) (
  void (*func)(int mode,
               int type,
					     const char *file,
					     int line)
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_SET_ID_CB) (
  unsigned long (*func)(void)
);

typedef
int
(EFIAPI *OPENSSL_CRYPTO_ADD) (
  int *pointer,
  int amount,
  int type
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_FREE) (
  void *str
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_EVP_CIPHER_CTX_INIT) (
  EVP_CIPHER_CTX *a
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_EVP_CIPHER_CTX_CLEANUP) (
  EVP_CIPHER_CTX *a
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_EVP_CIPHER_CTX_SET_PADDING) (
  EVP_CIPHER_CTX *c, 
  int pad
);

typedef
void 
(EFIAPI *OPENSSL_CRYPTO_EVP_PKEY_FREE) (
  EVP_PKEY *pkey
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_EVP_CLEANUP) (
  void
);

typedef
const EVP_MD *
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA256) (
  void
);

typedef
const EVP_MD *
(EFIAPI *OPENSSL_CRYPTO_EVP_MD5) (
  void
);

typedef
const EVP_MD *
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA1) (
  void
);

typedef
const EVP_CIPHER *
(EFIAPI *OPENSSL_CRYPTO_EVP_DES_EDE3_CBC) (
  void
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_EVP_ENCRYPTINIT_EX) (
  EVP_CIPHER_CTX *ctx,
  const EVP_CIPHER *cipher, 
  ENGINE *impl, 
  const unsigned char *key, 
  const unsigned char *iv
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_EVP_ENCRYPTUPDATE) (
  EVP_CIPHER_CTX *ctx, 
  unsigned char *out, 
  int *outl, 
  const unsigned char *in, 
  int inl
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_EVP_DECRYPTINIT_EX) (
  EVP_CIPHER_CTX *ctx,
  const EVP_CIPHER *cipher, 
  ENGINE *impl, 
  const unsigned char *key, 
  const unsigned char *iv
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_EVP_DECRYPTUPDATE) (
  EVP_CIPHER_CTX *ctx, 
  unsigned char *out, 
  int *outl, 
  const unsigned char *in, 
  int inl
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_RAND_SEED) (
  const void *buf,
  int num
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_RAND_PSEUDO_BYTES) (
  unsigned char *buf,
  int num
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_RAND_BYTES) (
  unsigned char *buf,
  int num
);

typedef
void
(EFIAPI *OPENSSL_CRYPTO_CONFIG_MEM) (
  const char *config_name,
  BIO *bp
);

typedef
unsigned char *
(EFIAPI *OPENSSL_CRYPTO_ASN1_STRING_DATA) (
  ASN1_STRING *x
);

typedef
int
(EFIAPI *OPENSSL_CRYPTO_ASN1_STRING_LENGTH) (
  const ASN1_STRING *x
);

typedef
int 
(EFIAPI *OPENSSL_CRYPTO_ASN1_STRING_TO_UTF8) (
  unsigned char **out, 
  ASN1_STRING *in
);

typedef
size_t
(EFIAPI *OPENSSL_CRYPTO_I2D_X509_NAME) (
  X509_NAME *a,
  unsigned char **out
);

typedef
int	
(EFIAPI *OPENSSL_CRYPTO_I2D_PUBLICKEY) (
  EVP_PKEY *a, 
  unsigned char **pp
);

typedef
X509 *
(EFIAPI *OPENSSL_CRYPTO_D2I_X509) (
  X509 **a, 
  const unsigned char **in, 
  long len
);


struct _SSL_OPENSSL_CRYPTO_OP {
  OPENSSL_CRYPTO_RC4                    RC4;
  OPENSSL_CRYPTO_RC4_SET_KEY            RC4_set_key;

  OPENSSL_CRYPTO_MD4_INIT               MD4_Init;
  OPENSSL_CRYPTO_MD4_UPDATE             MD4_Update;
  OPENSSL_CRYPTO_MD4_FINAL              MD4_Final;

  OPENSSL_CRYPTO_MD5_INIT               MD5_Init;
  OPENSSL_CRYPTO_MD5_UPDATE             MD5_Update;
  OPENSSL_CRYPTO_MD5_FINAL              MD5_Final;

  OPENSSL_CRYPTO_SHA1_INIT              SHA1_Init;
  OPENSSL_CRYPTO_SHA1_UPDATE            SHA1_Update;
  OPENSSL_CRYPTO_SHA1_FINAL             SHA1_Final;

  OPENSSL_CRYPTO_HMAC_CTX_INIT          HMAC_CTX_init;
  OPENSSL_CRYPTO_HMAC_CTX_CLEANUP       HMAC_CTX_cleanup;

  OPENSSL_CRYPTO_HMAC                   HMAC;
  OPENSSL_CRYPTO_HMAC_INIT_EX           HMAC_Init_ex;
  OPENSSL_CRYPTO_HMAC_UPDATE            HMAC_Update;
  OPENSSL_CRYPTO_HMAC_FINAL             HMAC_Final;

  OPENSSL_CRYPTO_BN_CTX_NEW             BN_CTX_new;
  OPENSSL_CRYPTO_BN_CTX_FREE            BN_CTX_free;

  OPENSSL_CRYPTO_BN_NEW                 BN_new;
  OPENSSL_CRYPTO_BN_FREE                BN_free;
  OPENSSL_CRYPTO_BN_INIT                BN_init;
  OPENSSL_CRYPTO_BN_CLEAR_FREE          BN_clear_free;
  OPENSSL_CRYPTO_BN_SET_WORD            BN_set_word;
  OPENSSL_CRYPTO_BN_MOD_EXP             BN_mod_exp;
  OPENSSL_CRYPTO_BN_NUM_BITS            BN_num_bits;
  OPENSSL_CRYPTO_BN_NUM_BYTES           BN_num_bytes_func;
  OPENSSL_CRYPTO_BN_BIN2BN              BN_bin2bn;
  OPENSSL_CRYPTO_BN_BN2BIN              BN_bn2bin;

  OPENSSL_CRYPTO_OBJ_CMP                OBJ_cmp;
  OPENSSL_CRYPTO_OBJ_NIB_2_OBJ          OBJ_nid2obj;

  OPENSSL_CRYPTO_ERR_ERROR_STRING       ERR_error_string;
  OPENSSL_CRYPTO_ERR_STR_N              ERR_error_string_n;
  OPENSSL_CRYPTO_ERR_PEEK_ERROR         ERR_peek_error;
  OPENSSL_CRYPTO_ERR_GET_ERROR          ERR_get_error;
  OPENSSL_CRYPTO_ERR_GET_ERR_LINE       ERR_get_error_line;
  OPENSSL_CRYPTO_ERR_REMOVE_STATE       ERR_remove_state;
  OPENSSL_CRYPTO_ERR_FREE_STRINGS       ERR_free_strings;

  OPENSSL_CRYPTO_PEM_READ_BIO_DHPARAM   PEM_read_bio_DHparams_func;
  OPENSSL_CRYPTO_PEM_READ_BIO_RSAPRIVATEKEY PEM_read_bio_RSAPrivateKey;

  OPENSSL_CRYPTO_RSA_GENERATE_KEY       RSA_generate_key_func;
  OPENSSL_CRYPTO_RSA_GENERATE_KEY_EX    RSA_generate_key_ex;
  OPENSSL_CRYPTO_RSA_NEW                RSA_new;
  OPENSSL_CRYPTO_RSA_FREE               RSA_free;
  OPENSSL_CRYPTO_RSA_CHECK_KEY          RSA_check_key;

  OPENSSL_CRYPTO_GENERAL_NAMES_FREE     GENERAL_NAMES_free_func;

  OPENSSL_CRYPTO_DH_GEN_PARAMETERS      DH_generate_parameters;
  OPENSSL_CRYPTO_DH_SIZE                DH_size;

  OPENSSL_CRYPTO_SET_LOCKING_CB         CRYPTO_set_locking_callback;
  OPENSSL_CRYPTO_SET_ID_CB              CRYPTO_set_id_callback;
  OPENSSL_CRYPTO_ADD                    CRYPTO_add_func;
  OPENSSL_CRYPTO_FREE                   CRYPTO_free;

  OPENSSL_CRYPTO_EVP_CIPHER_CTX_INIT        EVP_CIPHER_CTX_init;
  OPENSSL_CRYPTO_EVP_CIPHER_CTX_CLEANUP     EVP_CIPHER_CTX_cleanup;
  OPENSSL_CRYPTO_EVP_CIPHER_CTX_SET_PADDING EVP_CIPHER_CTX_set_padding;
  
  OPENSSL_CRYPTO_EVP_PKEY_FREE          EVP_PKEY_free;

  OPENSSL_CRYPTO_EVP_CLEANUP            EVP_cleanup;

  OPENSSL_CRYPTO_EVP_SHA256             EVP_sha256;
  OPENSSL_CRYPTO_EVP_MD5                EVP_md5;
  OPENSSL_CRYPTO_EVP_SHA1               EVP_sha1;
  OPENSSL_CRYPTO_EVP_DES_EDE3_CBC       EVP_des_ede3_cbc;

  OPENSSL_CRYPTO_EVP_ENCRYPTINIT_EX     EVP_EncryptInit_ex;
  OPENSSL_CRYPTO_EVP_ENCRYPTUPDATE      EVP_EncryptUpdate;
  OPENSSL_CRYPTO_EVP_DECRYPTINIT_EX     EVP_DecryptInit_ex;
  OPENSSL_CRYPTO_EVP_DECRYPTUPDATE      EVP_DecryptUpdate;

  OPENSSL_CRYPTO_RAND_SEED              RAND_seed;
  OPENSSL_CRYPTO_RAND_PSEUDO_BYTES      RAND_pseudo_bytes;
  OPENSSL_CRYPTO_RAND_BYTES             RAND_bytes;

  OPENSSL_CRYPTO_CONFIG_MEM             OPENSSL_config_mem;

  OPENSSL_CRYPTO_ASN1_STRING_DATA       ASN1_STRING_data;
  OPENSSL_CRYPTO_ASN1_STRING_LENGTH     ASN1_STRING_length;
  OPENSSL_CRYPTO_ASN1_STRING_TO_UTF8    ASN1_STRING_to_UTF8;

  OPENSSL_CRYPTO_I2D_X509_NAME          i2d_X509_NAME_func;
  OPENSSL_CRYPTO_I2D_PUBLICKEY          i2d_PublicKey;
  OPENSSL_CRYPTO_D2I_X509               d2i_X509;
};

typedef struct _SSL_OPENSSL_CRYPTO_OP SSL_OPENSSL_CRYPTO_OP;

