/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/OpensslCryptoOp.h>

#include "OpenSSLDxeInternal.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static SSL_OPENSSL_CRYPTO_OP internalCryptoOperations;

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_RC4(
  RC4_KEY *key, 
  size_t len, 
  const unsigned char *indata, 
  unsigned char *outdata
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  RC4(key, len, indata, outdata);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_RC4_set_key(
  RC4_KEY *key, 
  int len, 
  const unsigned char *data
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  RC4_set_key(key, len, data);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD4_Init(
  MD4_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD4_Init(c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD4_Update(
  MD4_CTX *c, 
  const void *data, 
  size_t len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD4_Update(c, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD4_Final(
  unsigned char *md, 
  MD4_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD4_Final(md, c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD5_Init(
  MD5_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD5_Init(c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD5_Update(
  MD5_CTX *c, 
  const void *data, 
  size_t len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD5_Update(c, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_MD5_Final(
  unsigned char *md, 
  MD5_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = MD5_Final(md, c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SHA1_Init(
  SHA_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SHA1_Init(c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SHA1_Update(
  SHA_CTX *c, 
  const void *data, 
  size_t len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SHA1_Update(c, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SHA1_Final(
  unsigned char *md, 
  SHA_CTX *c
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SHA1_Final(md, c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_HMAC_CTX_init(
  HMAC_CTX *ctx
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  HMAC_CTX_init(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_HMAC_CTX_cleanup(
  HMAC_CTX *ctx
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  HMAC_CTX_cleanup(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned char *
OPENSSL_HMAC(
  const EVP_MD *evp_md, 
  const void *key, 
  int key_len, 
  const unsigned char *d, 
  size_t n, 
  unsigned char *md, 
  unsigned int *md_len
)
{
  unsigned char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = HMAC(evp_md, key, key_len, d, n, md, md_len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_HMAC_Init_ex(
  HMAC_CTX *ctx, 
  const void *key, 
  int len, 
  const EVP_MD *md, 
  ENGINE *impl
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = HMAC_Init_ex(ctx, key, len, md, impl);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_HMAC_Update(
  HMAC_CTX *ctx, 
  const unsigned char *data, 
  size_t len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = HMAC_Update(ctx, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_HMAC_Final(
  HMAC_CTX *ctx, 
  unsigned char *md, 
  unsigned int *len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = HMAC_Final(ctx, md, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BN_CTX *
OPENSSL_BN_CTX_new(
  void
)
{
  BN_CTX *ctx;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ctx = BN_CTX_new();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return ctx;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_BN_CTX_free(
  BN_CTX *c
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BN_CTX_free(c);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIGNUM *
OPENSSL_BN_new (
  void
)
{
  BIGNUM *bn;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  bn = BN_new();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return bn;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_BN_free (
  BIGNUM *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BN_free(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_BN_init(
  BIGNUM *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BN_init(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_BN_clear_free(
  BIGNUM *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BN_clear_free(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_BN_set_word (
  BIGNUM *a,
  BN_ULONG w
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BN_set_word(a, w);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BN_mod_exp(
  BIGNUM *r, 
  const BIGNUM *a, 
  const BIGNUM *p, 
  const BIGNUM *m,
  BN_CTX *ctx
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BN_mod_exp(r, a, p, m, ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BN_num_bits(
  const BIGNUM *a
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BN_num_bits(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BN_num_bytes(
  const BIGNUM *a
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BN_num_bytes(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIGNUM *
OPENSSL_BN_bin2bn(
  const unsigned char *s,
  int len,
  BIGNUM *ret
)
{
  BIGNUM *bn;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  bn = BN_bin2bn(s, len, ret);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return bn;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BN_bn2bin(
  const BIGNUM *a, 
  unsigned char *to
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BN_bn2bin(a, to);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_OBJ_cmp (
  const ASN1_OBJECT *a,
  const ASN1_OBJECT *b
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = OBJ_cmp(a, b);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
ASN1_OBJECT *
OPENSSL_OBJ_nid2obj (
  int n
)
{
  ASN1_OBJECT *obj;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  obj = OBJ_nid2obj(n);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return obj;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
char *
OPENSSL_ERR_error_string(
  unsigned long e,
  char *buf
)
{
  char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = ERR_error_string(e, buf);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_ERR_error_string_n (
  unsigned long e,
  char *buf,
  size_t len
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ERR_error_string_n(e, buf, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned long
OPENSSL_ERR_peek_error (
  void
)
{
  unsigned long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = ERR_peek_error();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned long 
OPENSSL_ERR_get_error(
  void
)
{
  unsigned long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = ERR_get_error();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned long
OPENSSL_ERR_get_error_line (
  const char **file,
  int *line
)
{
  unsigned long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = ERR_get_error_line(file, line);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_ERR_remove_state (
  unsigned long pid
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ERR_remove_state(pid);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_ERR_free_strings (
  void
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ERR_free_strings();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
DH *
OPENSSL_PEM_read_bio_DHparams (
  BIO *bp,
  DH **x,
  pem_password_cb *cb,
  void *u
)
{
  DH *dh;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  dh = PEM_read_bio_DHparams(bp, x, cb, u);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return dh;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
RSA *
OPENSSL_PEM_read_bio_RSAPrivateKey (
  BIO *bp,
  RSA **x,
  pem_password_cb *cb,
  void *u
)
{
  RSA *rsa;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rsa = PEM_read_bio_RSAPrivateKey(bp, x, cb, u);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return rsa;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
RSA *
OPENSSL_RSA_generate_key_func (
  int bits,
  unsigned long e_value,
  void (*callback)(int,int,void *),
  void *cb_arg
)
{
  RSA *rsa;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rsa = RSA_generate_key(bits, e_value, callback, cb_arg);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return rsa;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_RSA_generate_key_ex (
  RSA *rsa,
  int bits,
  BIGNUM *e_value,
  BN_GENCB *cb
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = RSA_generate_key_ex(rsa, bits, e_value, cb);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
RSA *
OPENSSL_RSA_new (
  void
)
{
  RSA *rsa;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rsa = RSA_new();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return rsa;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_RSA_free (
  RSA *r
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  RSA_free(r);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_RSA_check_key(
  const RSA *key
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = RSA_check_key(key);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_GENERAL_NAMES_free (
  STACK_OF(GENERAL_NAME) *alt
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  GENERAL_NAMES_free(alt);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
DH *
OPENSSL_DH_generate_parameters (
  int prime_len,
  int generator,
  void (*callback)(int,int,void *),
  void *cb_arg
)
{
  DH *dh;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  dh = DH_generate_parameters(prime_len, generator, callback, cb_arg);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return dh;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_DH_size (
  const DH *dh
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = DH_size(dh);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_CRYPTO_set_locking_callback (
  void (*func)(int mode,
               int type,
					     const char *file,
					     int line)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CRYPTO_set_locking_callback(func);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_CRYPTO_set_id_callback (
  unsigned long (*func)(void)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CRYPTO_set_id_callback(func);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_CRYPTO_add_func (
  int *pointer,
  int amount,
  int type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = CRYPTO_add(pointer, amount, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_CRYPTO_free (
  void *str
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CRYPTO_free(str);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_EVP_CIPHER_CTX_init(
  EVP_CIPHER_CTX *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  EVP_CIPHER_CTX_init(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_EVP_CIPHER_CTX_cleanup(
  EVP_CIPHER_CTX *a
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_CIPHER_CTX_cleanup(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_EVP_CIPHER_CTX_set_padding(
  EVP_CIPHER_CTX *c, 
  int pad
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_CIPHER_CTX_set_padding(c, pad);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_EVP_PKEY_free(
  EVP_PKEY *pkey
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  EVP_PKEY_free(pkey);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_EVP_cleanup (
  void
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  EVP_cleanup();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const EVP_MD *
OPENSSL_EVP_sha256(
  void
)
{
  const EVP_MD *md;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  md = EVP_sha256();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return md;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const EVP_MD *
OPENSSL_EVP_md5(
  void
)
{
  const EVP_MD *md;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  md = EVP_md5();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return md;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const EVP_MD *
OPENSSL_EVP_sha1(
  void
)
{
  const EVP_MD *md;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  md = EVP_sha1();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return md;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const EVP_CIPHER *
OPENSSL_EVP_des_ede3_cbc(
  void
)
{
  const EVP_CIPHER *cipher;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cipher = EVP_des_ede3_cbc();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cipher;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_EVP_EncryptInit_ex(
  EVP_CIPHER_CTX *ctx,
  const EVP_CIPHER *cipher, 
  ENGINE *impl, 
  const unsigned char *key, 
  const unsigned char *iv
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_EVP_EncryptUpdate(
  EVP_CIPHER_CTX *ctx, 
  unsigned char *out, 
  int *outl, 
  const unsigned char *in, 
  int inl
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_EncryptUpdate(ctx, out, outl, in, inl);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_EVP_DecryptInit_ex(
  EVP_CIPHER_CTX *ctx,
  const EVP_CIPHER *cipher, 
  ENGINE *impl, 
  const unsigned char *key, 
  const unsigned char *iv
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_EVP_DecryptUpdate(
  EVP_CIPHER_CTX *ctx, 
  unsigned char *out, 
  int *outl, 
  const unsigned char *in, 
  int inl
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = EVP_DecryptUpdate(ctx, out, outl, in, inl);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_RAND_seed (
  const void *buf,
  int num
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  RAND_seed(buf, num);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_RAND_pseudo_bytes(
  unsigned char *buf,
  int num
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = RAND_pseudo_bytes(buf, num);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_RAND_bytes(
  unsigned char *buf,
  int num
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = RAND_bytes(buf, num);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_OPENSSL_config_mem (
  const char *config_name,
  BIO *bp
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  OPENSSL_config_mem(config_name, bp);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned char *
OPENSSL_ASN1_STRING_data (
  ASN1_STRING *x
)
{
  unsigned char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = ASN1_STRING_data(x);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_ASN1_STRING_length (
  const ASN1_STRING *x
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = ASN1_STRING_length(x);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_ASN1_STRING_to_UTF8(
  unsigned char **out, 
  ASN1_STRING *in
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = ASN1_STRING_to_UTF8(out, in);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
size_t
OPENSSL_i2d_X509_NAME (
  X509_NAME *a,
  unsigned char **out
)
{
  size_t d;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  d = i2d_X509_NAME(a, out);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return d;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_i2d_PublicKey(
  EVP_PKEY *a, 
  unsigned char **pp
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = i2d_PublicKey(a, pp);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509 *
OPENSSL_d2i_X509(
  X509 **a, 
  const unsigned char **in, 
  long len
)
{
  X509 *cert;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cert = d2i_X509(a, in, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cert;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL direct operations structure */
//------------------------------------------------------------------------------
VOID*
InitCryptoDirectOp (
  IN VOID
)
{
  internalCryptoOperations.RC4                  = OPENSSL_RC4;
  internalCryptoOperations.RC4_set_key          = OPENSSL_RC4_set_key;

  internalCryptoOperations.MD4_Init             = OPENSSL_MD4_Init;
  internalCryptoOperations.MD4_Update           = OPENSSL_MD4_Update;
  internalCryptoOperations.MD4_Final            = OPENSSL_MD4_Final;

  internalCryptoOperations.MD5_Init             = OPENSSL_MD5_Init;
  internalCryptoOperations.MD5_Update           = OPENSSL_MD5_Update;
  internalCryptoOperations.MD5_Final            = OPENSSL_MD5_Final;

  internalCryptoOperations.SHA1_Init            = OPENSSL_SHA1_Init;
  internalCryptoOperations.SHA1_Update          = OPENSSL_SHA1_Update;
  internalCryptoOperations.SHA1_Final           = OPENSSL_SHA1_Final;

  internalCryptoOperations.HMAC_CTX_init        = OPENSSL_HMAC_CTX_init;
  internalCryptoOperations.HMAC_CTX_cleanup     = OPENSSL_HMAC_CTX_cleanup;

  internalCryptoOperations.HMAC                 = OPENSSL_HMAC;
  internalCryptoOperations.HMAC_Init_ex         = OPENSSL_HMAC_Init_ex;
  internalCryptoOperations.HMAC_Update          = OPENSSL_HMAC_Update;
  internalCryptoOperations.HMAC_Final           = OPENSSL_HMAC_Final;

  internalCryptoOperations.BN_CTX_new           = OPENSSL_BN_CTX_new;
  internalCryptoOperations.BN_CTX_free          = OPENSSL_BN_CTX_free;

  internalCryptoOperations.BN_new               = OPENSSL_BN_new;
  internalCryptoOperations.BN_free              = OPENSSL_BN_free;
  internalCryptoOperations.BN_init              = OPENSSL_BN_init;
  internalCryptoOperations.BN_clear_free        = OPENSSL_BN_clear_free;
  internalCryptoOperations.BN_set_word          = OPENSSL_BN_set_word;
  internalCryptoOperations.BN_mod_exp           = OPENSSL_BN_mod_exp;
  internalCryptoOperations.BN_num_bits          = OPENSSL_BN_num_bits;
  internalCryptoOperations.BN_num_bytes_func    = OPENSSL_BN_num_bytes;
  internalCryptoOperations.BN_bin2bn            = OPENSSL_BN_bin2bn;
  internalCryptoOperations.BN_bn2bin            = OPENSSL_BN_bn2bin;

  internalCryptoOperations.OBJ_cmp              = OPENSSL_OBJ_cmp;
  internalCryptoOperations.OBJ_nid2obj          = OPENSSL_OBJ_nid2obj;

  internalCryptoOperations.ERR_error_string     = OPENSSL_ERR_error_string;
  internalCryptoOperations.ERR_error_string_n   = OPENSSL_ERR_error_string_n;
  internalCryptoOperations.ERR_peek_error       = OPENSSL_ERR_peek_error;
  internalCryptoOperations.ERR_get_error        = OPENSSL_ERR_get_error;
  internalCryptoOperations.ERR_get_error_line   = OPENSSL_ERR_get_error_line;
  internalCryptoOperations.ERR_remove_state     = OPENSSL_ERR_remove_state;
  internalCryptoOperations.ERR_free_strings     = OPENSSL_ERR_free_strings;

  internalCryptoOperations.PEM_read_bio_DHparams_func = OPENSSL_PEM_read_bio_DHparams;
  internalCryptoOperations.PEM_read_bio_RSAPrivateKey = OPENSSL_PEM_read_bio_RSAPrivateKey;

  internalCryptoOperations.RSA_generate_key_func    = OPENSSL_RSA_generate_key_func;
  internalCryptoOperations.RSA_generate_key_ex      = OPENSSL_RSA_generate_key_ex;
  internalCryptoOperations.RSA_new                  = OPENSSL_RSA_new;
  internalCryptoOperations.RSA_free                 = OPENSSL_RSA_free;
  internalCryptoOperations.RSA_check_key            = OPENSSL_RSA_check_key;

  internalCryptoOperations.GENERAL_NAMES_free_func  = OPENSSL_GENERAL_NAMES_free;

  internalCryptoOperations.DH_generate_parameters   = OPENSSL_DH_generate_parameters;
  internalCryptoOperations.DH_size                  = OPENSSL_DH_size;

  internalCryptoOperations.CRYPTO_set_locking_callback = OPENSSL_CRYPTO_set_locking_callback;
  internalCryptoOperations.CRYPTO_set_id_callback      = OPENSSL_CRYPTO_set_id_callback;
  internalCryptoOperations.CRYPTO_add_func             = OPENSSL_CRYPTO_add_func;
  internalCryptoOperations.CRYPTO_free                 = OPENSSL_CRYPTO_free;

  internalCryptoOperations.EVP_CIPHER_CTX_init        = OPENSSL_EVP_CIPHER_CTX_init;
  internalCryptoOperations.EVP_CIPHER_CTX_cleanup     = OPENSSL_EVP_CIPHER_CTX_cleanup;
  internalCryptoOperations.EVP_CIPHER_CTX_set_padding = OPENSSL_EVP_CIPHER_CTX_set_padding;

  internalCryptoOperations.EVP_PKEY_free        = OPENSSL_EVP_PKEY_free;

  internalCryptoOperations.EVP_cleanup          = OPENSSL_EVP_cleanup;

  internalCryptoOperations.EVP_EncryptInit_ex   = OPENSSL_EVP_EncryptInit_ex;
  internalCryptoOperations.EVP_EncryptUpdate    = OPENSSL_EVP_EncryptUpdate;
  internalCryptoOperations.EVP_DecryptInit_ex   = OPENSSL_EVP_DecryptInit_ex;
  internalCryptoOperations.EVP_DecryptUpdate    = OPENSSL_EVP_DecryptUpdate;

  internalCryptoOperations.EVP_sha256           = OPENSSL_EVP_sha256;
  internalCryptoOperations.EVP_md5              = OPENSSL_EVP_md5;
  internalCryptoOperations.EVP_sha1             = OPENSSL_EVP_sha1;
  internalCryptoOperations.EVP_des_ede3_cbc     = OPENSSL_EVP_des_ede3_cbc;

  internalCryptoOperations.RAND_seed            = OPENSSL_RAND_seed;
  internalCryptoOperations.RAND_pseudo_bytes    = OPENSSL_RAND_pseudo_bytes;
  internalCryptoOperations.RAND_bytes           = OPENSSL_RAND_bytes;

  internalCryptoOperations.OPENSSL_config_mem   = OPENSSL_OPENSSL_config_mem;

  internalCryptoOperations.ASN1_STRING_data     = OPENSSL_ASN1_STRING_data;
  internalCryptoOperations.ASN1_STRING_length   = OPENSSL_ASN1_STRING_length;
  internalCryptoOperations.ASN1_STRING_to_UTF8  = OPENSSL_ASN1_STRING_to_UTF8;

  internalCryptoOperations.i2d_X509_NAME_func   = OPENSSL_i2d_X509_NAME;
  internalCryptoOperations.i2d_PublicKey        = OPENSSL_i2d_PublicKey;
  internalCryptoOperations.d2i_X509             = OPENSSL_d2i_X509;

  return (VOID*)&internalCryptoOperations;
}
//------------------------------------------------------------------------------

