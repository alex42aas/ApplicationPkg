/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/OpensslProtocol.h>
#include <Protocol/OpensslSSLOp.h>

#include "OpenSSLDxeInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static SSL_OPENSSL_DIRECT_OP internalSSLDirectOperations;

//------------------------------------------------------------------------------
/*! \brief Initialize all algorithms of OpenSSL lib */
//------------------------------------------------------------------------------
int
OPENSSL_SSL_library_init (
  void
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  retval = SSL_library_init();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_load_error_strings (
  void
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_load_error_strings();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
SSL *
OPENSSL_SSL_new (
  SSL_CTX *ctx
)
{
  SSL *ssl;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ssl = SSL_new(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return ssl;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_SSL_free (
  SSL *ssl
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_free(ssl);
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_SSL_pending (
  const SSL *s
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_pending(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_shutdown (
  SSL *s
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_shutdown(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_connect (
  SSL *s
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_connect(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_accept (
  SSL *s
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_accept(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_read (
  SSL *s,
  void *buf,
  int num
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_read(s, buf, num);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_write (
  SSL *s,
  const void *buf,
  int num
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_write(s, buf, num);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const char *
OPENSSL_SSL_state_string_long (
  const SSL *s
)
{
  const char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = SSL_state_string_long(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STACK_OF(X509_NAME) *
OPENSSL_SSL_load_client_CA_file (
  const char *file
)
{
  STACK_OF(X509_NAME) *stack;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  stack = SSL_load_client_CA_file(file);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return stack;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_SSL_use_certificate_file(
  SSL *ssl, 
  const char *file, 
  int type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_use_certificate_file(ssl, file, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_add_dir_cert_subjects_to_stack (
  STACK_OF(X509_NAME) *stack,
  const char *dir
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_add_dir_cert_subjects_to_stack(stack, dir);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const char *
OPENSSL_SSL_alert_type_string_long (
  int value
)
{
  const char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = SSL_alert_type_string_long(value);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const char *
OPENSSL_SSL_alert_desc_string_long(
  int value
)
{
  const char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = SSL_alert_desc_string_long(value);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_set_bio (
  SSL *s,
  BIO *rbio,
  BIO *wbio
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_set_bio(s, rbio, wbio);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const SSL_CIPHER *
OPENSSL_SSL_get_current_cipher (
  const SSL *s
)
{
  const SSL_CIPHER *cipher;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cipher = SSL_get_current_cipher(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cipher;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_get_error (
  const SSL *s,
  int i
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_get_error(s, i);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long 
OPENSSL_SSL_get_verify_result (
  const SSL *ssl
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_get_verify_result(ssl);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509 *
OPENSSL_SSL_get_certificate (
  const SSL *s
)
{
  X509 *cert;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cert = SSL_get_certificate(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cert;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509 *
OPENSSL_SSL_get_peer_certificate (
  const SSL *s
)
{
  X509 *cert;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cert = SSL_get_peer_certificate(s);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cert;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_CTX_use_certificate_file (
  SSL_CTX *ctx,
  const char *file,
  int type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_use_certificate_file(ctx, file, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_CTX_use_PrivateKey_file (
  SSL_CTX *ctx,
  const char *file,
  int type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_use_PrivateKey_file(ctx, file, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_SSL_CTX_use_RSAPrivateKey_file(
  SSL_CTX *ctx, 
  const char *file, 
  int type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_use_RSAPrivateKey_file(ctx, file, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_CTX_set_info_callback (
  SSL_CTX *ctx, 
	void (*cb)(const SSL *ssl,int type,int val)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_CTX_set_info_callback(ctx, cb);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_SSL_CTX_set_verify (
  SSL_CTX *ctx,
  int mode,
  int (*cb)(int, X509_STORE_CTX *)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_CTX_set_verify(ctx, mode, cb);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_CTX_set_tmp_rsa_callback (
  SSL_CTX *ctx,
  RSA *(*cb)(SSL *ssl,
             int is_export,
             int keylength)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_CTX_set_tmp_rsa_callback(ctx, cb);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_CTX_set_tmp_dh_callback (
  SSL_CTX *ctx,
  DH *(*dh)(SSL *ssl,
            int is_export,
            int keylength)
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_CTX_set_tmp_dh_callback(ctx, dh);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_CTX_set_session_id_context (
  SSL_CTX *ctx,
  const unsigned char *sid_ctx,
  unsigned int sid_ctx_len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long
OPENSSL_SSL_CTX_set_options(
  SSL_CTX *ctx,
  long op
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_set_options(ctx, op);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_CTX_set_cipher_list (
  SSL_CTX *ctx,
  const char *str
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_set_cipher_list(ctx, str);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long
OPENSSL_SSL_CTX_set_mode(
  SSL_CTX *ctx,
  long op
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_set_mode(ctx, op);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_STORE *
OPENSSL_SSL_CTX_get_cert_store (
  const SSL_CTX *ctx
)
{
  X509_STORE *store;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  store = SSL_CTX_get_cert_store(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return store;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
SSL_CTX *
OPENSSL_SSL_CTX_new (
  const SSL_METHOD *meth
)
{
  SSL_CTX *ctx;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ctx = SSL_CTX_new(meth);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return ctx;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_SSL_CTX_free (
  SSL_CTX *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  SSL_CTX_free(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long 
OPENSSL_SSL_CTX_ctrl(
  SSL_CTX *ctx,
  int cmd, 
  long larg, 
  void *parg
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CTX_ctrl(ctx, cmd, larg, parg);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_SSL_CIPHER_get_bits (
  const SSL_CIPHER *c,
  int *alg_bits
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = SSL_CIPHER_get_bits(c, alg_bits);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const SSL_METHOD *
OPENSSL_SSLv23_method (
  void
)
{
  const SSL_METHOD *meths;

  meths = SSLv23_method();

  return meths;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const SSL_METHOD *
OPENSSL_SSLv23_server_method(
  void
)
{
  const SSL_METHOD *meths;

  meths = SSLv23_server_method();

  return meths;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const SSL_METHOD *
OPENSSL_TLSv1_client_method(
  void
)
{
  const SSL_METHOD *meths;

  meths = TLSv1_client_method();

  return meths;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
const SSL_METHOD *
OPENSSL_TLSv1_server_method(
  void
)
{
  const SSL_METHOD *meths;

  meths = TLSv1_server_method();

  return meths;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL SSL direct operations structure */
//------------------------------------------------------------------------------
VOID *
InitSSLDirectOp (
  IN VOID
)
{
  internalSSLDirectOperations.SSL_library_init        = OPENSSL_SSL_library_init;
  internalSSLDirectOperations.SSL_load_error_strings  = OPENSSL_SSL_load_error_strings;

  internalSSLDirectOperations.SSL_new          = OPENSSL_SSL_new;
  internalSSLDirectOperations.SSL_free         = OPENSSL_SSL_free;
  internalSSLDirectOperations.SSL_pending      = OPENSSL_SSL_pending;
  internalSSLDirectOperations.SSL_shutdown     = OPENSSL_SSL_shutdown;
  internalSSLDirectOperations.SSL_connect      = OPENSSL_SSL_connect;
  internalSSLDirectOperations.SSL_accept       = OPENSSL_SSL_accept;
  internalSSLDirectOperations.SSL_read         = OPENSSL_SSL_read;
  internalSSLDirectOperations.SSL_write        = OPENSSL_SSL_write;
  internalSSLDirectOperations.SSL_state_string_long  = OPENSSL_SSL_state_string_long;
  internalSSLDirectOperations.SSL_load_client_CA_file = OPENSSL_SSL_load_client_CA_file;
  internalSSLDirectOperations.SSL_use_certificate_file = OPENSSL_SSL_use_certificate_file;
  internalSSLDirectOperations.SSL_add_dir_cert_subjects_to_stack = OPENSSL_SSL_add_dir_cert_subjects_to_stack;

  internalSSLDirectOperations.SSL_alert_type_string_long = OPENSSL_SSL_alert_type_string_long;
  internalSSLDirectOperations.SSL_alert_desc_string_long = OPENSSL_SSL_alert_desc_string_long;

  internalSSLDirectOperations.SSL_set_bio  = OPENSSL_SSL_set_bio;

  internalSSLDirectOperations.SSL_get_current_cipher    = OPENSSL_SSL_get_current_cipher;
  internalSSLDirectOperations.SSL_get_error             = OPENSSL_SSL_get_error;
  internalSSLDirectOperations.SSL_get_verify_result     = OPENSSL_SSL_get_verify_result;
  internalSSLDirectOperations.SSL_get_certificate       = OPENSSL_SSL_get_certificate;
  internalSSLDirectOperations.SSL_get_peer_certificate  = OPENSSL_SSL_get_peer_certificate;

  internalSSLDirectOperations.SSL_CTX_use_certificate_file    = OPENSSL_SSL_CTX_use_certificate_file;
  internalSSLDirectOperations.SSL_CTX_use_PrivateKey_file     = OPENSSL_SSL_CTX_use_PrivateKey_file;
  internalSSLDirectOperations.SSL_CTX_use_RSAPrivateKey_file  = OPENSSL_SSL_CTX_use_RSAPrivateKey_file;

  internalSSLDirectOperations.SSL_CTX_set_info_callback       = OPENSSL_SSL_CTX_set_info_callback;
  internalSSLDirectOperations.SSL_CTX_set_verify              = OPENSSL_SSL_CTX_set_verify;
  internalSSLDirectOperations.SSL_CTX_set_tmp_rsa_callback    = OPENSSL_SSL_CTX_set_tmp_rsa_callback;
  internalSSLDirectOperations.SSL_CTX_set_tmp_dh_callback     = OPENSSL_SSL_CTX_set_tmp_dh_callback;
  internalSSLDirectOperations.SSL_CTX_set_session_id_context  = OPENSSL_SSL_CTX_set_session_id_context;
  internalSSLDirectOperations.SSL_CTX_set_options_func        = OPENSSL_SSL_CTX_set_options;
  internalSSLDirectOperations.SSL_CTX_set_cipher_list         = OPENSSL_SSL_CTX_set_cipher_list;
  internalSSLDirectOperations.SSL_CTX_set_mode_func           = OPENSSL_SSL_CTX_set_mode;

  internalSSLDirectOperations.SSL_CTX_get_cert_store  = OPENSSL_SSL_CTX_get_cert_store;

  internalSSLDirectOperations.SSL_CTX_new  = OPENSSL_SSL_CTX_new;
  internalSSLDirectOperations.SSL_CTX_free = OPENSSL_SSL_CTX_free;
  internalSSLDirectOperations.SSL_CTX_ctrl = OPENSSL_SSL_CTX_ctrl;

  internalSSLDirectOperations.SSL_CIPHER_get_bits = OPENSSL_SSL_CIPHER_get_bits;

  internalSSLDirectOperations.SSLv23_method        = OPENSSL_SSLv23_method;
  internalSSLDirectOperations.SSLv23_server_method = OPENSSL_SSLv23_server_method;
  internalSSLDirectOperations.TLSv1_client_method  = OPENSSL_TLSv1_client_method;
  internalSSLDirectOperations.TLSv1_server_method  = OPENSSL_TLSv1_server_method;

  return (VOID*)&internalSSLDirectOperations;
}
//------------------------------------------------------------------------------

