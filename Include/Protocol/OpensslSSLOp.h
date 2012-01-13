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
 *  \brief OpenSSL SSL direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#ifndef OPENSSL_SSL_OP_H_
#define OPENSSL_SSL_OP_H_

#include <openssl/ssl.h>

typedef
int
(EFIAPI *OPENSSL_SSL_LIBRARY_INIT) (
  void
);

typedef
void 
(EFIAPI *OPENSSL_SSL_LOAD_ERROR_STRINGS) (
  void
);

typedef
SSL_CTX *
(EFIAPI *OPENSSL_SSL_CTX_NEW) (
  const SSL_METHOD *meth
);

typedef
void 
(EFIAPI *OPENSSL_SSL_CTX_FREE) (
  SSL_CTX *a
);

typedef
int
(EFIAPI *OPENSSL_SSL_PENDING) (
  const SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_SHUTDOWN) (
  SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CONNECT) (
  SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_ACCEPT) (
  SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_READ) (
  SSL *s,
  void *buf,
  int num
);

typedef
int 
(EFIAPI *OPENSSL_SSL_WRITE) (
  SSL *s,
  const void *buf,
  int num
);

typedef
const char *
(EFIAPI *OPENSSL_SSL_STATE_STRING_LONG) (
  const SSL *s
);

typedef
STACK_OF(X509_NAME) *
(EFIAPI *OPENSSL_SSL_LOAD_CLIENT_CA_FILE) (
  const char *file
);

typedef
int	
(EFIAPI *OPENSSL_SSL_USE_CERTIFICATE_FILE) (
  SSL *ssl, 
  const char *file, 
  int type
);

typedef
int 
(EFIAPI *OPENSSL_SSL_ADD_DIR_CERT_SUBJ_TO_STACK) (
  STACK_OF(X509_NAME) *stack,
  const char *dir
);

typedef
const char *
(EFIAPI *OPENSSL_SSL_ALERT_TYPE_STRING_LONG) (
  int value
);

typedef
const char *
(EFIAPI *OPENSSL_SSL_ALERT_DESC_STRING_LONG) (
  int value
);

typedef
void 
(EFIAPI *OPENSSL_SSL_SET_BIO) (
  SSL *s,
  BIO *rbio,
  BIO *wbio
);

typedef
const SSL_CIPHER *
(EFIAPI *OPENSSL_SSL_GET_CURRENT_CHIPER) (
  const SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_GET_ERROR) (
  const SSL *s,
  int i
);

typedef
long 
(EFIAPI *OPENSSL_SSP_GET_VERIFY_RESULT) (
  const SSL *ssl
);

typedef
X509 *
(EFIAPI *OPENSSL_SSL_GET_CERTIFICATE) (
  const SSL *s
);

typedef
X509 *
(EFIAPI *OPENSSL_SSL_GET_PEER_CERTIFICATE) (
  const SSL *s
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CTX_USE_CERT_FILE) (
  SSL_CTX *ctx,
  const char *file,
  int type
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CTX_USE_PVK_FILE) (
  SSL_CTX *ctx,
  const char *file,
  int type
);

typedef
int	
(EFIAPI *OPENSSL_SSL_CTX_USE_RSAPRIVATEKEY_FILE) (
  SSL_CTX *ctx, 
  const char *file, 
  int type
);


typedef
void 
(EFIAPI *OPENSSL_SSL_CTX_SET_INFO_CB) (
  SSL_CTX *ctx, 
	void (*cb)(const SSL *ssl,int type,int val)
);

typedef
void
(EFIAPI *OPENSSL_SSL_CTX_SET_VERIFY) (
  SSL_CTX *ctx,
  int mode,
  int (*cb)(int, X509_STORE_CTX *)
);

typedef
void 
(EFIAPI *OPENSSL_SSL_CTX_SET_TMP_RSA_CB) (
  SSL_CTX *ctx,
  RSA *(*cb)(SSL *ssl,
             int is_export,
             int keylength)
);

typedef
void 
(EFIAPI *OPENSSL_SSL_CTX_SET_TMP_DH_CB) (
  SSL_CTX *ctx,
  DH *(*dh)(SSL *ssl,
            int is_export,
            int keylength)
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CTX_SET_SESSION_ID_CTX) (
  SSL_CTX *ctx,
  const unsigned char *sid_ctx,
  unsigned int sid_ctx_len
);

typedef
long
(EFIAPI *OPENSSL_SSL_CTX_SET_OPTIONS)(
  SSL_CTX *ctx,
  long op
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CTX_SET_CIPHER_LIST) (
  SSL_CTX *ctx,
  const char *str
);

typedef
long
(EFIAPI *OPENSSL_SSL_CTX_SET_MODE)(
  SSL_CTX *ctx,
  long op
);

typedef
X509_STORE *
(EFIAPI *OPENSSL_SSL_CTX_GET_CERT_STORE) (
  const SSL_CTX *ctx
);

typedef
SSL *
(EFIAPI *OPENSSL_SSL_NEW) (
  SSL_CTX *ctx
);

typedef
void
(EFIAPI *OPENSSL_SSL_FREE) (
  SSL *ssl
);

typedef
long 
(EFIAPI *OPENSSL_SSL_CTX_CTRL) (
  SSL_CTX *ctx,
  int cmd, 
  long larg, 
  void *parg
);

typedef
int 
(EFIAPI *OPENSSL_SSL_CHIPER_GET_BITS) (
  const SSL_CIPHER *c,
  int *alg_bits
);

typedef
const SSL_METHOD *
(EFIAPI *OPENSSL_SSLv23_METHOD) (
  void
);

typedef
const SSL_METHOD *
(EFIAPI *OPENSSL_SSLV23_SERVER_METHOD) (
  void
);

typedef
const SSL_METHOD *
(EFIAPI *OPENSSL_TLSV1_CLIENT_METHOD) (
  void
);

typedef
const SSL_METHOD *
(EFIAPI *OPENSSL_TLSV1_SERVER_METHOD) (
  void
);

struct _SSL_OPENSSL_DIRECT_OP {
  OPENSSL_SSL_LIBRARY_INIT               SSL_library_init;
  OPENSSL_SSL_LOAD_ERROR_STRINGS         SSL_load_error_strings;

  OPENSSL_SSL_NEW                        SSL_new;
  OPENSSL_SSL_FREE                       SSL_free;
  OPENSSL_SSL_PENDING                    SSL_pending;
  OPENSSL_SSL_SHUTDOWN                   SSL_shutdown;
  OPENSSL_SSL_CONNECT                    SSL_connect;
  OPENSSL_SSL_ACCEPT                     SSL_accept;
  OPENSSL_SSL_READ                       SSL_read;
  OPENSSL_SSL_WRITE                      SSL_write;
  OPENSSL_SSL_STATE_STRING_LONG          SSL_state_string_long;
  OPENSSL_SSL_LOAD_CLIENT_CA_FILE        SSL_load_client_CA_file;  
  OPENSSL_SSL_USE_CERTIFICATE_FILE       SSL_use_certificate_file;
  OPENSSL_SSL_ADD_DIR_CERT_SUBJ_TO_STACK SSL_add_dir_cert_subjects_to_stack;

  OPENSSL_SSL_ALERT_TYPE_STRING_LONG     SSL_alert_type_string_long;
  OPENSSL_SSL_ALERT_DESC_STRING_LONG     SSL_alert_desc_string_long;

  OPENSSL_SSL_SET_BIO                    SSL_set_bio;

  OPENSSL_SSL_GET_CURRENT_CHIPER         SSL_get_current_cipher;
  OPENSSL_SSL_GET_ERROR                  SSL_get_error;
  OPENSSL_SSP_GET_VERIFY_RESULT          SSL_get_verify_result;
  OPENSSL_SSL_GET_CERTIFICATE            SSL_get_certificate;
  OPENSSL_SSL_GET_PEER_CERTIFICATE       SSL_get_peer_certificate;

  OPENSSL_SSL_CTX_USE_CERT_FILE          SSL_CTX_use_certificate_file;
  OPENSSL_SSL_CTX_USE_PVK_FILE           SSL_CTX_use_PrivateKey_file;
  OPENSSL_SSL_CTX_USE_RSAPRIVATEKEY_FILE SSL_CTX_use_RSAPrivateKey_file;

  OPENSSL_SSL_CTX_SET_INFO_CB            SSL_CTX_set_info_callback;
  OPENSSL_SSL_CTX_SET_VERIFY             SSL_CTX_set_verify;
  OPENSSL_SSL_CTX_SET_TMP_RSA_CB         SSL_CTX_set_tmp_rsa_callback;
  OPENSSL_SSL_CTX_SET_TMP_DH_CB          SSL_CTX_set_tmp_dh_callback;
  OPENSSL_SSL_CTX_SET_SESSION_ID_CTX     SSL_CTX_set_session_id_context;
  OPENSSL_SSL_CTX_SET_OPTIONS            SSL_CTX_set_options_func;
  OPENSSL_SSL_CTX_SET_CIPHER_LIST        SSL_CTX_set_cipher_list;
  OPENSSL_SSL_CTX_SET_MODE               SSL_CTX_set_mode_func;

  OPENSSL_SSL_CTX_GET_CERT_STORE         SSL_CTX_get_cert_store;

  OPENSSL_SSL_CTX_NEW                    SSL_CTX_new;
  OPENSSL_SSL_CTX_FREE                   SSL_CTX_free;
  OPENSSL_SSL_CTX_CTRL                   SSL_CTX_ctrl;

  OPENSSL_SSL_CHIPER_GET_BITS            SSL_CIPHER_get_bits;  

  OPENSSL_SSLv23_METHOD                  SSLv23_method;
  OPENSSL_SSLV23_SERVER_METHOD           SSLv23_server_method;
  OPENSSL_TLSV1_CLIENT_METHOD            TLSv1_client_method;
  OPENSSL_TLSV1_SERVER_METHOD            TLSv1_server_method;
};

typedef struct _SSL_OPENSSL_DIRECT_OP SSL_OPENSSL_DIRECT_OP;

#endif // OPENSSL_SSL_OP_H_

