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
 *  \brief OpenSSL X509 direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#ifndef OPENSSL_X509_OP_H_
#define OPENSSL_X509_OP_H_

#include <openssl/ssl.h>

typedef
ASN1_STRING *
(EFIAPI *OPENSSL_X509_NAME_ENTRY_GET_DATA) (
  X509_NAME_ENTRY *ne
);

typedef
int 
(EFIAPI *OPENSSL_X509_NAME_ENTRY_ENTRY_COUNT) (
  X509_NAME *name
);

typedef
X509_NAME_ENTRY *
(EFIAPI* OPENSSL_X509_NAME_GET_ENTRY) (
  X509_NAME *name,
  int loc
);

typedef
int	
(EFIAPI *OPENSSL_X509_NAME_GET_INDEX_BY_NID) (
  X509_NAME *name,
  int nid,
  int lastpos
);

typedef
char *
(EFIAPI *OPENSSL_X509_NAME_ONELINE) (
  X509_NAME *a,
  char *buf,
  int len
);

typedef
int 
(EFIAPI *OPENSSL_X509_NAME_PRINT_EX) (
  BIO *out, 
  X509_NAME *nm, 
  int indent, 
  unsigned long flags
);

typedef
int 
(EFIAPI *OPENSSL_X509_DIGEST) (
  const X509 *data,
  const EVP_MD *type, 
  unsigned char *md, 
  unsigned int *len
);

typedef
int	
(EFIAPI *OPENSSL_X509_VERIFY_CERT) (
  X509_STORE_CTX *ctx
);

typedef
const char *
(EFIAPI *OPENSSL_X509_VERIFY_CERT_ERROR_STR) (
  long n
);

typedef
X509_NAME *
(EFIAPI *OPENSSL_X509_GET_ISSUER_NAME) (
  X509 *a
);

typedef
X509_NAME *
(EFIAPI *OPENSSL_X509_GET_SUBJECT_NAME) (
  X509 *a
);

typedef
EVP_PKEY *
(EFIAPI *OPENSSL_X509_GET_PUBKEY) (
  X509 *x
);

typedef
int 
(EFIAPI* OPENSSL_X509_GET_EXT_BY_NID) (
  X509 *x,
  int nid,
  int lastpos
);

typedef
X509_EXTENSION *
(EFIAPI* OPENSSL_X509_GET_EXT) (
  X509 *x,
  int loc
);

typedef
void *
(EFIAPI *OPENSSL_X509_GET_EXT_D2I) (
  X509 *x, 
  int nid, 
  int *crit, 
  int *idx
);

typedef
void
(EFIAPI *OPENSSL_X509_FREE) (
  X509 *a
);

typedef
int 
(EFIAPI *OPENSSL_X509_LOOKUP_CTRL) (
  X509_LOOKUP *ctx, 
  int cmd, 
  const char *argc, 
  long argl, 
  char **ret
);

typedef
X509_LOOKUP_METHOD *
(EFIAPI *OPENSSL_X509_LOOKUP_FILE) (
  void
);

typedef
X509_LOOKUP_METHOD *
(EFIAPI *OPENSSL_X509_LOOKUP_HASH_DIR) (
  void
);

typedef
int 
(EFIAPI *OPENSSL_X509_LOOKUP_ADD_DIR) (
  X509_LOOKUP *x, 
  const char *name, 
  long type
);

typedef
X509_STORE_CTX *
(EFIAPI *OPENSSL_X509_STORE_CTX_NEW) (
  void
);

typedef
int 
(EFIAPI *OPENSSL_X509_STORE_CTX_INIT) (
  X509_STORE_CTX *ctx, 
  X509_STORE *store, 
  X509 *x509, 
  STACK_OF(X509) *chain
);

typedef
void 
(EFIAPI *OPENSSL_X509_STORE_CTX_FREE) (
  X509_STORE_CTX *ctx
);

typedef
X509 *
(EFIAPI *OPENSSL_X509_STORE_CTX_GET_CURRENT_CERT) (
  X509_STORE_CTX *ctx
);

typedef
int
(EFIAPI *OPENSSL_X509_STORE_CTX_GET_ERROR) (
  X509_STORE_CTX *ctx
);

typedef
int 
(EFIAPI *OPENSSL_X509_STORE_CTX_GET_ERROR_DEPTH) (
  X509_STORE_CTX *ctx
);

typedef
X509_STORE *
(EFIAPI *OPENSSL_X509_STORE_NEW) (
  void
);

typedef
void 
(EFIAPI *OPENSSL_X509_STORE_FREE) (
  X509_STORE *v
);

typedef
X509_LOOKUP *
(EFIAPI *OPENSSL_X509_STORE_ADD_LOOKUP) (
  X509_STORE *v, 
  X509_LOOKUP_METHOD *m
);

typedef
int
(EFIAPI *OPENSSL_X509_STORE_SET_FLAGS) (
  X509_STORE *ctx,
  unsigned long flags
);

typedef
int 
(EFIAPI *OPENSSL_X509V3_ADD_STANDART_EXTENSIONS) (
  void
);

typedef
void *
(EFIAPI *OPENSSL_X509V3_EXT_D2I) (
  X509_EXTENSION *ext
);

struct _X509_OPENSSL_DIRECT_OP {
  OPENSSL_X509_NAME_ENTRY_GET_DATA        X509_NAME_ENTRY_get_data;
  OPENSSL_X509_NAME_ENTRY_ENTRY_COUNT     X509_NAME_entry_count;
  OPENSSL_X509_NAME_GET_ENTRY             X509_NAME_get_entry;
  OPENSSL_X509_NAME_GET_INDEX_BY_NID      X509_NAME_get_index_by_NID;
  OPENSSL_X509_NAME_ONELINE               X509_NAME_oneline;
  OPENSSL_X509_NAME_PRINT_EX              X509_NAME_print_ex;

  OPENSSL_X509_DIGEST                     X509_digest;
  OPENSSL_X509_VERIFY_CERT                X509_verify_cert;
  OPENSSL_X509_VERIFY_CERT_ERROR_STR      X509_verify_cert_error_string;
  OPENSSL_X509_GET_ISSUER_NAME            X509_get_issuer_name;
  OPENSSL_X509_GET_SUBJECT_NAME           X509_get_subject_name;
  OPENSSL_X509_GET_PUBKEY                 X509_get_pubkey;
  OPENSSL_X509_GET_EXT_BY_NID             X509_get_ext_by_NID;
  OPENSSL_X509_GET_EXT                    X509_get_ext;
  OPENSSL_X509_GET_EXT_D2I                X509_get_ext_d2i;
  OPENSSL_X509_FREE                       X509_free;

  OPENSSL_X509_LOOKUP_CTRL                X509_LOOKUP_ctrl;
  OPENSSL_X509_LOOKUP_FILE                X509_LOOKUP_file;
  OPENSSL_X509_LOOKUP_HASH_DIR            X509_LOOKUP_hash_dir;
  OPENSSL_X509_LOOKUP_ADD_DIR             X509_LOOKUP_add_dir_func;

  OPENSSL_X509_STORE_CTX_NEW              X509_STORE_CTX_new;
  OPENSSL_X509_STORE_CTX_INIT             X509_STORE_CTX_init;
  OPENSSL_X509_STORE_CTX_FREE             X509_STORE_CTX_free;
  OPENSSL_X509_STORE_CTX_GET_CURRENT_CERT X509_STORE_CTX_get_current_cert;
  OPENSSL_X509_STORE_CTX_GET_ERROR        X509_STORE_CTX_get_error;
  OPENSSL_X509_STORE_CTX_GET_ERROR_DEPTH  X509_STORE_CTX_get_error_depth;

  OPENSSL_X509_STORE_NEW                  X509_STORE_new;
  OPENSSL_X509_STORE_FREE                 X509_STORE_free;
  OPENSSL_X509_STORE_ADD_LOOKUP           X509_STORE_add_lookup;
  OPENSSL_X509_STORE_SET_FLAGS            X509_STORE_set_flags;

  OPENSSL_X509V3_ADD_STANDART_EXTENSIONS  X509V3_add_standard_extensions;
  OPENSSL_X509V3_EXT_D2I                  X509V3_EXT_d2i;
  };

typedef struct _X509_OPENSSL_DIRECT_OP X509_OPENSSL_DIRECT_OP;

#endif // OPENSSL_X509_OP_H_