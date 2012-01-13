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
#include <Protocol/OpensslX509Op.h>

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "OpenSSLDxeInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC X509_OPENSSL_DIRECT_OP internalX509DirectOperations;

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
ASN1_STRING *
OPENSSL_X509_NAME_ENTRY_get_data (
  X509_NAME_ENTRY *ne
)
{
  ASN1_STRING *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = X509_NAME_ENTRY_get_data(ne);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_NAME_entry_count (
  X509_NAME *name
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_NAME_entry_count(name);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_NAME_ENTRY *
OPENSSL_X509_NAME_get_entry(
  X509_NAME *name,
  int loc
)
{
  X509_NAME_ENTRY *entry;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  entry = X509_NAME_get_entry(name, loc);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return entry;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_X509_NAME_get_index_by_NID(
  X509_NAME *name,
  int nid,
  int lastpos
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_NAME_get_index_by_NID(name, nid, lastpos);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
char *
OPENSSL_X509_NAME_oneline (
  X509_NAME *a,
  char *buf,
  int len
)
{
  char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = X509_NAME_oneline(a, buf, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int 
OPENSSL_X509_NAME_print_ex(
  BIO *out, 
  X509_NAME *nm, 
  int indent, 
  unsigned long flags
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_NAME_print_ex(out, nm, indent, flags);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int 
OPENSSL_X509_digest(
  const X509 *data,
  const EVP_MD *type, 
  unsigned char *md, 
  unsigned int *len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_digest(data, type, md, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int	
OPENSSL_X509_verify_cert(
  X509_STORE_CTX *ctx
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_verify_cert(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
const char *
OPENSSL_X509_verify_cert_error_string(
  long n
)
{
  const char *str;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  str = X509_verify_cert_error_string(n);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return str;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_NAME *
OPENSSL_X509_get_issuer_name (
  X509 *a
)
{
  X509_NAME *name;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  name = X509_get_issuer_name(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return name;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_NAME *
OPENSSL_X509_get_subject_name (
  X509 *a
)
{
  X509_NAME *name;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  name = X509_get_subject_name(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return name;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
EVP_PKEY *
OPENSSL_X509_get_pubkey(
  X509 *x
)
{
  EVP_PKEY *key;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  key = X509_get_pubkey(x);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return key;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_get_ext_by_NID (
  X509 *x,
  int nid,
  int lastpos
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_get_ext_by_NID(x, nid, lastpos);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_EXTENSION *
OPENSSL_X509_get_ext (
  X509 *x,
  int loc
)
{
  X509_EXTENSION *exten;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  exten = X509_get_ext(x, loc);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return exten;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void *
OPENSSL_X509_get_ext_d2i(
  X509 *x, 
  int nid, 
  int *crit, 
  int *idx
)
{
  void *obj;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  obj = X509_get_ext_d2i(x, nid, crit, idx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return obj;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_X509_free (
  X509 *a
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  X509_free(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_LOOKUP_ctrl(
  X509_LOOKUP *ctx, 
  int cmd, 
  const char *argc, 
  long argl, 
  char **ret
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_LOOKUP_ctrl(ctx, cmd, argc, argl, ret);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_LOOKUP_METHOD *
OPENSSL_X509_LOOKUP_file(
  void
)
{
  X509_LOOKUP_METHOD *method;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  method = X509_LOOKUP_file();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return method;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_LOOKUP_METHOD *
OPENSSL_X509_LOOKUP_hash_dir(
  void
)
{
  X509_LOOKUP_METHOD *method;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  method = X509_LOOKUP_hash_dir();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return method;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_LOOKUP_add_dir(
  X509_LOOKUP *x, 
  const char *name, 
  long type
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_LOOKUP_add_dir(x,name,type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_STORE_CTX *
OPENSSL_X509_STORE_CTX_new(
  void
)
{
  X509_STORE_CTX *ctx;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ctx = X509_STORE_CTX_new();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return ctx;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_STORE_CTX_init(
  X509_STORE_CTX *ctx, 
  X509_STORE *store, 
  X509 *x509, 
  STACK_OF(X509) *chain
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_STORE_CTX_init(ctx, store, x509, chain);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_X509_STORE_CTX_free(
  X509_STORE_CTX *ctx
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  X509_STORE_CTX_free(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509 *
OPENSSL_X509_STORE_CTX_get_current_cert (
  X509_STORE_CTX *ctx
)
{
  X509 *cert;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cert = X509_STORE_CTX_get_current_cert(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return cert;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_X509_STORE_CTX_get_error (
  X509_STORE_CTX *ctx
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_STORE_CTX_get_error(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509_STORE_CTX_get_error_depth (
  X509_STORE_CTX *ctx
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_STORE_CTX_get_error_depth(ctx);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_STORE *
OPENSSL_X509_STORE_new(
  void
)
{
  X509_STORE *store;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  store = X509_STORE_new();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return store;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void 
OPENSSL_X509_STORE_free(
  X509_STORE *v
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  X509_STORE_free(v);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
X509_LOOKUP *
OPENSSL_X509_STORE_add_lookup(
  X509_STORE *v, 
  X509_LOOKUP_METHOD *m
)
{
  X509_LOOKUP *lookup;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  lookup = X509_STORE_add_lookup(v, m);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return lookup;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_X509_STORE_set_flags (
  X509_STORE *ctx,
  unsigned long flags
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509_STORE_set_flags(ctx, flags);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int 
OPENSSL_X509V3_add_standard_extensions (
  void
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = X509V3_add_standard_extensions();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void *
OPENSSL_X509V3_EXT_d2i (
  X509_EXTENSION *ext
)
{
  void *obj;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  obj = X509V3_EXT_d2i(ext);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return obj;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL X509 direct operations structure */
//------------------------------------------------------------------------------
VOID*
InitX509DirectOp (
  IN VOID
)
{
  internalX509DirectOperations.X509_NAME_ENTRY_get_data = OPENSSL_X509_NAME_ENTRY_get_data;
  internalX509DirectOperations.X509_NAME_entry_count    = OPENSSL_X509_NAME_entry_count;
  internalX509DirectOperations.X509_NAME_get_entry      = OPENSSL_X509_NAME_get_entry;
  internalX509DirectOperations.X509_NAME_get_index_by_NID = OPENSSL_X509_NAME_get_index_by_NID;
  internalX509DirectOperations.X509_NAME_oneline        = OPENSSL_X509_NAME_oneline;
  internalX509DirectOperations.X509_NAME_print_ex       = OPENSSL_X509_NAME_print_ex;

  internalX509DirectOperations.X509_digest                   = OPENSSL_X509_digest;
  internalX509DirectOperations.X509_verify_cert              = OPENSSL_X509_verify_cert;
  internalX509DirectOperations.X509_verify_cert_error_string = OPENSSL_X509_verify_cert_error_string;
  internalX509DirectOperations.X509_get_issuer_name          = OPENSSL_X509_get_issuer_name;
  internalX509DirectOperations.X509_get_subject_name         = OPENSSL_X509_get_subject_name;
  internalX509DirectOperations.X509_get_pubkey               = OPENSSL_X509_get_pubkey;
  internalX509DirectOperations.X509_get_ext_by_NID           = OPENSSL_X509_get_ext_by_NID;
  internalX509DirectOperations.X509_get_ext                  = OPENSSL_X509_get_ext;
  internalX509DirectOperations.X509_get_ext_d2i              = OPENSSL_X509_get_ext_d2i;
  internalX509DirectOperations.X509_free                     = OPENSSL_X509_free;

  internalX509DirectOperations.X509_LOOKUP_ctrl              = OPENSSL_X509_LOOKUP_ctrl;
  internalX509DirectOperations.X509_LOOKUP_file              = OPENSSL_X509_LOOKUP_file;
  internalX509DirectOperations.X509_LOOKUP_hash_dir          = OPENSSL_X509_LOOKUP_hash_dir;
  internalX509DirectOperations.X509_LOOKUP_add_dir_func      = OPENSSL_X509_LOOKUP_add_dir;

  internalX509DirectOperations.X509_STORE_CTX_new              = OPENSSL_X509_STORE_CTX_new;
  internalX509DirectOperations.X509_STORE_CTX_init             = OPENSSL_X509_STORE_CTX_init;
  internalX509DirectOperations.X509_STORE_CTX_free             = OPENSSL_X509_STORE_CTX_free;
  internalX509DirectOperations.X509_STORE_CTX_get_current_cert = OPENSSL_X509_STORE_CTX_get_current_cert;
  internalX509DirectOperations.X509_STORE_CTX_get_error        = OPENSSL_X509_STORE_CTX_get_error;
  internalX509DirectOperations.X509_STORE_CTX_get_error_depth  = OPENSSL_X509_STORE_CTX_get_error_depth;

  internalX509DirectOperations.X509_STORE_new        = OPENSSL_X509_STORE_new;
  internalX509DirectOperations.X509_STORE_free       = OPENSSL_X509_STORE_free;
  internalX509DirectOperations.X509_STORE_add_lookup = OPENSSL_X509_STORE_add_lookup;
  internalX509DirectOperations.X509_STORE_set_flags  = OPENSSL_X509_STORE_set_flags;

  internalX509DirectOperations.X509V3_add_standard_extensions = OPENSSL_X509V3_add_standard_extensions;

  internalX509DirectOperations.X509V3_EXT_d2i = OPENSSL_X509V3_EXT_d2i;

  return (VOID*)&internalX509DirectOperations;
}
//------------------------------------------------------------------------------

