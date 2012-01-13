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
 *  \brief OpenSSL direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#ifndef OPENSSL_DIRECT_OP_H_
#define OPENSSL_DIRECT_OP_H_

#include <openssl/ssl.h>

typedef
int
(EFIAPI *OPENSSL_SET_CRL_STACK_FOR_TLS) (
  VOID *stackToSet
);

typedef
void
(EFIAPI *OPENSSL_FREE_CRL_STACK_FOR_TLS) (
  void
);

typedef
STACK_OF(X509_CRL)*
(EFIAPI *OPENSSL_LOOKUP_CRLS_IN_CA_CHAIN) (
  X509_STORE_CTX *ctx,
  X509_NAME *nm
);

typedef
STACK_OF(X509)*
(EFIAPI *OPENSSL_LOOKUP_TRUSTED_CHAIN) (
  X509_STORE_CTX *ctx,
  X509_NAME *nm
);

typedef
int
(EFIAPI *OPENSSL_SET_TRUSTED_CHAIN) (
  VOID *x509Stack
);

typedef
void
(EFIAPI *OPENSSL_FREE_TRUSTED_CHAIN) (
  void
);

struct _OPENSSL_DIRECT_OP {
  OPENSSL_SET_CRL_STACK_FOR_TLS   SetCRLStackForTLS;
  OPENSSL_FREE_CRL_STACK_FOR_TLS  FreeCRLStackForTLS;
  OPENSSL_LOOKUP_CRLS_IN_CA_CHAIN LookupCrlsInCAChain;
  OPENSSL_LOOKUP_TRUSTED_CHAIN    LookupTrustedChain;
  OPENSSL_SET_TRUSTED_CHAIN       SetTrustedChain;
  OPENSSL_FREE_TRUSTED_CHAIN      FreeTrustedChain;
  };
  
typedef struct _OPENSSL_DIRECT_OP OPENSSL_DIRECT_OP;

#endif // OPENSSL_DIRECT_OP_H_