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
 *  \brief OpenSSL stack direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#include <openssl/ssl.h>

typedef
int
(EFIAPI *OPENSSL_STACK_SK_NUM) (
  const _STACK *st
);

typedef
void *
(EFIAPI *OPENSSL_STACK_SK_VALUE) (
  const _STACK *st, 
  int i
);

typedef
void *
(EFIAPI *OPENSSL_STACK_GN_VALUE) (
  const STACK_OF(GENERAL_NAME) *st,
  int i
);

typedef
int
(EFIAPI *OPENSSL_STACK_GN_NUM) (
  const STACK_OF(GENERAL_NAME) *st
);

struct _SSL_OPENSSL_STACK_OP {
  OPENSSL_STACK_SK_NUM    sk_num;
  OPENSSL_STACK_SK_VALUE  sk_value;
  OPENSSL_STACK_GN_VALUE  sk_GENERAL_NAME_value_func;
  OPENSSL_STACK_GN_NUM    sk_GENERAL_NAME_num_func;
};

typedef struct _SSL_OPENSSL_STACK_OP SSL_OPENSSL_STACK_OP;

