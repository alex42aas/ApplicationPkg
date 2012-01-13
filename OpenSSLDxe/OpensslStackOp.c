/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/OpensslStackOp.h>

#include "OpenSSLDxeInternal.h"

#include <openssl/x509v3.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static SSL_OPENSSL_STACK_OP internalStackOperations;

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_sk_num (
  const _STACK *st
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = sk_num(st);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void *
OPENSSL_sk_value (
  const _STACK *st, 
  int i
)
{
  void *val;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  val = sk_value(st, i);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return val;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void *
OPENSSL_sk_GENERAL_NAME_value (
  const STACK_OF(GENERAL_NAME) *st,
  int i
)
{
  void *val;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  val = sk_GENERAL_NAME_value(st, i);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return val;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_sk_GENERAL_NAME_num (
  const STACK_OF(GENERAL_NAME) *st
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = sk_GENERAL_NAME_num(st);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL direct operations structure */
//------------------------------------------------------------------------------
VOID*
InitStackDirectOp (
  IN VOID
)
{
  internalStackOperations.sk_num                      = OPENSSL_sk_num;
  internalStackOperations.sk_value                    = OPENSSL_sk_value;
  internalStackOperations.sk_GENERAL_NAME_value_func  = OPENSSL_sk_GENERAL_NAME_value;
  internalStackOperations.sk_GENERAL_NAME_num_func    = OPENSSL_sk_GENERAL_NAME_num;

  return (VOID*)&internalStackOperations;
}
//------------------------------------------------------------------------------

