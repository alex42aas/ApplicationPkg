/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/OpensslDirectOp.h>

#include "OpenSSLDxeInternal.h"
#include "OpensslFunctionsInternal.h"

STATIC OPENSSL_DIRECT_OP internalDirectOperations;

STATIC STACK_OF(X509_CRL) *tlsCRLStack;  // Our CRL Stack
STATIC STACK_OF(X509)        *trustedChain; // Our Trusted Stack

//------------------------------------------------------------------------------
/*! \brief Copy X509 Stack */
/*! Deep copy of the stack. All certs from the stack will be copied */
/*! \param[in] *stackToCopy X509 Stack to copy */
/*! \return Deep copy of the Stack */
//------------------------------------------------------------------------------
STATIC
STACK_OF(X509)*
DeepCopyX509Stack (
  STACK_OF(X509) *stackToCopy
)
{
  int i;
  STACK_OF(X509) *stack  = NULL;
  X509 *newCert = NULL, *certForStack = NULL;

  stack = sk_X509_new_null();
  if (stack == NULL)
    goto _error;

  for(i = 0; i < sk_X509_num(stackToCopy); i++) {
    newCert = sk_X509_value (stackToCopy, i);
    certForStack = X509_dup(newCert);
    if (!sk_X509_push(stack, certForStack))
      goto _error;
  }

  return stack;

_error:
  if (stack != NULL)
    sk_X509_free(stack);

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Copy CRL Stack */
/*! Deep copy of the stack. All CRLs from the stack will be copied */
/*! \param[in] *stackToCopy CRL Stack to copy */
/*! \return Deep copy of the Stack */
//------------------------------------------------------------------------------
STATIC
STACK_OF(X509_CRL)*
DeepCopyCrlStack (
  STACK_OF(X509_CRL) *stackToCopy
)
{
  int i;
  STACK_OF(X509_CRL) *crls  = NULL;
  X509_CRL *newCRL = NULL, *crlForStack = NULL;

  crls = sk_X509_CRL_new_null();
  if (crls == NULL)
    goto _error;

  for(i = 0; i < sk_X509_CRL_num(stackToCopy); i++) {
    newCRL = sk_X509_CRL_value (stackToCopy, i);
    crlForStack = X509_CRL_dup(newCRL);
    if (!sk_X509_CRL_push(crls, crlForStack))
      goto _error;
  }

  return crls;

_error:
  if (crls != NULL)
    sk_X509_CRL_free(crls);

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int
SetCRLStackForTLS (
 VOID *stackToSet
)
{
  STACK_OF(X509_CRL) *stack;

  if (stackToSet == NULL)
    return -1;

  stack = (STACK_OF(X509_CRL) *)stackToSet;
  if (NULL != tlsCRLStack)
    sk_X509_CRL_free(tlsCRLStack);

  tlsCRLStack = stack;

  return 0;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
void
FreeCRLStackForTLS (
  void
)
{
  if (NULL != tlsCRLStack)
    sk_X509_CRL_free(tlsCRLStack);

  tlsCRLStack = NULL;

  return;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int
SetTrustedChain (
  VOID *x509Stack
)
{
  if (x509Stack == NULL)
    return -1;

  if (NULL != trustedChain)
    sk_X509_free(trustedChain);

  trustedChain = (STACK_OF(X509) *)x509Stack;

  return 0;  
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free ldap TLS trusted chain stack */
/*! Use this function if you previously passed a copy of the trusted stack */
//------------------------------------------------------------------------------
void
FreeTrustedChain (
  void
  )
{
  if (NULL != trustedChain)
    sk_X509_free(trustedChain);

  trustedChain = NULL;

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check if CA trusted chain was loaded for CTX */
//------------------------------------------------------------------------------
STACK_OF(X509)*
LookupTrustedChain (
  X509_STORE_CTX *ctx,
  X509_NAME *nm

)
{
  STACK_OF(X509) *stackToReturn;
 
  if (trustedChain == NULL) {
    LogOpensslMessage ( EFI_D_ERROR, "Error: %a", "CA trusted chain is empty!");
    return NULL;
  }

  stackToReturn = DeepCopyX509Stack(trustedChain);

  return stackToReturn;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check if CRL stack was loaded for CTX */
//------------------------------------------------------------------------------
STACK_OF(X509_CRL)*
LookupCrlsInCAChain (
  X509_STORE_CTX *ctx,
  X509_NAME *nm
)
{
  STACK_OF(X509_CRL) *stackToReturn;
 
  if (tlsCRLStack == NULL) {
    LogOpensslMessage ( EFI_D_ERROR, "Error: %a", "CRL stack is empty!");
    return NULL;
  }

  stackToReturn = DeepCopyCrlStack(tlsCRLStack);
 
  return stackToReturn;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL direct operations structure */
//------------------------------------------------------------------------------
VOID*
InitDirectOp (
  IN VOID
)
{
  internalDirectOperations.SetCRLStackForTLS  = SetCRLStackForTLS;
  internalDirectOperations.FreeCRLStackForTLS = FreeCRLStackForTLS;

  internalDirectOperations.SetTrustedChain    = SetTrustedChain;
  internalDirectOperations.FreeTrustedChain   = FreeTrustedChain;

  internalDirectOperations.LookupCrlsInCAChain = LookupCrlsInCAChain;
  internalDirectOperations.LookupTrustedChain  = LookupTrustedChain;

  return (VOID*)&internalDirectOperations;
}
//------------------------------------------------------------------------------

