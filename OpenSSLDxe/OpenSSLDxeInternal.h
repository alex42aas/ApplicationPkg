/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_DXE_INTERNAL_H_
#define OPENSSL_DXE_INTERNAL_H_

#include <Protocol/OpenSSLProtocol.h>

/** Internal data of the OpenSSL DXE protocol */
typedef struct _OPENSSL_INTERNAL_DATA {
  EFI_HANDLE            DriverHandle;       //!< Handle of the OpenSSL DXE driver
  OPENSSL_PROTOCOL      OpenSSLPtotocol;    //!< OpenSSL DXE protocol
} OPENSSL_INTERNAL_DATA;

VOID*
InitDirectOp (
  IN VOID
);

VOID*
InitSSLDirectOp (
  IN VOID
);

VOID*
InitX509DirectOp (
  IN VOID
);

VOID*
InitCryptoDirectOp (
  IN VOID
);

VOID*
InitBioDirectOp (
  IN VOID
);

VOID*
InitStackDirectOp (
  IN VOID
);

#endif // OPENSSL_DXE_INTERNAL_H_

