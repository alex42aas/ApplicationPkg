/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef TOKEN_VIEWER_INTERNALS_H_
#define TOKEN_VIEWER_INTERNALS_H_

#include <Library/BIOSLib/OpensslFunctions.h>

typedef struct {
  OSSL_CERT_INFO_T *certInfo; //!< Certificate info

  UINTN  *certId;     //!< A pointer to the cert ID
  UINTN  lenId;       //!< A length of the cert ID
  UINTN  menuCertId;  //!< An menu's item ID of a certificate
} CERT_T;

EFI_STATUS
GetTestCertListFromToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
);

EFI_STATUS
GetCertListFromToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
);

VOID
FreeCertList(
  CERT_T *certList,
  UINTN   certCount
);

#endif // TOKEN_VIEWER_INTERNALS_H_
