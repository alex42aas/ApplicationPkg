/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef CDP_INTERNAL_H_
#define CDP_INTERNAL_H_

#include <Library/CDPSupportLib/CDPSupport.h>

#define LDAP_CDP_NUM_ARGS  13  //!< Number of arguments in the CDP ldap request

CDP_STATUS
SearchListOfCRLFromLDAP (
  IN BOOLEAN useSSL,
  IN CHAR8 *host,
  IN CHAR8 *port,
  IN CHAR8 *dn,
  OUT UINTN *numCRLs
);

VOID
FreeReceivedCRLs (
  VOID
);

VOID
GetCRLByNum (
  IN  UINTN numberOfCRL,
  OUT UINT8 **crlData,
  OUT UINTN *lenOfData
);

VOID
SetCDPLastError (
  IN CDP_STATUS status
);

#endif // CDP_INTERNAL_H_