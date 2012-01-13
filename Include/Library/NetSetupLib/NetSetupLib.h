/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef NIC_SETUP_H_
#define NIC_SETUP_H_

#include <Protocol/GlobalConfigType.h>

typedef struct {
  UINT8 StationLocalAddress[4];
  BOOLEAN isMediaPresent;
  } NIC_IP_CONFIG;

EFI_STATUS
SetupNetworkInterfaces(
  VOID
  );

NIC_IP_CONFIG*
GetLocalIPforActiveNICs (
  OUT UINTN *numActiveNICs,
  OUT EFI_STATUS *Status
  );

EFI_STATUS
EFIAPI
WaitForNetworkConfigured (
  UINTN Timeout
  );

#endif // NIC_SETUP_H_