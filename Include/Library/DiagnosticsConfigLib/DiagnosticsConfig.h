/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef DIAGNOSTICS_CONFIG_LIB_H_
#define DIAGNOSTICS_CONFIG_LIB_H_

#include <Uefi/UefiBaseType.h>
#include <Protocol/GlobalConfigType.h>

#define NOT_USE     0x00  //!< Don't use setting
#define USE         0x01  //!< Use setting


EFI_STATUS
ReadDiagnosticsConfig (
  VOID
);

VOID
DeleteDiagnosticsConfig (
  VOID
);

EFI_STATUS
SetDiagnosticsLogUsageFlag (
  IN UINT16 usageFlag
);

EFI_STATUS
SetComPortUsageFlag (
  IN UINT16 usageFlag
);

EFI_STATUS
SetNetLogUsageFlag (
  IN UINT16 usageFlag
);

EFI_STATUS
SetRamLogUsageFlag (
  IN UINT16 usageFlag
);

UINT16
GetDiagnosticsLogUsageFlag (
  VOID
);

UINT16
GetComPortUsageFlag (
  VOID
);

UINT16
GetNetLogUsageFlag (
  VOID
);

UINT16
GetRamLogUsageFlag (
  VOID
);

EFI_STATUS
SaveDiagnosticsConfig (
  VOID
);

VOID
ResetDiagnosticsConfig (
  VOID
  );


#endif // DIAGNOSTICS_CONFIG_LIB_H_
