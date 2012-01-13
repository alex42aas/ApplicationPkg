/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/FaultTolerance.h>


EFI_STATUS
FtUpdateLoadCounter(
  VOID
  )
{
  EFI_STATUS Status;
  UINT8 LoadCounter;
  
  Status = GetSetupLoadCounter(&LoadCounter);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (LoadCounter <= FT_MAX_LOAD_COUNTER) {
    LoadCounter++;
  }
  return SetSetupLoadCounter(LoadCounter);
}


EFI_STATUS
FtGetLoadCounter(
  IN OUT UINT8 *LoadCounter
  )
{
  return GetSetupLoadCounter(LoadCounter);
}


EFI_STATUS
FtGetStatus(
  IN OUT UINT8 *VarStatus
  )
{
  return GetSetupPakStatus(VarStatus);
}

EFI_STATUS
FtSetStatus(
  IN UINT8 VarStatus
  )
{
  return SetSetupPakStatus(VarStatus);
}
