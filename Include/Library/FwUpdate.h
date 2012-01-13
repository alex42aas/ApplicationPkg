/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __FW__UPDATE__H
#define __FW__UPDATE__H


//#include <Library/ExtHdrUtils.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Library/PcdLib.h>


#define FW_CHUNK_SIZE             (1024 * 4)


VOID 
BiosUpdateSetHelperStrings(
  IN CHAR16 *WrStr, 
  IN CHAR16 *EraseStr, 
  IN CHAR16 *RestStr
  );

EFI_STATUS
BiosUpdateFromByteBuf(
  IN UINT8 *ByteBuf,
  IN UINTN BufSize,
  IN BOOLEAN bUpdateEfiVars
  );

EFI_STATUS
BiosUpdateFromByteBufFsm(
  IN UINT8 *ByteBuf,
  IN UINTN Size,
  IN BOOLEAN bUpdateEfiVars,
  IN OUT CHAR16 *ProgressStr,
  IN BOOLEAN bRestart,
  IN OUT BOOLEAN *bUpdateDone
  );


VOID
BiosRdWrTest(
  VOID
  );

  
EFI_STATUS
GetFvbHandleByAddressSize (
  IN EFI_PHYSICAL_ADDRESS Address,
  IN OUT UINTN *Limit,
  OUT EFI_HANDLE *FvbHandle
  );

#endif	/* #ifndef __FW__UPDATE__H */