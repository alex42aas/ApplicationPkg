/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/FsUtils.h>
#include <Library/Messages.h>
#include <InternalErrDesc.h>

#include "OpensslCnfFv.h"

static CHAR8 *ConfBuf; 

static
EFI_STATUS
LoadOpensslCfg(
  VOID
  );

CHAR8*
GetOpensslConfigFromFV(
  VOID
  )
{
  LoadOpensslCfg();
  
  return ConfBuf;
}

static
EFI_STATUS
LoadOpensslCfg(
  VOID
  )
{
  CHAR8 Fname[255];
  EFI_STATUS Status;
  UINTN Size;
  CHAR8 *Data = NULL;
  
  AsciiSPrint(Fname, sizeof(Fname), "fv:%g", 
    PcdGetPtr(PcdOpensslConfigFile));
  DEBUG((EFI_D_ERROR, "%a.%d %a\n", __FUNCTION__, __LINE__, Fname));
  
  if(ConfBuf) {
    DEBUG((EFI_D_ERROR, "%a.%d ATTENTION! Config allready loaded!\n", 
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }

  Status = FsUtilsLoadFileData(Fname, &Data, &Size);  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  ConfBuf = AllocateZeroPool(Size + 1);
  if (ConfBuf != NULL) {
    CopyMem(ConfBuf, Data, Size);
  }
  if (Data != NULL) {
    FreePool(Data);
  }
  
  return EFI_SUCCESS;
}
