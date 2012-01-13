/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "GostHashHelperDxe.h"
#include <Library/GostHashLib.h>


STATIC GOST_HASH_HELPER_PRIVATE_DATA gPrivateData;


EFI_STATUS
ThisGostHashInit (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN OUT EFI_HANDLE *Handle,
  IN GOST_PARAM_SET ParamSet
  )
{
  EFI_STATUS Status;
  gost_hash_ctx *pctx = NULL;

  if (This == NULL || 
      Handle == NULL || 
      ParamSet >= GOSTR3411_94_ERROR_PARAMSET ||
      ParamSet < 0) {
    return EFI_INVALID_PARAMETER;
  }
  *Handle = NULL;

  pctx = AllocateZeroPool(sizeof(*pctx));
  if (pctx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  GostHashSelectParamSet (ParamSet);
  Status = GostHashInit2(pctx);
  if (EFI_ERROR(Status)) {
    FreePool(pctx);
  } else {
    DEBUG ((EFI_D_INFO, "%a.%d Handle=%p\n", __FUNCTION__, __LINE__, pctx));
    *Handle = (EFI_HANDLE)pctx;
  }
  
  return Status;
}

EFI_STATUS
ThisGostHashUpdate (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *Data,
  IN UINTN DataLen
  )
{
  gost_hash_ctx *ctx = NULL;

  if (This == NULL || Handle == NULL || Data == NULL || DataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ctx = (gost_hash_ctx*)Handle;
  
  GostHashUpdate2(
    ctx, 
    Data, 
    DataLen
    );
  return EFI_SUCCESS;
}


EFI_STATUS
ThisGostHashFinal (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN OUT UINT8 *Hash
  )
{
  gost_hash_ctx *ctx = NULL;

  if (This == NULL || Handle == NULL || Hash == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  ctx = (gost_hash_ctx*)Handle;
  GostHashFinal2(ctx, Hash);
  DEBUG ((EFI_D_INFO, "%a.%d Handle=%p\n", __FUNCTION__, __LINE__, Handle));
  FreePool (Handle);
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
GostHashHelperDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  gPrivateData.HandlerProtocol.Init = ThisGostHashInit;
  gPrivateData.HandlerProtocol.Update = ThisGostHashUpdate;
  gPrivateData.HandlerProtocol.Final = ThisGostHashFinal;

  Status = gBS->InstallProtocolInterface( 
    &gPrivateData.DriverHandle, 
    &gGostHashHelperProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gPrivateData.HandlerProtocol
    );

  DEBUG ((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

