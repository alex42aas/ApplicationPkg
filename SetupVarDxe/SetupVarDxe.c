/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <SetupVarDxe.h>


SETUP_VAR_PRIVATE_DATA gSetupPrivateData;


EFI_STATUS
EFIAPI
GetPciDaDevices(
  IN CONST SETUP_VAR_PROTOCOL *This,
  IN OUT   UINT8 **Data,
  IN OUT   UINTN *RecordsNum
  )
{
  EFI_STATUS Status;
  
  Status = GetSetupPciDevList(Data, RecordsNum);
  return Status;
}


EFI_STATUS
SetPciDaDevices(
  IN CONST SETUP_VAR_PROTOCOL *This,
  IN       UINTN ModeIndex,
  IN       UINT8 *Data,  
  IN       UINTN RecordsNum
  )
{
  EFI_STATUS Status;

  Status = SetSetupPciDevList(ModeIndex, Data, RecordsNum);
  return Status;
}


EFI_STATUS
EFIAPI  
SetDefaultPciDaDevices(
  IN CONST SETUP_VAR_PROTOCOL  *This
  )
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  UINT8 *DaDevices;
  UINT8 i, ModesNum, RecordsNum;  
  UINT16 ModeId;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DaDevices = FixedPcdGetPtr(PciDaDevices);
  if (NULL == DaDevices) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  ModesNum = DaDevices[0];
  DaDevices++;
  DEBUG((EFI_D_ERROR, "%a.%d ModesNum=0x%X\n", 
    __FUNCTION__, __LINE__, ModesNum));
  if (ModesNum == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  for (i = 0; i < ModesNum; i++) {
    ModeId = DaDevices[0] | (DaDevices[1] << 8);
    DEBUG((EFI_D_ERROR, "%a.%d ModeId=0x%X\n", 
      __FUNCTION__, __LINE__, ModeId));  
    DaDevices += 2;
    RecordsNum = DaDevices[0];
    DEBUG((EFI_D_ERROR, "%a.%d RecordsNum=0x%X\n", 
      __FUNCTION__, __LINE__, RecordsNum));  
    DaDevices++;
    Status = SetSetupPciDevList(ModeId, DaDevices, RecordsNum);
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
    DaDevices += RecordsNum * sizeof(DA_DEV_REC);
  }
_exit:  
  return Status;
}


EFI_STATUS
EFIAPI
SetupVarInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;
  SETUP_VAR_PROTOCOL *pSetupVarProtocol;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  pSetupVarProtocol = &gSetupPrivateData.SetupVarProtocol;

  pSetupVarProtocol->SetPciDaDevices = SetPciDaDevices;
  pSetupVarProtocol->GetPciDaDevices = GetPciDaDevices;
  pSetupVarProtocol->SetDefaultPciDaDevices = SetDefaultPciDaDevices;

  Status = gBS->InstallProtocolInterface( 
    &gSetupPrivateData.DriverHandle, 
    &gSetupVarProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gSetupPrivateData.SetupVarProtocol
    );
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = InitSetupEfiVar("PlatformNameNotSet");
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  //Status = SetDefaultPciDaDevices(pSetupVarProtocol);
  
  return Status;
}


