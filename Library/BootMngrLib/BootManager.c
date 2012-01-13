/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "BootManager.h"
#include "BootXmlCfg.h"
#include <Protocol/DiskInfo.h>
#include <IndustryStandard/Mbr.h>
#include <Protocol/SmartCard.h>
#include <Protocol/BdsHelperProtocol.h>
#include <Protocol/PcdHelperProtocol.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Library/BIOSLib/History.h>
#include <Protocol/RemoteCfgTlsProtocol.h>
#include <Protocol/LegacyRegion.h> 
#include <Protocol/LegacyBios.h>
#include <Guid/Acpi.h>
#include <Protocol/GraphicsOutput.h>


#define LOG_BOOT_MANAGER 0


#if	1
#define LOG(MSG)
#else
#define LOG(MSG) DEBUG(MSG)
#endif

STATIC EFI_EVENT gExitBootServicesEvent;
STATIC BDS_HELPER_PROTOCOL *gBdsHelperProtocol;
STATIC BOOLEAN gConnectAllHappened = FALSE;
EFI_HII_HANDLE gStringPackHandle;
EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC UINT16 CurrentMode = MAIN_BOOT_UNDEF;
STATIC UINT16 CurrentFormId = MAIN_BOOT_MANAGER_ID;
STATIC UINT16 NewMode = MAIN_BOOT_UNDEF;
STATIC UINT8 CurrentBootOption;
STATIC UINT8 gBootDefaultKey;
STATIC UINT8 gBootFromFsKey;
STATIC LIST_ENTRY IcflList;
STATIC BOOLEAN bIcflListWasChanged;
STATIC CBCFG_LIST *mCurrentBootConfigList;
STATIC EFI_STRING_ID ModuleTypeTokens[] = {
  STRING_TOKEN(STR_MODULE_LINUX_TYPE),
  STRING_TOKEN(STR_MODULE_MULTIBOOT_TYPE),
  STRING_TOKEN(STR_MODULE_EFI_TYPE)
  };
STATIC UINTN ModuleTypeIndexes[] = {
  MODULE_TYPE_LINUX, MODULE_TYPE_MULTIBOOT, MODULE_TYPE_EFI
  };
STATIC BOOLEAN DoFeMode; // flag for run file explorer (FE)
STATIC CHAR16 *SelectedModuleDevPath; // pointer to current device path string, which was selected
STATIC CHAR16 *CurUsbPathStr;
STATIC CHAR16 *gVarsDescStr[MAX_VARS_GUIDS];
STATIC UINTN gVarsDescStrMap[MAX_VARS_GUIDS] = {0, 1, 2};
STATIC EFI_GUID gVarsGuid[MAX_VARS_GUIDS];
STATIC EFI_GUID *gBootSelectedOptGuid;
STATIC UINT16 gVarsQId[MAX_VARS_GUIDS];
STATIC UINTN gVarsGuidIdx;
STATIC UINT8 gBootMngrMenuMode;
STATIC BOOLEAN bIntegrityPageCheckHash = FALSE;
STATIC CHAR16 *BootEfiArgs;
STATIC PCD_HELPER_PROTOCOL *gPcdHelperProtocol;
STATIC HISTORY_HANDLER_PROTOCOL *gHistoryHandlerProtocol;
STATIC BOOLEAN bBootDevicesRefresh = FALSE;
STATIC UINT32 GopOldMode;
STATIC EFI_GRAPHICS_OUTPUT_MODE_INFORMATION GopOldInfo;
STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL *gGop = NULL;
extern EFI_GUID gEfiEventExitBootServicesGuid;


#define BOOT_MNGR_OPTIONS_VAR_NAME        L"BmngrOpt"


STATIC
VOID
ShowOptionContent (
  IN BDS_COMMON_OPTION *Option
  )
{
  CHAR16                  *TempStr;
  
  LOG ((EFI_D_INFO, "\tOptionName=%s\n", Option->OptionName));
  LOG ((EFI_D_INFO, "\tBootCurrent=%04d\n", Option->BootCurrent));
  LOG ((EFI_D_INFO, "\tOptionNumber=%04d\n", Option->OptionNumber));
  LOG ((EFI_D_INFO, "\tDescription=%s\n", Option->Description));
  TempStr = DevicePathToStr (Option->DevicePath);
  LOG ((EFI_D_INFO, "\tDevicePath=%s\n", TempStr));
}

STATIC
VOID
ShowBootOptionsList (
  IN LIST_ENTRY *OptionsList
  )
{
  BDS_COMMON_OPTION       *Option;
  LIST_ENTRY              *Link;
  UINTN                   OptNum;  

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_INFO, "================================\n"));
  for (Link = GetFirstNode (OptionsList), OptNum = 0; 
       !IsNull (OptionsList, Link); 
       Link = GetNextNode (OptionsList, Link), OptNum++) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    //
    // Don't display the boot option marked as LOAD_OPTION_HIDDEN
    //
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }

    ASSERT (Option->Description != NULL);
    LOG ((EFI_D_INFO, "Option#%04d\n", OptNum));
    
    ShowOptionContent (Option);
  }
  DEBUG((EFI_D_INFO, "================================\n"));
}

VOID
UpdateModeFlagsForConfigModeFormRefresh(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d NewMode=%X CurrentMode=%X\n", 
    __FUNCTION__, __LINE__, NewMode, CurrentMode));
  NewMode = CurrentMode; /* save current mode (current menu) */
  CurrentMode = MAIN_BOOT_UNDEF; /* set current mode as previous menu */
  bBootDevicesRefresh = TRUE;
}


STATIC
EFI_STATUS
PcdHelperInit (
  VOID
  )
{
  EFI_STATUS Status;

  if (gPcdHelperProtocol) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (
        &gPcdHelperProtocolGuid,
        NULL,
        (VOID **)&gPcdHelperProtocol
        );
  if (EFI_ERROR(Status)) {
    gPcdHelperProtocol = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }
  return Status;
}



VOID
Init_gVarsDescStrMap(
  VOID
  )
{
  UINTN Idx;

  gVarsGuidIdx = 0;  
  for (Idx = 0; 
       Idx < sizeof(gVarsDescStrMap) / sizeof(gVarsDescStrMap[0]); 
       Idx++) {
    gVarsDescStrMap[Idx] = Idx;
  }
}


VOID*
AllocateZeroPoolDbg(
  IN UINTN Size
  )
{
  VOID *Ptr = AllocateZeroPool(Size);
  LOG((EFI_D_INFO, "%a.%d Ptr=%lp (%d)\n", 
    __FUNCTION__, __LINE__, Ptr, Size));
  return Ptr;
}

VOID
FreePoolDbg(
  IN VOID *Ptr
  )
{
  LOG((EFI_D_INFO, "%a.%d Ptr=%lp\n", 
    __FUNCTION__, __LINE__, Ptr));
  FreePool(Ptr);
}


VOID
DumpDevicePath(
  IN EFI_DEVICE_PATH_PROTOCOL *DevPath
  );


EFI_HANDLE
GetDiskIoHandleByFsDevPath(
  EFI_DEVICE_PATH_PROTOCOL *FsDevicePath
  );

EFI_HANDLE
GetBlkIoHandleByFsDevPath(
  EFI_DEVICE_PATH_PROTOCOL *FsDevicePath
  );


EFI_BLOCK_IO_PROTOCOL*
GetBlkIoForLegacyDevPath (
  IN EFI_DEVICE_PATH_PROTOCOL *LegacyDevicePath
  )
{
  UINTN NumBlkIo, Index;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_STATUS Status;
  EFI_HANDLE *pIop;
  EFI_HANDLE ResultHandle;
  CHAR16 *TempStr1, *TempStr2;
  UINTN PortNumber;
  EFI_BLOCK_IO_PROTOCOL *BlkIo = NULL;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  ResultHandle = NULL;
  
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiBlockIoProtocolGuid,
        NULL,
        &NumBlkIo,
        &pIop
        );

  TempStr1 = DevicePathToStr(LegacyDevicePath);
  LOG((EFI_D_INFO, "%a.%d TempStr1=%s\n", __FUNCTION__, __LINE__, TempStr1));
  if (TempStr1 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  TempStr2 = StrStr(TempStr1, L",P");
  if (TempStr2 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  TempStr2 += 2;
  LOG((EFI_D_INFO, "%a.%d TempStr2=%s\n", __FUNCTION__, __LINE__, TempStr2));
  TempStr1 = StrStr(TempStr2, L"-");
  if (TempStr1 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  *TempStr1 = 0;
  LOG((EFI_D_INFO, "%a.%d TempStr2=%s\n", __FUNCTION__, __LINE__, TempStr2));
  PortNumber = StrDecimalToUintn(TempStr2);
  *TempStr1 = L'-';

  LOG((EFI_D_INFO, "%a.%d PortNumber=%d\n", 
        __FUNCTION__, __LINE__, PortNumber));
  
  for (Index = 0; Index < NumBlkIo; Index++) {
    Status = gBS->HandleProtocol (
      pIop[Index],
      &gEfiDevicePathProtocolGuid,
      (VOID *) &DevicePath);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Index=%d\n", 
        __FUNCTION__, __LINE__, Index));
      continue;
    }
    
    TempStr1 = DevicePathToStr(DevicePath);
    LOG((EFI_D_INFO, "%a.%d DevicePath=%s\n", 
        __FUNCTION__, __LINE__, TempStr1));
    DumpDevicePath(DevicePath);
    for ( ; !IsDevicePathEnd(DevicePath); DevicePath = NextDevicePathNode(DevicePath)) {
      if (DevicePath->Type == MESSAGING_DEVICE_PATH) {
        LOG((EFI_D_INFO, "%a.%d {%X, %X}\n", 
          __FUNCTION__, __LINE__,
          DevicePath->Type,
          DevicePath->SubType));
      }
      if (DevicePath->Type == MESSAGING_DEVICE_PATH && 
          DevicePath->SubType == MSG_ATAPI_DP) {
        ATAPI_DEVICE_PATH *pDp = (ATAPI_DEVICE_PATH*)DevicePath;
        UINTN DpPort;

        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        LOG ((EFI_D_INFO, "pDp->Lun=%X\n", pDp->Lun));
        LOG ((EFI_D_INFO, "pDp->PrimarySecondary=%X\n", 
          pDp->PrimarySecondary));
        LOG ((EFI_D_INFO, "pDp->SlaveMaster=%X\n", 
          pDp->SlaveMaster));
        DpPort = (pDp->PrimarySecondary & 1) << 1;
        DpPort |= (pDp->SlaveMaster & 1);

        if (DpPort != PortNumber) {
          continue;
        }

        ResultHandle = pIop[Index];
        goto Done;
      }
      if (DevicePath->Type == MESSAGING_DEVICE_PATH && 
          DevicePath->SubType == MSG_SATA_DP) {        
        SATA_DEVICE_PATH *pDp = (SATA_DEVICE_PATH*)DevicePath;
        LOG((EFI_D_INFO, "%a.%d pDp->HBAPortNumber=%d\n", 
          __FUNCTION__, __LINE__, pDp->HBAPortNumber));
        if (pDp->HBAPortNumber != PortNumber) {
          continue;
        }

        ResultHandle = pIop[Index];
        goto Done;
      }   
    }
  }
Done:  
  if (ResultHandle != NULL) {
    gBS->HandleProtocol (
                    ResultHandle,
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlkIo
                    );
  }

  if (pIop) {
    FreePoolDbg(pIop);
  }
  
  return BlkIo;
}



EFI_STATUS
GetLegacyDiskInfo (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  EFI_STATUS                Status;
  EFI_LEGACY_BIOS_PROTOCOL  *LegacyBios;
  UINT16 HddCount, BbsCount, Idx;
  HDD_INFO *HddInfo;
  BBS_TABLE *BbsTable;
  MASTER_BOOT_RECORD *Mbr;

  if (DevicePath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiLegacyBiosProtocolGuid, NULL, (VOID **) &LegacyBios);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_UNSUPPORTED;
  }

  HddCount = 0;
  BbsCount = 0;
  HddInfo  = NULL;
  BbsTable = NULL;

  Status = LegacyBios->GetBbsInfo(
                        LegacyBios, 
                        &HddCount,
                        &HddInfo,
                        &BbsCount,
                        &BbsTable);
  
  LOG((EFI_D_INFO, "%a.%d Status = 0x%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  LOG((EFI_D_INFO, "%a.%d BbsCount = 0x%X\n", __FUNCTION__, __LINE__, BbsCount));
  for (Idx = 0; Idx < BbsCount; Idx++) {
    CHAR16 *Str;
    
    Str = (CHAR16*)(UINTN)(BbsTable[Idx].DescStringSegment * 16 + 
      BbsTable[Idx].DescStringOffset);
    if (Str == NULL) {
      continue;
    }
    LOG((EFI_D_INFO, "Idx = %d:\n", Idx));
    LOG((EFI_D_INFO, "BbsTable[Idx].AssignedDriveNumber=%d\n", 
      BbsTable[Idx].AssignedDriveNumber));
    
    LOG((EFI_D_INFO, "Str=%p {%a}\n", Str, Str));

    Str = (CHAR16*)(UINTN)(BbsTable[Idx].MfgStringSegment * 16 + 
      BbsTable[Idx].MfgStringOffset);
    if (Str == NULL) {
      continue;
    }
    LOG((EFI_D_INFO, "Str=%p {%a}\n", Str, Str));

  }
  

  LOG((EFI_D_INFO, "%a.%d HddCount = 0x%X\n", __FUNCTION__, __LINE__, HddCount));
  for (Idx = 0; Idx < HddCount; Idx++) {
    if (HddInfo[Idx].Bus == 0 && 
        HddInfo[Idx].Device == 0 && 
        HddInfo[Idx].Function == 0) {
      continue;
    }
    LOG((EFI_D_INFO, "Idx = %d [0]:\n", Idx));
    LOG((EFI_D_INFO, "(%02X.%02X:%02X)\n", 
      HddInfo[Idx].Bus,
      HddInfo[Idx].Device,
      HddInfo[Idx].Function));

    DumpBytes((UINT8*)&HddInfo[Idx].IdentifyDrive[0], 512);
    Mbr = (MASTER_BOOT_RECORD*)&HddInfo[Idx].IdentifyDrive[0];
    LOG((EFI_D_INFO, "Mbr->Signature=%04X\n", Mbr->Signature));
    LOG((EFI_D_INFO, "Idx = %d [1]:\n", Idx));
    DumpBytes((UINT8*)&HddInfo[Idx].IdentifyDrive[1], 512); 
    Mbr = (MASTER_BOOT_RECORD*)&HddInfo[Idx].IdentifyDrive[0];
    LOG((EFI_D_INFO, "Mbr->Signature=%04X\n", Mbr->Signature));
  }
  
  return Status;  
}


CBCFG_LIST *
BootCfgGetListItemByNum(
  IN CBCFG_LIST *List,
  IN UINTN Num
  )
{
  UINTN Idx;
  LIST_ENTRY *Link;
  CBCFG_LIST *TmpList;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (List == NULL) {
    return NULL;
  }

  for (Link = GetFirstNode (&List->Entry), Idx = 0; 
       !IsNull (&List->Entry, Link); 
       Link = GetNextNode (&List->Entry, Link)) {
    TmpList = (CBCFG_LIST*)Link;
    if (TmpList->DataSet == NULL) {
      /* ignore empty item */
      continue;
    }
    if (Idx == Num) {
      return TmpList;
    }
    Idx++;
  }
  return NULL;
}


CBCFG_DATA_SET *
BootCfgGetDataSetByNum(
  IN CBCFG_LIST *List,
  IN UINTN Num
  )
{
  UINTN Idx;
  LIST_ENTRY *Link;
  CBCFG_LIST *TmpList;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (List == NULL) {
    return NULL;
  }

  for (Link = GetFirstNode (&List->Entry), Idx = 0; 
       !IsNull (&List->Entry, Link); 
       Link = GetNextNode (&List->Entry, Link)) {
    TmpList = (CBCFG_LIST*)Link;
    if (TmpList->DataSet == NULL) {
      /* ignore empty item */
      continue;
    }
    if (Idx == Num) {
      return TmpList->DataSet;
    }
    Idx++;
  }
  return NULL;
}


CBCFG_DATA_SET *
BootCfgGetDataSetByBootType(
  IN CBCFG_LIST *List,
  IN UINT32 BootType
  )
{
  LIST_ENTRY *Link;
  CBCFG_LIST *TmpList;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (List == NULL) {
    return NULL;
  }

  for (Link = GetFirstNode (&List->Entry); 
       !IsNull (&List->Entry, Link); 
       Link = GetNextNode (&List->Entry, Link)) {
    TmpList = (CBCFG_LIST*)Link;
    if (TmpList->DataSet && TmpList->DataSet->BootType == BootType) {
      return TmpList->DataSet;
    }
  }
  return NULL;
}


EFI_STATUS
BootFromFsDestroyModules(
  IN CBCFG_LIST *List
  )
{
  LIST_ENTRY *Link;
  CBCFG_LIST *TmpList;
  CBCFG_DATA_SET *DataSet;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (List == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  for (Link = GetFirstNode (&List->Entry); 
       !IsNull (&List->Entry, Link); 
       Link = GetNextNode (&List->Entry, Link)) {
    TmpList = (CBCFG_LIST*)Link;
    if (TmpList->DataSet == NULL) {
      continue;
    }
    if (TmpList->DataSet->BootType != BOOT_TYPE_FROM_FS) {
      continue;
    }
    LOG((EFI_D_INFO, "%a.%d TmpList->DataSet->BootOptionsNum = 0x%X\n", 
      __FUNCTION__, __LINE__, TmpList->DataSet->BootOptionsNum));

    DataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - 1 + 
      sizeof(CBCFG_RECORD));
    if (DataSet == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(DataSet, TmpList->DataSet, sizeof(CBCFG_DATA_SET) - 1);
    
    FreePoolDbg(TmpList->DataSet);
    TmpList->DataSet = DataSet;
    TmpList->DataSet->BootOptionsNum = 1;
    LOG((EFI_D_INFO, "%a.%d TmpList->DataSet->BootOptionsNum = 0x%X\n", 
      __FUNCTION__, __LINE__, TmpList->DataSet->BootOptionsNum));
    return EFI_SUCCESS;
  }
       
  DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}


EFI_STATUS
BootFromFsAddNewModule(
  IN CBCFG_LIST *List,
  IN CHAR16 *NewDevPath,
  IN CHAR16 *NewArgs
  )
{
  LIST_ENTRY *Link;
  CBCFG_LIST *TmpList;
  UINT8 *Ptr;
  CBCFG_DATA_SET *DataSet;
  CBCFG_RECORD *Rec;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (List == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  for (Link = GetFirstNode (&List->Entry); 
       !IsNull (&List->Entry, Link); 
       Link = GetNextNode (&List->Entry, Link)) {
    TmpList = (CBCFG_LIST*)Link;
    if (TmpList->DataSet == NULL) {
      continue;
    }
    if (TmpList->DataSet->BootType != BOOT_TYPE_FROM_FS) {
      continue;
    }
    LOG((EFI_D_INFO, "%a.%d TmpList->DataSet->BootOptionsNum = 0x%X\n", 
      __FUNCTION__, __LINE__, TmpList->DataSet->BootOptionsNum));

    if (TmpList->DataSet->BootOptionsNum + 1 > MAXIMUM_BOOT_OPTIONS) {
      return EFI_ABORTED;
    }
    
    DataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - 1 + 
      (TmpList->DataSet->BootOptionsNum + 1) * sizeof(CBCFG_RECORD));
    if (DataSet == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(DataSet, TmpList->DataSet, sizeof(CBCFG_DATA_SET) - 1 + 
      TmpList->DataSet->BootOptionsNum * sizeof(CBCFG_RECORD));
    Ptr = DataSet->Data;
    Ptr += TmpList->DataSet->BootOptionsNum * sizeof(CBCFG_RECORD);
    Rec = (CBCFG_RECORD*)Ptr;
    if (NewDevPath && StrLen(NewDevPath) < MULTIBOOT_MAX_STRING) {
      CHAR16 ShortName[5];
      StrCpy(Rec->DevPath, NewDevPath);
      CopyMem(ShortName, NewDevPath, 4 * sizeof(CHAR16));
      ShortName[4] = 0;
      StrCpy(Rec->DeviceFullName, FsDescTableGetFullName(ShortName));
    }
    if (NewArgs && StrLen(NewArgs) < MULTIBOOT_MAX_STRING) {
      StrCpy(Rec->Args, NewArgs);
    }
    FreePoolDbg(TmpList->DataSet);
    TmpList->DataSet = DataSet;
    TmpList->DataSet->BootOptionsNum++;
    LOG((EFI_D_INFO, "%a.%d TmpList->DataSet->BootOptionsNum = 0x%X\n", 
      __FUNCTION__, __LINE__, TmpList->DataSet->BootOptionsNum));
    return EFI_SUCCESS;
  }
       
  DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}


VOID
DestroyIcflList(
  IN LIST_ENTRY *IcflList
  )
{
  LIST_ENTRY *Link, *PrevLink;
  ICFL_LIST *List;

  if (IsListEmpty(IcflList)) {
    return;
  }

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    PrevLink = Link;
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);    
    LOG((EFI_D_INFO, "%a.%d PrevLink=%p\n", __FUNCTION__, __LINE__, PrevLink));
    RemoveEntryList (PrevLink);
    FreePoolDbg(PrevLink);
  }
}


BOOLEAN
IcflStoragePresent(
  VOID
  )
{
  EFI_STATUS Status;
  
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StoragePresent(ICFL_VARIABLE_NAME, &gVarsGuid[gVarsGuidIdx]);
  return EFI_ERROR(Status) ? FALSE : TRUE;
}


EFI_STATUS
IcflStorageInitEmpty(
  VOID
  )
{
  EFI_STATUS Status;
  COMMON_VAR_DATA IcflData;

  LOG((EFI_D_INFO, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageInitEmpty(ICFL_VARIABLE_NAME, &gVarsGuid[gVarsGuidIdx],
    NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
    
  IcflData.Data[0] = 0;
  IcflData.DataLen = 0;
  
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageSetRawData2(&gVarsGuid[gVarsGuidIdx],
    ICFL_VARIABLE_NAME, (UINT8*)&IcflData,
    sizeof(COMMON_VAR_DATA),
    (ICFL_VARIABLE_MAX_STORAGE_SIZE + ICFL_VARIABLE_MAX_CARD_SIZE) / 
          ICFL_VARIABLE_MAX_CARD_SIZE,
    ICFL_VARIABLE_MAX_STORAGE_SIZE,
    ICFL_VARIABLE_MAX_CARD_SIZE, 
    FALSE
    );

  return Status;
}


EFI_STATUS
IcflStorageGetData(
  IN OUT LIST_ENTRY *IcflList
  )
{
  STORAGE_DATA StorageData;
  COMMON_VAR_DATA *IcflData;
  ICFL_LIST *List;
  UINTN Size, Len;
  CHAR8 *Ptr, *Ptr2;
  EFI_STATUS Status = EFI_SUCCESS;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (IcflList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  LOG((EFI_D_INFO, "%a.%d gVarsGuidIdx=%d\n", 
    __FUNCTION__, __LINE__, gVarsGuidIdx));  
  LOG((EFI_D_INFO, "%a.%d &gVarsGuid[gVarsGuidIdx]=%g\n", 
    __FUNCTION__, __LINE__, &gVarsGuid[gVarsGuidIdx]));

  IcflData = NULL;
  StorageData.Data = NULL;
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageGetData2(&gVarsGuid[gVarsGuidIdx], ICFL_VARIABLE_NAME,
    &StorageData, ICFL_VARIABLE_MAX_STORAGE_SIZE);
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Size = StorageData.DataLen;
  LOG((EFI_D_INFO, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));

  if (Size < (sizeof(COMMON_VAR_DATA) - 1)) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  IcflData = (COMMON_VAR_DATA *)StorageData.Data;
  if (IcflData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_INFO, "Size=%d IcflData->DataLen=%d sizeof(COMMON_VAR_DATA)=%d\n", 
    Size, IcflData->DataLen, sizeof(COMMON_VAR_DATA)));
  if (IcflData->DataLen && 
      IcflData->DataLen != Size - sizeof(COMMON_VAR_DATA) + 1) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    goto Done;
  }

  DestroyIcflList(IcflList);

  /* TODO: make list of strings */
  InitializeListHead(IcflList);

  Ptr = IcflData->Data;
  Size = IcflData->DataLen;
  while (Size) {
    Ptr2 = Ptr + sizeof(List->Hash);
    Len = StrSize((CHAR16*)Ptr2);
    if (Len > Size) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
      goto Done;
    }
    List = AllocateZeroPoolDbg(sizeof(ICFL_LIST) - sizeof(CHAR16) + Len);
    LOG((EFI_D_INFO, "%a.%d List=%p\n", __FUNCTION__, __LINE__, List));
    if (List == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    CopyMem(List->Hash, Ptr, sizeof(List->Hash));
    Ptr += sizeof(List->Hash);
    
    Size -= sizeof(List->Hash);
    
    CopyMem(List->FileName, Ptr, Len);
    InsertTailList (IcflList, &List->Entry);
    
    LOG((EFI_D_INFO, "Added: %s\n", List->FileName));
    Size -= Len;
    Ptr += Len;
  }
  
Done:
  if (IcflData != NULL) {
    FreePoolDbg(IcflData);
  }
  if (EFI_ERROR(Status)) {
    DestroyIcflList(IcflList);
  }

  return Status;
}


EFI_STATUS
IcflStorageCheckIntegrity(
  VOID
  )
{
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_UNSUPPORTED;
}


EFI_STATUS
IcflStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_INFO, "%a.%d gVarsGuidIdx=%d\n", 
    __FUNCTION__, __LINE__, gVarsGuidIdx));  
  LOG((EFI_D_INFO, "%a.%d &gVarsGuid[gVarsGuidIdx]=%g\n", 
    __FUNCTION__, __LINE__, &gVarsGuid[gVarsGuidIdx]));

  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageSetRawData2(
    &gVarsGuid[gVarsGuidIdx], 
    ICFL_VARIABLE_NAME,
    (UINT8*)RawData,
    RawDataLen,
    (ICFL_VARIABLE_MAX_STORAGE_SIZE + ICFL_VARIABLE_MAX_CARD_SIZE) / 
          ICFL_VARIABLE_MAX_CARD_SIZE,
    ICFL_VARIABLE_MAX_STORAGE_SIZE,
    ICFL_VARIABLE_MAX_CARD_SIZE,
    FALSE);

  LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  if (gHistoryHandlerProtocol != NULL) {
    gHistoryHandlerProtocol->AddRecord(
      gHistoryHandlerProtocol,
      HEVENT_BOOT_ICFL_CHANGE, 
      EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  }
  return Status; 
}



BOOLEAN
CbcfgStoragePresent(
  VOID
  )
{
  EFI_STATUS Status;
  
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StoragePresent(CBCFG_VARIABLE_NAME, &gVarsGuid[gVarsGuidIdx]);
  return EFI_ERROR(Status) ? FALSE : TRUE;
}

BOOLEAN
isCbcfgStorageEmpty (
  VOID
  )
{
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  return IsStorageEmpty(CBCFG_VARIABLE_NAME, &gVarsGuid[gVarsGuidIdx]);
}



EFI_STATUS
CbcfgStorageInitEmpty(
  VOID
  )
{
  EFI_STATUS Status;
  COMMON_VAR_DATA CbcfgData;  

  LOG((EFI_D_INFO, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageInitEmpty(CBCFG_VARIABLE_NAME, &gVarsGuid[gVarsGuidIdx],
    NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
    
  CbcfgData.Data[0] = 0;
  CbcfgData.DataLen = 0;
  
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageSetRawData2(&gVarsGuid[gVarsGuidIdx],
    CBCFG_VARIABLE_NAME, 
    (UINT8*)&CbcfgData,
    sizeof(COMMON_VAR_DATA),
    (CBCFG_VARIABLE_MAX_STORAGE_SIZE + CBCFG_VARIABLE_MAX_CARD_SIZE) / 
          CBCFG_VARIABLE_MAX_CARD_SIZE,
    CBCFG_VARIABLE_MAX_STORAGE_SIZE,
    CBCFG_VARIABLE_MAX_CARD_SIZE, 
    FALSE
    );
  DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
CbcfgStorageGetDataByGuid(
  IN OUT CBCFG_DATA_SET **CbcfgDataSet,
  OUT UINTN *DataSetSize,
  GUID	*Guid
  )
{
  STORAGE_DATA StorageData;
  COMMON_VAR_DATA *CbcfgData;
  UINTN Size;
  EFI_STATUS Status = EFI_SUCCESS;

  if (DataSetSize == NULL || CbcfgDataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if(Guid == NULL)
  {
    LOG((EFI_D_INFO, "%a.%d gVarsGuidIdx=%d\n", __FUNCTION__, __LINE__, gVarsGuidIdx));  
    LOG((EFI_D_INFO, "%a.%d &gVarsGuid[gVarsGuidIdx]=%g\n", __FUNCTION__, __LINE__, &gVarsGuid[gVarsGuidIdx]));
    Guid = &gVarsGuid[gVarsGuidIdx];
  }

  CbcfgData = NULL;
  StorageData.Data = NULL;
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageGetData2(Guid, CBCFG_VARIABLE_NAME,
    &StorageData, CBCFG_VARIABLE_MAX_STORAGE_SIZE);
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Size = StorageData.DataLen;
  LOG((EFI_D_INFO, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));

  if (Size <= (sizeof(COMMON_VAR_DATA) - 1)) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  CbcfgData = (COMMON_VAR_DATA *)StorageData.Data;
  if (CbcfgData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_INFO, "Size=%d IcflData->DataLen=%d\n", 
    Size, CbcfgData->DataLen));
  if (CbcfgData->DataLen != Size - sizeof(COMMON_VAR_DATA) + 1) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    goto Done;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  *DataSetSize = CbcfgData->DataLen;
  *CbcfgDataSet = AllocateCopyPool(CbcfgData->DataLen, CbcfgData->Data);
  if (NULL == *CbcfgDataSet) {
    Status = EFI_OUT_OF_RESOURCES;
  }

Done:
  if (CbcfgData != NULL) {
    FreePoolDbg(CbcfgData);
  }
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
CbcfgStorageGetData(
  IN OUT CBCFG_DATA_SET **CbcfgDataSet,
  OUT UINTN *DataSetSize
  )
{
  return CbcfgStorageGetDataByGuid(CbcfgDataSet, DataSetSize, NULL);
}


EFI_STATUS
CbcfgStorageCheckIntegrity(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_UNSUPPORTED;
}


EFI_STATUS
CbcfgStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageSetRawData2(
    &gVarsGuid[gVarsGuidIdx], 
    CBCFG_VARIABLE_NAME,
    (UINT8*)RawData,
    RawDataLen,
    (CBCFG_VARIABLE_MAX_STORAGE_SIZE + CBCFG_VARIABLE_MAX_CARD_SIZE) / 
          CBCFG_VARIABLE_MAX_CARD_SIZE,
    CBCFG_VARIABLE_MAX_STORAGE_SIZE,
    CBCFG_VARIABLE_MAX_CARD_SIZE,
    FALSE
    );

  LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  if (gHistoryHandlerProtocol != NULL) {
    gHistoryHandlerProtocol->AddRecord(
      gHistoryHandlerProtocol,
      HEVENT_BOOT_CFG_CHANGE, 
      EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  }
  return Status; 
}

EFI_STATUS
CbcfgSave(
  IN CBCFG_DATA_SET *DataSet
  )
{
  COMMON_VAR_DATA *CvarData;
  UINTN DataLen;
  EFI_STATUS Status;

  if (DataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DataLen = sizeof(CBCFG_DATA_SET) - 1 + 
    DataSet->BootOptionsNum * sizeof(CBCFG_RECORD);
  LOG((EFI_D_INFO, "%a.%d BootOptionsNum=%d BootType=0x%X\n", 
    __FUNCTION__, __LINE__, DataSet->BootOptionsNum, DataSet->BootType));
  CvarData = AllocateZeroPoolDbg(sizeof(COMMON_VAR_DATA) - 1 + DataLen);
  if (NULL == CvarData) {
    return EFI_OUT_OF_RESOURCES;
  }
  CvarData->DataLen = (UINT32)DataLen;
  CopyMem(CvarData->Data, DataSet, DataLen);
  Status = CbcfgStorageSetRawData((UINT8*)CvarData, 
    sizeof(COMMON_VAR_DATA) - 1 + DataLen);
  FreePoolDbg(CvarData);
  return Status;
}


/**
  This function allows a caller to extract the current configuration for one
  or more named elements from the target driver.
**/
STATIC
EFI_STATUS
EFIAPI
FakeExtractConfigBm (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Request,
  OUT EFI_STRING                             *Progress,
  OUT EFI_STRING                             *Results
  )
{
  if (Progress == NULL || Results == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Progress = Request;
  return EFI_NOT_FOUND;
}

/**
  This function processes the results of changes in configuration.
**/
STATIC
EFI_STATUS
EFIAPI
FakeRouteConfigBm (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Configuration,
  OUT EFI_STRING                             *Progress
  )
{
  if (Configuration == NULL || Progress == NULL) {
    return EFI_INVALID_PARAMETER;
  }
#if 0
  *Progress = Configuration;
  if (!HiiIsConfigHdrMatch (Configuration, &mBootMaintGuid, mBootMaintStorageName)
      && !HiiIsConfigHdrMatch (Configuration, &mFileExplorerGuid, mFileExplorerStorageName)) {
    return EFI_NOT_FOUND;
  }

  *Progress = Configuration + StrLen (Configuration);
#endif
  return EFI_SUCCESS;
}

STATIC
CHAR16 *
GetStringById_1 (
  IN  EFI_STRING_ID   Id
  )
{
  return HiiGetString (gStringPackHandle, Id, NULL);
}

STATIC UINT16 mKeyInput = 0xFFFF;
STATIC EFI_GUID mBootManagerGuid = BOOT_MANAGER_FORMSET_GUID;
STATIC LIST_ENTRY mBootOptionsList;
STATIC LIST_ENTRY mBootOptionsList2;
STATIC BDS_COMMON_OPTION  *gOption;

HII_VENDOR_DEVICE_PATH  mBootManagerHiiVendorDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_VENDOR_DP,
      {
        (UINT8) (sizeof (VENDOR_DEVICE_PATH)),
        (UINT8) ((sizeof (VENDOR_DEVICE_PATH)) >> 8)
      }
    },
    //
    // {1DDDBE15-481D-4d2b-8277-B191EAF66525}
    //
    { 0x1dddbe15, 0x481d, 0x4d2b, { 0x82, 0x77, 0xb1, 0x91, 0xea, 0xf6, 0x65, 0x25 } }
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { 
      (UINT8) (END_DEVICE_PATH_LENGTH),
      (UINT8) ((END_DEVICE_PATH_LENGTH) >> 8)
    }
  }
};


STATIC BOOT_MANAGER_CALLBACK_DATA  gBootManagerPrivate = {
  BOOT_MANAGER_CALLBACK_DATA_SIGNATURE,
  NULL,
  NULL,
  {
    FakeExtractConfigBm,
    FakeRouteConfigBm,
    BootManagerCallback
  }
};


VOID
WaitForDevicesRefresh(
  VOID
  )
{
  gST->ConOut->ClearScreen(gST->ConOut);
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", 
    HiiGetString(
      gBootManagerPrivate.HiiHandle,
      STRING_TOKEN(STR_WAIT_FOT_DEV_LIST_UPDATING), NULL
      ), 
    L"", L"", NULL);
}


VOID
DeleteItemFromIcflListByNum(
  IN LIST_ENTRY *IcflList,
  IN UINTN Num
  )
{
  LIST_ENTRY *Link, *PrevLink;
  ICFL_LIST *List;
  UINTN Idx;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (IcflList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Invalid parameter!\n", __FUNCTION__, __LINE__));
    return;
  }

  if (IsListEmpty(IcflList)) {
    return;
  }

  for (Link = GetFirstNode(IcflList), Idx = 0; 
       !IsNull(IcflList, Link); Idx++
       ) {
    PrevLink = Link;
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);

    if (Idx == Num) {
      LOG((EFI_D_INFO, "%a.%d Idx == Num %d\n", 
        __FUNCTION__, __LINE__, Num));      
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      RemoveEntryList (PrevLink);
      FreePoolDbg(PrevLink);
      break;
    }
  }
}


/*
  obtain integrity checking files list
*/
EFI_STATUS
GetIcfl(
  IN OUT LIST_ENTRY *IcflList
  )
{
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (!IcflStoragePresent()) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    IcflStorageInitEmpty();
    return EFI_NOT_FOUND;
  }
  return IcflStorageGetData(IcflList);
}


UINTN
IcflListSize(
  IN LIST_ENTRY *IcflList
  )
{
  LIST_ENTRY *Link;
  UINTN Size;
  ICFL_LIST *List;

  if (IcflList == NULL) {
    return 0;
  }

  if (IsListEmpty(IcflList)) {
    return 0;
  }

  Size = 0;
  
  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);
    Size += sizeof(List->Hash);
    Size += StrSize(List->FileName);
  }
  return Size;
}

UINTN
IcflListItemsCount(
  IN LIST_ENTRY *IcflList
  )
{
  LIST_ENTRY *Link;
  UINTN ItemsCount;
  ICFL_LIST *List;

  if (IcflList == NULL) {
    return 0;
  }

  if (IsListEmpty(IcflList)) {
    return 0;
  }

  ItemsCount = 0;
  
  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);
    ItemsCount++;
  }
  return ItemsCount;
}



EFI_STATUS
FillDataFromIcflList(
  IN LIST_ENTRY *IcflList,
  IN OUT UINT8 *Data
  )
{
  LIST_ENTRY *Link;
  UINTN Size;
  ICFL_LIST *List;

  if (IcflList == NULL || IsListEmpty(IcflList) || Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);
    
    Size = StrSize(List->FileName);
    
    CopyMem(Data, List->Hash, sizeof(List->Hash));
    Data += sizeof(List->Hash);
    
    CopyMem(Data, List->FileName, Size);
    Data += Size;
  }
  return EFI_SUCCESS;
}



EFI_STATUS
StoreIcfl(
  IN LIST_ENTRY *IcflList
  )
{
  COMMON_VAR_DATA *IcflData = NULL;
  UINTN Size;
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (IcflList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  Size = IcflListSize(IcflList);
  LOG((EFI_D_INFO, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));

  IcflData = AllocateZeroPoolDbg(sizeof(COMMON_VAR_DATA) - 1 + Size);
  if (IcflData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  IcflData->DataLen = (UINT32)Size;

  if (Size) {
    FillDataFromIcflList(IcflList, IcflData->Data);
  }

  Status = IcflStorageSetRawData((UINT8*)IcflData, 
                                  sizeof(COMMON_VAR_DATA) - 1 + Size
                                 );
  
  if (IcflData != NULL) {
    FreePoolDbg(IcflData);
  }
  if (EFI_ERROR(Status)) {
    DestroyIcflList(IcflList);
  } else {
    bIcflListWasChanged = FALSE;
  }
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}


BOOLEAN
IcflItemPresent(
  IN CHAR16 *String,
  IN LIST_ENTRY *IcflList
  )
{
  LIST_ENTRY *Link;
  ICFL_LIST *List;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (String == NULL || IcflList == NULL) {
    return FALSE;
  }

  if (IsListEmpty(IcflList)) {
    return FALSE;
  }

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);

    
    LOG((EFI_D_INFO, "List->FileName=%s\n", List->FileName));
    LOG((EFI_D_INFO, "String=%s\n", String));
     
    if (0 == StrCmp(List->FileName, String)) {
      return TRUE;
    }
  }
  return FALSE;
}

EFI_STATUS
IcflUpdateItem (
  IN CHAR16 *String,
  IN CHAR16 *Path,
  IN LIST_ENTRY *IcflList
  )
{
  LIST_ENTRY *Link;
  ICFL_LIST *List;
  EFI_STATUS Status;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (String == NULL || IcflList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (IsListEmpty(IcflList)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);

    
    LOG((EFI_D_INFO, "List->FileName=%s\n", List->FileName));
    LOG((EFI_D_INFO, "String=%s\n", String));
     
    if (0 == StrCmp(List->FileName, String)) {
       Status = CalcHashCsOnFile16(Path, PRIMARY_HASH_TYPE, List->Hash);
       LOG ((EFI_D_INFO, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
       return Status;
    }
  }
  return EFI_NOT_FOUND;
}


/*
  * Hash parameter may be NULL
  */
EFI_STATUS
IcflAddItem(
  IN CHAR16 *String,
  IN BOOLEAN bAddToHead,
  IN BOOLEAN bQuitet,
  IN UINT8 *Hash OPTIONAL
  )
{
  UINTN Len;
  ICFL_LIST *List;
  EFI_STATUS Status;
  CHAR16 *FilePath, *FullPath, *Str = NULL;
  CHAR16 ShortName[10];
  UINTN Idx;

  Status = EFI_SUCCESS;
  LOG((EFI_D_INFO, "%a.%d String=%s\n", 
    __FUNCTION__, __LINE__, String));

  if (String == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  Len = StrSize(String);
  if (Len <= 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  
  if (Hash) {
    Len += StrSize(ICFL_SEPARATOR) + StrSize(L"MBR");
    Str = AllocateZeroPoolDbg(Len);
    if (Str == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    UnicodeSPrint(Str, Len, L"%s%sMBR", String, ICFL_SEPARATOR);
    if (IcflItemPresent(Str, &IcflList)) {
      if (!bQuitet) {
        ShowErrorPopup(gStringPackHandle, HiiGetString(gStringPackHandle, 
          STRING_TOKEN(STR_FILE_ALLREADY_PRESENT_ERR), NULL));
        Status =  EFI_ALREADY_STARTED;
      } else {
        Status = IcflUpdateItem (Str, String, &IcflList);
      }
      LOG((EFI_D_INFO, "%a.%d Status = %r\n", 
        __FUNCTION__, __LINE__, Status));
      goto Exit;
    }
    List = AllocateZeroPoolDbg(sizeof(ICFL_LIST) - sizeof(CHAR16) + Len);
    if (List == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Exit;
    }

    CopyMem(List->FileName, Str, Len);
    CopyMem(List->Hash, Hash, sizeof(List->Hash));    
    goto Done;
  }
  
  for (Idx = 0; String[Idx] != 0; Idx++) {
    if (String[Idx] == L':') {
      ShortName[Idx] = 0;
      break;
    }
    if (Idx >= ARRAY_ITEMS(ShortName)) {
      break;
    }
    ShortName[Idx] = String[Idx];
  }
  if (Idx >= StrLen(String)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  //CopyMem(ShortName, String, sizeof(CHAR16) * 4);
  //ShortName[4] = 0;
  
  FilePath = &String[Idx + 1];

  FullPath = FsDescTableGetFullName(ShortName);
  if (NULL == FullPath) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  Len = StrSize(FullPath) + StrSize(FilePath) + StrSize(ICFL_SEPARATOR);
  Str = AllocateZeroPoolDbg(Len);
  if (NULL == Str) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  UnicodeSPrint(Str, Len, L"%s%s%s", FullPath, ICFL_SEPARATOR, FilePath);
  FixHDDevicePathString(Str);
  LOG((EFI_D_INFO, "%a.%d Str=\"%s\"\n", 
    __FUNCTION__, __LINE__, Str));
  
  if (IcflItemPresent(Str, &IcflList)) {
    if (!bQuitet) {
      ShowErrorPopup(gStringPackHandle, HiiGetString(gStringPackHandle, 
        STRING_TOKEN(STR_FILE_ALLREADY_PRESENT_ERR), NULL));
      Status =  EFI_ALREADY_STARTED;
    } else {
      Status = IcflUpdateItem (Str, String, &IcflList);
    }
    LOG((EFI_D_INFO, "%a.%d Status = %r\n", 
        __FUNCTION__, __LINE__, Status));
    goto Exit;
  }
  
  Len = StrSize(Str);
  LOG((EFI_D_INFO, "%a.%d Len=%d\n", 
    __FUNCTION__, __LINE__, Len));
  if (Len <= 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status =  EFI_INVALID_PARAMETER;
    goto Exit;
  }
  List = AllocateZeroPoolDbg(sizeof(ICFL_LIST) - sizeof(CHAR16) + Len);
  if (List == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  CopyMem(List->FileName, Str, Len);

  LOG((EFI_D_INFO, "%a.%d List->FileName=%s\n", 
    __FUNCTION__, __LINE__, List->FileName));
  
  Status = CalcHashCsOnFile16(String, PRIMARY_HASH_TYPE, List->Hash);
  if (EFI_ERROR(Status)) {
    FreePoolDbg(List);
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    Status = EFI_ABORTED;
    goto Exit;
  }
  
Done:  
  LOG((EFI_D_INFO, "file hash:\n"));
  DumpBytes(List->Hash, sizeof(List->Hash));

  if (bAddToHead) {
    InsertHeadList (&IcflList, &List->Entry);
  } else {
    InsertTailList (&IcflList, &List->Entry);
  }
  LOG((EFI_D_INFO, "%a.%d Added FileName=%s\n", 
      __FUNCTION__, __LINE__, List->FileName));
  bIcflListWasChanged = TRUE;
Exit:
  if (Str) {
    FreePoolDbg(Str);
  }
  return Status;
}

EFI_STATUS
IcflItemCalcHash(
  IN ICFL_LIST *ListEntry,
  IN OUT UINT8 *HashData
  )
{
  EFI_DEVICE_PATH_PROTOCOL *Dp;
  EFI_FILE_HANDLE File;
  EFI_STATUS Status;
  CHAR16 *DevPath, *Ptr16;
  CHAR16 *FilePath;

  if (ListEntry == NULL || HashData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DevPath = ListEntry->FileName;
  Ptr16 = StrStr(ListEntry->FileName, ICFL_SEPARATOR);
  if (!Ptr16) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }
  *Ptr16 = 0;
  /* skip separator */
  FilePath = Ptr16 + StrLen(ICFL_SEPARATOR);
  LOG((EFI_D_INFO, "DevPath=%s FilePath=%s\n", DevPath, FilePath));

  Dp = StrToDevicePath(DevPath);
  *Ptr16 = L'|';

  if (IsLegacyBootDevPath(ListEntry->FileName)) {
    Status = CalcHashForMbr(ListEntry->FileName, PRIMARY_HASH_TYPE, HashData);
  } else { 
    File = LibFsOpenFileByDevPath(Dp, FilePath, EFI_FILE_MODE_READ, 0);
    if (File != NULL) {
      Status = CalcHashCsOnFileWithHandle(File, PRIMARY_HASH_TYPE, HashData);
      LibFsCloseFile(File);
    } else {
      Status = EFI_ABORTED;
    }
  }
Done:  
  return Status;
}

EFI_STATUS
IcflCheckIntegrity(
  VOID
  )
{
  LIST_ENTRY *Link;
  ICFL_LIST *List;
  CHAR8 HashData[MAX_HASH_LEN];
  EFI_STATUS Status;  
  LIST_ENTRY *IcflList, IcflListTmp;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  InitializeListHead(&IcflListTmp);
  IcflList = &IcflListTmp;
  Status = GetIcfl(IcflList);
  /* this case: list not exist */
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    return EFI_SUCCESS;
  }

  if (IsListEmpty(IcflList)) {
    LOG((EFI_D_INFO, "%a.%d List empty!\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);

    Status = IcflItemCalcHash(List, HashData);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
      goto Done;
    }
    if (CompareMem(HashData, List->Hash, sizeof(HashData))) {
      DEBUG((EFI_D_ERROR, "%a.%d EFI_CRC_ERROR\n", 
        __FUNCTION__, __LINE__));
#if 1
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      DumpBytes(HashData, MAX_HASH_LEN);
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      DumpBytes(List->Hash, MAX_HASH_LEN);
#endif
      Status = EFI_CRC_ERROR;
      goto Done;
    }
  }
  Status = EFI_SUCCESS;
Done:
  if (!IsListEmpty(IcflList)) {
    DestroyIcflList(IcflList);
  }
  return Status;
}


STATIC
EFI_STATUS
SaveExportedBootOptions(
  IN CHAR16 *UsbPathStr,
  IN CHAR16 *ExportData
  )
{
  CHAR16 FileName[255];
  EFI_TIME EfiTime;
  EFI_STATUS Status;
  EFI_FILE_HANDLE File = NULL;
  UINTN Size;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (!CheckFsPathPresent (UsbPathStr, NULL)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(gBootManagerPrivate.HiiHandle,
      HiiGetString(gBootManagerPrivate.HiiHandle, 
        STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), 
        NULL));
    return EFI_ABORTED;
  }
  
  Status = gRT->GetTime(&EfiTime, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  if (UsbPathStr == NULL || ExportData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  /* UsbPathStr must be like this: 'fs4:\'  */
  UnicodeSPrint(FileName, sizeof(FileName), 
    L"%sExportBootCfg_%04d%02d%02d_%02d%02d%02d.cfg", 
    UsbPathStr,
    EfiTime.Year,
    EfiTime.Month,
    EfiTime.Day,  
    EfiTime.Hour,
    EfiTime.Minute, 
    EfiTime.Second);

  LOG((EFI_D_INFO, "%a.%d FileName=%s\n", 
    __FUNCTION__, __LINE__, FileName));
  
  File = LibFsCreateFile16(FileName);
  if (File == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while LibFsCreateFile!\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Size = StrSize(ExportData);
  Status = LibFsWriteFile(File, &Size, ExportData);  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }
  LibFsCloseFile(File);
  return Status;
}


EFI_STATUS
GetBootTypeFromString(
  IN CHAR16 *Str,
  IN OUT UINT32 *BootType
  )
{
  if (Str == NULL || BootType == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_BOOT_TYPE_EFI), NULL))) {
    *BootType = BOOT_TYPE_EFI;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_BOOT_TYPE_FROM_FS), NULL))) {
    *BootType = BOOT_TYPE_FROM_FS;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_BOOT_TYPE_LEGACY), NULL))) {
    *BootType = BOOT_TYPE_LEGACY;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_BOOT_TYPE_DEFAULT), NULL))) {
    *BootType = BOOT_TYPE_DEFAULT;
    return EFI_SUCCESS;
  }
    
  return EFI_ABORTED;
}


CHAR16*
GetBootTypeStr(
  IN UINT32 BootType
  )
{
  switch (BootType) {
  case BOOT_TYPE_DEFAULT:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                        STRING_TOKEN(STR_BOOT_TYPE_DEFAULT), 
                        NULL);

  case BOOT_TYPE_EFI:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                        STRING_TOKEN(STR_BOOT_TYPE_EFI), 
                        NULL);
    
  case BOOT_TYPE_FROM_FS:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                        STRING_TOKEN(STR_BOOT_TYPE_FROM_FS),
                        NULL);
    
  case BOOT_TYPE_LEGACY:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                        STRING_TOKEN(STR_BOOT_TYPE_LEGACY),
                        NULL);
  }
  return NULL;
}



EFI_STATUS
GetModuleTypeFromString(
  IN CHAR16 *Str,
  IN OUT UINT32 *ModuleType
  )
{
  if (Str == NULL || ModuleType == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_MODULE_LINUX_TYPE), NULL))) {
    *ModuleType = MODULE_TYPE_LINUX;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_MODULE_MULTIBOOT_TYPE), NULL))) {
    *ModuleType = MODULE_TYPE_MULTIBOOT;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_MODULE_EFI_TYPE), NULL))) {
    *ModuleType = MODULE_TYPE_EFI;
    return EFI_SUCCESS;
  }
  if (0 == StrNoCaseCompare(Str, HiiGetString(gBootManagerPrivate.HiiHandle,
                              STRING_TOKEN(STR_MODULE_DEFAULT_TYPE), NULL))) {
    *ModuleType = MODULE_TYPE_DEFAULT;
    return EFI_SUCCESS;
  }
    
  return EFI_ABORTED;
}


CHAR16*
GetModuleTypeStr(
  IN UINT32 ModulesType
  )
{
  switch (ModulesType) {
  case MODULE_TYPE_LINUX:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                             STRING_TOKEN(STR_MODULE_LINUX_TYPE), 
                             NULL);
    
  case MODULE_TYPE_MULTIBOOT:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                             STRING_TOKEN(STR_MODULE_MULTIBOOT_TYPE),
                             NULL);
    
  case MODULE_TYPE_EFI:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                             STRING_TOKEN(STR_MODULE_EFI_TYPE),
                             NULL);
    
  case MODULE_TYPE_DEFAULT:
    return HiiGetString(gBootManagerPrivate.HiiHandle,
                             STRING_TOKEN(STR_MODULE_DEFAULT_TYPE),
                             NULL);
  }
  return NULL;
}


EFI_STATUS
ExportBootOptions(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *BootOptionsGuid,
  OUT CHAR16 **ExpStr
  )
{
  CBCFG_DATA_SET *CbcfgDataSet = NULL;
  UINTN DataSetSize, Size, Offs, Idx, IcflItemsCnt;
  EFI_STATUS Status;
  CHAR16 *ExportData = NULL, *EndStr, *BegStr, *TmpStrPtr;
  LIST_ENTRY IcflList, *Link;
  ICFL_LIST *List;
  UINT8 *DataPtr;
  CBCFG_RECORD *Rec;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (HiiHandle == NULL || BootOptionsGuid == NULL || ExpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  InitializeListHead(&IcflList);
  
  Status = CbcfgStorageGetData(&CbcfgDataSet, &DataSetSize);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }
  
  Status = GetIcfl(&IcflList);
  if (EFI_ERROR(Status)) {
    if (Status != EFI_NOT_FOUND) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto Done;
    }
  }

  Size = DataSetSize + IcflListSize(&IcflList);
  LOG((EFI_D_INFO, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));
  IcflItemsCnt = IcflListItemsCount(&IcflList);
  LOG((EFI_D_INFO, "%a.%d CbcfgDataSet->BootOptionsNum=%d\n", 
    __FUNCTION__, __LINE__, CbcfgDataSet->BootOptionsNum));
  LOG((EFI_D_INFO, "TAGS_TOTAL_LEN=%d\n", TAGS_TOTAL_LEN));
  LOG((EFI_D_INFO, "CbcfgDataSet->BootOptionsNum * ONE_MODULE_TAGS_LEN=%d\n", 
    CbcfgDataSet->BootOptionsNum * ONE_MODULE_TAGS_LEN));
  LOG((EFI_D_INFO, "IcflItemsCnt * ICFL_TAGS_LEN=%d\n", 
    IcflItemsCnt * ICFL_TAGS_LEN));

  if (GetBootTypeStr(CbcfgDataSet->BootType) == NULL ||
      GetModuleTypeStr(CbcfgDataSet->ModulesType) == NULL) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! CbcfgDataSet->ModulesType=%X\n", 
      __FUNCTION__, __LINE__, CbcfgDataSet->ModulesType));
    goto Done;
  }

  Size *= 2;
  Size += TAGS_TOTAL_LEN + CbcfgDataSet->BootOptionsNum * ONE_MODULE_TAGS_LEN + 
    IcflItemsCnt * ICFL_TAGS_LEN + sizeof(EFI_GUID) * 3 * sizeof(CHAR16) +
    StrSize(GetBootTypeStr(CbcfgDataSet->BootType)) + 
    StrSize(GetModuleTypeStr(CbcfgDataSet->ModulesType));
  ExportData = AllocateZeroPoolDbg(Size);
  if (ExportData == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  LOG((EFI_D_INFO, "%a.%d CbcfgDataSet->BootOptionsNum=%d\n", 
    __FUNCTION__, __LINE__, CbcfgDataSet->BootOptionsNum));

  BegStr = EndStr = ExportData;

  Offs = UnicodeSPrint(EndStr, Size, L"%s\n", BOOTCONF_TAG_BEG);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  Offs = UnicodeSPrint(EndStr, Size, L"%s%g%s\n", 
    BOOT_CONF_GUID_TAG_BEG, BootOptionsGuid, BOOT_CONF_GUID_TAG_END);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  TmpStrPtr = GetBootTypeStr(CbcfgDataSet->BootType);
  if (NULL == TmpStrPtr) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! CbcfgDataSet->BootType=%X\n", 
      __FUNCTION__, __LINE__, CbcfgDataSet->BootType));
    goto Done;
  }
  Offs = UnicodeSPrint(EndStr, Size, L"  %s%s%s\n", 
    BOOT_CONF_TYPE_TAG_BEG, TmpStrPtr, BOOT_CONF_TYPE_TAG_END);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  TmpStrPtr = GetModuleTypeStr(CbcfgDataSet->ModulesType);
  if (NULL == TmpStrPtr) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! CbcfgDataSet->ModulesType=%X\n", 
      __FUNCTION__, __LINE__, CbcfgDataSet->ModulesType));
    goto Done;
  }

  Offs = UnicodeSPrint(EndStr, Size, L"  %s%s%s\n", 
    BOOT_TYPE_TAG_BEG, TmpStrPtr, BOOT_TYPE_TAG_END);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  DataPtr = CbcfgDataSet->Data;
  
  for (Idx = 0; Idx < CbcfgDataSet->BootOptionsNum; Idx++) {
    Offs = UnicodeSPrint(EndStr, Size, L"  %s\n", MODULECONF_TAG_BEG);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    Rec = (CBCFG_RECORD*)DataPtr;

    if (CbcfgDataSet->BootType == BOOT_TYPE_EFI) {
      CHAR16 *FileName, *StrDevPath, *EfiFileName;
      CHAR16 FilePath[255];

      FileName = StrStr(Rec->DevPath, L"\\");
      StrDevPath = NULL;
      EfiFileName = NULL;
      
      if (FileName) {
        EfiFileName = StrStr (FileName, EFI_REMOVABLE_MEDIA_FILE_NAME);
        if (EfiFileName == NULL) {
          UnicodeSPrint(FilePath, sizeof(FilePath), 
            L"%s", FileName);
          EfiFileName = FilePath;
        }
        *FileName = 0;
        StrDevPath = GetFullDevicePathFromShortStringPath(Rec->DevPath, 
          EfiFileName ? EfiFileName : NULL);
        *FileName = L'\\';
      }

      if ((FileName == NULL && StrStr(Rec->DevPath, L")/FvFile(")) ||
           IsLegacyBootDevPath (Rec->DevPath)) {
        Offs = UnicodeSPrint(EndStr, Size, L"    %s%s%s\n", 
         DEVPATH_TAG_BEG,
         Rec->DevPath,
         DEVPATH_TAG_END);
      } else {
        Offs = UnicodeSPrint(EndStr, Size, L"    %s%s/%s%s\n", 
         DEVPATH_TAG_BEG,
         StrDevPath ? StrDevPath : Rec->DevPath,
         FileName ? FileName : EFI_REMOVABLE_MEDIA_FILE_NAME, 
         DEVPATH_TAG_END);
      }
    } else   {
      Offs = UnicodeSPrint(EndStr, Size, L"    %s%s/%s%s\n", DEVPATH_TAG_BEG,
        Rec->DeviceFullName, &Rec->DevPath[5], DEVPATH_TAG_END);
    }
    
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    if (StrLen(Rec->Args)) {
      Offs = UnicodeSPrint(EndStr, Size, L"    %s%s%s\n", PARAMS_TAG_BEG,
        Rec->Args, PARAMS_TAG_END);
      EndStr += Offs;
    }
      
    Offs = UnicodeSPrint(EndStr, Size, L"  %s\n", MODULECONF_TAG_END);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    DataPtr += sizeof(CBCFG_RECORD);
  }

  Offs = UnicodeSPrint(EndStr, Size, L"%s\n", BOOTCONF_TAG_END);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  Offs = UnicodeSPrint(EndStr, Size, L"\n%s\n", ICFL_TAG_BEG);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  LOG((EFI_D_INFO, "%a.%d IcflListSize(&IcflList)=%d\n", 
    __FUNCTION__, __LINE__, IcflListSize(&IcflList)));


  for (Link = GetFirstNode(&IcflList); 
       !IsNull(&IcflList, Link); 
       ) {
    CHAR16 TmpStr[255];
    
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (&IcflList, Link);

    Offs = UnicodeSPrint(EndStr, Size, L"  %s\n", ENTRY_TAG_BEG);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    LOG((EFI_D_INFO, "%a.%d List->FileName=\"%s\"\n", 
      __FUNCTION__, __LINE__, List->FileName));

    Offs = UnicodeSPrint(EndStr, Size, L"    %s%s%s\n", 
      FILE_TAG_BEG, List->FileName, FILE_TAG_END);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    GetDigestStr16(TmpStr, List->Hash, PRIMARY_HASH_TYPE);
    Offs = UnicodeSPrint(EndStr, Size, L"    %s%s%s\n", 
      HASH_TAG_BEG, TmpStr, HASH_TAG_END);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);

    Offs = UnicodeSPrint(EndStr, Size, L"  %s\n", ENTRY_TAG_END);
    EndStr += Offs;
    Size -= Offs * sizeof(CHAR16);
  }

  LOG((EFI_D_INFO, "%a.%d RESULT_DATA:\n", 
    __FUNCTION__, __LINE__));

  Offs = UnicodeSPrint(EndStr, Size, L"%s\n", ICFL_TAG_END);
  EndStr += Offs;
  Size -= Offs * sizeof(CHAR16);

  LOG((EFI_D_INFO, "\n"));
  while (BegStr != EndStr) {
    LOG((EFI_D_INFO, "%c", *BegStr));
    BegStr++;
  }
  LOG((EFI_D_INFO, "\n"));

Done:
  if (EFI_ERROR(Status)) {
    if (ExportData) {
      FreePool(ExportData);
    }
  } else {
    *ExpStr = ExportData;
  }
  
  if (CbcfgDataSet != NULL) {
    FreePoolDbg(CbcfgDataSet);
  }
  if (!IsListEmpty(&IcflList)) {
    DestroyIcflList(&IcflList);
  }
    
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


INTN
ImportBootOptions (
  IN CHAR16 *FilePath
  )
{
  INTN Status = 0;
  EFI_FILE_HANDLE File;
  UINTN Size, RdSize;
  CHAR16 *Data = NULL;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (NULL == FilePath || StrLen(FilePath) == 0) {
    // TODO: show error   
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return -1;
  }

  File = LibFsOpenFile16(FilePath, EFI_FILE_MODE_READ, 0);
  if (File == NULL) {
    return -2;
  }

  Size = LibFsSizeFile(File);
  if (Size == 0) {
    Status = -3;
    goto Done;
  }

  Data = AllocateZeroPoolDbg(Size);
  if (Data == NULL) {
    Status = -3;
    goto Done;
  }
  RdSize = Size;
  Status = LibFsReadFile(File, &RdSize, Data);
  if (EFI_ERROR(Status)) {
    Status = -4;
    goto Done;
  }

  Status = Xml16ConfigRead(Data, Size / 2);
  if (EFI_ERROR(Status)) {
    Status = -5;
    goto Done;
  }

  //ShowSuccessPopup(HiiHandle, 
  //  HiiGetString(HiiHandle,STRING_TOKEN(STR_IMPORT_OK), NULL));

Done:
  if (Data) {
    FreePoolDbg(Data);
  }
  LibFsCloseFile(File);
  return Status;
}

VOID
ImportBootOptionsFromFs(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 *FsPath
  )
{
  CHAR16 *FilePath;
  EFI_STATUS Status = EFI_ABORTED;
  INTN RetVal;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (HiiHandle == NULL || FsPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }

  if (!CheckFsPathPresent (FsPath, NULL)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(HiiHandle,
      HiiGetString(HiiHandle, 
        STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), 
        NULL));
    return;
  }
  FeLibSetDevicePath(FsPath);
  Status = FeLibTest(HiiHandle, &mBootManagerGuid, 
        CurrentFormId, 0xF000, LABEL_BOOT_OPTION, LABEL_BOOT_OPTION_END);
  if (EFI_ERROR(Status)) {
    // TODO: show error
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }

  FilePath = FeGetSelectedString();
  if ((FilePath != NULL) && StrLen(FilePath)) {
    ShowInfoPopup (
      gBootManagerPrivate.HiiHandle,
      HiiGetString(
        gBootManagerPrivate.HiiHandle,
        STRING_TOKEN (STR_BOOT_CFG_IMPORT_PLS_WAIT),
        NULL)
        );
  } else {
    return;
  }
  
  RetVal = ImportBootOptions(FilePath);
  gST->ConOut->ClearScreen(gST->ConOut);
  switch (RetVal) {
  case 0:
    ShowSuccessPopup(HiiHandle, 
      HiiGetString(HiiHandle,STRING_TOKEN(STR_IMPORT_OK), NULL));
    break;

  case -1:
    // no file selected
    break;

  case -2:  
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle,STRING_TOKEN(STR_ERR_OPEN_FILE), NULL));
    break;

  case -3:
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle,STRING_TOKEN(STR_ERR_SIZE_OF_FILE), NULL));
    break;

  case -4:
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle,STRING_TOKEN(STR_ERR_MEM_ALLOC), NULL));
    break;

  case -5:
  default:
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle,STRING_TOKEN(STR_ERR_XML_PARSE), NULL));
    break;
  }
}

EFI_STATUS
ImportBootOptionsFromDataBuf (
  IN UINT8 *Data,
  IN UINTN Size
  )
{
  EFI_STATUS Status;

  if (Data == NULL || Size == 0) {
    return EFI_INVALID_PARAMETER;
  }
  Status = Xml16ConfigRead((CHAR16*)Data, Size / 2);
  return Status;
}


EFI_STATUS
EFIAPI
MainModeCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  STATIC BOOLEAN bFormClose;
  
  if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
    return EFI_SUCCESS;
  }
  if (Action == EFI_BROWSER_ACTION_FORM_CLOSE) {
    if (bFormClose) {

    } else {
      if (NewMode != MAIN_BOOT_MANAGER_ID) {
        NewMode = CurrentMode = MAIN_BOOT_UNDEF;
      }
    }
    return EFI_SUCCESS;
  }
  if ((Value == NULL) || (ActionRequest == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  switch (QuestionId) {
  case MAIN_BOOT_IMPORT_ID:
    LOG((EFI_D_INFO, "%a.%d MAIN_BOOT_IMPORT_ID\n", 
      __FUNCTION__, __LINE__));    
    
    ImportBootOptionsFromFs(gBootManagerPrivate.HiiHandle, CurUsbPathStr);
    LOG((EFI_D_INFO, "%a.%d CurrentBootOption=%X gBootFromFsKey=%X\n", 
      __FUNCTION__, __LINE__, CurrentBootOption, gBootFromFsKey));

    /* read all options */
    
    DestroyBootCfgList(mCurrentBootConfigList);
    mCurrentBootConfigList = NULL;
    Init_gVarsDescStrMap();

    DestroyIcflList(&IcflList);
    InitializeListHead(&IcflList);
    GetIcfl(&IcflList);

    if (gHistoryHandlerProtocol != NULL) {
      gHistoryHandlerProtocol->AddRecord(
        gHistoryHandlerProtocol,
        HEVENT_BOOT_MNGR_IMPORT_OPT, 
        SEVERITY_LVL_INFO,
        HISTORY_RECORD_FLAG_RESULT_OK);
    }
    break;

  case MAIN_BOOT_EXPORT_ID:
    if (gHistoryHandlerProtocol != NULL) {
      gHistoryHandlerProtocol->AddRecord(
        gHistoryHandlerProtocol,
        HEVENT_BOOT_MNGR_EXPORT_OPT, 
        SEVERITY_LVL_INFO,
        HISTORY_RECORD_FLAG_RESULT_OK);
    }
    {
      UINTN Idx, SaveCurIdx = 0;
      EFI_STATUS Status = EFI_SUCCESS;
      CHAR16 *ExpStr[MAX_VARS_GUIDS];
      CHAR16 *ExpDataStr;
      UINTN TotalLen;

      LOG((EFI_D_INFO, "%a.%d MAIN_BOOT_EXPORT_ID\n", 
        __FUNCTION__, __LINE__));

      for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
        ExpStr[Idx] = NULL;
      }

      // Export current boot settings to xml
      for (Idx = 0, TotalLen = 0; Idx < MAX_VARS_GUIDS; Idx++) {
        if (gVarsDescStr[Idx] == NULL) {
          continue;
        }

        SaveCurIdx = gVarsGuidIdx;

        BootMngrSetVarsGuidIdx(Idx);
        Status = ExportBootOptions(
          gBootManagerPrivate.HiiHandle, 
          &gVarsGuid[Idx],
          &ExpStr[Idx]
          );
        
        gVarsGuidIdx = SaveCurIdx;
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(gBootManagerPrivate.HiiHandle, 
            HiiGetString(gBootManagerPrivate.HiiHandle, 
              STRING_TOKEN(STR_ERR_EXPORT), NULL));
          break;
        }
        if (ExpStr[Idx] != NULL) {
          TotalLen += StrSize(ExpStr[Idx]);
        }
      }

      LOG((EFI_D_INFO, "%a.%d TotalLen=%d\n", 
        __FUNCTION__, __LINE__, TotalLen));

      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        break;
      }

      ExpDataStr = AllocateZeroPoolDbg(TotalLen);
      if (ExpDataStr == NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        ShowErrorPopup(gBootManagerPrivate.HiiHandle, 
            HiiGetString(gBootManagerPrivate.HiiHandle, 
              STRING_TOKEN(STR_ERR_EXPORT), NULL));
        break;
      }

      LOG((EFI_D_INFO, "%a.%d TotalLen=%d\n", 
        __FUNCTION__, __LINE__, TotalLen));

      for (Idx = 0, TotalLen = 0; Idx < MAX_VARS_GUIDS; Idx++) {
        if (ExpStr[Idx] != NULL) {
          StrCat(ExpDataStr, ExpStr[Idx]);
          LOG((EFI_D_INFO, "%a.%d ExpStr[%d]=%lp\n", 
            __FUNCTION__, __LINE__, Idx, ExpStr[Idx]));
          FreePoolDbg(ExpStr[Idx]);
        }
      }

      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

      Status = SaveExportedBootOptions(CurUsbPathStr, ExpDataStr);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        ShowErrorPopup(gBootManagerPrivate.HiiHandle, 
            HiiGetString(gBootManagerPrivate.HiiHandle, 
              STRING_TOKEN(STR_ERR_EXPORT), NULL));
      } else {
        ShowSuccessPopup(gBootManagerPrivate.HiiHandle, 
          HiiGetString(gBootManagerPrivate.HiiHandle, 
            STRING_TOKEN(STR_EXPORT_OK), NULL));
      }
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      if (ExpDataStr) {
        FreePoolDbg(ExpDataStr);
      }
    }
    break;

  case MAIN_BOOT_UPDATE_DEVICES_LIST_ID:
    WaitForDevicesRefresh();
    BdsLibConnectAllDriversToAllControllers();    
    break;

  default:
    if(QuestionId != 0)		// workaround; 0 недопустимое значение (для NewMode, во всяком случае), но, тем не менее, иногда попадает на вход данной функции
    {
	NewMode = QuestionId;
    }
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bFormClose = TRUE;
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
IntegrityModeCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  STATIC BOOLEAN bFormClose;
  EFI_STATUS Status;

  if (Action == EFI_BROWSER_ACTION_FORM_CLOSE) {
    if (bFormClose) {
      
    } else {
      NewMode = MAIN_BOOT_CONFIG_ID; //MAIN_BOOT_UNDEF;
      CurrentMode = MAIN_BOOT_UNDEF; //
    }
  }
  if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
    bFormClose = FALSE;
  }

  if ((Action == EFI_BROWSER_ACTION_FORM_OPEN) || (Action == EFI_BROWSER_ACTION_FORM_CLOSE)) {
    return EFI_SUCCESS;
  }
  if ((Value == NULL) || (ActionRequest == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (QuestionId >= ICFL_LIST_START) {
    DeleteItemFromIcflListByNum(&IcflList, QuestionId - ICFL_LIST_START);
    bFormClose = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    NewMode = CurrentMode; // save current mode (current menu)
    CurrentMode = MAIN_BOOT_CONFIG_ID; // set current mode as previous menu
    return EFI_SUCCESS;
  }

  switch (QuestionId) {
  case MAIN_BOOT_ADD_FILE_ID:
    NewMode = MAIN_BOOT_SELECT_FILE_ID;
    bFormClose = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  case MAIN_REFRESH_FILES_LIST_ID:
    bFormClose = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    NewMode = CurrentMode; // save current mode (current menu)
    CurrentMode = MAIN_BOOT_CONFIG_ID; // set current mode as previous menu
    bIntegrityPageCheckHash = TRUE;
    break;
    
  case MAIN_CLEAN_FILES_LIST_ID:
    bFormClose = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    NewMode = CurrentMode; // save current mode (current menu)
    CurrentMode = MAIN_BOOT_CONFIG_ID; // set current mode as previous menu
    DestroyIcflList(&IcflList);
    InitializeListHead(&IcflList);
    break;

  case MAIN_BOOT_UPDATE_DEVICES_LIST_ID:
    WaitForDevicesRefresh();
    BdsLibConnectAllDriversToAllControllers();
    break;

  case MAIN_BOOT_SAVE_FILES_LIST_ID:
    Status = StoreIcfl(&IcflList);
    if (!EFI_ERROR(Status)) {
      ShowSuccessPopup(gStringPackHandle, 
        HiiGetString(gStringPackHandle, 
          STRING_TOKEN(STR_SAVE_FILES_LIST_OK), NULL));
    } else {
      ShowErrorPopup(gStringPackHandle, HiiGetString(gStringPackHandle, 
          STRING_TOKEN(STR_SAVE_FILES_LIST_ERR), NULL));
    }
    break;
  }
  
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
ManagerModeCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  BDS_COMMON_OPTION       *Option;
  LIST_ENTRY              *Link;
  UINT16                  KeyCount;
  STATIC BOOLEAN bFormClose;
  
  if (Action == EFI_BROWSER_ACTION_FORM_CLOSE) {
    if (bFormClose) {
      
    } else {
      NewMode = MAIN_BOOT_UNDEF;
    }
  }
  if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
    bFormClose = FALSE;
  }

  if ((Action == EFI_BROWSER_ACTION_FORM_OPEN) || (Action == EFI_BROWSER_ACTION_FORM_CLOSE)) {
    return EFI_SUCCESS;
  }
  if ((Value == NULL) || (ActionRequest == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (QuestionId == MAIN_BOOT_UPDATE_DEVICES_LIST_ID) {
    WaitForDevicesRefresh();
    BdsLibConnectAllDriversToAllControllers();
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bFormClose = TRUE;
    UpdateModeFlagsForConfigModeFormRefresh();
    return EFI_SUCCESS;
  }
  
  //
  // Initialize the key count
  //
  KeyCount = 0;
  mKeyInput = 0xFFFF;

  for (Link = GetFirstNode (&mBootOptionsList); 
       !IsNull (&mBootOptionsList, Link); 
       Link = GetNextNode (&mBootOptionsList, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    KeyCount++;

    gOption = Option;

    if (Option->OptionNumber == QuestionId) {
      mKeyInput = QuestionId;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      break;
    }
  }

  if (mKeyInput != 0xFFFF) {
    return EFI_SUCCESS;
  }

  for (KeyCount = 0; KeyCount < MAX_VARS_GUIDS; KeyCount++) {
    if (gVarsQId[KeyCount] == QuestionId) {
      mKeyInput = QuestionId;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      gOption = NULL;
      return EFI_SUCCESS;
    }
  }

  for (Link = GetFirstNode (&mBootOptionsList2); !IsNull (&mBootOptionsList2, Link); Link = GetNextNode (&mBootOptionsList2, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    KeyCount++;

    gOption = Option;

    if (QuestionId == Option->OptionNumber) {
      mKeyInput = QuestionId;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      break;
    }
  }
  return EFI_SUCCESS;
}


CHAR16 *
GetSelectedModuleDevicePathString(
  IN UINTN RecIdx
  )
{
  UINTN Num;
  CBCFG_DATA_SET *DataSet;
  UINT8 *Ptr;
  CBCFG_RECORD *Rec;
  
  Num = CurrentBootOption;
  DataSet = BootCfgGetDataSetByNum(mCurrentBootConfigList, Num);
  if (DataSet == NULL) {
    DEBUG((EFI_D_ERROR, "\n%a.%d **** BUG BUG BUG ****  DataSet = NULL\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  if (RecIdx >= DataSet->BootOptionsNum) {
    DEBUG((EFI_D_ERROR, "\n%a.%d **** BUG BUG BUG ****  Idx = %d, Num = %d\n", 
      __FUNCTION__, __LINE__, RecIdx, DataSet->BootOptionsNum));
    return NULL;
  }
  Ptr = DataSet->Data + RecIdx * sizeof(CBCFG_RECORD);
  Rec = (CBCFG_RECORD*)Ptr;
  return Rec->DevPath;
}

VOID
UpdateRecordArgsString(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_IFR_TYPE_VALUE *Value,
  IN UINTN RecIdx
  )
{
  UINTN Num;
  CBCFG_DATA_SET *DataSet;
  UINT8 *Ptr;
  CBCFG_RECORD *Rec;
  CHAR16 *TmpStr;
  
  if (HiiHandle == NULL || Value == NULL) {
    DEBUG((EFI_D_ERROR, "\n%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return;
  }
  
  Num = CurrentBootOption;
  DataSet = BootCfgGetDataSetByNum(mCurrentBootConfigList, Num);
  if (DataSet == NULL || RecIdx >= DataSet->BootOptionsNum) {
    DEBUG((EFI_D_ERROR, "\n%a.%d **** BUG BUG BUG ****\n", 
      __FUNCTION__, __LINE__));
    return;
  }
  Ptr = DataSet->Data + RecIdx * sizeof(CBCFG_RECORD);
  Rec = (CBCFG_RECORD*)Ptr;

  TmpStr = HiiGetString(HiiHandle, Value->string, NULL);
  LOG((EFI_D_INFO, "\n%a.%d TmpStr=%s\n", 
    __FUNCTION__, __LINE__, TmpStr));

  if (StrSize(TmpStr) <= sizeof(Rec->Args)) {
    StrCpy(Rec->Args, TmpStr);
  }
}


EFI_STATUS
ConfigModeRetriveFormData(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )  
{
  CHAR16 *Str16;
  UINTN Num, RecIdx;
  CBCFG_DATA_SET *DataSet;
  CBCFG_RECORD *Rec;
  UINT8 *Ptr;

  Str16 = (CHAR16*)Value;
  
  LOG((EFI_D_INFO, "%a.%d QuestionId=%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  if (QuestionId < MAIN_BOOT_MODULES_START || 
      QuestionId >= ICFL_LIST_START) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;//EFI_INVALID_PARAMETER;
  }

  RecIdx = (QuestionId - MAIN_BOOT_MODULES_START) / 2;
  LOG((EFI_D_INFO, "%a.%d RecIdx=0x%X\n", __FUNCTION__, __LINE__, RecIdx));

  Num = CurrentBootOption;
  DataSet = BootCfgGetDataSetByNum(mCurrentBootConfigList, Num);
  if (DataSet == NULL || RecIdx >= DataSet->BootOptionsNum) {
    DEBUG((EFI_D_ERROR, "\n%a.%d **** BUG BUG BUG ****\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Ptr = DataSet->Data + RecIdx * sizeof(CBCFG_RECORD);
  Rec = (CBCFG_RECORD*)Ptr;
  
  if ((QuestionId & 0x1) == 0) { /* it is device path */
#if 0    
    UnicodeSPrint(Str16, sizeof(Rec->DevPath), L"%s",
      StrLen(Rec->DevPath) ? Rec->DevPath : L"-");
#endif
  } else { /* it is arguments */
    UnicodeSPrint(Str16, sizeof(Rec->Args), L"%s",
      StrLen(Rec->Args) ? Rec->Args : L"-");
  }

  return EFI_SUCCESS;
}


EFI_FILE_HANDLE
OpenEfiDevPath(
  IN CHAR16 *EfiDevPath,
  IN BOOLEAN bAddToIcfl
  )
{
  CHAR16 *FileName, *Ptr16, *DevPath;
  EFI_FILE_HANDLE FileHandle;
  EFI_STATUS Status;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (EfiDevPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
  Ptr16 = StrStr(EfiDevPath, L"\\/");
  if (NULL == Ptr16) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  *Ptr16 = 0;
  DevPath = AllocateCopyPool(StrSize(EfiDevPath), EfiDevPath);
  if (DevPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  UnicodeSPrint(DevPath, StrSize(EfiDevPath), L"%s", EfiDevPath);
  FileName = AllocateCopyPool(StrSize(&Ptr16[1]), &Ptr16[1]);
  if (FileName == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePoolDbg(DevPath);
    return NULL;
  }
  UnicodeSPrint(FileName, StrSize(&Ptr16[1]), L"d00:%s", &Ptr16[1]);
  *Ptr16 = L'\\';

  LOG((EFI_D_INFO, "%a.%d DevPath=\"%s\"\n", 
    __FUNCTION__, __LINE__, DevPath));
  LOG((EFI_D_INFO, "%a.%d FileName=\"%s\"\n", 
    __FUNCTION__, __LINE__, FileName));

  if (FsDescTableGetFullName(L"d00")) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FsDescTableRemoveLastItem();
  }

  AddFsDescTableItem(L"d00", DevPath, FALSE);

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (bAddToIcfl) {
    Status = IcflAddItem(FileName, TRUE, TRUE, NULL);
    if (EFI_ERROR(Status)) {
      FreePoolDbg(FileName);
      FreePoolDbg(DevPath);
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return NULL;
    }
  }
  FileHandle = LibFsOpenFile16(FileName, EFI_FILE_MODE_READ, 0);
  FreePoolDbg(FileName);
  FreePoolDbg(DevPath);
  return FileHandle;
}


EFI_STATUS
CalcHashForMbr(
  IN CHAR16 *DevPath,
  IN UINT8 CsType,
  IN OUT UINT8 *Hash
  )
{
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  MASTER_BOOT_RECORD *Mbr;
  EFI_STATUS Status;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  DevicePath = StrToDevicePath(DevPath);
  
  LOG((EFI_D_INFO, "%a.%d DevPath=%s\n", 
    __FUNCTION__, __LINE__, DevPath));
 

  BlockIo = GetBlkIoForLegacyDevPath(DevicePath);
  
  if (BlockIo == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG((EFI_D_INFO, "%a.%d BlockIo->Media->BlockSize=%d\n", 
    __FUNCTION__, __LINE__, BlockIo->Media->BlockSize));

  if (BlockIo->Media->BlockSize == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  Mbr = AllocateZeroPool (BlockIo->Media->BlockSize);
  if (Mbr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = BlockIo->ReadBlocks (
         BlockIo,
         BlockIo->Media->MediaId,
         0,
         BlockIo->Media->BlockSize,
         Mbr
         );
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  if (!EFI_ERROR (Status)) {
    LOG((EFI_D_INFO, "%a.%d Mbr->Signature=%04X\n", 
      __FUNCTION__, __LINE__, Mbr->Signature));
    Status = CalcHashCs(CsType, (UINT8*)Mbr, sizeof(*Mbr), 
      CALC_CS_RESET | CALC_CS_FINALIZE, Hash);
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes((UINT8*)Mbr, sizeof(*Mbr));
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes((UINT8*)Hash, MAX_HASH_LEN);

  FreePoolDbg(Mbr);
  return Status;
}


EFI_STATUS
UpdateModulesHash(
  IN CBCFG_DATA_SET *DataSet
  )
{
  UINTN Idx;
  UINT8 *DataPtr;
  CBCFG_RECORD *Rec;
  EFI_FILE_HANDLE File;
  EFI_STATUS Status;
  int ret_val;
  UINTN ErrCnt = 0;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (DataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (DataSet->BootType == BOOT_TYPE_DEFAULT) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  DataPtr = DataSet->Data;
  LOG((EFI_D_INFO, "%a.%d DataSet->BootOptionsNum=%d\n", 
    __FUNCTION__, __LINE__, DataSet->BootOptionsNum));
  
  for (Idx = 0; Idx < DataSet->BootOptionsNum; Idx++) {
    LOG((EFI_D_INFO, "%a.%d Idx=%d\n", __FUNCTION__, __LINE__, Idx));
    if (FsDescTableGetFullName(L"d00")) {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      FsDescTableRemoveLastItem();
    }
    
    Rec = (CBCFG_RECORD*)DataPtr;
    DataPtr += sizeof(CBCFG_RECORD);

    LOG((EFI_D_INFO, "%a.%d DataSet->BootType=0x%X\n",
        __FUNCTION__, __LINE__, DataSet->BootType));
    LOG((EFI_D_INFO, "%a.%d Rec->DevPath=\"%s\"\n",
        __FUNCTION__, __LINE__, Rec->DevPath));
    LOG((EFI_D_INFO, "%a.%d Rec->DeviceFullName=\"%s\"\n",
        __FUNCTION__, __LINE__, Rec->DeviceFullName));
    LOG((EFI_D_INFO, "%a.%d Rec->Args=\"%s\"\n",
        __FUNCTION__, __LINE__, Rec->Args));    

    ZeroMem(Rec->Hash, sizeof(Rec->Hash));

    if (DataSet->BootType == BOOT_TYPE_EFI) {

      CHAR16 *FileName, *StrDevPath, *EfiFileName;
      CHAR16 FilePath[255], TmpPath[255]; 

      // пропускаем для опции EFI NETWORK
      if (NULL != StrStr (Rec->DevPath, L"MAC(")) continue;
      
      if (IsLegacyBootDevPath(Rec->DevPath)) {
         
        // WORKAROUND: пропускаем MBR для DVD-ROM
        // TODO: проверить на внешнем USB DVD, CD-ROM
        if  (NULL != StrStr (Rec->DeviceFullName, L"DVD")) continue;
        
        Status = CalcHashForMbr(Rec->DevPath, PRIMARY_HASH_TYPE, Rec->Hash);
        LOG((EFI_D_INFO, "%a.%d Status = %X\n", 
          __FUNCTION__, __LINE__, Status));
        if (!EFI_ERROR(Status)) {
          Status = IcflAddItem(Rec->DevPath, TRUE, TRUE, Rec->Hash);
          if (EFI_ERROR(Status)) {
            ErrCnt++;
          }
        } else {
          ErrCnt++;
        }
        continue;
      }

      FileName = StrStr(Rec->DevPath, L"\\");
      EfiFileName = NULL;
      
      if (FileName) {
        EfiFileName = StrStr (FileName, EFI_REMOVABLE_MEDIA_FILE_NAME);
        if (EfiFileName == NULL) {
          EfiFileName = TmpPath;
          UnicodeSPrint(EfiFileName, sizeof(TmpPath), 
            L"%s", FileName);
        }
        *FileName = 0;
        StrDevPath = GetFullDevicePathFromShortStringPath(Rec->DevPath,
          EfiFileName ? EfiFileName : NULL);
        ret_val = AddFsDescTableItem(L"d00", StrDevPath, FALSE);
        *FileName = L'\\';
      } else {
        ret_val = AddFsDescTableItem(L"d00", Rec->DevPath, FALSE);
      }

      if (-1 == ret_val) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }

      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      UnicodeSPrint(FilePath, sizeof(FilePath), 
        L"d00:%s", EfiFileName ? EfiFileName : EFI_REMOVABLE_MEDIA_FILE_NAME);
      LOG ((EFI_D_INFO, "FilePath=%s\n", FilePath));
      File = LibFsOpenFile16(FilePath, EFI_FILE_MODE_READ, 0);
      if (File == NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n",
          __FUNCTION__, __LINE__));
        File = OpenEfiDevPath(Rec->DevPath, TRUE);
        if (File == NULL) {
          DEBUG((EFI_D_ERROR, "%a.%d Error!\n",
            __FUNCTION__, __LINE__));
          ErrCnt++;
          return EFI_NOT_FOUND;
        }
      } else {
        Status = IcflAddItem(FilePath, TRUE, TRUE, NULL);
        if (EFI_ERROR (Status)) {
          DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
          __FUNCTION__, __LINE__, Status));
          ErrCnt++;
        }
      }

      Status = CalcHashCsOnFileWithHandle(File, PRIMARY_HASH_TYPE, Rec->Hash);
      LibFsCloseFile(File);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
          __FUNCTION__, __LINE__, Status));
        ErrCnt++;
      }
    } // if (DataSet->BootType == BOOT_TYPE_EFI)
    
    else { // BOOT_TYPE_FROM_FS | BOOT_TYPE_LEGACY

      Status = IcflAddItem(Rec->DevPath, TRUE, TRUE, NULL);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
        return EFI_NOT_FOUND;
      }
      Status = CalcHashCsOnFile16(Rec->DevPath, PRIMARY_HASH_TYPE, Rec->Hash);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
          __FUNCTION__, __LINE__, Status));
        ErrCnt++;
      }
    }
  } // for (Idx < BootOptionsNum) 

  if (FsDescTableGetFullName(L"d00")) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FsDescTableRemoveLastItem();
  }

  LOG((EFI_D_INFO, "%a.%d ErrCnt=%d\n", __FUNCTION__, __LINE__, ErrCnt));
  
  return ErrCnt ? EFI_ABORTED : EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
ConfigModeCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  STATIC BOOLEAN bFormClose;
  EFI_STATUS Status;
  
  if (Action == EFI_BROWSER_ACTION_FORM_CLOSE) {
    if (bFormClose) {
      
    } else {
      NewMode = MAIN_BOOT_UNDEF;
    }
  }
  if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
    bFormClose = FALSE;
  }
  if ((Action == EFI_BROWSER_ACTION_FORM_OPEN) || 
      (Action == EFI_BROWSER_ACTION_FORM_CLOSE)) {
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_RETRIEVE == Action) {
    return ConfigModeRetriveFormData(This, Action, QuestionId, Type, Value, 
      ActionRequest);
  }
  if ((Value == NULL) || (ActionRequest == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_INFO, "\n%a.%d ++++ QuestionId=%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  if (QuestionId >= MAIN_BOOT_MODULES_START && QuestionId < ICFL_LIST_START) {    
    if ((QuestionId & 0x1) == 0) { /* it is device path */
      DoFeMode = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      UpdateModeFlagsForConfigModeFormRefresh();
      SelectedModuleDevPath = GetSelectedModuleDevicePathString(
        (QuestionId - MAIN_BOOT_MODULES_START) / 2);
    } else { /* it is arguments */
      UpdateRecordArgsString(gStringPackHandle, 
        Value, (QuestionId - MAIN_BOOT_MODULES_START) / 2);
    }
    return EFI_SUCCESS;
  }

  switch (QuestionId) {
  case MAIN_BOOT_MODE_ID:
    if (Value) {
#if 1
      UINTN Idx, Idx2;

      DestroyBootCfgList(mCurrentBootConfigList);
      mCurrentBootConfigList = NULL;
      if (Value->u8 >= ARRAY_ITEMS(gVarsDescStrMap)) {
        break;
      }
      
      gVarsGuidIdx = gVarsDescStrMap[Value->u8];
      gVarsDescStrMap[0] = gVarsGuidIdx;
      for (Idx = 0, Idx2 = 1; Idx < MAX_VARS_GUIDS; Idx++) {
        if (Idx == gVarsGuidIdx) {
          continue;
        }
        gVarsDescStrMap[Idx2++] = Idx;  
      }

      
      DestroyIcflList(&IcflList);
      InitializeListHead(&IcflList);
      GetIcfl(&IcflList);
      
#else
      if (gVarsGuidIdx != Value->u8) {
        DestroyBootCfgList(mCurrentBootConfigList);
        mCurrentBootConfigList = NULL;
      }
      gVarsGuidIdx = Value->u8;
#endif      
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      UpdateModeFlagsForConfigModeFormRefresh();      
      LOG((EFI_D_INFO, "\n%a.%d gVarsGuidIdx=0x%X\n", 
                __FUNCTION__, __LINE__, gVarsGuidIdx));
    }
    break;
    
  case MAIN_BOOT_CONFIG_MN_ITEM_ID:
    if (Value) {
      LOG((EFI_D_INFO, "\n%a.%d Value->u8=0x%X\n", 
          __FUNCTION__, __LINE__, Value->u8));
#if 0
      if ((CurrentBootOption == gBootFromFsKey && 
           Value->u8 != gBootFromFsKey) ||
          (gBootFromFsKey && Value->u8 == gBootFromFsKey)) {
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
        bFormClose = TRUE;
        UpdateModeFlagsForConfigModeFormRefresh();  
      }
#else
      if (CurrentBootOption != Value->u8) {
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
        bFormClose = TRUE;
        UpdateModeFlagsForConfigModeFormRefresh();
      }
      CurrentBootOption = Value->u8;
    }
#endif    
    break;

  case MAIN_BOOT_TYPE_SELECT_ID:
    {
      CBCFG_DATA_SET *DataSet;
      UINTN Num;

      if (Value == NULL) {
        break;
      }

      LOG((EFI_D_INFO, "\n%a.%d Value->u8=0x%X\n", 
          __FUNCTION__, __LINE__, Value->u8));

      Num = CurrentBootOption;
      DataSet = BootCfgGetDataSetByNum(mCurrentBootConfigList, Num);
      if (NULL == DataSet) {
        break;
      }
      if (Value->u8 >= ARRAY_ITEMS(ModuleTypeIndexes)) {
        break;
      }
      DataSet->ModulesType = (UINT32)ModuleTypeIndexes[Value->u8];
      LOG((EFI_D_INFO, "\n%a.%d DataSet->ModulesType=0x%X\n", 
          __FUNCTION__, __LINE__, DataSet->ModulesType));
    }
    break;

  case MAIN_REMOVE_MODULES_ID:
    LOG((EFI_D_INFO, "%a.%d MAIN_REMOVE_MODULES_ID\n", __FUNCTION__, __LINE__));
    BootFromFsDestroyModules(mCurrentBootConfigList);
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bFormClose = TRUE;
    UpdateModeFlagsForConfigModeFormRefresh();
    break;

  case MAIN_ADD_MODULE_ID:
    LOG((EFI_D_INFO, "%a.%d MAIN_ADD_MODULE_ID\n", __FUNCTION__, __LINE__));
    Status = BootFromFsAddNewModule(mCurrentBootConfigList, NULL, NULL);
    LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      ShowErrorPopup(gStringPackHandle, 
        HiiGetString(gStringPackHandle, 
          Status == EFI_ABORTED ? 
            STRING_TOKEN(STR_ERR_MAX_MODULES) :
            STRING_TOKEN(STR_ADD_NEW_MODULE_ERR), NULL));
    } else {
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bFormClose = TRUE;
      UpdateModeFlagsForConfigModeFormRefresh();
    }
    break;

  case MAIN_BOOT_INTEGRITY_ID:
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bFormClose = TRUE;
    NewMode = MAIN_BOOT_INTEGRITY_ID;
    break;

  case MAIN_BOOT_UPDATE_DEVICES_LIST_ID:
    WaitForDevicesRefresh();
    BdsLibConnectAllDriversToAllControllers();
    break;

  case MAIN_BOOT_SAVE_CURRENT_CFG_ID:
    {
      CBCFG_LIST *CbcfgList;
      COMMON_VAR_DATA *CvarData;
      UINTN DataLen;
      
      if (mCurrentBootConfigList == NULL || 
          IsListEmpty(&mCurrentBootConfigList->Entry)) {
        /* TODO: show error */
        break;
      }
      LOG((EFI_D_INFO, "%a.%d Starting to find item (0x%X)...\n", 
        __FUNCTION__, __LINE__, CurrentBootOption));
      /* find selected item */
      CbcfgList = BootCfgGetListItemByNum(
        mCurrentBootConfigList, CurrentBootOption);      

      if (NULL == CbcfgList) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }

      Status = UpdateModulesHash(CbcfgList->DataSet);
      if (EFI_NOT_FOUND == Status) {
        ShowErrorPopup(gStringPackHandle, 
          HiiGetString(gStringPackHandle, STRING_TOKEN(STR_DEV_PATH_NOT_FOUND), NULL));
        
        // критическая ошибка
        break;
      }
      else if (EFI_ERROR(Status)) {
        ShowErrorPopup(gStringPackHandle, 
          HiiGetString(gStringPackHandle, STRING_TOKEN(STR_WARN_CANNT_UPDATE_HASH), NULL));
      }

      DataLen = sizeof(CBCFG_DATA_SET) - 1 + 
        CbcfgList->DataSet->BootOptionsNum * sizeof(CBCFG_RECORD);
      LOG((EFI_D_INFO, "%a.%d BootOptionsNum=%d BootType=0x%X DataLen=%d\n", 
        __FUNCTION__, __LINE__, CbcfgList->DataSet->BootOptionsNum, 
        CbcfgList->DataSet->BootType,
        DataLen
        ));
      CvarData = AllocateZeroPoolDbg(sizeof(COMMON_VAR_DATA) - 1 + DataLen);
      if (NULL == CvarData) {          
        ShowErrorPopup(gStringPackHandle, 
          HiiGetString(gStringPackHandle, 
            STRING_TOKEN(STR_SAVE_CURR_CFG_ERR), NULL));
        break;
      }
      CvarData->DataLen = (UINT32)DataLen;
      CopyMem(CvarData->Data, CbcfgList->DataSet, DataLen);
      Status = CbcfgStorageSetRawData((UINT8*)CvarData, 
        sizeof(COMMON_VAR_DATA) - 1 + DataLen);
      FreePoolDbg(CvarData);
      
      LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));

      if (bIcflListWasChanged && !EFI_ERROR(Status)) {
        Status = StoreIcfl(&IcflList);
      }
      
      if (EFI_ERROR(Status)) {
        ShowErrorPopup(gStringPackHandle, 
          HiiGetString(gStringPackHandle, 
            STRING_TOKEN(STR_SAVE_CURR_CFG_ERR), NULL));
      } else {
        ShowSuccessPopup(gStringPackHandle, 
          HiiGetString(gStringPackHandle, 
            STRING_TOKEN(STR_SAVE_CURR_CFG_OK), NULL));
      }
    }
    break;
  }

  
  return EFI_SUCCESS;
}




/**
  This call back function is registered with Boot Manager formset.
  When user selects a boot option, this call back function will
  be triggered. The boot option is saved for later processing.
**/
EFI_STATUS
EFIAPI
BootManagerCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  LOG((EFI_D_INFO, "\n%a.%d Action=0x%X QuestionId=0x%X CurrentMode=0x%X\n", 
    __FUNCTION__, __LINE__, Action, QuestionId, CurrentMode));

  if (QuestionId >= 0xF000 && QuestionId <= 0xFFFF) {
    return FeCallback(This, Action, QuestionId, Type, Value, ActionRequest);
  }  

  switch (CurrentMode) {
  case MAIN_BOOT_UNDEF:        
    return MainModeCallback(
                This,
                Action,
                QuestionId,
                Type,
                Value,
                ActionRequest);

  case MAIN_BOOT_CONFIG_ID:
    return ConfigModeCallback(
                This,
                Action,
                QuestionId,
                Type,
                Value,
                ActionRequest);

  case MAIN_BOOT_MANAGER_ID:    
    return ManagerModeCallback(
                This,
                Action,
                QuestionId,
                Type,
                Value,
                ActionRequest);

  case MAIN_BOOT_INTEGRITY_ID:
    return IntegrityModeCallback(
                This,
                Action,
                QuestionId,
                Type,
                Value,
                ActionRequest);
  }

  

  return EFI_SUCCESS;
}


VOID
EFIAPI
BootMngrNotifyExitBootServices (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
{

}


EFI_STATUS
InitializeBootManager (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN Idx;  

  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
    CopyGuid(&gVarsGuid[Idx], &gVendorGuid);
  }
  gVarsGuidIdx = 0;

  InitializeListHead (&mBootOptionsList);
  InitializeListHead (&mBootOptionsList2);
  InitializeListHead (&IcflList);

  Status = gBS->LocateProtocol (
        &gBdsHelperProtocolGuid,
        NULL,
        (VOID **)&gBdsHelperProtocol
        );
  if (EFI_ERROR(Status)) {
    gBdsHelperProtocol = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }

  //
  // Install Device Path Protocol and Config Access protocol to driver handle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &gBootManagerPrivate.DriverHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mBootManagerHiiVendorDevicePath,
                  &gEfiHiiConfigAccessProtocolGuid,
                  &gBootManagerPrivate.ConfigAccess,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
    (VOID **) &gHistoryHandlerProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }
  

  //
  // Publish our HII data
  //
  gBootManagerPrivate.HiiHandle = HiiAddPackages (
                                    &mBootManagerGuid,
                                    gBootManagerPrivate.DriverHandle,
                                    BootManagerVfrBin,
                                    BootMngrLibStrings,
                                    NULL
                                    );
  if (gBootManagerPrivate.HiiHandle == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
  } else {
    Status = EFI_SUCCESS;
  }

  GopOldMode = 0;
  ZeroMem (&GopOldMode, sizeof (GopOldMode));
  if (!PcdGetBool (PcdBiosVideoSetTextVgaModeEnable)) {
    Status = gBS->HandleProtocol(
                    gST->ConsoleOutHandle, 
                    &gEfiGraphicsOutputProtocolGuid, 
                    (VOID**)&gGop
                    );
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_INFO, "HandleProtocol(gEfiGraphicsOutputProtocolGuid): Status = %r\n", Status));
    } else {
      GopOldMode = gGop->Mode->Mode;
      CopyMem (&GopOldInfo, gGop->Mode->Info, sizeof (GopOldInfo));
    }
    //
    // Create EXIT_BOOT_SERIVES Event
    //
    LOG ((EFI_D_INFO, "%a.%d GopOldMode=%X\n", 
      __FUNCTION__, __LINE__, GopOldMode));
    Status = gBS->CreateEventEx (
                    EVT_NOTIFY_SIGNAL,
                    TPL_NOTIFY,
                    BootMngrNotifyExitBootServices,
                    NULL,
                    &gEfiEventExitBootServicesGuid,
                    &gExitBootServicesEvent
                    );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    }
  }
  
  return Status;
}


extern
EFI_HANDLE
EFIAPI
BdsLibGetBootableHandle (
  IN  EFI_DEVICE_PATH_PROTOCOL      *DevicePath
  );


extern 
BOOLEAN
IsBootOptionValidNVVarialbe (
  IN  BDS_COMMON_OPTION             *OptionToCheck
  );

EFI_STATUS
EFIAPI
LoadAdditionalOption(
  IN EFI_HII_HANDLE HiiHandle,
  IN BDS_COMMON_OPTION *Option,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT UINTN *ExitDataSize,
  OUT CHAR16 **ExitData
  )
{
  EFI_STATUS Status;
  CHAR16 *TempStr, *FsPath;

  *ExitDataSize = 0;
  *ExitData     = NULL;

  if (Option == NULL || HiiHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  TempStr = DevicePathToStr (gOption->DevicePath);
  LOG((EFI_D_INFO, "%a.%d fd0=%s\n", __FUNCTION__, __LINE__, TempStr));
  FsPath = FsDescTableGetFullName(L"fd0");
  LOG((EFI_D_INFO, "%a.%d FsPath=%s\n", __FUNCTION__, __LINE__, FsPath));
  if (FsPath == NULL) {
    AddFsDescTableItem(L"fd0", TempStr, FALSE);
  }
  FeLibSetDevicePath(L"fd0:\\");
  Status = FeLibTest(HiiHandle, &mBootManagerGuid, 
    CurrentFormId, 0xF000, LABEL_BOOT_OPTION, LABEL_BOOT_OPTION_END);
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  Status = EFI_ABORTED;
  FsPath = FeGetSelectedString();
  if (FsPath == NULL || StrLen(FsPath) == 0) {
    goto Done;
  }

  if (IsBootOptionValidNVVarialbe (Option)) {    
    gRT->SetVariable (
          L"BootCurrent",
          &gEfiGlobalVariableGuid,
          EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
          sizeof (UINT16),
          &Option->BootCurrent
          );
  }

  if (Option->Description == NULL) {
    LOG ((DEBUG_INFO | DEBUG_LOAD, "Booting from unknown device path\n"));
  } else {
    LOG ((DEBUG_INFO | DEBUG_LOAD, "Booting %S\n", Option->Description));
  }

  Status = BootEfi(mBdsImageHandle, DevicePath, FsPath, ExitDataSize, ExitData, 4);

  //
  // Clear the Watchdog Timer after the image returns
  //
  gBS->SetWatchdogTimer (0x0000, 0x0000, 0x0000, NULL);

Done:
  /* remove temporary mapping path if exist one */
  if (FsDescTableGetFullName(L"fd0")) {
    FsDescTableRemoveLastItem();
  }
  //
  // Clear Boot Current
  //
  gRT->SetVariable (
        L"BootCurrent",
        &gEfiGlobalVariableGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        0,
        &Option->BootCurrent
        );
  LOG((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

VOID
DumpDevicePath(
  IN EFI_DEVICE_PATH_PROTOCOL *DevPath
  )
{
  CHAR16 *TmpStr;

  if (DevPath == NULL) {
    return;
  }

  
  for ( ; !IsDevicePathEnd(DevPath); DevPath = NextDevicePathNode(DevPath)) {
    TmpStr = DevicePathToStr (DevPath);
    DEBUG((EFI_D_INFO, "%a.%d Type=0x%02X SubType=0x%02X DevicePath = %s\n", 
      __FUNCTION__, __LINE__, DevPath->Type, DevPath->SubType, TmpStr));
  }
}

CHAR16 *
GetDescriptionFromDevicePath(
  IN EFI_DEVICE_PATH_PROTOCOL *DevPath
  )
{
  EFI_DEVICE_PATH_PROTOCOL *PrePrevDP = DevPath;
  EFI_DEVICE_PATH_PROTOCOL *DP;
  UINTN Idx;

  if (DevPath == NULL) {
    return NULL;
  }
  
  for (DP = DevPath, Idx = 0; !IsDevicePathEnd(DP); 
       DP = NextDevicePathNode(DP), Idx++) {
    if (Idx >= 2) {
      PrePrevDP = NextDevicePathNode(PrePrevDP);
    }    
  }
  
  return DevicePathToStr(PrePrevDP);
}

VOID
FixDescriptionFromDevicePath(
  IN OUT CHAR16 *DpStr
  )
{
  UINTN Len, TmpLen;
  CHAR16 *EndStr;
  
  if (DpStr == NULL) {
    return;
  }
  TmpLen = Len = StrLen(DpStr);
  EndStr = &DpStr[Len - 1];
  if (*EndStr != L')') {
    return;
  }
  while (*EndStr != '(') {
    TmpLen--;
    EndStr--;
    if (TmpLen == 0) {
      return;
    }
  }
  
  while (*EndStr != L',') {
    TmpLen++;
    if (TmpLen >= Len) {
      return;
    }
    EndStr++;
  }
  *EndStr++ = L')';
  *EndStr = 0;
}


EFI_HANDLE
GetBlkIoHandleByFsDevPath(
  IN EFI_DEVICE_PATH_PROTOCOL *FsDevicePath
  )
{
  UINTN NumBlkIo, Index, Len1, Len2;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_STATUS Status;
  EFI_HANDLE *pIop;
  EFI_HANDLE ResultHandle;
  CHAR16 *TempStr1, *TempStr2;
  INTN CmpResult;

  if (FsDevicePath == NULL) {
    return NULL;
  }

  ResultHandle = NULL;
  
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiBlockIoProtocolGuid,
        NULL,
        &NumBlkIo,
        &pIop
        );
  
  for (Index = 0; Index < NumBlkIo; Index++) {
    Status = gBS->HandleProtocol (
      pIop[Index],
      &gEfiDevicePathProtocolGuid,
      (VOID *) &DevicePath);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Index=%d\n", 
        __FUNCTION__, __LINE__, Index));
      continue;
    }
    TempStr1 = DevicePathToStr (DevicePath);
    TempStr2 = DevicePathToStr (FsDevicePath);

    DumpDevicePath(DevicePath);

    LOG((EFI_D_INFO, "%a.%d TempStr1=%s\n", __FUNCTION__, __LINE__, TempStr1));
    LOG((EFI_D_INFO, "%a.%d TempStr2=%s\n", __FUNCTION__, __LINE__, TempStr2));

    if (TempStr1 == NULL) {
      continue;
    }

    if (TempStr2 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
        __FUNCTION__, __LINE__));
      return NULL;
    }
    
    Len1 = StrLen(TempStr1);
    Len2 = StrLen(TempStr2);
    if (Len1 > Len2) {
      CmpResult = CompareMem(TempStr1, TempStr2, (Len2 - 1) * sizeof(CHAR16));
    } else {
      CmpResult = CompareMem(TempStr1, TempStr2, (Len1 - 1) * sizeof(CHAR16));
    }
    if (CmpResult == 0) {
      ResultHandle = pIop[Index];
      break;
    }
  }
  if (pIop) {
    FreePoolDbg(pIop);
  }
  return ResultHandle;
}

EFI_HANDLE
GetDiskIoHandleByFsDevPath(
  IN EFI_DEVICE_PATH_PROTOCOL *FsDevicePath
  )
{
  UINTN NumBlkIo, Index, Len1, Len2;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_STATUS Status;
  EFI_HANDLE *pDiskIop;
  EFI_HANDLE ResultHandle;
  CHAR16 *TempStr1, *TempStr2;
  INTN CmpResult;

  if (FsDevicePath == NULL) {
    return NULL;
  }

  ResultHandle = NULL;
  
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiDiskIoProtocolGuid,
        NULL,
        &NumBlkIo,
        &pDiskIop
        );
  
  for (Index = 0; Index < NumBlkIo; Index++) {
    Status = gBS->HandleProtocol (
      pDiskIop[Index],
      &gEfiDevicePathProtocolGuid,
      (VOID *) &DevicePath);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Index=%d\n", 
        __FUNCTION__, __LINE__, Index));
      continue;
    }
    TempStr1 = DevicePathToStr (DevicePath);
    TempStr2 = DevicePathToStr (FsDevicePath);

    LOG((EFI_D_INFO, "%a.%d TempStr1=%s\n", __FUNCTION__, __LINE__, TempStr1));
    LOG((EFI_D_INFO, "%a.%d TempStr2=%s\n", __FUNCTION__, __LINE__, TempStr2));

    if (TempStr1 == NULL) {
      continue;
    }

    if (TempStr2 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
        __FUNCTION__, __LINE__));
      return NULL;
    }
    
    Len1 = StrLen(TempStr1);
    Len2 = StrLen(TempStr2);
    if (Len1 > Len2) {
      CmpResult = CompareMem(TempStr1, TempStr2, (Len2 - 1) * sizeof(CHAR16));
    } else {
      CmpResult = CompareMem(TempStr1, TempStr2, (Len1 - 1) * sizeof(CHAR16));
    }
    if (CmpResult == 0) {
      ResultHandle = pDiskIop[Index];
      break;
    }
  }
  if (pDiskIop) {
    FreePoolDbg(pDiskIop);
  }
  return ResultHandle;
}


// заполняем список опциями загрузки с файловой системы
EFI_STATUS
EnumerateLoadFromFsOptions(
  IN OUT LIST_ENTRY *BootFromFsOptionList
  )
{
  UINTN NumberHandles, Index;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_HANDLE *pFsp;
  BDS_COMMON_OPTION *Option2;
  CHAR16 *TempStr;

  if (BootFromFsOptionList == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        &NumberHandles,
        &pFsp
        );

  LOG((EFI_D_INFO, "%a.%d NumberHandles = %d\n", 
    __FUNCTION__, __LINE__, NumberHandles));

  for (Index = 0; Index < NumberHandles; Index++) {
    Status = gBS->HandleProtocol (
      pFsp[Index],
      &gEfiDevicePathProtocolGuid,
      (VOID *) &DevicePath);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Index=%d\n", 
        __FUNCTION__, __LINE__, Index));
      continue;
    }

    TempStr = DevicePathToStr (DevicePath);
    LOG((EFI_D_INFO, "%a.%d DevicePath = %s\n", 
      __FUNCTION__, __LINE__, TempStr));
    DumpDevicePath(DevicePath);
    
    Option2 = AllocateZeroPool (sizeof (BDS_COMMON_OPTION));
    if (Option2 == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    
    Option2->Signature   = BDS_LOAD_OPTION_SIGNATURE;
    Option2->OptionNumber = ADDITIONAL_OPT_START + Index;
    Option2->DevicePath  = AllocateZeroPool (
      GetDevicePathSize (DevicePath));
    ASSERT(Option2->DevicePath != NULL);
    
    CopyMem (Option2->DevicePath, DevicePath, 
      GetDevicePathSize (DevicePath));
  
    TempStr = GetDeviceName(GetBlkIoHandleByFsDevPath(DevicePath), DevicePath);
    if (TempStr) {
      Option2->Description = AllocateCopyPool (StrSize(TempStr), TempStr);
      ASSERT(Option2->Description != NULL);
    } else {
      TempStr = GetDescriptionFromDevicePath(DevicePath);
      if (TempStr) {
        Option2->Description = AllocateCopyPool (StrSize(TempStr), TempStr);        
        ASSERT(Option2->Description != NULL);
      }      
      FixDescriptionFromDevicePath(Option2->Description);
    }
  
    InsertTailList (BootFromFsOptionList, &Option2->Link);
  }
Done:
  if (pFsp) {
    FreePoolDbg(pFsp);
  }
  return Status;
}


VOID
DestroyOption(
  IN BDS_COMMON_OPTION *Option
  )
{
  if (Option == NULL) {
    return;
  }
  if (Option->Description) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePoolDbg(Option->Description);
  }
  if (Option->OptionName) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePoolDbg(Option->OptionName);
  }
  if (Option->LoadOptions) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePoolDbg(Option->LoadOptions);
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  FreePoolDbg(Option);
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
}

VOID
DestroyOptionList(
  IN LIST_ENTRY *BootFromFsOptionList
  )
{
  LIST_ENTRY *Link, *PrevLink;
  BDS_COMMON_OPTION *Option;

  if (BootFromFsOptionList == NULL || IsListEmpty(BootFromFsOptionList)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  for (Link = GetFirstNode (BootFromFsOptionList); 
       !IsNull (BootFromFsOptionList, Link); 
       
       ) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);
    PrevLink = Link;    
    Link = GetNextNode (BootFromFsOptionList, Link);
    RemoveEntryList (PrevLink);
    if (Option) {
      DestroyOption(Option);
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    }
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  InitializeListHead(BootFromFsOptionList);
}


EFI_STATUS
CreateIntegrityFilesList(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle
  )
{
  EFI_STRING_ID Token;
  EFI_STRING_ID HelpToken;
  LIST_ENTRY *Link;
  ICFL_LIST *List;
  UINT16 FileId;
  CHAR16 TmpStr[255];
  EFI_STATUS Status;
  UINT8 TmpBuf[MAX_HASH_LEN];
  BOOLEAN bNeedToSaveIcfl = FALSE;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (HiiHandle == NULL || StartOpCodeHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_INTEGRITY);
#if 1
  HiiCreateSubTitleOpCode(
    StartOpCodeHandle,
    Token,
    0,
    0,
    1);
#else
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_INTEGRITY_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
#endif

  if (!IsListEmpty(&IcflList)) {
    FileId = ICFL_LIST_START;
    
    for (Link = GetFirstNode(&IcflList); 
         !IsNull(&IcflList, Link); 
         ) {
      List = (ICFL_LIST*)Link;
      Link = GetNextNode (&IcflList, Link);
      LOG((EFI_D_INFO, "List->FileName=%s\n", List->FileName));

      Token = HiiSetString (HiiHandle, 0, List->FileName, NULL);

      if (bIntegrityPageCheckHash) {
        Status = IcflItemCalcHash(List, TmpBuf);
      } else {
        Status = EFI_SUCCESS;
        CopyMem(TmpBuf, List->Hash, MAX_HASH_LEN);
      }
      if (!EFI_ERROR(Status)) {
        if (CompareMem(TmpBuf, List->Hash, MAX_HASH_LEN)) {
          CopyMem(List->Hash, TmpBuf, MAX_HASH_LEN);
          bNeedToSaveIcfl = TRUE;
        }
        GetDigestStr16(TmpStr, List->Hash, PRIMARY_HASH_TYPE);
        StrCat(TmpStr, HiiGetString(HiiHandle, 
          STRING_TOKEN(STR_PRESS_ENTER_TO_REMOVE_ITEM), NULL));
        HelpToken = HiiSetString (HiiHandle, 0, TmpStr, NULL);          
      } else {
        HelpToken = STRING_TOKEN(STR_ERROR_OBJECT_NOT_FOUND);
      }

      HiiCreateActionOpCode (
          StartOpCodeHandle,
          FileId++,
          Token,
          HelpToken,
          EFI_IFR_FLAG_CALLBACK,
          0
          );
    }
  }

  bIntegrityPageCheckHash = FALSE;

  if (bNeedToSaveIcfl) {
    StoreIcfl(&IcflList);
  }

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_ADD_FILE);

  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_ADD_FILE_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_CLEAN_FILES_LIST);

  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_CLEAN_FILES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_REFRESH_FILES_LIST);

  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_REFRESH_FILES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_UPDATE_DEVICES_LIST);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_UPDATE_DEVICES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_SAVE_FILES_LIST);

  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_SAVE_FILES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );  
  
  return EFI_SUCCESS;
}



EFI_STATUS
CreateBootMainMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle
  )
{
  EFI_STRING_ID Token;
  EFI_STRING_ID HelpToken;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (HiiHandle == NULL || StartOpCodeHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Token = STRING_TOKEN (STR_BM_BANNER);
  HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      1);

  LOG((EFI_D_INFO, "\"%s\"\n\n", 
    HiiGetString(HiiHandle, STRING_TOKEN (STR_BOOT_CTRL_MENU), NULL)));
  
  if (gBootMngrMenuMode != BOOT_MNGR_HIDE_CTRL_MODE) {
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    Token = STRING_TOKEN (STR_BOOT_CTRL_MENU);
    HiiCreateActionOpCode (
        StartOpCodeHandle,
        MAIN_BOOT_MANAGER_ID,
        Token,
        HelpToken,
        EFI_IFR_FLAG_CALLBACK,
        0
        );
  }
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_EDIT_BOOT_CFG);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_CONFIG_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );  
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_CFG_IMPORT);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_IMPORT_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_CFG_EXPORT);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_EXPORT_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );
#if 0
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_UPDATE_DEVICES_LIST);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_UPDATE_DEVICES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );
#endif  
  return EFI_SUCCESS;
}


VOID
DestroyBootCfgList(
  IN CBCFG_LIST *CbcfgList
  )
{
  LIST_ENTRY *Link, *PrevLink;
  CBCFG_LIST *TmpList;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (CbcfgList == NULL) {
    return;
  }
  if (IsListEmpty(&CbcfgList->Entry)) {
    return;
  }
  //CbcfgList
  for (Link = GetFirstNode (&CbcfgList->Entry); 
       !IsNull (&CbcfgList->Entry, Link); 
       ) {
    PrevLink = Link;    
    Link = GetNextNode (&CbcfgList->Entry, Link);
    RemoveEntryList (PrevLink);
    TmpList = (CBCFG_LIST*)PrevLink;

    if (TmpList->DataSet) {
      FreePoolDbg(TmpList->DataSet);
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    }
    FreePoolDbg(PrevLink);
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  }
  FreePoolDbg(CbcfgList);
}


CBCFG_LIST *
CreateCopyBootCfgList(
  IN CBCFG_LIST *InputList
  )
{
  CBCFG_LIST *CbcfgList, *List;
  LIST_ENTRY *ListHead, *Link;
  CBCFG_DATA_SET *DataSet1, *DataSet2;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (InputList == NULL || IsListEmpty(&InputList->Entry)) {
    return NULL;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  // create first empty item
  CbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
  if (NULL == CbcfgList) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  InitializeListHead(&CbcfgList->Entry);
  ListHead = &CbcfgList->Entry;

  for (Link = GetFirstNode (&InputList->Entry); 
       !IsNull (&InputList->Entry, Link); 
       Link = GetNextNode (&InputList->Entry, Link)) {
    List = (CBCFG_LIST*)Link;
    DataSet1 = List->DataSet;
    CbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
    if (NULL == CbcfgList) {
      DestroyBootCfgList((CBCFG_LIST*)ListHead);
      DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    DataSet2 = AllocateCopyPool(sizeof(CBCFG_DATA_SET) - 1 + 
      DataSet1->BootOptionsNum * sizeof(CBCFG_RECORD), DataSet1);
    if (DataSet2 == NULL) {      
      FreePoolDbg(CbcfgList);
      DestroyBootCfgList((CBCFG_LIST*)ListHead);
      DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    CbcfgList->DataSet = DataSet2;
    InsertTailList(ListHead, &CbcfgList->Entry);
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    
  return (CBCFG_LIST*)ListHead;
}


BOOLEAN
BootCfgIsDataSetsSame(
  IN CBCFG_DATA_SET *DataSet1, 
  IN CBCFG_DATA_SET *DataSet2
  )
{
  UINT32 Idx;
  UINT8 *Ptr1, *Ptr2;
  CBCFG_RECORD *Rec1, *Rec2;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (DataSet1 == NULL || DataSet2 == NULL) {
    return FALSE;
  }

  if (DataSet1->BootOptionsNum != DataSet2->BootOptionsNum) {
    return FALSE;
  }
  if (DataSet1->BootType != DataSet2->BootType) {
    return FALSE;
  }
  if (DataSet1->ModulesType != DataSet2->ModulesType) {
    return FALSE;
  }

  Ptr1 = DataSet1->Data;
  Ptr2 = DataSet2->Data;
  for (Idx = 0; Idx < DataSet1->BootOptionsNum; Idx++) {
    Rec1 = (CBCFG_RECORD*)Ptr1;
    Rec2 = (CBCFG_RECORD*)Ptr2;

    if (StrCmp(Rec1->DeviceFullName, Rec2->DeviceFullName)) {
      return FALSE;
    }
    
    if (StrCmp(Rec1->DevPath, Rec2->DevPath)) {
      return FALSE;
    }
    if (StrCmp(Rec1->Args, Rec2->Args)) {
      return FALSE;
    }
      
    Ptr1 += sizeof(CBCFG_RECORD);
    Ptr2 += sizeof(CBCFG_RECORD);
  }
  
  return TRUE;
}

CHAR16 *
FindOptionDescriptionByDevPathStr(
  IN CHAR16 *DevicePathStr,
  IN LIST_ENTRY *List
  )
{
  LIST_ENTRY *Link;
  BDS_COMMON_OPTION *Option;
  CHAR16 *StrPtr;
  UINTN Len1, Len2, Idx;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (DevicePathStr == NULL || List == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
  for (Link = GetFirstNode (List); 
       !IsNull (List, Link); 
       Link = GetNextNode (List, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
#if 1
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }
#endif    
      
    ASSERT (Option->Description != NULL);  
    
    StrPtr = DevicePathToStr (Option->DevicePath);
    if (StrPtr == NULL) {
      continue;
    }
    
    LOG((EFI_D_INFO, "%a.%d StrPtr=%s\n", 
      __FUNCTION__, __LINE__, StrPtr));
    LOG((EFI_D_INFO, "%a.%d DevicePathStr=%s\n", 
      __FUNCTION__, __LINE__, DevicePathStr));

    for (Idx = 0; Idx < 2; Idx++) {
      Len1 = StrLen(StrPtr);
      Len2 = StrLen(DevicePathStr);

      if (Len1 == 0 || Len2 == 0) {
        break;
      }
      
      if (Len1 > Len2) {
        if (CompareMem(DevicePathStr, StrPtr, (Len2 - 1) * sizeof(CHAR16)) == 0) {
          return Option->Description;
        }
      } else {
        if (CompareMem(DevicePathStr, StrPtr, (Len1 - 1) * sizeof(CHAR16)) == 0) {
          LOG((EFI_D_INFO, "%a.%d Option->Description=%s\n", 
            __FUNCTION__, __LINE__, Option->Description));
          return Option->Description;
        }
      }
      FixHDDevicePathString(StrPtr);
    }
  }
  return NULL;
}


BDS_COMMON_OPTION *
FindOptionByDevPathStr(
  IN CHAR16 *DevicePathStr,
  IN LIST_ENTRY *List
  )
{
  LIST_ENTRY *Link;
  BDS_COMMON_OPTION *Option;
  CHAR16 *StrPtr;
  UINTN Len1, Len2, Idx;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (DevicePathStr == NULL || List == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
  for (Link = GetFirstNode (List); 
       !IsNull (List, Link); 
       Link = GetNextNode (List, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
#if 1
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }
#endif    
      
    StrPtr = DevicePathToStr (Option->DevicePath);
    if (StrPtr == NULL) {
      continue;
    }

    LOG((EFI_D_INFO, "%a.%d StrPtr=%s\n", 
      __FUNCTION__, __LINE__, StrPtr));
    LOG((EFI_D_INFO, "%a.%d DevicePathStr=%s\n", 
      __FUNCTION__, __LINE__, DevicePathStr));

    for (Idx = 0; Idx < 2; Idx++) {
      Len1 = StrLen(StrPtr);
      Len2 = StrLen(DevicePathStr);

      if (Len1 == 0 || Len2 == 0) {
        break;
      }
      
      if (Len1 > Len2) {
        if (CompareMem(DevicePathStr, StrPtr, (Len2 - 1) * sizeof(CHAR16)) == 0) {
          return Option;
        }
      } else {
        if (CompareMem(DevicePathStr, StrPtr, (Len1 - 1) * sizeof(CHAR16)) == 0) {
          return Option;
        }
      }
      FixHDDevicePathString(StrPtr);
    }
  }
  return NULL;
}


CHAR16 *
FindDescriptionForEfiBoot(
  IN CHAR16 *DevicePathStr
  )
{
  LOG((EFI_D_INFO, "%a.%d DevicePathStr=%s\n", 
    __FUNCTION__, __LINE__, DevicePathStr));
  return FindOptionDescriptionByDevPathStr(DevicePathStr, &mBootOptionsList);
}


CHAR16 *
FindDescriptionForBootFromFs(
  IN CHAR16 *DevicePathStr
  )
{
  if (DevicePathStr == NULL) {
    return NULL;
  }
  LOG((EFI_D_INFO, "%a.%d DevicePathStr=%s\n", 
    __FUNCTION__, __LINE__, DevicePathStr));
  return FindOptionDescriptionByDevPathStr(DevicePathStr, &mBootOptionsList2);
}


EFI_STATUS
ObtainBootCfgMenuList(
  IN OUT CBCFG_LIST **CurrentBootConfigList
  )
{
  CBCFG_RECORD *CbcfgRecord;
  CBCFG_LIST *CbcfgList, *FirstEntry, *CopyCbcfgList;
  LIST_ENTRY *ListHead, *Link;
  BDS_COMMON_OPTION *Option;
  CBCFG_DATA_SET *CbcfgDataSet, *CurrentDataSet;
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR16 *TempStr;
  UINTN TempSize;
  UINT8 Idx;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (CurrentBootConfigList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_INFO, 
    "%a.%d gBootDefaultKey=0x%X gBootFromFsKey=0x%X CurrentBootOption=0x%X\n", 
    __FUNCTION__, __LINE__, 
    gBootDefaultKey, 
    gBootFromFsKey, 
    CurrentBootOption));

  CopyCbcfgList = NULL;
  CurrentDataSet = NULL;
  
  if (*CurrentBootConfigList != NULL) {
    LOG((EFI_D_INFO, "%a.%d <<<<<<<<<<<<<>>>>>>>>>>>>\n", 
      __FUNCTION__, __LINE__));
    CopyCbcfgList = CreateCopyBootCfgList(*CurrentBootConfigList);
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    CurrentDataSet = BootCfgGetDataSetByNum(CopyCbcfgList, CurrentBootOption);
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    DestroyBootCfgList(*CurrentBootConfigList);
    *CurrentBootConfigList = NULL;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  // create first empty item
  CbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
  if (NULL == CbcfgList) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  InitializeListHead(&CbcfgList->Entry);
  ListHead = &CbcfgList->Entry;

  FirstEntry = NULL;

  // obtain config from CurBootCfg
  Status = CbcfgStorageGetData(&CbcfgDataSet, &TempSize);
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  if (!EFI_ERROR(Status)) {
    CbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
    if (NULL == CbcfgList) {
      Status = EFI_OUT_OF_RESOURCES;
    }
    
    LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    LOG((EFI_D_INFO, "BootOptionsNum=%d BootType=0x%X\n", 
      CbcfgDataSet->BootOptionsNum, CbcfgDataSet->BootType));
    if (EFI_ERROR(Status)) {
      FreePoolDbg(CbcfgDataSet);
      goto Done;
    }

    /* Boot from file system item may be changed at runtime, check it */
    if (CbcfgDataSet->BootType == BOOT_TYPE_FROM_FS && 
        CopyCbcfgList && CurrentDataSet) {
      if (CurrentDataSet->BootType != BOOT_TYPE_FROM_FS) {
        goto SkipLocalCopy;
      }

      if (!BootCfgIsDataSetsSame(CurrentDataSet, CbcfgDataSet)) {
        FreePoolDbg(CbcfgDataSet);
        CbcfgDataSet = AllocateCopyPool(sizeof(CBCFG_DATA_SET) - 1 + 
          CurrentDataSet->BootOptionsNum * sizeof(CBCFG_RECORD), 
          CurrentDataSet);
        if (CbcfgDataSet == NULL) {
          FreePoolDbg(CbcfgList);
          Status = EFI_OUT_OF_RESOURCES;
          goto Done;
        }
      }
    }
SkipLocalCopy:    
    CbcfgList->DataSet = CbcfgDataSet;
    InsertTailList(ListHead, &CbcfgList->Entry);
    FirstEntry = CbcfgList;
  } // if (CbcfgStorageGetData() == STATUS_OK)

  for (Link = GetFirstNode (&mBootOptionsList), Idx = 0; 
       !IsNull (&mBootOptionsList, Link); 
       Link = GetNextNode (&mBootOptionsList, Link), Idx++) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }    
      
    TempStr = DevicePathToStr (Option->DevicePath);
    TempSize = StrSize (TempStr);

    /* check if option allready present in list as current */
    if (FirstEntry) {
      CbcfgDataSet = FirstEntry->DataSet;
      CbcfgRecord = (CBCFG_RECORD*) CbcfgDataSet->Data;

      if (CbcfgDataSet->BootType == BOOT_TYPE_EFI &&
          CbcfgDataSet->BootOptionsNum == 1 &&
          StrCmp(CbcfgRecord->DevPath, TempStr) == 0) {
        continue;
      }
    }

    CbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
    if (NULL == CbcfgList) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    CbcfgDataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - 1 + 
      sizeof(CBCFG_RECORD));
    if (NULL == CbcfgDataSet) {
      FreePoolDbg(CbcfgList);
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    CbcfgList->DataSet = CbcfgDataSet;
    CbcfgDataSet->BootOptionsNum = 1;
    CbcfgDataSet->BootType = BOOT_TYPE_EFI;
    CbcfgDataSet->ModulesType = MODULE_TYPE_EFI;

    CbcfgRecord = (CBCFG_RECORD*)CbcfgDataSet->Data;
    StrCpy(CbcfgRecord->DevPath, TempStr);
    StrCpy(CbcfgRecord->DeviceFullName, TempStr);
    FixHDDevicePathString(CbcfgRecord->DeviceFullName); 

#if 1
    if (CurrentDataSet && BootCfgIsDataSetsSame(CbcfgDataSet, CurrentDataSet)) {
      InsertHeadList(ListHead, &CbcfgList->Entry);
    } else {
      InsertTailList(ListHead, &CbcfgList->Entry);
    }
#else
    if (FirstEntry && CurrentBootOption && (CurrentBootOption - 1 == Idx)) {
      InsertHeadList(ListHead, &CbcfgList->Entry);
    } else if (FirstEntry == NULL && CurrentBootOption == Idx) {
      InsertHeadList(ListHead, &CbcfgList->Entry);
    } else {
      InsertTailList(ListHead, &CbcfgList->Entry);
    }
#endif    
  } // for (; !IsNull (&mBootOptionsList, Link); )

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Link = GetFirstNode (ListHead);
  //Link = GetNextNode(ListHead, Link);
  CbcfgList = (CBCFG_LIST*)Link;

  /* default boot type */
  if (CbcfgList->DataSet && CbcfgList->DataSet->BootType != BOOT_TYPE_DEFAULT) {
    CBCFG_LIST *TmpCbcfgList;

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    /* if option allready present just skip  */
    if (FirstEntry != NULL && FirstEntry->DataSet->BootType == BOOT_TYPE_DEFAULT) {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      goto SkipBootTypeDefault;
    }
    
    TmpCbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
    if (NULL == TmpCbcfgList) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    CbcfgDataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - 1 + 
      sizeof(CBCFG_RECORD));
    if (NULL == CbcfgDataSet) {
      Status = EFI_OUT_OF_RESOURCES;
      FreePoolDbg(TmpCbcfgList);
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      goto Done;
    }

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    TmpCbcfgList->DataSet = CbcfgDataSet;
    CbcfgDataSet->BootOptionsNum = 0;
    CbcfgDataSet->BootType = BOOT_TYPE_DEFAULT;
    CbcfgDataSet->ModulesType = MODULE_TYPE_DEFAULT;

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (CurrentDataSet && gBootDefaultKey == CurrentBootOption) {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      InsertHeadList(ListHead, &TmpCbcfgList->Entry);
    } else {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      InsertTailList(ListHead, &TmpCbcfgList->Entry);
    }
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  }

SkipBootTypeDefault:

  if (FirstEntry != NULL) {
    LOG((EFI_D_INFO, "FirstEntry->DataSet->BootType=%X\n", 
      FirstEntry->DataSet->BootType));
  }
  LOG((EFI_D_INFO, "CbcfgList->DataSet->BootType=%X\n", 
    CbcfgList->DataSet->BootType));

  /* boot from fs */
  if (CbcfgList->DataSet && CbcfgList->DataSet->BootType != BOOT_TYPE_FROM_FS) {
    CBCFG_LIST *TmpCbcfgList;

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    if (FirstEntry != NULL && FirstEntry->DataSet->BootType == BOOT_TYPE_FROM_FS) {
      LOG((EFI_D_INFO, "%a.%d FirstEntry=%p\n", 
        __FUNCTION__, __LINE__, FirstEntry));
      goto SkipBootTypeFromFs;
    }

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    
    TmpCbcfgList = AllocateZeroPoolDbg(sizeof(CBCFG_LIST));
    if (NULL == TmpCbcfgList) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    CbcfgDataSet = BootCfgGetDataSetByBootType(CopyCbcfgList, 
      BOOT_TYPE_FROM_FS);
    if (CbcfgDataSet == NULL) {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      CbcfgDataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - 1 + 
        sizeof(CBCFG_RECORD));
      if (NULL == CbcfgList) {
        Status = EFI_OUT_OF_RESOURCES;
        FreePoolDbg(TmpCbcfgList);
        goto Done;
      }
      CbcfgDataSet->BootType = BOOT_TYPE_FROM_FS;
      CbcfgDataSet->BootOptionsNum = 1;
      CbcfgDataSet->ModulesType = MODULE_TYPE_LINUX; // lowest option in the list
    } else {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      TempSize = sizeof(CBCFG_DATA_SET) - 1 + 
        CbcfgDataSet->BootOptionsNum * sizeof(CBCFG_RECORD);
      CbcfgDataSet = AllocateCopyPool(TempSize, CbcfgDataSet);
      if (NULL == CbcfgDataSet) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        Status = EFI_OUT_OF_RESOURCES;
        FreePoolDbg(TmpCbcfgList);
        goto Done;
      }
    }
    TmpCbcfgList->DataSet = CbcfgDataSet;

    LOG((EFI_D_INFO, 
      "%a.%d CbcfgDataSet->BootType=0x%X CbcfgDataSet->ModulesType=0x%X\n", 
      __FUNCTION__, __LINE__, 
      CbcfgDataSet->BootType, 
      CbcfgDataSet->ModulesType
      ));

    // if boot from fs must be selected boot option place it first in the list
    if (CurrentDataSet && gBootFromFsKey == CurrentBootOption) {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      InsertHeadList(ListHead, &TmpCbcfgList->Entry);
    } else {
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      InsertTailList(ListHead, &TmpCbcfgList->Entry);
    }
  }

SkipBootTypeFromFs:  

  Status = EFI_SUCCESS;

Done:
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  if (CopyCbcfgList) {
    DestroyBootCfgList(CopyCbcfgList);
  }
  if (EFI_ERROR(Status)) {
    DestroyBootCfgList((CBCFG_LIST*)ListHead);
    *CurrentBootConfigList = NULL;    
  } else {
    *CurrentBootConfigList = (CBCFG_LIST*)ListHead;
  }
  
  return Status;
}


EFI_STATUS
UpdateModuleTypeIndexes(
  VOID
  )
{
  CBCFG_DATA_SET *DataSet;
  UINTN Idx, TmpVal;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DataSet = BootCfgGetDataSetByBootType(mCurrentBootConfigList, 
                                        BOOT_TYPE_FROM_FS);
  if (NULL == DataSet) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  TmpVal = ModuleTypeIndexes[0];
  for (Idx = 0; Idx < ARRAY_ITEMS(ModuleTypeIndexes); Idx++) {
    if (ModuleTypeIndexes[Idx] != DataSet->ModulesType) {
      continue;
    }
    ModuleTypeIndexes[0] = DataSet->ModulesType;
    ModuleTypeIndexes[Idx] = TmpVal;
  }

  LOG((EFI_D_INFO, "%a.%d DataSet->ModulesType = 0x%X\n", 
    __FUNCTION__, __LINE__, DataSet->ModulesType));
  
  for (Idx = 0; Idx < ARRAY_ITEMS(ModuleTypeIndexes); Idx++) {
    LOG((EFI_D_INFO, "\tModuleTypeIndexes[%d] = 0x%X\n", 
      Idx, ModuleTypeIndexes[Idx]));
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

EFI_STATUS
CreateBootFromFsOptions(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN CBCFG_DATA_SET *BootFromFsDataSet
  )
{
  EFI_STRING_ID Token;
  EFI_STRING_ID HelpToken;
  VOID *OptionsOpCodeHandle;
  UINT16 OptNum = 0;
  UINT32 Idx;
  CBCFG_RECORD *CbcfgRecord;
  UINT8 *DataPtr;
  CHAR16 *TmpStrPtr;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (StartOpCodeHandle == NULL || BootFromFsDataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", 
      __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  // строки для формы "тип загрузки"
  UpdateModuleTypeIndexes();
  for (Idx = 0; Idx < ARRAY_ITEMS(ModuleTypeTokens); Idx++) {
    UINTN Num = ModuleTypeIndexes[Idx];
    HiiCreateOneOfOptionOpCode (
        OptionsOpCodeHandle,
        ModuleTypeTokens[Num],
        0,                      // Flags
        EFI_IFR_NUMERIC_SIZE_1, // Types
        OptNum++
        );
  }
  // форма "тип загрузки":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_TYPE);
  HiiCreateOneOfOpCode (
        StartOpCodeHandle, 
        MAIN_BOOT_TYPE_SELECT_ID, 
        0,  
        0, 
        Token, 
        HelpToken, 
        EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
        EFI_IFR_NUMERIC_SIZE_1, 
        OptionsOpCodeHandle, 
        NULL
        );

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  HiiFreeOpCodeHandle (OptionsOpCodeHandle);

  LOG((EFI_D_INFO, "%a.%d BootFromFsDataSet->BootOptionsNum=%d\n", 
    __FUNCTION__, __LINE__, BootFromFsDataSet->BootOptionsNum));

  // перебираем модули для загрузки c ФС из массива BootFromFsDataSet->Data:
  /* create modules list: module dev_path and args */
  DataPtr = BootFromFsDataSet->Data;
  
  for (Idx = 0, OptNum = MAIN_BOOT_MODULES_START; 
       Idx < BootFromFsDataSet->BootOptionsNum; 
       Idx++) {
    CHAR16 TmpStr16[255];
    CHAR16 HelpStr16[255];

    // рисуем номер модуля:
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s #%d", 
      HiiGetString(HiiHandle, STRING_TOKEN (STR_MODULE), NULL),
      Idx + 1
      );
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      0,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
    // текущая запись с информацией о модуле:	
    CbcfgRecord = (CBCFG_RECORD*)DataPtr;

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_INFO, "DeviceFullName = {%s}\n", CbcfgRecord->DeviceFullName));
    LOG((EFI_D_INFO, "DevPath = {%s}\n", CbcfgRecord->DevPath));
    // удаляем из полного пути сведения о типе MBR и разделе(если они там указаны):
    FixHDDevicePathString(CbcfgRecord->DevPath);			// это путь внутри файловой системы fsnn:
    FixHDDevicePathString(CbcfgRecord->DeviceFullName);		// это PCI-путь от PciRoot
    LOG((EFI_D_INFO, "DevPath = {%s}\n", CbcfgRecord->DevPath));

    // текст "Путь к устройству:"
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"    %s: %s", 
      HiiGetString(HiiHandle, STRING_TOKEN (STR_DEV_PATH), NULL),
      CbcfgRecord->DevPath);
    // собственно путь к загружаемому модулю:
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);		// например, "fs02:\EFI\Kaspersky\run_av_scan.efi"
    // по урезанному пути ищем заново полный путь с разделом и MBR
    TmpStrPtr = FindDescriptionForBootFromFs(CbcfgRecord->DeviceFullName);
    // если находим, отображаем в качестве подсказки найденный путь, иначе - урезанный путь
    UnicodeSPrint(HelpStr16, sizeof(HelpStr16), L"%s %s", 
      TmpStrPtr ? TmpStrPtr : L"", CbcfgRecord->DeviceFullName);
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_INFO, "{%s}\n", TmpStr16));
    LOG((EFI_D_INFO, "{%s}\n", CbcfgRecord->DeviceFullName));
    // путь к носителю, где находится данная файловая система:
    HelpToken = HiiSetString(HiiHandle, 0, HelpStr16, NULL);	// например, PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x4,0x0,0x0)/HD(2)
    // создаем форму для отображения (и изменения) пути:
    // форма позволяет изменять текст, лежащий в записи с индексом (OptNum - MAIN_BOOT_MODULES_START) / 2,
    // а тип записи определяется четностью OptNum(в данном случае - 0, соответствует Rec->DevPath)
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      OptNum++,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

    // создаем форму под отображение (и изменение) параметров загрузки:
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"    %s:",
      HiiGetString(HiiHandle, STRING_TOKEN (STR_ARGS), NULL));
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);
    HelpToken = HiiSetString(HiiHandle, 0, L"", NULL);

    // форма позволяет изменять текст, лежащий в записи с индексом (OptNum - MAIN_BOOT_MODULES_START) / 2,
    // четность OptNum в данном случае 1, соответствует полю Rec->Args
    HiiCreateStringOpCode (
          StartOpCodeHandle, 
          OptNum++, 
          0, 
          0, 
          Token, 
          HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          EFI_IFR_STRING_MULTI_LINE /*StringFlags*/,
          0, 
          MULTIBOOT_MAX_STRING - 1, 
          NULL
          );
    DataPtr += sizeof(CBCFG_RECORD);
  }

#ifdef MULTIMODULE_BOOT
// на случай последовательной загрузки с файловой системы нескольких модулей одного типа:
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  Token = STRING_TOKEN (STR_ADD_MODULE);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_ADD_MODULE_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  Token = STRING_TOKEN (STR_CLEAN_MODULES_LIST);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_REMOVE_MODULES_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );  
#endif // MULTIMODULE_BOOT

  return EFI_SUCCESS;
}

// создаем форму для ввода пути к KUEFI:
EFI_STATUS
CreateKuefiBootFromFsOptions(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN CBCFG_DATA_SET *BootFromFsDataSet
  )
{
  EFI_STRING_ID Token;
  EFI_STRING_ID HelpToken;
  VOID *OptionsOpCodeHandle;
  UINT16 OptNum = 0;
  UINT32 Idx;
  CBCFG_RECORD *CbcfgRecord;
  UINT8 *DataPtr;
  CHAR16 *TmpStrPtr;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (StartOpCodeHandle == NULL || BootFromFsDataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", 
      __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  // строки для формы "тип загрузки"
  UpdateModuleTypeIndexes();
  for (Idx = 0; Idx < ARRAY_ITEMS(ModuleTypeTokens); Idx++) {
    UINTN Num = ModuleTypeIndexes[Idx];
    HiiCreateOneOfOptionOpCode (
        OptionsOpCodeHandle,
        ModuleTypeTokens[Num],
        0,                      // Flags
        EFI_IFR_NUMERIC_SIZE_1, // Types
        OptNum++
        );
  }
  // форма "тип загрузки":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_TYPE);
  HiiCreateOneOfOpCode (
        StartOpCodeHandle, 
        MAIN_BOOT_TYPE_SELECT_ID, 
        0,  
        0, 
        Token, 
        HelpToken, 
        EFI_IFR_FLAG_READ_ONLY,
        EFI_IFR_NUMERIC_SIZE_1, 
        OptionsOpCodeHandle, 
        NULL
        );

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  HiiFreeOpCodeHandle (OptionsOpCodeHandle);

  LOG((EFI_D_INFO, "%a.%d BootFromFsDataSet->BootOptionsNum=%d\n", 
    __FUNCTION__, __LINE__, BootFromFsDataSet->BootOptionsNum));

  // перебираем модули для загрузки c ФС из массива BootFromFsDataSet->Data:
  /* create modules list: module dev_path and args */
  DataPtr = BootFromFsDataSet->Data;
  
  OptNum = MAIN_BOOT_MODULES_START; 
{
    CHAR16 TmpStr16[255];
    CHAR16 HelpStr16[255];

    // текущая запись с информацией о модуле:	
    CbcfgRecord = (CBCFG_RECORD*)DataPtr;

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_INFO, "DeviceFullName = {%s}\n", CbcfgRecord->DeviceFullName));
    LOG((EFI_D_INFO, "DevPath = {%s}\n", CbcfgRecord->DevPath));
    // удаляем из полного пути сведения о типе MBR и разделе(если они там указаны):
    FixHDDevicePathString(CbcfgRecord->DevPath);			// это путь внутри файловой системы fsnn:
    FixHDDevicePathString(CbcfgRecord->DeviceFullName);		// это PCI-путь от PciRoot
    LOG((EFI_D_INFO, "DevPath = {%s}\n", CbcfgRecord->DevPath));

    // текст "Путь к устройству:"
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"    %s: %s", 
      HiiGetString(HiiHandle, STRING_TOKEN (STR_DEV_PATH), NULL),
      CbcfgRecord->DevPath);
    // собственно путь к загружаемому модулю:
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);		// например, "fs02:\EFI\Kaspersky\run_av_scan.efi"
    // по урезанному пути ищем заново полный путь с разделом и MBR
    TmpStrPtr = FindDescriptionForBootFromFs(CbcfgRecord->DeviceFullName);
    // если находим, отображаем в качестве подсказки найденный путь, иначе - урезанный путь
    UnicodeSPrint(HelpStr16, sizeof(HelpStr16), L"%s %s", 
      TmpStrPtr ? TmpStrPtr : L"", CbcfgRecord->DeviceFullName);
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_INFO, "{%s}\n", TmpStr16));
    LOG((EFI_D_INFO, "{%s}\n", CbcfgRecord->DeviceFullName));
    // путь к носителю, где находится данная файловая система:
    HelpToken = HiiSetString(HiiHandle, 0, HelpStr16, NULL);	// например, PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x4,0x0,0x0)/HD(2)
    // создаем форму для отображения (и изменения) пути:
    // форма позволяет изменять текст, лежащий в записи с индексом (OptNum - MAIN_BOOT_MODULES_START) / 2,
    // а тип записи определяется четностью OptNum(в данном случае - 0, соответствует Rec->DevPath)
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      OptNum++,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  if((CbcfgRecord->DevPath[0] != 0) && (CbcfgRecord->DevPath[0] != ' '))
  { // если присутствует путь к модулю KUEFI, даем возможность его отключить:
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

    Token = STRING_TOKEN (STR_DISABLE_KUEFI);
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_REMOVE_MODULES_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );  
  }
}

  return EFI_SUCCESS;
}


EFI_STATUS
CreateBootCfgMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle
  )  
{
  EFI_STRING_ID Token;
  EFI_STRING_ID HelpToken;
  LIST_ENTRY *Link;
  VOID *OptionsOpCodeHandle;
  EFI_STATUS Status = EFI_SUCCESS;
  CBCFG_LIST *CbcfgList;
  CBCFG_DATA_SET *CbcfgDataSet, *BootFromFsDataSet;
  CHAR16 *StrPtr;
  UINTN Idx;
  BOOLEAN bInvalidPath = FALSE, bFirstItem = TRUE;
  BOOLEAN	bKuefi = FALSE;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (HiiHandle == NULL || StartOpCodeHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  BootFromFsDataSet = NULL;

  Status = ObtainBootCfgMenuList(&mCurrentBootConfigList);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  mKeyInput = 0;

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (OptionsOpCodeHandle != NULL);

  LOG((EFI_D_INFO, "%a.%d CurrentBootOption=%X\n", __FUNCTION__, __LINE__, CurrentBootOption));

  if (gVarsGuidIdx >= MAX_VARS_GUIDS) {
    return EFI_ABORTED;
  }
  // строки для опции "Режим":
  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {    
    UINTN Idx2;

    Idx2 = gVarsDescStrMap[Idx];
    if (gVarsDescStr[Idx2] == NULL) {
      mKeyInput++;
      continue;
    }
    LOG((EFI_D_INFO, "%a.%d gVarsDescStr[%d] = %ls\n", 
      __FUNCTION__, __LINE__, Idx2, gVarsDescStr[Idx2]));
    HelpToken = HiiSetString(HiiHandle, 0, gVarsDescStr[Idx2], NULL);
    HiiCreateOneOfOptionOpCode (
        OptionsOpCodeHandle,
        HelpToken,
        0,
        EFI_IFR_NUMERIC_SIZE_1,
        mKeyInput++
        );
  }
  if (CompareGuid(&gKuefiGuid, &gVarsGuid[gVarsDescStrMap[0]])) 
					bKuefi = TRUE;
					  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  // заголовок "Редактирование конфигурации":
  Token = STRING_TOKEN (STR_EDIT_BOOT_CFG);
  HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      1);

  // Опция "Режим":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_MODE);

  HiiCreateOneOfOpCode (
    StartOpCodeHandle, 
    MAIN_BOOT_MODE_ID, 
    0,  
    0, 
    Token, 
    HelpToken, 
    EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
    EFI_IFR_NUMERIC_SIZE_1, 
    OptionsOpCodeHandle, 
    NULL
    );

  HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  // строки для опции "Конфигурация":
  mKeyInput = 0;

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (OptionsOpCodeHandle != NULL);
  // перебираем все способы загрузки:
  for (Link = GetFirstNode (&mCurrentBootConfigList->Entry), bFirstItem = TRUE; 
       !IsNull (&mCurrentBootConfigList->Entry, Link); 
       Link = GetNextNode (&mCurrentBootConfigList->Entry, Link)) {

    CBCFG_RECORD *TmpRecord;
        
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    CbcfgList = (CBCFG_LIST*)Link;
    CbcfgDataSet = CbcfgList->DataSet;
    if (NULL == CbcfgDataSet) {
      /* skip empty item (first) */
      continue;
    }
    
    TmpRecord = (CBCFG_RECORD*)CbcfgDataSet->Data;

    LOG((EFI_D_INFO, "%a.%d CbcfgDataSet->BootType=0x%X\n", 
      __FUNCTION__, __LINE__, CbcfgDataSet->BootType));
    LOG((EFI_D_INFO, 
      "mKeyInput=0x%X gBootDefaultKey=0x%X gBootFromFsKey=0x%X\n", 
      mKeyInput, gBootDefaultKey, gBootFromFsKey));

    switch (CbcfgDataSet->BootType) {
    case BOOT_TYPE_EFI:	// EFI и legacy опции
      StrPtr = FindDescriptionForEfiBoot(TmpRecord->DevPath);
      if (StrPtr == NULL) {
        LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        if (bFirstItem) {
          bInvalidPath = TRUE;
        }
      }
      if (TmpRecord->Description[0] != 0) {
        StrPtr = TmpRecord->Description;
      } else {        
        if (StrPtr) {
          StrCpy(TmpRecord->Description, StrPtr);
        } else {
          TmpRecord->Description[0] = 0;
        }
      }

      if (StrPtr) {
        TrimString16FromEnd(StrPtr, TRUE);
      }

      HelpToken = HiiSetString (HiiHandle, 0, 
        StrPtr ? StrPtr : TmpRecord->DevPath, NULL);
      LOG((EFI_D_INFO, "%a.%d TmpRecord->DevPath=%s\n", 
      __FUNCTION__, __LINE__, TmpRecord->DevPath));
      break;

    case BOOT_TYPE_DEFAULT:	// "Загрузка по умолчанию"
      gBootDefaultKey = (UINT8)(mKeyInput & 0xFF);
      HelpToken = STRING_TOKEN(STR_BOOT_DEFAULT);
      break;

    case BOOT_TYPE_FROM_FS:	// "Загрузка с файловой системы":
      LOG((EFI_D_INFO, "%a.%d BOOT_TYPE_FROM_FS\n", 
      __FUNCTION__, __LINE__));
      gBootFromFsKey = (UINT8)(mKeyInput & 0xFF);
      HelpToken = STRING_TOKEN(STR_BOOT_FROM_FS);
      BootFromFsDataSet = CbcfgDataSet;
      break;

    default:
      continue;
    }

    bFirstItem = FALSE;
    // запоминаем очередную строку для опции "Конфигурация"
    HiiCreateOneOfOptionOpCode (
        OptionsOpCodeHandle,
        HelpToken,
        0,
        EFI_IFR_NUMERIC_SIZE_1,
        mKeyInput++
        );
  } // for

  if (bInvalidPath) {
    HelpToken = STRING_TOKEN(STR_DEV_PATH_NOT_FOUND);
  } else {
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  }
  Token = STRING_TOKEN (STR_BOOT_CFG_MENU);
{
  UINT8 tmpFlags = EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY;
  if(bKuefi)
	tmpFlags = EFI_IFR_FLAG_READ_ONLY;
  // опция "Конфигурация":
  HiiCreateOneOfOpCode (
    StartOpCodeHandle, 
    MAIN_BOOT_CONFIG_MN_ITEM_ID, 
    0,  
    0, 
    Token, 
    HelpToken, 
    tmpFlags,
    EFI_IFR_NUMERIC_SIZE_1, 
    OptionsOpCodeHandle, 
    NULL
    );
}
  HiiFreeOpCodeHandle (OptionsOpCodeHandle);

  LOG((EFI_D_INFO, "%a.%d gBootFromFsKey=%X CurrentBootOption=%X\n", 
    __FUNCTION__, __LINE__, gBootFromFsKey, CurrentBootOption));
  if (gBootFromFsKey == 0) { // if boot from fs is first option (slected option)
  // создаем подменю для загрузки с файловой системы (Тип, Путь, Параметры):
    if (IsListEmpty(&mBootOptionsList2)) {
      // если не создан, то создаем список опций для загрузки с ФС:
      EnumerateLoadFromFsOptions(&mBootOptionsList2);
    }
    // создаем подменю загрузки с ФС:
    if(bKuefi)
    { // для KUEFI есть отличия:
	CreateKuefiBootFromFsOptions(HiiHandle, StartOpCodeHandle, BootFromFsDataSet);
    }
    else
    { // для всех, кроме KUEFI:
	CreateBootFromFsOptions(HiiHandle, StartOpCodeHandle, BootFromFsDataSet);
    }
  }

  // команда "Сохранить текущую конфигурацию":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_SAVE_CURRENT_BOOT_CFG);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_SAVE_CURRENT_CFG_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  // команда "обновить список устройств":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_UPDATE_DEVICES_LIST);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_UPDATE_DEVICES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

  // раздел "Проверка целостности":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_INTEGRITY);

  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_INTEGRITY_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );
  CurrentBootOption = 0;
  return EFI_SUCCESS;
}


// создание страницы "Меню загрузки":
EFI_STATUS
CreateBootCtrlMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle
  )  
{
  EFI_STRING_ID Token;
  CHAR16 *HelpString;
  EFI_STRING_ID HelpToken;
  UINT16 *TempStr;
  UINTN TempSize;
  BDS_COMMON_OPTION *Option;
  LIST_ENTRY *Link;
  UINTN Idx, LegacyBootCnt;

  if (HiiHandle == NULL || StartOpCodeHandle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  mKeyInput = 0;

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_EFI_BOOT1);
#if 1
// раздел *[EFI-загрузка]:
  HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      0);
#else
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
#endif
  //mKeyInput++;

  LegacyBootCnt = 0;

// опции EFI-загрузки (извлекаем из mBootOptionsList):
  for (Link = GetFirstNode (&mBootOptionsList); 
       !IsNull (&mBootOptionsList, Link); 
       Link = GetNextNode (&mBootOptionsList, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    //
    // At this stage we are creating a menu entry, thus the Keys are reproduceable
    //
    mKeyInput++;

    //
    // Don't display the boot option marked as LOAD_OPTION_HIDDEN
    //
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }

    Option->OptionNumber = mKeyInput;
      
    ASSERT (Option->Description != NULL);  
    
    Token = HiiSetString (HiiHandle, 0, Option->Description, NULL);

    TempStr = DevPathToString (Option->DevicePath, FALSE, TRUE);
    if (IsLegacyBootDevPath(TempStr)) {
      LegacyBootCnt++;
      continue;
    }
    
    TempSize = StrSize (TempStr);
    HelpString = AllocateZeroPool (TempSize + StrSize (L"Device Path : "));
    ASSERT (HelpString != NULL);
    StrCat (HelpString, L"Device Path : ");
    StrCat (HelpString, TempStr);

    HelpToken = HiiSetString (HiiHandle, 0, HelpString, NULL);

// очередная опция EFI-загрузки:
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

    LOG((EFI_D_INFO, "HelpString=\"%s\"\n", HelpString));
  }


// разделитель (пустая строка):
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);  
  Token = STRING_TOKEN (STR_LAST_STRING);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
  mKeyInput++;


  if (LegacyBootCnt) {
// раздел *[Legacy-загрузка]:
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    Token = STRING_TOKEN (STR_LEGACY_BOOT);
#if 1
    HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      0);    
#else
    HiiCreateActionOpCode (
        StartOpCodeHandle,
        mKeyInput,
        Token,
        HelpToken,
        EFI_IFR_FLAG_READ_ONLY,
        0
        );
#endif
    mKeyInput++;
    
// опции Legacy-загрузки (извлекаем из mBootOptionsList):
    for (Link = GetFirstNode (&mBootOptionsList); 
         !IsNull (&mBootOptionsList, Link); 
         Link = GetNextNode (&mBootOptionsList, Link)) {
      Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);
  
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
      //
      // Don't display the boot option marked as LOAD_OPTION_HIDDEN
      //
      if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
        continue;
      }
  
      ASSERT (Option->Description != NULL);  
      
      Token = HiiSetString (HiiHandle, 0, Option->Description, NULL);
  
      TempStr = DevicePathToStr (Option->DevicePath);
  
      if (!IsLegacyBootDevPath(TempStr)) {
        continue;
      }
      
      TempSize = StrSize (TempStr);
      HelpString = AllocateZeroPool (TempSize + StrSize (L"Device Path : "));
      ASSERT (HelpString != NULL);
      StrCat (HelpString, L"Device Path : ");
      StrCat (HelpString, TempStr);
  
      HelpToken = HiiSetString (HiiHandle, 0, HelpString, NULL);
  
// очередная опция Legacy-загрузки:
      HiiCreateActionOpCode (
        StartOpCodeHandle,
        (EFI_QUESTION_ID)Option->OptionNumber,
        Token,
        HelpToken,
        EFI_IFR_FLAG_CALLBACK,
        0
        );
  
      LOG((EFI_D_INFO, "HelpString=\"%s\"\n", HelpString));
    }    
// разделитель (пустая строка):
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);  
    Token = STRING_TOKEN (STR_LAST_STRING);
    HiiCreateActionOpCode (
        StartOpCodeHandle,
        mKeyInput,
        Token,
        HelpToken,
        EFI_IFR_FLAG_READ_ONLY,
        0
        );
    mKeyInput++;
  }
  
  
// раздел *[ Режим загрузки ]:
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_BOOT_MODE2);
#if 1
  HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      0);
#else  
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
#endif
  mKeyInput++;
  
// опции раздела *[ Режим загрузки ]:
  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
    if (gVarsDescStr[Idx] == NULL) {
      gVarsQId[Idx] = 0xFFFE;
      continue;
    }
    if (CompareGuid(&gKuefiGuid, &gVarsGuid[Idx]))  {
      gVarsQId[Idx] = 0xFFFE;
      continue;
    }

    gVarsQId[Idx] = mKeyInput;
    Token = HiiSetString (HiiHandle, 0, gVarsDescStr[Idx], NULL);
    
    HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );
    mKeyInput++;
  }

  EnumerateLoadFromFsOptions(&mBootOptionsList2);

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

// разделитель (пустая строка):
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);  
  Token = STRING_TOKEN (STR_LAST_STRING);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
  mKeyInput++;
  
// раздел *[ Загрузка EFI с файловой системы ] (опции извлекаем из mBootOptionsList2):
  Token = STRING_TOKEN (STR_EFI_BOOT2);
#if 1
  HiiCreateSubTitleOpCode(
      StartOpCodeHandle,
      Token,
      0,
      0,
      0);
#else
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      mKeyInput,
      Token,
      HelpToken,
      EFI_IFR_FLAG_READ_ONLY,
      0
      );
#endif
  mKeyInput++;

  for (Link = GetFirstNode (&mBootOptionsList2); 
       !IsNull (&mBootOptionsList2, Link); 
       Link = GetNextNode (&mBootOptionsList2, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    //
    // Don't display the boot option marked as LOAD_OPTION_HIDDEN
    //
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }
      
    ASSERT (Option->Description != NULL);

    Token = HiiSetString (HiiHandle, 0, Option->Description, NULL);

    TempStr = DevicePathToStr (Option->DevicePath);
    TempSize = StrSize (TempStr);
    HelpString = AllocateZeroPool (TempSize + StrSize (L"Device Path : "));
    ASSERT (HelpString != NULL);
    StrCat (HelpString, L"Device Path : ");
    StrCat (HelpString, TempStr);

    HelpToken = HiiSetString (HiiHandle, 0, HelpString, NULL);

    HiiCreateActionOpCode (
      StartOpCodeHandle,
      (EFI_QUESTION_ID)Option->OptionNumber,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );

    LOG((EFI_D_INFO, "HelpString=\"%s\"\n", HelpString));
  }

// опция "Обновить список устройств":
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  Token = STRING_TOKEN (STR_UPDATE_DEVICES_LIST);
  HiiCreateActionOpCode (
      StartOpCodeHandle,
      MAIN_BOOT_UPDATE_DEVICES_LIST_ID,
      Token,
      HelpToken,
      EFI_IFR_FLAG_CALLBACK,
      0
      );
       
  return EFI_SUCCESS;
}


VOID
RemoveSmardCardCallBack (
  VOID
  )
{
  EFI_STATUS Status;
  SMART_CARD_PROTOCOL *SmartCardProtocol = NULL;

  Status = gBS->LocateProtocol(
              &gSmartCardProtocolGuid,
              NULL,
              (VOID**) &SmartCardProtocol
              );
  if (EFI_ERROR (Status)) {
    return;
  }
  if (SmartCardProtocol != NULL) {
    SmartCardProtocol->EjectNotify = NULL;
    SmartCardProtocol->EjectNotifyContext = NULL;
  }
}

EFI_STATUS
LoadFromSelectedOption(
  IN EFI_HII_HANDLE HiiHandle,
  OUT UINTN *ExitDataSize,
  OUT CHAR16 **ExitData
  )
{
  EFI_STATUS Status;
  CHAR16 *TempStr;
  REMOTE_CFG_TLS_PROTOCOL   *RCTP = NULL;
  
  if (gHistoryHandlerProtocol != NULL) {
    gHistoryHandlerProtocol->AddRecord(
      gHistoryHandlerProtocol,
      HEVENT_QUICK_BOOT_START, 
      SEVERITY_LVL_INFO,
      HISTORY_RECORD_FLAG_RESULT_OK);
  }
  
  if (mKeyInput == 0xFFFF) {
    /* no option selected */
    return EFI_SUCCESS;
  } else if (mKeyInput >= ADDITIONAL_OPT_START) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = LoadAdditionalOption(HiiHandle, gOption,
      gOption->DevicePath, ExitDataSize, ExitData);
    LOG((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    if (Status == EFI_ABORTED) {
      Status = EFI_NOT_FOUND; // !Fix me!
      goto Exit;
    }
  } else {
    //
    // parse the selected option
    //
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    TempStr = DevicePathToStr (gOption->DevicePath);
    LOG((EFI_D_INFO, "%a.%d Device path: %s\n", __FUNCTION__, __LINE__, TempStr));
    if (IsLegacyBootDevPath(DevPathToString(gOption->DevicePath, FALSE, TRUE))) {
      RemoveSmardCardCallBack ();
    }
    Status = gBS->LocateProtocol(
                              &gRemoteCfgTlsProtocolGuid,
                              NULL,
                              (VOID **)&RCTP
                              );
    if (!EFI_ERROR(Status) && RCTP != NULL) {
      Status = RCTP->Stop (RCTP);
      LOG ((DEBUG_INFO | DEBUG_LOAD, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
    }

    if ((DevicePathType (gOption->DevicePath) == BBS_DEVICE_PATH) &&
        (DevicePathSubType (gOption->DevicePath) == BBS_BBS_DP)
        ) {      
      // legacy boot
    } else {
      BmCopyAcpi ();
    }
    BmSignalReadyToBoot();
    Status = BdsLibBootViaBootOption (gOption, gOption->DevicePath, 
      ExitDataSize, ExitData);
    LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }
  
  if (!EFI_ERROR (Status)) {
    gOption->StatusString = GetStringById_1 (STRING_TOKEN (STR_BOOT_SUCCEEDED));
    if (gBdsHelperProtocol) {
      gBdsHelperProtocol->PlatformBdsBootSuccess (
                              gBdsHelperProtocol, 
                              gOption);
    }
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  } else {
    gOption->StatusString = GetStringById_1 (STRING_TOKEN (STR_BOOT_FAILED));
    if (gBdsHelperProtocol) {
      gBdsHelperProtocol->PlatformBdsBootFail (
                              gBdsHelperProtocol,
                              gOption, 
                              Status, 
                              *ExitData, 
                              *ExitDataSize);
    }
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  }
Exit:
  if (gHistoryHandlerProtocol != NULL) {
    gHistoryHandlerProtocol->AddRecord(
      gHistoryHandlerProtocol,
      HEVENT_QUICK_BOOT_END, 
      EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  }
  return Status;
}


EFI_STATUS
AddUsbPath(
  IN UINT8 OpCode,
  IN CHAR16 *UsbPathStr
  )
{
  STATIC CHAR16 *UsbFullPath;
  CHAR16 *TempStr, *ShortName;
  EFI_STATUS Status = EFI_ABORTED;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (UsbPathStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  LOG((EFI_D_INFO, "UsbPathStr = \"%s\"\n", UsbPathStr));

  switch (OpCode) {
  case OPCODE_SAVE_USB_FULL_PATH:
    if (UsbFullPath) {
      FreePoolDbg(UsbFullPath);
    }
    
    UsbFullPath = NULL;
    ShortName = AllocateCopyPool(StrSize(UsbPathStr), UsbPathStr);
    if (ShortName == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    TempStr = StrStr(ShortName, L":\\");
    *TempStr = 0;
    TempStr = FsDescTableGetFullName(ShortName);
    FreePoolDbg(ShortName);
    
    if (TempStr == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
        __FUNCTION__, __LINE__));
      Status = EFI_INVALID_PARAMETER;
    } else {
      UsbFullPath = AllocateCopyPool(StrSize(TempStr), TempStr);  
      if (UsbFullPath) {
        Status = EFI_SUCCESS;
      } else {
        Status = EFI_OUT_OF_RESOURCES;
      }
    }
    break;

  case OPCODE_ADD_USB_PATH:
    if (UsbFullPath) {
      ShortName = AllocateCopyPool(StrSize(UsbPathStr), UsbPathStr);
      if (ShortName == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
      
      TempStr = StrStr(ShortName, L":\\");
      *TempStr = 0;
      if (-1 != AddFsDescTableItem(ShortName, UsbFullPath, FALSE)) {
        Status = EFI_SUCCESS;
      }
      FreePoolDbg(ShortName);
      FreePoolDbg(UsbFullPath);
      UsbFullPath = NULL;
    }
    break;
  }

  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  
  return Status;
}

extern 
BOOLEAN
BdsLibNetworkBootWithMediaPresent (
  IN  EFI_DEVICE_PATH_PROTOCOL      *DevicePath
  );

// удаляем EFI-переменные типа "bootxxxx", содержащие дублирующие опции загрузки:
STATIC
EFI_STATUS
BdsDeleteDuplicateEfiBootOption (
  VOID
  )
{
  UINT16                    *BootOrder;
  UINT8                     *BootOptionVar;
  UINT8                     *BootOptionVar2;
  UINTN                     BootOrderSize;
  UINTN                     BootOptionSize;
  EFI_STATUS                Status;
  UINTN                     Index;
  UINTN                     Index2;
  UINT16                    BootOption[BOOT_OPTION_MAX_CHAR];
  UINT16                    BootOption2[BOOT_OPTION_MAX_CHAR];
  EFI_DEVICE_PATH_PROTOCOL  *OptionDevicePath, *OptionDevicePath2;
  UINT8                     *TempPtr;
  CHAR16                    *Description;
  UINTN                     MaxOpt;
  CHAR16                    *Opt1devPathStr, *Opt2devPathStr;

  Status        = EFI_SUCCESS;
  BootOrder     = NULL;
  BootOrderSize = 0;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Check "BootOrder" variable firstly, this variable hold the number of boot options
  //
  BootOrder = BdsLibGetVariableAndSize (
                L"BootOrder",
                &gEfiGlobalVariableGuid,
                &BootOrderSize
                );
  if (NULL == BootOrder) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Index = 0;
  MaxOpt = BootOrderSize / sizeof (UINT16);

  while (Index < MaxOpt) {
    Index2 = Index + 1;
    if (Index2 == MaxOpt) {
      break;
    }
    if (BootOrder[Index] == 0xFFFF) {
      Index++;
      continue;
    }
    while (Index2 < MaxOpt) {
      if (BootOrder[Index] == BootOrder[Index2]) {
        BootOrder[Index2] = 0xFFFF;
      }
      Index2++;
    }
    Index++;
  }

  Index = 0;
  while (Index < MaxOpt) {
    Index2 = Index + 1;
    if (Index2 == MaxOpt) {
      break;
    }
    if (BootOrder[Index] == 0xFFFF) {
      Index++;
      continue;
    }
    UnicodeSPrint (BootOption, sizeof (BootOption), L"Boot%04x", BootOrder[Index]);    
    
    LOG((EFI_D_INFO, "%a.%d BootOption=%s\n", 
      __FUNCTION__, __LINE__, BootOption));
    BootOptionVar = BdsLibGetVariableAndSize (
                      BootOption,
                      &gEfiGlobalVariableGuid,
                      &BootOptionSize
                      );
    if (NULL == BootOptionVar) {
      Index++;
      continue;
    }

    TempPtr = BootOptionVar;
    TempPtr += sizeof (UINT32) + sizeof (UINT16);
    Description = (CHAR16 *) TempPtr;
    TempPtr += StrSize ((CHAR16 *) TempPtr);
    OptionDevicePath = (EFI_DEVICE_PATH_PROTOCOL *) TempPtr;

    {
      Opt1devPathStr = DevPathToString(OptionDevicePath, FALSE, TRUE);
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      if (Opt1devPathStr) {
        LOG((EFI_D_INFO, "%a.%d Opt1devPathStr=%s\n",
          __FUNCTION__, __LINE__, Opt1devPathStr));
      }
    }

    //
    // Skip legacy boot option (BBS boot device)
    //
    if ((DevicePathType (OptionDevicePath) == BBS_DEVICE_PATH) &&
        (DevicePathSubType (OptionDevicePath) == BBS_BBS_DP)) {
      FreePool (BootOptionVar);
      Index++;
      continue;
    }

    

    while (Index2 < MaxOpt) {
      UnicodeSPrint (BootOption2, sizeof (BootOption2), L"Boot%04x", BootOrder[Index2]);
    
      LOG((EFI_D_INFO, "%a.%d BootOption2=%s\n", 
        __FUNCTION__, __LINE__, BootOption2));
      BootOptionVar2 = BdsLibGetVariableAndSize (
                        BootOption2,
                        &gEfiGlobalVariableGuid,
                        &BootOptionSize
                        );
      if (NULL == BootOptionVar2) {
        Index2++;
        continue;
      }
      LOG((EFI_D_INFO, "%a.%d BootOption2=%s\n",
        __FUNCTION__, __LINE__, BootOption2));

      TempPtr = BootOptionVar2;
      TempPtr += sizeof (UINT32) + sizeof (UINT16);
      Description = (CHAR16 *) TempPtr;
      TempPtr += StrSize ((CHAR16 *) TempPtr);
      OptionDevicePath2 = (EFI_DEVICE_PATH_PROTOCOL *) TempPtr;

      {
        Opt2devPathStr = DevPathToString(OptionDevicePath2, FALSE, TRUE);
        LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        if (Opt2devPathStr) {
          LOG((EFI_D_INFO, "%a.%d Opt2devPathStr=%s\n",
            __FUNCTION__, __LINE__, Opt2devPathStr));
        }
      }

      if (StrCmp(Opt1devPathStr, Opt2devPathStr)) {
        Index2++;
        FreePool (BootOptionVar2);
        continue;
      }
      //
      // Delete this invalid boot option "Boot####"
      //
      LOG ((EFI_D_INFO, "DELETE DUP: %s\n", Opt2devPathStr));
      Status = gRT->SetVariable (
                      BootOption2,
                      &gEfiGlobalVariableGuid,
                      EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                      0,
                      NULL
                      );
      //
      // Mark this boot option in boot order as deleted
      //
      BootOrder[Index2] = 0xffff;
      FreePool (BootOptionVar2);
      Index2++;
    }
    FreePool (BootOptionVar);
    Index++;
  }

  //
  // Adjust boot order array
  //
  Index2 = 0;
  for (Index = 0; Index < MaxOpt; Index++) {
    if (BootOrder[Index] != 0xffff) {
      BootOrder[Index2] = BootOrder[Index];
      Index2 ++;
    }
  }
  Status = gRT->SetVariable (
                  L"BootOrder",
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | 
                    EFI_VARIABLE_RUNTIME_ACCESS | 
                    EFI_VARIABLE_NON_VOLATILE,
                  Index2 * sizeof (UINT16),
                  BootOrder
                  );

  FreePool (BootOrder);

  return Status;
}



extern EFI_STATUS
EFIAPI
BdsLibGetImageHeader (
  IN  EFI_HANDLE                  Device,
  IN  CHAR16                      *FileName,
  OUT EFI_IMAGE_DOS_HEADER        *DosHeader,
  OUT EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr
  );
  
extern VOID
  EFIAPI
  BdsLibBuildOptionFromHandle (
    IN  EFI_HANDLE                 Handle,
    IN  LIST_ENTRY                 *BdsBootOptionList,
    IN  CHAR16                     *String
    );

extern EFI_STATUS
BdsLibDeleteOptionFromHandle (
  IN  EFI_HANDLE                 Handle
  );


BDS_COMMON_OPTION *
EFIAPI
BootMngrLibVariableToOption (
  IN OUT LIST_ENTRY                   *BdsCommonOptionList,
  IN  CHAR16                          *VariableName
  )
{
  UINT32                    Attribute;
  UINT16                    FilePathSize;
  UINT8                     *Variable;
  UINT8                     *TempPtr;
  UINTN                     VariableSize;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  BDS_COMMON_OPTION         *Option;
  VOID                      *LoadOptions;
  UINT32                    LoadOptionsSize;
  CHAR16                    *Description;
  UINT8                     NumOff;
  //
  // Read the variable. We will never free this data.
  //
  Variable = BdsLibGetVariableAndSize (
              VariableName,
              &gEfiGlobalVariableGuid,
              &VariableSize
              );
  if (Variable == NULL) {
    return NULL;
  }
  //
  // Notes: careful defined the variable of Boot#### or
  // Driver####, consider use some macro to abstract the code
  //
  //
  // Get the option attribute
  //
  TempPtr   =  Variable;
  Attribute =  *(UINT32 *) Variable;
  TempPtr   += sizeof (UINT32);

  //
  // Get the option's device path size
  //
  FilePathSize =  *(UINT16 *) TempPtr;
  TempPtr      += sizeof (UINT16);

  //
  // Get the option's description string
  //
  Description = (CHAR16 *) TempPtr;

  //
  // Get the option's description string size
  //
  TempPtr     += StrSize ((CHAR16 *) TempPtr);

  //
  // Get the option's device path
  //
  DevicePath =  (EFI_DEVICE_PATH_PROTOCOL *) TempPtr;
  TempPtr    += FilePathSize;

  LoadOptions     = TempPtr;
  LoadOptionsSize = (UINT32) (VariableSize - (UINTN) (TempPtr - Variable));

  //
  // The Console variables may have multiple device paths, so make
  // an Entry for each one.
  //
  Option = AllocateZeroPool (sizeof (BDS_COMMON_OPTION));
  if (Option == NULL) {
    return NULL;
  }

  Option->Signature   = BDS_LOAD_OPTION_SIGNATURE;
  Option->DevicePath  = AllocateZeroPool (GetDevicePathSize (DevicePath));
  ASSERT(Option->DevicePath != NULL);
  CopyMem (Option->DevicePath, DevicePath, GetDevicePathSize (DevicePath));

  Option->Attribute   = Attribute;
  Option->Description = AllocateZeroPool (StrSize (Description));
  ASSERT(Option->Description != NULL);
  CopyMem (Option->Description, Description, StrSize (Description));

  Option->LoadOptions = AllocateZeroPool (LoadOptionsSize);
  ASSERT(Option->LoadOptions != NULL);
  CopyMem (Option->LoadOptions, LoadOptions, LoadOptionsSize);
  Option->LoadOptionsSize = LoadOptionsSize;

  //
  // Get the value from VariableName Unicode string
  // since the ISO standard assumes ASCII equivalent abbreviations, we can be safe in converting this
  // Unicode stream to ASCII without any loss in meaning.
  //
  if (*VariableName == 'B') {
    NumOff = (UINT8) (sizeof (L"Boot") / sizeof(CHAR16) - 1);
    Option->BootCurrent = (UINT16) ((VariableName[NumOff]  -'0') * 0x1000);
    Option->BootCurrent = (UINT16) (Option->BootCurrent + ((VariableName[NumOff+1]-'0') * 0x100));
    Option->BootCurrent = (UINT16) (Option->BootCurrent +  ((VariableName[NumOff+2]-'0') * 0x10));
    Option->BootCurrent = (UINT16) (Option->BootCurrent + ((VariableName[NumOff+3]-'0')));
  }
  //
  // Insert active entry to BdsDeviceList
  //
  if ((Option->Attribute & LOAD_OPTION_ACTIVE) == LOAD_OPTION_ACTIVE) {
    InsertTailList (BdsCommonOptionList, &Option->Link);
    FreePool (Variable);
    return Option;
  }

  FreePool (Variable);
  FreePool (Option);
  return NULL;

}

// извлекаем опции загрузки из EFI-переменных "BootOrder" и "bootxxxx"
// и добавляем их в список BdsCommonOptionList:
EFI_STATUS
EFIAPI
BootMngrLibBuildOptionFromVar (
  IN  LIST_ENTRY                      *BdsCommonOptionList,
  IN  CHAR16                          *VariableName
  )
{
  UINT16            *OptionOrder;
  UINTN             OptionOrderSize;
  UINTN             Index;
  BDS_COMMON_OPTION *Option;
  CHAR16            OptionName[20];

  //
  // Zero Buffer in order to get all BOOT#### variables
  //
  ZeroMem (OptionName, sizeof (OptionName));

  //
  // Read the BootOrder, or DriverOrder variable.
  //
  OptionOrder = BdsLibGetVariableAndSize (
                  VariableName,
                  &gEfiGlobalVariableGuid,
                  &OptionOrderSize
                  );
  if (OptionOrder == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  LOG ((EFI_D_INFO, "%a.%d OptionOrderSize / sizeof (UINT16) = %d\n",
    __FUNCTION__, __LINE__, OptionOrderSize / sizeof (UINT16)));

  for (Index = 0; Index < OptionOrderSize / sizeof (UINT16); Index++) {    
    if (*VariableName == 'B') {
      UnicodeSPrint (OptionName, sizeof (OptionName), L"Boot%04x", OptionOrder[Index]);
    } else {
      UnicodeSPrint (OptionName, sizeof (OptionName), L"Driver%04x", OptionOrder[Index]);
    }
    // извлекаем опцию из переменной "Bootxxxx" или "Driverxxxx" и помещаем ее в BdsCommonOptionList:
    Option              = BootMngrLibVariableToOption (
                              BdsCommonOptionList, 
                              OptionName);
    if (Option != NULL) {
      Option->BootCurrent = OptionOrder[Index];
      LOG ((EFI_D_INFO, "Added option #%04d:\n", Index));
      ShowOptionContent (Option);
    }
  }

  FreePool (OptionOrder);

  return EFI_SUCCESS;
}

BOOLEAN
EFIAPI
BootMngrLibIsValidEFIBootOptDevicePathExt (
  IN EFI_DEVICE_PATH_PROTOCOL     *DevPath,
  IN BOOLEAN                      CheckMedia,
  IN CHAR16                       *Description
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                Handle;
  EFI_DEVICE_PATH_PROTOCOL  *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *LastDeviceNode;
  EFI_BLOCK_IO_PROTOCOL     *BlockIo;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  TempDevicePath = DevPath;
  LastDeviceNode = DevPath;

  //
  // Check if it's a valid boot option for network boot device.
  // Check if there is EfiLoadFileProtocol installed. 
  // If yes, that means there is a boot option for network.
  //
  Status = gBS->LocateDevicePath (
                  &gEfiLoadFileProtocolGuid,
                  &TempDevicePath,
                  &Handle
                  );
  if (EFI_ERROR (Status)) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    //
    // Device not present so see if we need to connect it
    //
    TempDevicePath = DevPath;
    BdsLibConnectDevicePath (TempDevicePath);
    Status = gBS->LocateDevicePath (
                    &gEfiLoadFileProtocolGuid,
                    &TempDevicePath,
                    &Handle
                    );
  }

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (!EFI_ERROR (Status)) {
    if (!IsDevicePathEnd (TempDevicePath)) {
      //
      // LoadFile protocol is not installed on handle with exactly the same DevPath
      //
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      return FALSE;
    }

    if (CheckMedia) {
      //
      // Test if it is ready to boot now
      //
      if (BdsLibNetworkBootWithMediaPresent(DevPath)) {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        return TRUE;
      }
    } else {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      return TRUE;
    }    
  }

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // If the boot option point to a file, it is a valid EFI boot option,
  // and DON't assume it is ready to boot now
  //
  while (!IsDevicePathEnd (TempDevicePath)) {
	  LastDeviceNode = TempDevicePath;
	  TempDevicePath = NextDevicePathNode (TempDevicePath);
  }
  if ((DevicePathType (LastDeviceNode) == MEDIA_DEVICE_PATH) &&
	  (DevicePathSubType (LastDeviceNode) == MEDIA_FILEPATH_DP)) {
		  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
		  {
			  CHAR16 *Str16;
			  Str16 = DevPathToString(LastDeviceNode, FALSE, TRUE);
			  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
			  if (Str16) {
				  LOG((EFI_D_INFO, "%a.%d Str16=%s\n",
					  __FUNCTION__, __LINE__, Str16));
			  }
		  }

		  TempDevicePath = NULL;
		  if ((DevicePathType (DevPath) == MEDIA_DEVICE_PATH) &&
			  (DevicePathSubType (DevPath) == MEDIA_HARDDRIVE_DP)) {
				  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
				  TempDevicePath = BdsExpandPartitionPartialDevicePathToFull (
					  (HARDDRIVE_DEVICE_PATH *)DevPath
					  );
				  if (TempDevicePath != NULL) {
					  EFI_HANDLE ImageHandle;
					  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
					  {
						  CHAR16 *Str16;
						  Str16 = DevPathToString(TempDevicePath, FALSE, TRUE);
						  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
						  if (Str16) {
							  LOG((EFI_D_INFO, "%a.%d Str16=%s\n",
								  __FUNCTION__, __LINE__, Str16));
						  }
					  }
					  Status = gBS->LoadImage (
						  TRUE,
						  mBdsImageHandle,
						  TempDevicePath,
						  NULL,
						  0,
						  &ImageHandle
						  );
					  if (!EFI_ERROR(Status)) {
						  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
						  return TRUE;
					  }
				  }
		  } else {
			  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
			  return TRUE;
		  }
  }


  //
  // Check if it's a valid boot option for internal Shell
  //
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (EfiGetNameGuidFromFwVolDevicePathNode ((MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *) LastDeviceNode) != NULL) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    //
    // If the boot option point to Internal FV shell, make sure it is valid
    //
    TempDevicePath = DevPath;
    Status = BdsLibUpdateFvFileDevicePath (&TempDevicePath, PcdGetPtr(PcdShellFile));
    if (Status == EFI_ALREADY_STARTED) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      return TRUE;
    } else {
      if (Status == EFI_SUCCESS) {
        FreePool (TempDevicePath);
      }
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      return FALSE;
    }
  }

  //
  // If the boot option point to a blockIO device:
  //    if it is a removable blockIo device, it is valid.
  //    if it is a fixed blockIo device, check its description confliction.
  //
  TempDevicePath = DevPath;
  Status = gBS->LocateDevicePath (&gEfiBlockIoProtocolGuid, &TempDevicePath, &Handle);
  if (EFI_ERROR (Status)) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    //
    // Device not present so see if we need to connect it
    //
    Status = BdsLibConnectDevicePath (DevPath);
    if (!EFI_ERROR (Status)) {
      //
      // Try again to get the Block Io protocol after we did the connect
      //
      TempDevicePath = DevPath;
      Status = gBS->LocateDevicePath (&gEfiBlockIoProtocolGuid, &TempDevicePath, &Handle);
    }
  }

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (!EFI_ERROR (Status)) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = gBS->HandleProtocol (Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    if (!EFI_ERROR (Status)) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      if (CheckMedia) {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        //
        // Test if it is ready to boot now
        //
        if (BdsLibGetBootableHandle (DevPath) != NULL) {
          LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
          return TRUE;
        }
      } else {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        return TRUE;
      }
    }
  } else {
    //
    // if the boot option point to a simple file protocol which does not consume block Io protocol, it is also a valid EFI boot option,
    //
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &TempDevicePath, &Handle);
    if (!EFI_ERROR (Status)) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      if (CheckMedia) {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        //
        // Test if it is ready to boot now
        //
        if (BdsLibGetBootableHandle (DevPath) != NULL) {
          LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
          return TRUE;
        }
      } else {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        return TRUE;
      }
    }
  }
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return FALSE;
}

VOID *
EFIAPI
BootMngrLibGetVariableAndSize (
  IN  CHAR16              *Name,
  IN  EFI_GUID            *VendorGuid,
  OUT UINTN               *VariableSize
  )
{
  EFI_STATUS  Status;
  UINTN       BufferSize;
  VOID        *Buffer;

  Buffer = NULL;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // Pass in a zero size buffer to find the required buffer size.
  //
  BufferSize  = 0;
  LOG ((EFI_D_INFO, "Name=%s VendorGuid=%g\n", Name, VendorGuid));
  Status      = gRT->GetVariable (Name, VendorGuid, NULL, &BufferSize, Buffer);
  LOG ((EFI_D_INFO, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
  if (Status == EFI_BUFFER_TOO_SMALL) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    //
    // Allocate the buffer to return
    //
    Buffer = AllocateZeroPool (BufferSize);
    if (Buffer == NULL) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    //
    // Read variable into the allocated buffer.
    //
    Status = gRT->GetVariable (Name, VendorGuid, NULL, &BufferSize, Buffer);
    if (EFI_ERROR (Status)) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      BufferSize = 0;
    }
  }

  *VariableSize = BufferSize;
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return Buffer;
}

// удаляем EFI-переменные типа "bootxxxx", содержащие недействительные EFI-опции загрузки:
EFI_STATUS
BootMngrDeleteAllInvalidEfiBootOption (
  VOID
  )
{
  UINT16                    *BootOrder;
  UINT8                     *BootOptionVar;
  UINTN                     BootOrderSize;
  UINTN                     BootOptionSize;
  EFI_STATUS                Status;
  UINTN                     Index;
  UINTN                     Index2;
  UINT16                    BootOption[BOOT_OPTION_MAX_CHAR];
  EFI_DEVICE_PATH_PROTOCOL  *OptionDevicePath;
  UINT8                     *TempPtr;
  CHAR16                    *Description;

  Status        = EFI_SUCCESS;
  BootOrder     = NULL;
  BootOrderSize = 0;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Check "BootOrder" variable firstly, this variable hold the number of boot options
  //
  BootOrder = BdsLibGetVariableAndSize (
                L"BootOrder",
                &gEfiGlobalVariableGuid,
                &BootOrderSize
                );
  if (NULL == BootOrder) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG ((EFI_D_INFO, "%a.%d BootOrderSize / sizeof (UINT16)=%d\n", 
    __FUNCTION__, __LINE__, BootOrderSize / sizeof (UINT16)));

  Index = 0;
  while (Index < BootOrderSize / sizeof (UINT16)) {
    UnicodeSPrint (BootOption, sizeof (BootOption), L"Boot%04x", BootOrder[Index]);
    BootOptionVar = BootMngrLibGetVariableAndSize (
                      BootOption,
                      &gEfiGlobalVariableGuid,
                      &BootOptionSize
                      );
    LOG ((EFI_D_INFO, "%a.%d BootOption=%s\n", 
      __FUNCTION__, __LINE__, BootOption));
    if (NULL == BootOptionVar) {
      //FreePool (BootOrder);
      //return EFI_OUT_OF_RESOURCES;
      Index++;
      continue;
    }

    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    TempPtr = BootOptionVar;
    TempPtr += sizeof (UINT32) + sizeof (UINT16);
    Description = (CHAR16 *) TempPtr;
    TempPtr += StrSize ((CHAR16 *) TempPtr);
    OptionDevicePath = (EFI_DEVICE_PATH_PROTOCOL *) TempPtr;

    {
      CHAR16                  *TempStr;
    
      TempStr = DevicePathToStr (OptionDevicePath);
      LOG ((EFI_D_INFO, "%a.%d OptionDevicePath=%s\n", 
        __FUNCTION__, __LINE__, TempStr));
    }

    //
    // Skip legacy boot option (BBS boot device)
    //
    if ((DevicePathType (OptionDevicePath) == BBS_DEVICE_PATH) &&
        (DevicePathSubType (OptionDevicePath) == BBS_BBS_DP)) {
      FreePool (BootOptionVar);
      Index++;
      continue;
    }
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (!BootMngrLibIsValidEFIBootOptDevicePathExt (
          OptionDevicePath, 
          TRUE, 
          Description)) {
      //
      // Delete this invalid boot option "Boot####"
      //
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = gRT->SetVariable (
                      BootOption,
                      &gEfiGlobalVariableGuid,
                      EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                      0,
                      NULL
                      );
      //
      // Mark this boot option in boot order as deleted
      //
      BootOrder[Index] = 0xffff;
    }

    FreePool (BootOptionVar);
    Index++;
  }

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Adjust boot order array
  //
  Index2 = 0;
  for (Index = 0; Index < BootOrderSize / sizeof (UINT16); Index++) {
    if (BootOrder[Index] != 0xffff) {
      BootOrder[Index2] = BootOrder[Index];
      Index2 ++;
    }
  }
  LOG ((EFI_D_INFO, "%a.%d Index2=%d\n", __FUNCTION__, __LINE__, Index2));
  Status = gRT->SetVariable (
                  L"BootOrder",
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  Index2 * sizeof (UINT16),
                  BootOrder
                  );

  FreePool (BootOrder);

  return Status;
}


// опция загрузки, определяемая Handle и описываемая String, заносится в EFI-переменные "BootOrder" и "Bootxxxx":
// BdsBootOptionList пока не задействован
VOID
EFIAPI
BootMngrLibBuildOptionFromHandle (
  IN  EFI_HANDLE                 Handle,
  IN  LIST_ENTRY                 *BdsBootOptionList,
  IN  CHAR16                     *String
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  DevicePath = DevicePathFromHandle (Handle);

  {
    CHAR16                  *TempStr;
  
    TempStr = DevicePathToStr (DevicePath);
    LOG ((EFI_D_INFO, "%a.%d DevicePath=%s\n", 
      __FUNCTION__, __LINE__, TempStr));
  }

  //
  // Create and register new boot option
  //
/*
	в функции BdsLibRegisterNewOption()
	опция заносится только в EFI-переменные!
	В BdsBootOptionList она не включается, это надо делать отдельно.
*/
  BdsLibRegisterNewOption (BdsBootOptionList, DevicePath, String, L"BootOrder");
}

// опции EFI и Legacy загрузки добавляются в список BdsBootOptionList
EFI_STATUS
EFIAPI
BootMngrLibEnumerateAllBootOption (
  IN OUT LIST_ENTRY          *BdsBootOptionList
  )
{
  EFI_STATUS                    Status;
  UINT16                        FloppyNumber;
  UINT16                        HardDriveNumber;
  UINT16                        CdromNumber;
  UINT16                        UsbNumber;
  UINT16                        MiscNumber;
  UINT16                        ScsiNumber;
  UINT16                        NonBlockNumber;
  EFI_BLOCK_IO_PROTOCOL         *BlkIo;
  UINTN                         Index;
  UINTN                         NumOfLoadFileHandles;
  EFI_HANDLE                    *LoadFileHandles;
  UINTN                         FvHandleCount;
  EFI_HANDLE                    *FvHandleBuffer;
  EFI_FV_FILETYPE               Type;
  UINTN                         Size;
  EFI_FV_FILE_ATTRIBUTES        Attributes;
  UINT32                        AuthenticationStatus;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL      *TempDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL      *ParentDevicePath;
  UINTN                         DevicePathType;
  CHAR16                        Buffer[40];
  EFI_HANDLE                    *FileSystemHandles;
  UINTN                         NumberFileSystemHandles;
  BOOLEAN                       NeedDelete;
  EFI_IMAGE_DOS_HEADER          DosHeader;
  CHAR8                         *PlatLang;
  CHAR8                         *LastLang;
  EFI_IMAGE_OPTIONAL_HEADER_UNION       HdrData;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr;
  STATIC BOOLEAN mEnumBootDevice = FALSE;
  EFI_GUID mBdsLibLastLangGuid = { 0xe8c545b, 0xa2ee, 0x470d, { 0x8e, 0x26, 0xbd, 0xa1, 0xa1, 0x3c, 0xa, 0xa3 } };

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  FloppyNumber    = 0;
  CdromNumber     = 0;
  HardDriveNumber = 0;
  UsbNumber       = 0;
  MiscNumber      = 0;
  ScsiNumber      = 0;
  PlatLang        = NULL;
  LastLang        = NULL;
  ZeroMem (Buffer, sizeof (Buffer));

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowBootOptionsList (BdsBootOptionList);

  //
  // If the boot device enumerate happened, just get the boot
  // device from the boot order variable
  //
  if (mEnumBootDevice) {
  // mEnumBootDevice постоянно равен FALSE,
  // поэтому этот фрагмент не работает:
    LastLang = GetVariable (L"LastEnumLang", &mBdsLibLastLangGuid);
    PlatLang = GetEfiGlobalVariable (L"PlatformLang");
    if (LastLang == PlatLang) {
      Status = BdsLibBuildOptionFromVar (BdsBootOptionList, L"BootOrder");
      return Status;
    } else {
      Status = gRT->SetVariable (
        L"LastEnumLang",
        &mBdsLibLastLangGuid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE,
        sizeof (PlatLang),
        PlatLang
        );
      ASSERT_EFI_ERROR (Status);
    }
  }

  //
  // Notes: this dirty code is to get the legacy boot option from the
  // BBS table and create to variable as the EFI boot option, it should
  // be removed after the CSM can provide legacy boot option directly
  //
  //REFRESH_LEGACY_BOOT_OPTIONS;

  //
  // Удаляем лишние опции из EFI-переменных:
  //
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  BdsDeleteAllInvalidLegacyBootOptions ();
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  BootMngrDeleteAllInvalidEfiBootOption ();
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  BdsDeleteDuplicateEfiBootOption ();

  //
  // Parse media
  //
  // 1. Добавляем опции, имеющие EfiSimpleFileSystemProtocol и EfiBlockIoProtocol;
  // кроме того, должен существовать стандартный путь EFI\BOOT\boot{machine}.efi
  //
  gBS->LocateHandleBuffer (
	  ByProtocol,
	  &gEfiSimpleFileSystemProtocolGuid,
	  NULL,
	  &NumberFileSystemHandles,
	  &FileSystemHandles
	  );

  LOG ((EFI_D_INFO, "%a.%d NumberBlockIoHandles=%d\n", 
    __FUNCTION__, __LINE__, NumberFileSystemHandles));

  for (Index = 0; Index < NumberFileSystemHandles; Index++) 
  {
    DevicePath  = DevicePathFromHandle (FileSystemHandles[Index]);
    LOG((EFI_D_INFO, "DevicePathStr=%s\n", 
      DevicePathToStr(DevicePath)));

	//
	// Delete all devices, which doesn't have. \EFI\BOOT\boot{machinename}.EFI
	//  machinename is ia32, ia64, x64, ...
	// on its file system
	//

	Hdr.Union  = &HdrData;
	Status     = BdsLibGetImageHeader (
		FileSystemHandles[Index],
		EFI_REMOVABLE_MEDIA_FILE_NAME,
		&DosHeader,
		Hdr
		);
	if (EFI_ERROR (Status) ||
		!EFI_IMAGE_MACHINE_TYPE_SUPPORTED (Hdr.Pe32->FileHeader.Machine) ||
		Hdr.Pe32->OptionalHeader.Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) 
	{
		continue;
	}
    
    Status = gBS->HandleProtocol (
                    FileSystemHandles[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlkIo
                    );
    if (EFI_ERROR (Status)) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }

	if (!BlkIo->Media->LogicalPartition)
	{
		LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
		continue;
	}

	// FIX: 
	// We need in all devices: removable and not

//    if (!BlkIo->Media->RemovableMedia) {
//     LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
//      continue;
//   }
    
	// getting main device path (with file system)
	DevicePath = DevicePathFromHandle (FileSystemHandles[Index]);

	// preparing parent device path
	// todo del ParentDevicePath
	ParentDevicePath = DuplicateDevicePath(DevicePath);
	TempDevicePathNode = ParentDevicePath;
	while (!IsDevicePathEnd(NextDevicePathNode(TempDevicePathNode)))
	{
		TempDevicePathNode = NextDevicePathNode(TempDevicePathNode);
	}
	SetDevicePathEndNode(TempDevicePathNode);

	DevicePathType = BdsGetBootTypeFromDevicePath (ParentDevicePath);
    {
      CHAR16                  *TempStr;
    
      TempStr = DevicePathToStr (ParentDevicePath);
      LOG ((EFI_D_INFO, "%a.%d DevicePath=%s\n", 
        __FUNCTION__, __LINE__, TempStr));
    }

	// free allocated resources
	FreePool(ParentDevicePath);
	ParentDevicePath = NULL;

    LOG((EFI_D_INFO, "%a.%d DevicePathType=0x%X\n", 
      __FUNCTION__, __LINE__, DevicePathType));    

    switch (DevicePathType) {
    case BDS_EFI_ACPI_FLOPPY_BOOT:
      if (FloppyNumber != 0) {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_FLOPPY), NULL), FloppyNumber);
      } else {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_FLOPPY), NULL));
      }
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      FloppyNumber++;
      break;

    //
    // Assume a removable SATA device should be the DVD/CD device
    //
    case BDS_EFI_MESSAGE_ATAPI_BOOT:
    case BDS_EFI_MESSAGE_SATA_BOOT:
	  if (BlkIo->Media->RemovableMedia)
	  {
		  if (CdromNumber != 0) {
			  UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
				  HiiGetString(
				  gBootManagerPrivate.HiiHandle,
				  STRING_TOKEN (STR_DESCRIPTION_CD_DVD), NULL), CdromNumber);
		  } else {
			  UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
				  HiiGetString(
				  gBootManagerPrivate.HiiHandle, STRING_TOKEN (STR_DESCRIPTION_CD_DVD), NULL));
		  }
		  CdromNumber++;
	  }
	  else
	  {
		  if (HardDriveNumber != 0) {
			  UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
				  HiiGetString(
				  gBootManagerPrivate.HiiHandle,
				  STRING_TOKEN (STR_DESCRIPTION_HARD_DRIVE), NULL), HardDriveNumber);
		  } else {
			  UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
				  HiiGetString(
				  gBootManagerPrivate.HiiHandle, STRING_TOKEN (STR_DESCRIPTION_HARD_DRIVE), NULL));
		  }
		  HardDriveNumber++;
	  }
 
      LOG ((DEBUG_INFO | DEBUG_LOAD, "Buffer: %S\n", Buffer));
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      break;

    case BDS_EFI_MESSAGE_USB_DEVICE_BOOT:
      if (UsbNumber != 0) {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_USB), NULL), UsbNumber);
      } else {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_USB), NULL));
      }
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      UsbNumber++;
      break;

    case BDS_EFI_MESSAGE_SCSI_BOOT:
      if (ScsiNumber != 0) {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_SCSI), NULL), ScsiNumber);
      } else {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_SCSI), NULL));
      }
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      ScsiNumber++;
      break;

    case BDS_EFI_MESSAGE_MISC_BOOT:
      if (MiscNumber != 0) {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_MISC), NULL), MiscNumber);
      } else {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_MISC), NULL));
      }
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      MiscNumber++;
      break;

    default:
      break;
    }
  }

  if (NumberFileSystemHandles != 0) {
    FreePool (FileSystemHandles);
  }

  // 2. Добавляем опции, имеющие EfiSimpleFileSystemProtocol но не имеющие EfiBlockIoProtocol:

  //
  // If there is simple file protocol which does not consume block Io protocol, create a boot option for it here.
  //
  NonBlockNumber = 0;

  // simple repeat getting SimpleFileSystemProtocol
  gBS->LocateHandleBuffer (
	  ByProtocol,
	  &gEfiSimpleFileSystemProtocolGuid,
	  NULL,
	  &NumberFileSystemHandles,
	  &FileSystemHandles
	  );
  LOG ((EFI_D_INFO, "%a.%d FileSystemHandles=%d\n", 
	  __FUNCTION__, __LINE__, FileSystemHandles));
  for (Index = 0; Index < NumberFileSystemHandles; Index++) {
    Status = gBS->HandleProtocol (
                    FileSystemHandles[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlkIo
                    );
     if (!EFI_ERROR (Status)) {
      //
      //  Skip if the file system handle supports a BlkIo protocol,
      //
      continue;
    }

    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    //
    // Do the removable Media thing. \EFI\BOOT\boot{machinename}.EFI
    //  machinename is ia32, ia64, x64, ...
    //
    Hdr.Union = &HdrData;
    NeedDelete = TRUE;
    Status     = BdsLibGetImageHeader (
                   FileSystemHandles[Index],
                   EFI_REMOVABLE_MEDIA_FILE_NAME,
                   &DosHeader,
                   Hdr
                   );
    if (!EFI_ERROR (Status) &&
        EFI_IMAGE_MACHINE_TYPE_SUPPORTED (Hdr.Pe32->FileHeader.Machine) &&
        Hdr.Pe32->OptionalHeader.Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
      NeedDelete = FALSE;
    }

    if (NeedDelete) {
      //
      // No such file or the file is not a EFI application, delete this boot option
      //
      Status = BdsLibDeleteOptionFromHandle (FileSystemHandles[Index]);
      LOG ((EFI_D_INFO, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
    } else {
      if (NonBlockNumber != 0) {
        LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_NON_BLOCK), NULL), NonBlockNumber);
      } else {
        UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
          HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_NON_BLOCK), NULL));
      }
      BootMngrLibBuildOptionFromHandle (FileSystemHandles[Index], BdsBootOptionList, Buffer);
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      NonBlockNumber++;
    }
  }

  if (NumberFileSystemHandles != 0) {
    FreePool (FileSystemHandles);
  }

  // 3. Добавляем опции, имеющие EfiLoadFileProtocol:

  //
  // Parse Network Boot Device
  //
  NumOfLoadFileHandles = 0;
  //
  // Search Load File protocol for PXE boot option.
  //
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiLoadFileProtocolGuid,
        NULL,
        &NumOfLoadFileHandles,
        &LoadFileHandles
        );

  LOG((EFI_D_INFO, "%a.%d NumOfLoadFileHandles=%d\n", 
    __FUNCTION__, __LINE__, NumOfLoadFileHandles));

  for (Index = 0; Index < NumOfLoadFileHandles; Index++) {
    if (Index != 0) {
      UnicodeSPrint (Buffer, sizeof (Buffer), L"%s %d", 
        HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_NETWORK), NULL), Index);
    } else {
      UnicodeSPrint (Buffer, sizeof (Buffer), L"%s", 
        HiiGetString(
            gBootManagerPrivate.HiiHandle,
            STRING_TOKEN (STR_DESCRIPTION_NETWORK), NULL));
    }
    BootMngrLibBuildOptionFromHandle (LoadFileHandles[Index], BdsBootOptionList, Buffer);
  }

  if (NumOfLoadFileHandles != 0) {
    FreePool (LoadFileHandles);
  }

  //
  // Check if we have on flash shell
  //
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiFirmwareVolume2ProtocolGuid,
        NULL,
        &FvHandleCount,
        &FvHandleBuffer
        );
  for (Index = 0; Index < FvHandleCount; Index++) {
    gBS->HandleProtocol (
          FvHandleBuffer[Index],
          &gEfiFirmwareVolume2ProtocolGuid,
          (VOID **) &Fv
          );

    Status = Fv->ReadFile (
                  Fv,
                  PcdGetPtr(PcdShellFile),
                  NULL,
                  &Size,
                  &Type,
                  &Attributes,
                  &AuthenticationStatus
                  );
    if (EFI_ERROR (Status)) {
      //
      // Skip if no shell file in the FV
      //
      continue;
    }
    //
    // Build the shell boot option
    //
    BdsLibBuildOptionFromShell (FvHandleBuffer[Index], BdsBootOptionList);
  }

  if (FvHandleCount != 0) {
    FreePool (FvHandleBuffer);
  }
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowBootOptionsList (BdsBootOptionList);
  
  //
  // 5. Извлекаем загрузочные опции из "BootOrder" и "Bootxxxx"
  // и включаем их в BdsBootOptionList:
  Status = BootMngrLibBuildOptionFromVar (BdsBootOptionList, L"BootOrder");
  //mEnumBootDevice = TRUE;
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowBootOptionsList (BdsBootOptionList);

  return Status;
}


VOID
SetBootManagerMenuMode(
  IN UINT8 Mode
  )
{
  gBootMngrMenuMode = Mode;
}

STATIC
VOID
HandleSelectedModule (
  IN EFI_HII_HANDLE HiiHandle
  )
{
  CHAR16 *TmpStr;
  UINTN Len;
  UINT8 *Hash;
  
  AddUsbPath(OPCODE_SAVE_USB_FULL_PATH, CurUsbPathStr);
  FsDescTableRemoveLastItem();
  
  FeLibSelectFromDevice(HiiHandle, &mBootManagerGuid, 
    BOOT_MANAGER_FORM_ID, 0xF000, LABEL_BOOT_OPTION, LABEL_BOOT_OPTION_END);
  
  AddUsbPath(OPCODE_ADD_USB_PATH, CurUsbPathStr);
  
  LOG((EFI_D_INFO, "%a.%d FeGetSelectedString()=%s\n", 
    __FUNCTION__, __LINE__, FeGetSelectedString()));
  
  if (SelectedModuleDevPath == NULL) {
    return;
  }

  LOG((EFI_D_INFO, "%a.%d SelectedModuleDevPath=%s\n", 
    __FUNCTION__, __LINE__, SelectedModuleDevPath));
    
    
  TmpStr = FeGetSelectedString();
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  Len = (TmpStr != NULL) ? StrLen(TmpStr) : 0;
  if (Len) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (Len < MULTIBOOT_MAX_STRING) {
      CHAR8 *Ptr8;
      CHAR16 ShortName[10];            

      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

      Ptr8 = (CHAR8*)SelectedModuleDevPath;
      Hash = Ptr8 + MULTIBOOT_MAX_STRING * sizeof(CHAR16) * 2;
      Ptr8 -= MULTIBOOT_MAX_STRING * sizeof(CHAR16);

/*
typedef struct {
  CHAR16 DeviceFullName[MULTIBOOT_MAX_STRING];			<- Ptr8
  CHAR16 DevPath[MULTIBOOT_MAX_STRING];				<- SelectedModuleDevPath	
  CHAR16 Description[MULTIBOOT_MAX_STRING];
  CHAR16 Args[MULTIBOOT_MAX_STRING];
  CHAR8 Hash[MAX_HASH_LEN];					<- Hash
} CBCFG_RECORD;
*/

#if 0
      Status = CalcHashCsOnFile16(TmpStr, PRIMARY_HASH_TYPE, Hash);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
          __FUNCTION__, __LINE__, Status));
      }
#endif            
      StrCpy(SelectedModuleDevPath, TmpStr);				// to Rec->DevPath

      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      CopyMem(ShortName, SelectedModuleDevPath, 4 * sizeof(CHAR16));
      ShortName[4] = 0;
      StrCpy((CHAR16*)Ptr8, FsDescTableGetFullName(ShortName));		// // to Rec->DeviceFullName
    } else {
      /* TODO: error string too long */
    }
  }
  LOG((EFI_D_INFO, "%a.%d SelectedModuleDevPath=%s\n", 
  __FUNCTION__, __LINE__, SelectedModuleDevPath));
  SelectedModuleDevPath = NULL;
}


VOID
ImportBootCfgFromFv (
  VOID
  )
{
  EFI_DEVICE_PATH_PROTOCOL *pDp = NULL;
  CHAR16 *PathString = NULL, *ShortName = NULL;
  CHAR16 FilePath[100];
  EFI_STATUS Status;
  BOOLEAN bNoBootConfig = TRUE;
  BOOLEAN bNeedReinit;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  bNeedReinit = BootManagerIsNeedReinit ();
  BootManagerNeedReinit (FALSE);
  
  Status = FindFileDpInVolume(PcdGetPtr(PcdBootMngrConfFile), 
    &pDp, &PathString);
  if (!EFI_ERROR(Status)) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    UnicodeSPrint(PathString, StrSize(PathString), L"%s", 
      MEMORY_MAPPED_NEW_FV_NAME);
    ShortName = FsDescTableGetShortName(PathString);
    if (ShortName == NULL) {
      LOG(( EFI_D_INFO, "-*-> %S\n", PathString ));
      AddFsDescTableItem(FVEX_PATH_SHORT_NAME, PathString, FALSE);
    }
  } else {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));    
    return;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (bNeedReinit) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    BootManagerDestroyAllSettings ();
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  for (gVarsGuidIdx = 0; gVarsGuidIdx < MAX_VARS_GUIDS; gVarsGuidIdx++) {
    if (isCbcfgStorageEmpty () ) {
      CBCFG_DATA_SET *DataSet;
      
      CbcfgStorageInitEmpty();
      DataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - sizeof(UINT8) + 
        sizeof(CBCFG_RECORD));
      if (DataSet) {
        DataSet->BootOptionsNum = 1;
        DataSet->BootType = BOOT_TYPE_DEFAULT;
        DataSet->ModulesType = MODULE_TYPE_DEFAULT;
        CbcfgSave(DataSet);
        FreePoolDbg(DataSet);
      }
    } else {
      bNoBootConfig = FALSE;
      LOG((EFI_D_INFO, "%a.%d gVarsGuidIdx=%d\n", __FUNCTION__, __LINE__, gVarsGuidIdx));
    }
    if (!IcflStoragePresent()) {
      IcflStorageInitEmpty();
    }
  }
  gVarsGuidIdx = 0;

  if (!bNoBootConfig) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }

  PcdHelperInit();
  
  if (gPcdHelperProtocol && 
      gPcdHelperProtocol->PcdGet32PcdNewFvSize (gPcdHelperProtocol)) {    
    ShortName = FsDescTableGetShortName(PathString);
    if (ShortName) {
      LOG((EFI_D_INFO, "%a.%d ShortName:%s PathString=%s\n", 
        __FUNCTION__, __LINE__, ShortName, PathString));
      UnicodeSPrint(FilePath, sizeof(FilePath), L"%s:%g",
        ShortName, PcdGetPtr(PcdBootMngrConfFile));
      LOG((EFI_D_INFO, "%a.%d FilePath:%s\n", 
      __FUNCTION__, __LINE__, FilePath));
      ImportBootOptions(FilePath);
    }
    if (PathString) {
      FreePool(PathString);
    }
  }
}


/**
  This function invokes Boot Manager. If all devices have not a chance to be connected,
  the connect all will be triggered. It then enumerate all boot options. If 
  a boot option from the Boot Manager page is selected, Boot Manager will boot
  from this boot option.
  
**/
VOID
CallBootManager (
  IN CHAR16 *UsbPathStr
  )
{
  EFI_STATUS                  Status;
  CHAR16                      *ExitData;
  UINTN                       ExitDataSize;
  EFI_HII_HANDLE              HiiHandle;
  EFI_BROWSER_ACTION_REQUEST  ActionRequest;
  VOID                        *StartOpCodeHandle = NULL;
  VOID                        *EndOpCodeHandle = NULL;
  EFI_IFR_GUID_LABEL          *StartLabel;
  EFI_IFR_GUID_LABEL          *EndLabel;
  UINTN                       Idx;
  BOOLEAN                     bNoBootConfig;  
  CHAR16                      *FilePath;

  LOG((EFI_D_INFO, "\n!!!TB_BOOTMANAGER_BootManagerLib!!!\n"));
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  CurUsbPathStr = UsbPathStr;
  gBootSelectedOptGuid = NULL;
  bIntegrityPageCheckHash = FALSE;
  Init_gVarsDescStrMap();

  gST->ConOut->ClearScreen(gST->ConOut);
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", 
    HiiGetString(
      gBootManagerPrivate.HiiHandle,
      STRING_TOKEN(STR_WAIT_FOT_BM_START), NULL
      ), 
    L"", L"", NULL);

  ExitDataSize = 0;
  ExitData     = NULL;
  bNoBootConfig = TRUE;
  
  for (gVarsGuidIdx = 0; gVarsGuidIdx < MAX_VARS_GUIDS; gVarsGuidIdx++) {
    if (!CbcfgStoragePresent()) {
      CBCFG_DATA_SET *DataSet;
      
      CbcfgStorageInitEmpty();
      DataSet = AllocateZeroPoolDbg(sizeof(CBCFG_DATA_SET) - sizeof(UINT8) + 
        sizeof(CBCFG_RECORD));
      if (DataSet) {
        DataSet->BootOptionsNum = 1;
        DataSet->BootType = BOOT_TYPE_DEFAULT;
        DataSet->ModulesType = MODULE_TYPE_DEFAULT;
	if(CompareGuid(&gVarsGuid[gVarsGuidIdx], &gKuefiGuid)){
          DataSet->BootType = BOOT_TYPE_FROM_FS;
          DataSet->ModulesType = MODULE_TYPE_EFI;
	}
        CbcfgSave(DataSet);
        FreePoolDbg(DataSet);
      }
    } else {
      bNoBootConfig = FALSE;
    }
    if (!IcflStoragePresent()) {
      IcflStorageInitEmpty();
    }
  }  
  
  gVarsGuidIdx = 0;

  InitializeListHead (&mBootOptionsList);
  InitializeListHead (&mBootOptionsList2);
  InitializeListHead(&IcflList);

  GetIcfl(&IcflList);

  AddUsbPath(OPCODE_SAVE_USB_FULL_PATH, UsbPathStr);

  Status = BakupFsDescTable();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return;
  }
  CreateFsDescMappingFromFs();
  AddUsbPath(OPCODE_ADD_USB_PATH, UsbPathStr);

  switch (gBootMngrMenuMode) {
  case BOOT_MNGR_BASIC_MODE:
  case BOOT_MNGR_HIDE_CTRL_MODE:
    CurrentMode = NewMode = MAIN_BOOT_UNDEF;
    break;

  case BOOT_MNGR_CTRL_ONLY_MODE:
    CurrentMode = NewMode = MAIN_BOOT_MANAGER_ID;
    break;

  default:
    /* TODO: Show error! */
    goto Done;
  }
  
DrawMenu:
  gOption = NULL;  

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DestroyOptionList(&mBootOptionsList);
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DestroyOptionList(&mBootOptionsList2);

  AddUsbPath(OPCODE_SAVE_USB_FULL_PATH, UsbPathStr);
  CreateFsDescMappingFromFs();
  AddUsbPath(OPCODE_ADD_USB_PATH, UsbPathStr);

  /* TODO: try to import xml from FV */
  LOG((EFI_D_INFO, "%a.%d bNoBootConfig=%d\n", 
    __FUNCTION__, __LINE__, bNoBootConfig));
  if (bNoBootConfig) {
    ImportBootCfgFromFv ();
    bNoBootConfig = FALSE;    
  }
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Connect all prior to entering the platform setup menu.
  //
  if (!gConnectAllHappened) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    BdsLibConnectAllDriversToAllControllers ();
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    gConnectAllHappened = TRUE;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //BdsLibEnumerateAllBootOption (&mBootOptionsList);
  BootMngrLibEnumerateAllBootOption (&mBootOptionsList);
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  HiiHandle = gBootManagerPrivate.HiiHandle;

  //
  // Allocate space for creation of UpdateData Buffer
  //
  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (StartOpCodeHandle != NULL);

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (EndOpCodeHandle != NULL);

  //
  // Create Hii Extend Label OpCode as the start opcode
  //
  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                          StartOpCodeHandle, 
                                          &gEfiIfrTianoGuid, 
                                          NULL, 
                                          sizeof (EFI_IFR_GUID_LABEL));
  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_BOOT_OPTION;

  //
  // Create Hii Extend Label OpCode as the end opcode
  //
  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                          EndOpCodeHandle, 
                                          &gEfiIfrTianoGuid, 
                                          NULL, 
                                          sizeof (EFI_IFR_GUID_LABEL));
  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_BOOT_OPTION_END;

  switch (CurrentMode) {
  case MAIN_BOOT_MANAGER_ID:
    CreateBootCtrlMenu(HiiHandle, StartOpCodeHandle);
    break;

  case MAIN_BOOT_CONFIG_ID:
    CreateBootCfgMenu(HiiHandle, StartOpCodeHandle);
    break;

  case MAIN_BOOT_UNDEF:
    CreateBootMainMenu(HiiHandle, StartOpCodeHandle);
    break;

  case MAIN_BOOT_INTEGRITY_ID:
    CreateIntegrityFilesList(HiiHandle, StartOpCodeHandle);
    break;
  }

  CurrentFormId = CurrentMode == MAIN_BOOT_MANAGER_ID ? 
    BOOT_MENU_FORM_ID : BOOT_MANAGER_FORM_ID ;
  
  Status = HiiUpdateForm (
    HiiHandle,
    &mBootManagerGuid,    
    CurrentFormId,
    StartOpCodeHandle,
    EndOpCodeHandle
    );

  LOG ((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  
  gStringPackHandle = HiiHandle;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  bBootDevicesRefresh = FALSE;
  mKeyInput = 0xFFFF;
  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = gFormBrowser2->SendForm (
                           gFormBrowser2,
                           &HiiHandle,
                           1,
                           &mBootManagerGuid,
                           CurrentFormId,
                           NULL,
                           &ActionRequest
                           );
  if (ActionRequest == EFI_BROWSER_ACTION_REQUEST_RESET) {
    EnableResetRequired ();
  }
  LOG((EFI_D_INFO, "%a.%d NewMode=0x%X CurrentMode=0x%X\n", 
    __FUNCTION__, __LINE__, NewMode, CurrentMode));
  LOG((EFI_D_INFO, "%a.%d gBootMngrMenuMode=0x%X\n", 
    __FUNCTION__, __LINE__, gBootMngrMenuMode));

  switch (NewMode) {
  case MAIN_BOOT_MANAGER_ID:
    if (CurrentMode == MAIN_BOOT_UNDEF && 
        gBootMngrMenuMode == BOOT_MNGR_BASIC_MODE) {
      CurrentMode = NewMode;
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      goto DrawMenu;
    } else if (CurrentMode == MAIN_BOOT_UNDEF && bBootDevicesRefresh) {
      CurrentMode = NewMode;
      LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      goto DrawMenu;
    }
    break;

  case MAIN_BOOT_CONFIG_ID:
    if (DoFeMode) {
      HandleSelectedModule(HiiHandle);
      DoFeMode = FALSE;
    }
    if (CurrentMode == MAIN_BOOT_UNDEF) {
      CurrentMode = NewMode;
      goto DrawMenu;
    }
    break;

  case MAIN_BOOT_UNDEF:
    if (CurrentMode != MAIN_BOOT_UNDEF && 
        gBootMngrMenuMode != BOOT_MNGR_CTRL_ONLY_MODE) {
      CurrentMode = NewMode;
      goto DrawMenu;
    } else {
      goto Done;
    }
    break;

  case MAIN_BOOT_INTEGRITY_ID:
    if (CurrentMode == MAIN_BOOT_CONFIG_ID) {
      CurrentMode = NewMode;
      goto DrawMenu;      
    }
    break;

  case MAIN_BOOT_SELECT_FILE_ID:
    CurrentMode = MAIN_BOOT_INTEGRITY_ID;
    AddUsbPath(OPCODE_SAVE_USB_FULL_PATH, CurUsbPathStr);
    FsDescTableRemoveLastItem();
    
    Status = FeLibSelectFromDevice(HiiHandle, &mBootManagerGuid, 
      BOOT_MANAGER_FORM_ID, 0xF000, LABEL_BOOT_OPTION, LABEL_BOOT_OPTION_END);
    if (Status == EFI_NOT_FOUND) {
      ShowErrorPopup(gBootManagerPrivate.HiiHandle, 
        HiiGetString(gBootManagerPrivate.HiiHandle, 
          STRING_TOKEN(STR_ABSENT_DEVICES_WITH_FS), NULL));
    }
    
    AddUsbPath(OPCODE_ADD_USB_PATH, CurUsbPathStr);
    FilePath = FeGetSelectedString();
    if ((FilePath != NULL) && StrLen(FilePath)) {
      Status = IcflAddItem(FilePath, FALSE, FALSE, NULL);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
        ShowErrorPopup(gBootManagerPrivate.HiiHandle, 
          HiiGetString(gBootManagerPrivate.HiiHandle, 
            STRING_TOKEN(STR_ERR_OPEN_FILE), NULL));
      }
    }
    goto DrawMenu;
    break;

  default:
    goto Done;
  }

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (gBootMngrMenuMode == BOOT_MNGR_CTRL_ONLY_MODE) {
    gBootSelectedOptGuid = NULL;
  }
  
  if (gOption == NULL) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (mKeyInput == 0xFFFF && gBootMngrMenuMode != BOOT_MNGR_CTRL_ONLY_MODE) {
      /* no option selected */
      goto DrawMenu;
    }

    gBootSelectedOptGuid = NULL;
    for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
      LOG((EFI_D_INFO, "%a.%d gVarsQId[%d]=0x%X\n", 
        __FUNCTION__, __LINE__, Idx, gVarsQId[Idx]));
      if (gVarsQId[Idx] == mKeyInput) {
        gBootSelectedOptGuid = &gVarsGuid[Idx];
        break;
      }
    }
    goto Done;
  }

  //
  // Will leave browser, check any reset required change is applied? if yes, reset system
  //
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  SetupResetReminder ();

  Status = LoadFromSelectedOption(HiiHandle, &ExitDataSize, &ExitData);
  RealodRuFont ();
  if (Status == EFI_NOT_FOUND) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    goto DrawMenu;
  }
  
Done:
  DestroyIcflList(&IcflList);
  DestroyBootCfgList(mCurrentBootConfigList);
  mCurrentBootConfigList = NULL;
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DestroyOptionList(&mBootOptionsList);
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DestroyOptionList(&mBootOptionsList2);
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  RecoverFsDescTableFromBakup();
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
}

EFI_STATUS
DoLegacyBoot (
  IN BDS_COMMON_OPTION *Option
  )
{
  EFI_STATUS                Status;
  EFI_LEGACY_BIOS_PROTOCOL  *LegacyBios;
  REMOTE_CFG_TLS_PROTOCOL   *RCTP = NULL;

  if (Option == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RemoveSmardCardCallBack ();

  Status = gBS->LocateProtocol (&gEfiLegacyBiosProtocolGuid, NULL, (VOID **) &LegacyBios);
  if (EFI_ERROR (Status)) {
    //
    // If no LegacyBios protocol we do not support legacy boot
    //
    return EFI_UNSUPPORTED;
  }
  BmSignalReadyToBoot ();
  //
  // Notes: if we separate the int 19, then we don't need to refresh BBS
  //
  BdsRefreshBbsTableForBoot (Option);

  Status = gBS->LocateProtocol(
                              &gRemoteCfgTlsProtocolGuid,
                              NULL,
                              (VOID **)&RCTP
                              );
  if (!EFI_ERROR(Status) && RCTP != NULL) {
    Status = RCTP->Stop (RCTP);
    LOG ((DEBUG_INFO | DEBUG_LOAD, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  }

  LOG ((DEBUG_INFO | DEBUG_LOAD, "Legacy Boot: %S\n", Option->Description));
  return LegacyBios->LegacyBoot (
                      LegacyBios,
                      (BBS_BBS_DEVICE_PATH *) Option->DevicePath,
                      Option->LoadOptionsSize,
                      Option->LoadOptions
                      );
}

EFI_STATUS
ConvertFvDevicePath (
  IN CHAR16 *FsPath,
  IN OUT EFI_DEVICE_PATH_PROTOCOL **DevPath
  )
{
  CHAR16 *TmpStr, SaveSymb, *FullName;
  CHAR8 TempText8[65];
  EFI_DEVICE_PATH_PROTOCOL *TmpDp;
  EFI_GUID FvFileGuid;
  EFI_STATUS Status;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH FileNode;

  if (FsPath == NULL || DevPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  LOG((EFI_D_INFO, "%a.%d FsPath=%s\n", __FUNCTION__, __LINE__, FsPath));
  TmpStr = StrStr(FsPath, L":");
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  SaveSymb = *TmpStr;
  *TmpStr = 0;
  FullName = FsDescTableGetFullName(FsPath);
  *TmpStr = SaveSymb;
  
  if (FullName == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  LOG((EFI_D_INFO, "%a.%d FullName=%s\n", __FUNCTION__, __LINE__, FullName));
  TmpStr = StrStr(FsPath, L"\\");
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  TmpStr++;
  LOG((EFI_D_INFO, "%a.%d TmpStr=%s\n", __FUNCTION__, __LINE__, TmpStr));

  TmpDp = StrToDevicePath(FullName);
  if (TmpDp == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  AsciiSPrint(TempText8, sizeof(TempText8), "%s", TmpStr);
  Status = StringToGuid_L(TempText8, &FvFileGuid);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  EfiInitializeFwVolDevicepathNode (&FileNode, &FvFileGuid);

  TmpDp = AppendDevicePathNode (TmpDp, (EFI_DEVICE_PATH_PROTOCOL *) &FileNode);
  if (TmpDp == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  
  Status = BdsLibUpdateFvFileDevicePath(&TmpDp, &FvFileGuid);
  LOG((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  *DevPath = TmpDp;
  return EFI_SUCCESS;
}


VOID
BmSignalReadyToBoot (
  VOID
  )
{
  STATIC BOOLEAN bAllreadySignalled;

  if (bAllreadySignalled) {
    return;
  }
  bAllreadySignalled = TRUE;
  EfiSignalEventReadyToBoot();
}


EFI_STATUS
EFIAPI
BootEfi(
  IN EFI_HANDLE ThisImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN CHAR16 *FsPath,
  OUT UINTN *ExitDataSize,
  OUT CHAR16 **ExitData,
  IN UINTN FsPathOffs
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                Handle;
  EFI_HANDLE                ImageHandle;
  EFI_DEVICE_PATH_PROTOCOL  *FilePath;
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL  *WorkingDevicePath;
  EFI_ACPI_S3_SAVE_PROTOCOL *AcpiS3Save;
  //STATIC CHAR16             TmpBuffer[256];
  CHAR16                    *TempStr;
  REMOTE_CFG_TLS_PROTOCOL   *RCTP = NULL;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  *ExitDataSize = 0;
  *ExitData     = NULL;

  if (DevicePath == NULL || FsPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    SetBootEfiArgs (NULL);
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_INFO, "%a.%d FsPath=%s\n", __FUNCTION__, __LINE__, FsPath));

  Status = gBS->LocateProtocol (&gEfiAcpiS3SaveProtocolGuid, NULL, (VOID **) &AcpiS3Save);
  if (!EFI_ERROR (Status)) {
    AcpiS3Save->S3Save (AcpiS3Save, NULL);
  }
  
  WorkingDevicePath = NULL;
  if ((DevicePathType (DevicePath) == MEDIA_DEVICE_PATH) &&
      (DevicePathSubType (DevicePath) == MEDIA_HARDDRIVE_DP)) {
    WorkingDevicePath = BdsExpandPartitionPartialDevicePathToFull (
                          (HARDDRIVE_DEVICE_PATH *)DevicePath
                          );
    if (WorkingDevicePath != NULL) {
      DevicePath = WorkingDevicePath;
    }
  }

  BmSignalReadyToBoot ();

  Status = EFI_ABORTED;

  if ((DevicePathType (DevicePath) == BBS_DEVICE_PATH) &&
      (DevicePathSubType (DevicePath) == BBS_BBS_DP)
    ) {
    BDS_COMMON_OPTION *Option;
    
    DestroyOptionList(&mBootOptionsList);
    TempStr = DevicePathToStr(DevicePath);
    LOG((EFI_D_INFO, "%a.%d DevicePath: %s\n", 
      __FUNCTION__, __LINE__, TempStr));
    //BdsLibEnumerateAllBootOption (&mBootOptionsList);
	BootMngrLibEnumerateAllBootOption (&mBootOptionsList);
    Option = FindOptionByDevPathStr(TempStr, &mBootOptionsList);
    if (Option) {
      LOG((EFI_D_INFO, "%a.%d Option->Description: %s\n", 
      __FUNCTION__, __LINE__, Option->Description));
    }
    SetBootEfiArgs (NULL);
    return DoLegacyBoot (Option);
  }

  if (DevicePathType (DevicePath) == HARDWARE_DEVICE_PATH && 
      DevicePathSubType (DevicePath) == HW_MEMMAP_DP) {
    EFI_DEVICE_PATH_PROTOCOL *TmpDp;

    Status = ConvertFvDevicePath(FsPath, &TmpDp);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    } else {
      DevicePath = TmpDp;
    }
  }

  // try to load directly
  Status = gBS->LoadImage (
                  TRUE,
                  ThisImageHandle,
                  DevicePath,
                  NULL,
                  0,
                  &ImageHandle
                  );
  LOG((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    TempStr = DevicePathToStr (DevicePath);
    LOG((EFI_D_INFO, "%a.%d DevicePath: %s\n", 
      __FUNCTION__, __LINE__, TempStr));
    Handle = BdsLibGetBootableHandle(DevicePath);
    if (Handle == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Handle = LibFsObtainDevHandler(DevicePath);
      if (Handle == NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        goto Done;
      }
    }

    LOG((EFI_D_INFO, "%a.%d &FsPath[FsPathOffs] = %s\n", 
      __FUNCTION__, __LINE__, &FsPath[FsPathOffs]));
    
    FilePath = FileDevicePath (Handle, &FsPath[FsPathOffs]);
    if (FilePath == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto Done;
    }

    TempStr = DevicePathToStr (FilePath);
    LOG((EFI_D_INFO, "%a.%d FilePath: %s\n", 
      __FUNCTION__, __LINE__, TempStr));
    
    Status = gBS->LoadImage (
                    TRUE,
                    ThisImageHandle,
                    FilePath,
                    NULL,
                    0,
                    &ImageHandle
                    );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto Done;
    }
  }

  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);
  ASSERT_EFI_ERROR (Status);

  TempStr = DevicePathToStr (ImageInfo->FilePath);
  LOG((EFI_D_INFO, "%a.%d Device path: %s\n", __FUNCTION__, __LINE__, TempStr));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->LoadOptionsSize=%d\n", __FUNCTION__, __LINE__, ImageInfo->LoadOptionsSize));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->ImageCodeType=%X\n", __FUNCTION__, __LINE__, ImageInfo->ImageCodeType));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->ImageDataType=%X\n", __FUNCTION__, __LINE__, ImageInfo->ImageDataType));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->SystemTable=%p\n", __FUNCTION__, __LINE__, ImageInfo->SystemTable));

  LOG((EFI_D_INFO, "%a.%d ImageInfo->DeviceHandle=%p\n", __FUNCTION__, __LINE__, ImageInfo->DeviceHandle));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->ImageBase=%p\n", __FUNCTION__, __LINE__, ImageInfo->ImageBase));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->ImageSize=%llX\n", __FUNCTION__, __LINE__, ImageInfo->ImageSize));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->ParentHandle=%p\n", __FUNCTION__, __LINE__, ImageInfo->ParentHandle));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->Reserved=%p\n", __FUNCTION__, __LINE__, ImageInfo->Reserved));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->Revision=%X\n", __FUNCTION__, __LINE__, ImageInfo->Revision));
  LOG((EFI_D_INFO, "%a.%d ImageInfo->Unload=%p\n", __FUNCTION__, __LINE__, ImageInfo->Unload));

  if (BootEfiArgs != NULL) {
    ImageInfo->LoadOptionsSize = (UINT32)StrSize (BootEfiArgs);
    ImageInfo->LoadOptions = BootEfiArgs;
  }

  //
  // Before calling the image, enable the Watchdog Timer for
  // the 5 Minute period
  //
  gBS->SetWatchdogTimer (5 * 60, 0x0000, 0x00, NULL);

  Status = gBS->LocateProtocol(
                              &gRemoteCfgTlsProtocolGuid,
                              NULL,
                              (VOID **)&RCTP
                              );
  if (!EFI_ERROR(Status) && RCTP != NULL) {
    Status = RCTP->Stop (RCTP);
    LOG ((DEBUG_INFO | DEBUG_LOAD, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  }

  BmCopyAcpi();

  Status = gBS->StartImage (ImageHandle, ExitDataSize, ExitData);
  LOG ((DEBUG_INFO | DEBUG_LOAD, "Image Return Status = %r\n", Status));

  //
  // Clear the Watchdog Timer after the image returns
  //
  gBS->SetWatchdogTimer (0x0000, 0x0000, 0x0000, NULL);

Done:
  SetBootEfiArgs (NULL); 
  LOG((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
LegacyBootFromHdd(
  VOID
  )
{
  BDS_COMMON_OPTION *Option;
  LIST_ENTRY *Link;
  CHAR16 *TempStr;
  
  InitializeListHead (&mBootOptionsList);
  //BdsLibEnumerateAllBootOption (&mBootOptionsList);
  BootMngrLibEnumerateAllBootOption (&mBootOptionsList);

  for (Link = GetFirstNode (&mBootOptionsList); 
       !IsNull (&mBootOptionsList, Link); 
       Link = GetNextNode (&mBootOptionsList, Link)) {
    Option = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    //
    // Don't display the boot option marked as LOAD_OPTION_HIDDEN
    //
    if ((Option->Attribute & LOAD_OPTION_HIDDEN) != 0) {
      continue;
    }

    ASSERT (Option->Description != NULL);  
    
    TempStr = DevicePathToStr (Option->DevicePath);
    LOG((EFI_D_INFO, "%a.%d TempStr=%s\n", 
      __FUNCTION__, __LINE__, TempStr));
    if (!IsLegacyBootDevPath(TempStr)) {
      continue;
    }
    
    if (StrStr(TempStr, L"HD(") || StrStr(TempStr, L"(HD,")) {
      return DoLegacyBoot(Option);
    }
  }


  DestroyOptionList(&mBootOptionsList);
  return EFI_ABORTED;
}

STATIC
EFI_HANDLE
EFIAPI
BdsLibGetBootableHandleExt (
  IN  EFI_DEVICE_PATH_PROTOCOL      *DevicePath,
  IN  CHAR16 *FilePath
  )
{
  EFI_STATUS                      Status;
  EFI_DEVICE_PATH_PROTOCOL        *UpdatedDevicePath;
  EFI_DEVICE_PATH_PROTOCOL        *DupDevicePath;
  EFI_HANDLE                      Handle;
  EFI_BLOCK_IO_PROTOCOL           *BlockIo;
  VOID                            *Buffer;
  EFI_DEVICE_PATH_PROTOCOL        *TempDevicePath;
  UINTN                           Size;
  UINTN                           TempSize;
  EFI_HANDLE                      ReturnHandle;
  EFI_HANDLE                      *SimpleFileSystemHandles;

  UINTN                           NumberSimpleFileSystemHandles;
  UINTN                           Index;
  EFI_IMAGE_DOS_HEADER            DosHeader;
  EFI_IMAGE_OPTIONAL_HEADER_UNION       HdrData;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr;

  UpdatedDevicePath = DevicePath;

  //
  // Check whether the device is connected
  //
  Status = gBS->LocateDevicePath (&gEfiBlockIoProtocolGuid, &UpdatedDevicePath, &Handle);
  if (EFI_ERROR (Status)) {
    //
    // Skip the case that the boot option point to a simple file protocol which does not consume block Io protocol,
    //
    Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &UpdatedDevicePath, &Handle);
    if (EFI_ERROR (Status)) {
      //
      // Fail to find the proper BlockIo and simple file protocol, maybe because device not present,  we need to connect it firstly
      //
      UpdatedDevicePath = DevicePath;
      Status            = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &UpdatedDevicePath, &Handle);
      gBS->ConnectController (Handle, NULL, NULL, TRUE);
    }
  } else {
    //
    // For removable device boot option, its contained device path only point to the removable device handle, 
    // should make sure all its children handles (its child partion or media handles) are created and connected. 
    //
    gBS->ConnectController (Handle, NULL, NULL, TRUE); 
    //
    // Get BlockIo protocol and check removable attribute
    //
    Status = gBS->HandleProtocol (Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    //
    // Issue a dummy read to the device to check for media change.
    // When the removable media is changed, any Block IO read/write will
    // cause the BlockIo protocol be reinstalled and EFI_MEDIA_CHANGED is
    // returned. After the Block IO protocol is reinstalled, subsequent
    // Block IO read/write will success.
    //
    Buffer = AllocatePool (BlockIo->Media->BlockSize);
    if (Buffer != NULL) {
      BlockIo->ReadBlocks (
               BlockIo,
               BlockIo->Media->MediaId,
               0,
               BlockIo->Media->BlockSize,
               Buffer
               );
      FreePool(Buffer);
    }
  }

  //
  // Detect the the default boot file from removable Media
  //

  //
  // If fail to get bootable handle specified by a USB boot option, the BDS should try to find other bootable device in the same USB bus
  // Try to locate the USB node device path first, if fail then use its previous PCI node to search
  //
  DupDevicePath = DuplicateDevicePath (DevicePath);
  ASSERT (DupDevicePath != NULL);

  UpdatedDevicePath = DupDevicePath;
  Status = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &UpdatedDevicePath, &Handle);
  //
  // if the resulting device path point to a usb node, and the usb node is a dummy node, should only let device path only point to the previous Pci node
  // Acpi()/Pci()/Usb() --> Acpi()/Pci()
  //
  if ((DevicePathType (UpdatedDevicePath) == MESSAGING_DEVICE_PATH) &&
      (DevicePathSubType (UpdatedDevicePath) == MSG_USB_DP)) {
    //
    // Remove the usb node, let the device path only point to PCI node
    //
    SetDevicePathEndNode (UpdatedDevicePath);
    UpdatedDevicePath = DupDevicePath;
  } else {
    UpdatedDevicePath = DevicePath;
  }

  //
  // Get the device path size of boot option
  //
  Size = GetDevicePathSize(UpdatedDevicePath) - sizeof (EFI_DEVICE_PATH_PROTOCOL); // minus the end node
  ReturnHandle = NULL;
  gBS->LocateHandleBuffer (
      ByProtocol,
      &gEfiSimpleFileSystemProtocolGuid,
      NULL,
      &NumberSimpleFileSystemHandles,
      &SimpleFileSystemHandles
      );
  for (Index = 0; Index < NumberSimpleFileSystemHandles; Index++) {
    //
    // Get the device path size of SimpleFileSystem handle
    //
    TempDevicePath = DevicePathFromHandle (SimpleFileSystemHandles[Index]);
    TempSize = GetDevicePathSize (TempDevicePath)- sizeof (EFI_DEVICE_PATH_PROTOCOL); // minus the end node
    //
    // Check whether the device path of boot option is part of the  SimpleFileSystem handle's device path
    //
    if (Size <= TempSize && CompareMem (TempDevicePath, UpdatedDevicePath, Size)==0) {
      //
      // Load the default boot file \EFI\BOOT\boot{machinename}.EFI from removable Media
      //  machinename is ia32, ia64, x64, ...
      //
      Hdr.Union = &HdrData;
      Status = BdsLibGetImageHeader (
                 SimpleFileSystemHandles[Index],
                 FilePath ? FilePath : EFI_REMOVABLE_MEDIA_FILE_NAME,
                 &DosHeader,
                 Hdr
                 );
      if (!EFI_ERROR (Status) &&
        EFI_IMAGE_MACHINE_TYPE_SUPPORTED (Hdr.Pe32->FileHeader.Machine) &&
        Hdr.Pe32->OptionalHeader.Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        ReturnHandle = SimpleFileSystemHandles[Index];
        break;
      }
    }
  }

  FreePool(DupDevicePath);

  if (SimpleFileSystemHandles != NULL) {
    FreePool(SimpleFileSystemHandles);
  }

  return ReturnHandle;
}

CHAR16 *
GetFullDevicePathFromShortStringPath(
  IN CHAR16 *ShortStringPath,
  IN CHAR16 *EfiFileName
  )
{
  EFI_HANDLE Handle;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath, *WorkingDevicePath;
  CHAR16 *FilePath;
  UINTN Len;

  LOG((EFI_D_INFO, "%a.%d ShortStringPath=%s EfiFileName=%s\n", 
    __FUNCTION__, __LINE__, ShortStringPath, EfiFileName));

  if (ShortStringPath == NULL) {
    return NULL;
  }

  DevicePath = StrToDevicePath(ShortStringPath);
  if (DevicePath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_INFO, "DevicePathType (DevicePath)=%X\n", 
    DevicePathType (DevicePath)));
  LOG((EFI_D_INFO, "DevicePathSubType (DevicePath)=%X\n", 
    DevicePathSubType (DevicePath)));
  
  if ((DevicePathType (DevicePath) == MEDIA_DEVICE_PATH) &&
      (DevicePathSubType (DevicePath) == MEDIA_HARDDRIVE_DP)) {
    WorkingDevicePath = BdsExpandPartitionPartialDevicePathToFull (
                          (HARDDRIVE_DEVICE_PATH *)DevicePath
                          );
    if (WorkingDevicePath != NULL) {
      DevicePath = WorkingDevicePath;
    }
  }
  
  Handle = BdsLibGetBootableHandleExt (DevicePath, EfiFileName);
  if (Handle == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  FilePath = DevicePathToStr (FileDevicePath (Handle, L"\\"));
  LOG((EFI_D_INFO, "%a.%d FilePath=\"%s\"\n", 
    __FUNCTION__, __LINE__, FilePath));

  if (FilePath) {
    Len = StrLen(FilePath);
  } else {
    Len = 0;
  }
  if (Len == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  } else {
    /* skip unusefull "\" */
    FilePath[Len - 1] = 0;
  }
  
  return FilePath;
}

EFI_STATUS
BootMngrSetVarsGuidAndDesc(
  IN UINTN VarIdx,
  IN EFI_GUID *pGuid,
  IN CHAR16 *Desc
  )
{
  if (pGuid == NULL || Desc == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (VarIdx >= MAX_VARS_GUIDS) {
    return EFI_ABORTED;
  }
  CopyGuid(&gVarsGuid[VarIdx], pGuid);
  if (gVarsDescStr[VarIdx]) {
    FreePoolDbg(gVarsDescStr[VarIdx]);
    gVarsDescStr[VarIdx] = NULL;
  }
  gVarsDescStr[VarIdx] = AllocateCopyPool(StrSize(Desc), Desc);
  if (gVarsDescStr[VarIdx] == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
BootMngrSetVarsGuidIdx(
  IN UINTN Idx
  )
{
  if (Idx >= MAX_VARS_GUIDS) {
    return EFI_ABORTED;
  }
  gVarsGuidIdx = Idx;
  return EFI_SUCCESS;
}

EFI_STATUS
BootMngrSetVarsGuidIdxByGuid(
  IN EFI_GUID *pGuid
  )
{
  UINTN Idx;

  if (pGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
    if (CompareGuid(pGuid, &gVarsGuid[Idx])) {
      gVarsGuidIdx = Idx;
      return EFI_SUCCESS;
    }
  }  
  return EFI_NOT_FOUND;
}


EFI_GUID *
BootMngrGetSelectedOptGuid(
  VOID
  )
{
  return gBootSelectedOptGuid;
}


CHAR16*
BootMngrGetVarsDesc(
  IN UINTN VarIdx
  )
{
  if (VarIdx >= MAX_VARS_GUIDS) {
    return NULL;
  }
  return gVarsDescStr[VarIdx];
}


BOOLEAN
IsLegacyBootDevPath(
  IN CHAR16 *DevPathStr
  )
{
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  
  DevicePath = StrToDevicePath(DevPathStr);
  if (DevicePath && 
      (DevicePathType (DevicePath) == BBS_DEVICE_PATH) &&
      (DevicePathSubType (DevicePath) == BBS_BBS_DP)) {
    return TRUE;
  }
  return FALSE;
}

VOID
SetBootEfiArgs (
  IN CHAR16 *Args
  )
{
  if (Args) {
    if (StrLen (Args) == 0) {
      BootEfiArgs = NULL;
      return;
    }
  }
  BootEfiArgs = Args;
}


VOID
BootManagerDestroyAllSettings (
  VOID
  )
{
  UINTN Idx;

  SetStorageAttributes(STORAGE_RDWR_ATTR);
  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
    StorageInitEmpty(CBCFG_VARIABLE_NAME, &gVarsGuid[Idx],
      NULL, 0, NULL, TRUE);
    StorageInitEmpty(ICFL_VARIABLE_NAME, &gVarsGuid[Idx],
      NULL, 0, NULL, TRUE);
  }
}

EFI_STATUS
BmCopyAcpi(
  VOID
  )
{
  volatile UINT32 CopySize;
  volatile VOID *AcpiTable, *AcpiPtr;
  volatile UINT8 Val8;
  EFI_STATUS Status;
  EFI_LEGACY_BIOS_PROTOCOL *LegacyBios;
  EFI_LEGACY_REGION_PROTOCOL *LegacyRegion;
    
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = gBS->LocateProtocol (&gEfiLegacyBiosProtocolGuid, NULL, (VOID **) &LegacyBios);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  CopySize = 0;
  AcpiTable = NULL;
  Status = EfiGetSystemConfigurationTable (
             &gEfiAcpi20TableGuid,
             (VOID**)&AcpiTable
             );
  LOG((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR (Status)) {
    Status = EfiGetSystemConfigurationTable (
               &gEfiAcpi10TableGuid,
               (VOID**)&AcpiTable
               );
    LOG((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  }
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  //
  // We do not ASSERT if AcpiTable not found. It is possbile that a platform does not produce AcpiTable.
  //
  if (AcpiTable == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  //
  // Get RSD Ptr table rev at offset 15 decimal
  // Rev = 0 Length is 20 decimal
  // Rev != 0 Length is UINT32 at offset 20 decimal
  //
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  AcpiPtr = AcpiTable;
  Val8 = *((UINT8 *) AcpiPtr + 15);
  if (Val8 == 0) {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    CopySize = 20;
  } else {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    AcpiPtr   = ((UINT8 *) AcpiPtr + 20);
    CopySize  = ReadUnaligned32((VOID*)AcpiPtr);
  }
  LOG((EFI_D_INFO, "%a.%d CopySize=%d\n", __FUNCTION__, __LINE__, CopySize));

  // Unlock F-segment
  Status = gBS->LocateProtocol(
      &gEfiLegacyRegionProtocolGuid,
      0,
      &LegacyRegion);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = LegacyRegion->UnLock(
      LegacyRegion,
      0x000F0000,
      0x00010000,
      NULL
      );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
  }
  return Status;
}


BOOLEAN
BootManagerIsNeedReinit (
  VOID
  )
{
  UINT64 Flags;
  UINTN BufferSize;
  EFI_STATUS Status;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  BufferSize = sizeof (Flags);
  Status = gRT->GetVariable (
              BOOT_MNGR_OPTIONS_VAR_NAME, 
              &gVendorGuid, 
              NULL, 
              &BufferSize, 
              &Flags);
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR (Status)) {
    return FALSE;
  }
  
  if (Flags & BOOT_MNGR_BOPT_NEED_REINIT) {
    return TRUE;
  }
  return FALSE;
}


EFI_STATUS
BootManagerNeedReinit (
  IN BOOLEAN bReinit
  )
{
  UINT64 Flags;
  UINTN BufferSize;
  EFI_STATUS Status;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  BufferSize = sizeof (Flags);
  Status = gRT->GetVariable (
              BOOT_MNGR_OPTIONS_VAR_NAME, 
              &gVendorGuid, 
              NULL, 
              &BufferSize, 
              &Flags);
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  
  if (bReinit) {
    Flags |= BOOT_MNGR_BOPT_NEED_REINIT;
  } else {
    Flags &= ~BOOT_MNGR_BOPT_NEED_REINIT;
  }
  
  Status = gRT->SetVariable (
          BOOT_MNGR_OPTIONS_VAR_NAME,
          &gVendorGuid,
          EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE,
          sizeof (Flags),
          &Flags
          );
  LOG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
