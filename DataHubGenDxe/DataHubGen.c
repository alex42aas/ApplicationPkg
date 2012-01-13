/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include "DataHubGen.h"
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/IniParserDxe.h>
#include <Library/BiosInfo.h>
#include <Library/ExtHdrUtils.h>
#include <CommonDefs.h>

EFI_HII_DATABASE_PROTOCOL        *gHiiDatabase;

extern UINT8                DataHubGenDxeStrings[];
// {4B4124FD-0002-4c51-8E49-3378B083EC04}
EFI_GUID mTestSystemUuid = { 0x4b4124fd, 0x2, 0x4c51, { 0x8e, 0x49, 0x33, 0x78, 0xb0, 0x83, 0xec, 0x4 } };

EFI_DATA_HUB_PROTOCOL       *gDataHub;
EFI_HII_HANDLE              gStringHandle;

EFI_SUBCLASS_TYPE1_HEADER mMiscSubclassDriverDataHeader = {
  EFI_MISC_SUBCLASS_VERSION,            // Version
  sizeof (EFI_SUBCLASS_TYPE1_HEADER),   // Header Size
  0,                                    // Instance, Initialize later
  EFI_SUBCLASS_INSTANCE_NON_APPLICABLE, // SubInstance
  0                                     // RecordType, Initialize later
};

extern GUID gSystemFileGuid;
extern GUID gBiosInfoFileGuid;

EFI_STATUS
GetSectionData (
  IN EFI_GUID *SecGuid,
  IN OUT UINT8 **SecData,
  IN OUT UINTN *SecDataLen
  )
{
  EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv;
  UINTN NumberHandles, Index, SectionSize;
  EFI_HANDLE *pFsp = NULL;
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 AuthenticationStatus;
  UINT8 *Section;
  
  NumberHandles = 0;
  Status = gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiFirmwareVolume2ProtocolGuid,
        NULL,
        &NumberHandles,
        &pFsp
        );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DEBUG((EFI_D_INFO, "%a.%d NumberHandles=%d\n", 
    __FUNCTION__, __LINE__, NumberHandles));
  for (Index = 0; Index < NumberHandles; Index++) {
    Status = gBS->HandleProtocol (
                pFsp[Index],
                &gEfiFirmwareVolume2ProtocolGuid,
                (VOID *) &Fv
                );
    DEBUG((EFI_D_INFO, "%a.%d Fv=%p\n",
      __FUNCTION__, __LINE__, Fv));

    SectionSize = 0;
    Section = NULL;
    Status = Fv->ReadSection (
                            Fv,
                            SecGuid,
                            EFI_SECTION_RAW,
                            0,
                            &Section,
                            &SectionSize,
                            &AuthenticationStatus
                            );
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_INFO, "%a.%d SectionSize=0x%X Section=%p\n", 
        __FUNCTION__, __LINE__, SectionSize, Section));      
      *SecDataLen = SectionSize;
      *SecData = Section;
      break;
    }
  } 
  if (pFsp != NULL) {
    FreePool(pFsp);
  }
  return Status;
}

EFI_STATUS
FindSysGuidInVolume (
  IN OUT EFI_GUID *SysGuid
  )
{
  UINTN SectionSize;
  EFI_STATUS Status = EFI_SUCCESS;
  UINT8 *Section;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (SysGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = GetSectionData(
              &gSystemFileGuid,
              &Section,
              &SectionSize);

  if (!EFI_ERROR(Status)) {
    if (SectionSize != sizeof(EFI_GUID)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Status = EFI_INVALID_PARAMETER;
    } else {
      CopyMem(SysGuid, Section, sizeof(EFI_GUID));
      DEBUG((EFI_D_INFO, "%a.%d SysGuid=%g\n", 
        __FUNCTION__, __LINE__, SysGuid));  
    }
  }
  return Status;
}

STATIC
CHAR8 *
GetReleaseDate (
  IN BiosInfoRecord *FwInfo
  )
{
  STATIC CHAR8 ReleaseData[BIOS_INFO_BUILD_STR_SIZE];
  CHAR8 *TmpPtr8;
  if (FwInfo == NULL) {
    return NULL;
  }

  TmpPtr8 = AsciiStrStr(FwInfo->BiosBuildStr, " ");
  if (TmpPtr8 == NULL) {
    return NULL;
  }

  AsciiStrCpy(ReleaseData, TmpPtr8 + 1);
  TmpPtr8 = AsciiStrStr(ReleaseData, ".");
  if (TmpPtr8 == NULL) {
    return NULL;
  }
  *TmpPtr8 = '/';
  TmpPtr8 = AsciiStrStr(ReleaseData, ".");
  if (TmpPtr8 == NULL) {
    return NULL;
  }
  *TmpPtr8 = '/';
  return ReleaseData;
}


EFI_STATUS
GetFwInfo (
  OUT BiosInfoRecord **FwInfo
  )
{
  struct tMainFvInfo MainFvInfo;
  BiosInfoRecord *pBiosInfo;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (-1 == FindMainFv(MAIN_FV_GUID_STR, &MainFvInfo)) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  pBiosInfo = (BiosInfoRecord*)FindBiosInfoRecord(&MainFvInfo);
  if (NULL == pBiosInfo) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));        
    return EFI_NOT_FOUND;
  }  

  *FwInfo = AllocateCopyPool(sizeof (*pBiosInfo), pBiosInfo);
  if (*FwInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}


VOID
InstallBiosMiscRecord(
    VOID
    )
{
  EFI_STATUS                        Status;
  EFI_MISC_SUBCLASS_DRIVER_DATA     DataRecord;
  STRING_REF                        Token;
  CHAR8                             *IniDateAString;
  CHAR8                             *AString;
  CHAR16                            *UString;
  dictionary *Dict = NULL;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;
  UINT8 *BiosInfoData = NULL;
  UINTN BiosInfoDataLen;
  BiosInfoRecord *FwInfo = NULL;

  DEBUG ((EFI_D_INFO, "%a.%d gBiosInfoFileGuid=%g\n", 
    __FUNCTION__, __LINE__, &gBiosInfoFileGuid));

  Status = GetSectionData (&gBiosInfoFileGuid, &BiosInfoData, &BiosInfoDataLen);
  DEBUG ((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));

  if (!EFI_ERROR(Status)) {
    DEBUG ((EFI_D_INFO, "%a.%d BiosInfoDataLen=%d\n", 
      __FUNCTION__, __LINE__, BiosInfoDataLen));
    Status = gBS->LocateProtocol (
               &gIniParserDxeProtocolGuid,
               NULL,
               (VOID **) &iniParserProtocol
               );    
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      iniParserProtocol = NULL;
    }
  } else {
    Status = GetFwInfo(&FwInfo);
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  }
  
  if (iniParserProtocol) {
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Dict = iniParserProtocol->NewIniDictionaryWithData(BiosInfoData, 
      BiosInfoDataLen);
    DEBUG ((EFI_D_INFO, "%a.%d Dict=%p\n", __FUNCTION__, __LINE__, Dict));
  }

  //
  // Record Header
  //
  CopyMem (&DataRecord, &mMiscSubclassDriverDataHeader, sizeof (DataRecord.Header));

  //
  // Record Type 0
  //
  ZeroMem(&DataRecord.Record, sizeof(DataRecord.Record));
  DataRecord.Header.RecordType = EFI_MISC_BIOS_VENDOR_RECORD_NUMBER;
  DataRecord.Header.Instance = 1;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "firmware", "FwBiosVendor");
    if (AString == NULL) {      
      AString = FIRMWARE_BIOS_VENDOR;
    }
  } else {
    AString = FIRMWARE_BIOS_VENDOR;
  }
  
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return;
  }

  DataRecord.Record.MiscBiosVendor.BiosVendor  = Token;

  if (FwInfo != NULL) {
    AString = FwInfo->BiosVerStr[0] == '0' ? 
      &FwInfo->BiosVerStr[1] : FwInfo->BiosVerStr;
  } else {
    AString = FIRMWARE_BIOS_VERSION;
  }
  if (iniParserProtocol) {
    IniDateAString = iniParserProtocol->GetString (Dict, "firmware", "FwBiosVersion");
    if (IniDateAString != NULL) {
      AString = IniDateAString;
    }
  } else {
    
  }

  DEBUG ((EFI_D_INFO, "%a.%d AString=%a\n", __FUNCTION__, __LINE__, AString));

  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return;
  }

  DataRecord.Record.MiscBiosVendor.BiosVersion = Token;

  AString = FIRMWARE_BIOS_RELEASE_DATE;
  if (FwInfo != NULL) {
    IniDateAString = GetReleaseDate(FwInfo);
    if (IniDateAString != NULL) {
      AString = IniDateAString;
    }
  }
  
  
  DEBUG((EFI_D_INFO, "### Firmware date:%a\n", AString));

  if (iniParserProtocol) {
    IniDateAString = iniParserProtocol->GetString (Dict, "firmware", "FwBiosReleaseDate");
    if (IniDateAString != NULL) {
      AString = IniDateAString;
    }
  }

  DEBUG((EFI_D_INFO, "### Firmware date:%a\n", AString));

  
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);
  
  if (Token == 0) {
    return;
  }

  Status = gDataHub->LogData (
                       gDataHub,
                       &gEfiMiscSubClassGuid,
                       &gEfiCallerIdGuid,
                       EFI_DATA_RECORD_CLASS_DATA,
                       &DataRecord,
                       sizeof (DataRecord.Header) + sizeof (DataRecord.Record.MiscBiosVendor)
                       );

  ASSERT_EFI_ERROR (Status);

  //
  // Record Type 3
  //
  ZeroMem(&DataRecord.Record, sizeof(DataRecord.Record));


  DataRecord.Header.RecordType = EFI_MISC_SYSTEM_MANUFACTURER_RECORD_NUMBER;
  DataRecord.Header.Instance = 1;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysManufacturerName");
    if (AString == NULL) {
      AString = SYSTEM_MANUFACTER_NAME;
    }
  } else {
    AString = SYSTEM_MANUFACTER_NAME;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemManufacturer  = Token;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysProductName");
    if (AString == NULL) {
      AString = SYSTEM_PRODUCT_NAME;
    }
  } else {
    AString = SYSTEM_PRODUCT_NAME;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemProductName = Token;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysVersion");
    if (AString == NULL) {
      AString = SYSTEM_VERSION;
    }
  } else {
    AString = SYSTEM_VERSION;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemVersion  = Token;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysSerial");
    if (AString == NULL) {
      AString = SYSTEM_SERIAL;
    }
  } else {
    AString = SYSTEM_SERIAL;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemSerialNumber  = Token;
  Status = FindSysGuidInVolume (
    &DataRecord.Record.MiscSystemManufacturer.SystemUuid);
  ASSERT(!EFI_ERROR(Status));
  DataRecord.Record.MiscSystemManufacturer.SystemWakeupType  = EfiSystemWakeupTypeReserved;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysSkuNumber");
    if (AString == NULL) {
      AString = SYSTEM_SKU_NUMBER;
    }
  } else {
    AString = SYSTEM_SKU_NUMBER;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemSKUNumber  = Token;

  if (iniParserProtocol) {
    AString = iniParserProtocol->GetString (Dict, "system", "SysFamily");
    if (AString == NULL) {
      AString = SYSTEM_FAMILY;
    }
  } else {
    AString = SYSTEM_FAMILY;
  }
  UString = AllocateZeroPool ((AsciiStrLen(AString) + 1) * sizeof(CHAR16));
  ASSERT (UString != NULL);
  AsciiStrToUnicodeStr ( AString, UString );

  Token = HiiSetString (gStringHandle, 0, UString, NULL);
  gBS->FreePool (UString);

  if (Token == 0) {
    return ;
  }

  DataRecord.Record.MiscSystemManufacturer.SystemFamily  = Token;

  Status = gDataHub->LogData (
                       gDataHub,
                       &gEfiMiscSubClassGuid,
                       &gEfiCallerIdGuid,
                       EFI_DATA_RECORD_CLASS_DATA,
                       &DataRecord,
                       sizeof (DataRecord.Header) + sizeof (DataRecord.Record.MiscSystemManufacturer)
                       );
  ASSERT_EFI_ERROR (Status);
  
}

EFI_STATUS
EFIAPI
DataHubGenEntrypoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  EFI_STATUS              Status;

  Status = gBS->LocateProtocol (
                  &gEfiDataHubProtocolGuid,
                  NULL,
                  (VOID**)&gDataHub
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gEfiHiiDatabaseProtocolGuid,
                  NULL,
                  (VOID**)&gHiiDatabase
                  );

  if (EFI_ERROR (Status)) {
    return Status;
  }
  
  gStringHandle = HiiAddPackages (
                    &gEfiCallerIdGuid,
                    NULL,
                    DataHubGenDxeStrings,
                    NULL
                    );
  ASSERT (gStringHandle != NULL);

  InstallBiosMiscRecord();

  return EFI_SUCCESS;
}

