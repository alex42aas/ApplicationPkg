/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __BOOTMNGR__LIB__H
#define __BOOTMNGR__LIB__H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <MultibootDesc.h>


extern GUID	gKuefiGuid;

// integrity checking file list
#define ICFL_VARIABLE_NAME                  L"ICFL"
#define ICFL_VARIABLE_NAME_WITH_NUM         L"ICFL_00000000"
#define ICFL_VARIABLE_MAX_NAME_LEN          (sizeof(ICFL_VARIABLE_NAME_WITH_NUM))

#define ICFL_VARIABLE_MAX_CARD_SIZE         (PcdGet32(PcdMaxVariableSize) - \
                                             sizeof (VARIABLE_HEADER) - \
                                             ICFL_VARIABLE_MAX_NAME_LEN)

#define ICFL_VARIABLE_MAX_STORAGE_SIZE      (1024 * 200)

// current boot config
#define CBCFG_VARIABLE_NAME                 L"CurBootCfg"
#define CBCFG_VARIABLE_NAME_WITH_NUM        L"CurBootCfg_00000000"
#define CBCFG_VARIABLE_MAX_NAME_LEN         (sizeof(CBCFG_VARIABLE_NAME_WITH_NUM))

#define CBCFG_VARIABLE_MAX_CARD_SIZE        (PcdGet32(PcdMaxVariableSize) - \
                                             sizeof (VARIABLE_HEADER) - \
                                             CBCFG_VARIABLE_MAX_NAME_LEN)

#define ICFL_SEPARATOR                      L"|"

#define CBCFG_VARIABLE_MAX_STORAGE_SIZE     (1040 * 10)

#define BOOT_TYPE_FROM_FS                   0x01
#define BOOT_TYPE_DEFAULT                   0x02
#define BOOT_TYPE_EFI                       0x03
#define BOOT_TYPE_LEGACY                    0x04


#define MODULE_TYPE_LINUX                   0x00
#define MODULE_TYPE_MULTIBOOT               0x01
#define MODULE_TYPE_EFI                     0x02
#define MODULE_TYPE_DEFAULT                 0x03

#define MAX_VARS_GUIDS                      3 

#define BOOT_MNGR_BASIC_MODE                0
#define BOOT_MNGR_CTRL_ONLY_MODE            1
#define BOOT_MNGR_HIDE_CTRL_MODE            2




typedef struct {
  UINT32 DataLen;
  UINT8  Data[1];
} COMMON_VAR_DATA;

typedef struct {
  LIST_ENTRY Entry;
  CHAR8 Hash[MAX_HASH_LEN];
  CHAR16 FileName[1];
} ICFL_LIST;

typedef struct {
  CHAR16 DeviceFullName[MULTIBOOT_MAX_STRING];
  CHAR16 DevPath[MULTIBOOT_MAX_STRING];
  CHAR16 Description[MULTIBOOT_MAX_STRING];
  CHAR16 Args[MULTIBOOT_MAX_STRING];
  CHAR8 Hash[MAX_HASH_LEN];
} CBCFG_RECORD;

typedef struct {  
  UINT32 BootType;
  UINT32 ModulesType;
  UINT32 BootOptionsNum;
  UINT8 Data[1];
} CBCFG_DATA_SET;

typedef struct {
  LIST_ENTRY Entry;
  CBCFG_DATA_SET *DataSet;
} CBCFG_LIST;



EFI_STATUS
InitializeBootManager (
  VOID
  );

VOID
CallBootManager (
  IN CHAR16 *UsbPathStr
  );

EFI_STATUS
CbcfgStorageGetData(
  IN OUT CBCFG_DATA_SET **CbcfgDataSet,
  OUT UINTN *DataSetSize
  );

EFI_STATUS
CbcfgStorageGetDataByGuid(
  IN OUT CBCFG_DATA_SET **CbcfgDataSet,
  OUT UINTN *DataSetSize,
  IN GUID *Guid
  );

EFI_STATUS
IcflStorageGetData(
  IN OUT LIST_ENTRY *IcflList
  );

EFI_STATUS
EFIAPI
BootEfi(
  IN EFI_HANDLE ThisImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN CHAR16 *FsPath,
  OUT UINTN *ExitDataSize,
  OUT CHAR16 **ExitData,
  IN UINTN FsPathOffs
  );


EFI_STATUS
IcflCheckIntegrity(
  VOID
  );

BOOLEAN
IcflItemPresent(
  IN CHAR16 *String,
  IN LIST_ENTRY *IcflList
  );

EFI_STATUS
GetIcfl(
  IN OUT LIST_ENTRY *IcflList
  );

CHAR16 *
GetFullDevicePathFromShortStringPath(
  IN CHAR16 *ShortStringPath,
  IN CHAR16 *EfiFileName
  );

EFI_STATUS
GetBootTypeFromString(
  IN CHAR16 *Str,
  IN OUT UINT32 *BootType
  );

CHAR16*
GetBootTypeStr(
  IN UINT32 BootType
  );

EFI_STATUS
GetModuleTypeFromString(
  IN CHAR16 *Str,
  IN OUT UINT32 *ModuleType
  );

EFI_STATUS
CbcfgSave(
  IN CBCFG_DATA_SET *CbcfgList
  );

EFI_STATUS
StoreIcfl(
  IN LIST_ENTRY *IcflList
  );

VOID
DestroyIcflList(
  IN LIST_ENTRY *IcflList
  );

VOID
DestroyBootCfgList(
  IN CBCFG_LIST *CbcfgList
  );

EFI_STATUS
BootMngrSetVarsGuidAndDesc(
  IN UINTN VarIdx,
  IN EFI_GUID *pGuid,
  IN CHAR16 *Desc
  );


EFI_STATUS
BootMngrSetVarsGuidIdx(
  IN UINTN Idx
  );

EFI_STATUS
BootMngrSetVarsGuidIdxByGuid(
  IN EFI_GUID *pGuid
  );

EFI_GUID *
BootMngrGetSelectedOptGuid(
  VOID
  );

CHAR16*
BootMngrGetVarsDesc(
  IN UINTN VarIdx
  );

BOOLEAN
IsLegacyBootDevPath(
  IN CHAR16 *DevPathStr
  );

EFI_STATUS
CalcHashForMbr(
  IN CHAR16 *DevPath,
  IN UINT8 CsType,
  IN OUT UINT8 *Hash
  );

VOID
SetBootManagerMenuMode(
  IN UINT8 Mode
  );

EFI_STATUS
LegacyBootFromHdd(
  VOID
  );

VOID
SetBootEfiArgs (
  IN CHAR16 *Args
  );

VOID
ImportBootCfgFromFv (
  VOID
  );

EFI_STATUS
ImportBootOptionsFromDataBuf (
  IN UINT8 *Data,
  IN UINTN Size
  );

VOID
BootManagerDestroyAllSettings (
  VOID
  );

VOID
BmSignalReadyToBoot (
  VOID
  );

EFI_STATUS
BmCopyAcpi(
  VOID
  );

VOID
BmForceSetVideoMode80x25_3 (
  VOID
  );

BOOLEAN
BootManagerIsNeedReinit (
  VOID
  );

EFI_STATUS
BootManagerNeedReinit (
  IN BOOLEAN bReinit
  );
  
#endif  /* #ifndef __BOOTMNGR__LIB__H */

