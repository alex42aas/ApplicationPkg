/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PCI__DEV__LIST__H
#define __PCI__DEV__LIST__H


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/VfrCommon.h>
#include <Library/MultibootDescUtils.h>
#include "vfrdata.h"

#include <Library/CommonUtils.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/Runtime.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Acpi.h>
#include <Library/Lib/PlatformCommon.h>
#include <Library/PciDevsDescLib.h>


#define CALC_EFI_PCI_ADDRESS(Bus, Dev, Func, Reg) \
    ((UINT64) ((((UINTN) Bus) << 24) + (((UINTN) Dev) << 16) + (((UINTN) Func) << 8) + ((UINTN) Reg)))

#define CALC_EFI_PCIEX_ADDRESS(Bus, Dev, Func, ExReg) ( \
      (UINT64) ((((UINTN) Bus) << 24) + (((UINTN) Dev) << 16) + (((UINTN) Func) << 8) + (LShiftU64 ((UINT64) ExReg, 32))) \
   );

#define PCI_DEV_EN_FLAG             (1 << 0)


#pragma pack(1)

typedef struct {
  EFI_LIST_ENTRY DevList;
  UINT32 Seg;
  UINT16 Bus;
  UINT16 Device;
  UINT16 Func;
  UINT16 Flags;  
} PCI_DEV_LIST;

typedef struct {
  EFI_LIST_ENTRY ListEntry;  
  UINT16 VendorId;
  UINT16 DeviceId;
  UINT8 RevisionId;
  UINT8 ClassCode[3];
} PCI_DEV_COMMON_LIST;


#pragma pack()


EFI_LIST_ENTRY *
GetPciDevList(
  VOID
  );

EFI_STATUS
PciDevListInit(
  VOID
  );


VOID
PciDevListTest(
  VOID
  );

EFI_STATUS
PciDevListCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

EFI_STATUS
PciDevListPageStart(
  IN EFI_HII_HANDLE HiiHandle
  );

BOOLEAN
PciDevPresent(
  IN UINT16 DeviceId,
  IN UINT16 VendorId
  ); 


#endif  /* #ifndef __PCI__DEV__LIST__H */

