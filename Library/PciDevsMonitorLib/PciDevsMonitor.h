/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PCI__DEVS__MONITOR__H
#define __PCI__DEVS__MONITOR__H


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>

#include <Library/CommonUtils.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/Runtime.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Acpi.h>

#include <Library/PciDevsDescLib.h>

#define MACHINE_ID_SAVED_VAR_NAME             L"MachineIdSaved"		// уникальный идентификатор аппаратной платформы, сохраненное значение

extern GUID gMachineIdSavedVarGuid;



#define CALC_EFI_PCI_ADDRESS(Bus, Dev, Func, Reg) \
    ((UINT64) ((((UINTN) Bus) << 24) + (((UINTN) Dev) << 16) + (((UINTN) Func) << 8) + ((UINTN) Reg)))

#define CALC_EFI_PCIEX_ADDRESS(Bus, Dev, Func, ExReg) ( \
      (UINT64) ((((UINTN) Bus) << 24) + (((UINTN) Dev) << 16) + (((UINTN) Func) << 8) + (LShiftU64 ((UINT64) ExReg, 32))) \
   );

#define PCI_DEV_MONITORED_FLAG              (1 << 0)
#define PCI_DEV_MON_ERR_FLAG                (1 << 1)

#define PCI_DEVS_MONITOR_ITEMS_CLEAN_ALL_ID (0x7001)
#define PCI_DEVS_MONITOR_ITEMS_SAVE_ALL_ID  (0x7002)
#define PCI_DEVS_MONITOR_MODE_ID            (0x7003)
#define PCI_DEVS_CTRL_ID                    (0x7004)
#define PCI_DEVS_MONITOR_CONTROL_ON_ID      (0x7005)
#define PCI_DEVS_MONITOR_CONTROL_OFF_ID     (0x7006)
#define PCI_DEVS_MONITOR_SAVE_USB_ID        (0x7007)



#define PCI_DEVS_MONITOR_ITEMS_START_ID     (0x7100)

// идент для xml-entry:
#define SAVE_HARDWARE_PLATFORM_ID	     0x9201

// уже есть в include/Library/PciDevsMonitorLib.h
/*
typedef struct {
  UINT32 Seg;
  UINT16 Bus;
  UINT16 Device;
  UINT16 Func;
  UINT16 Flags;
  UINT16 VendorId;
  UINT16 DeviceId;
  UINT8 RevisionId;
  UINT8 ClassCode[3];
} PCI_DEVS_MONITOR_DATA;

typedef struct {
  EFI_LIST_ENTRY ListEntry;
  PCI_DEVS_MONITOR_DATA Data;
} PCI_DEVS_MONITOR_LIST;
*/

typedef struct {
  //
  // HII relative handles
  //
  EFI_HII_HANDLE                  HiiHandle;
  EFI_HANDLE                      DriverHandle;

  //
  // Produced protocols
  //
  EFI_HII_CONFIG_ACCESS_PROTOCOL   ConfigAccess;
} PCI_DEVS_MONITOR_CALLBACK_DATA;



#endif  /* #ifndef __PCI__DEVS__MONITOR__H */

