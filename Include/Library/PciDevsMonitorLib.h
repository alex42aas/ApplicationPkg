/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PCI__DEVS__MONITOR__LIB__H
#define __PCI__DEVS__MONITOR__LIB__H


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/HiiLib.h>
#include <Guid/MdeModuleHii.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/Runtime.h>


enum {
  MODE_CHECK_PRESENCE_FROM_LIST = 0,
  MODE_CHECK_ABSENCE_IN_LIST = 1,
  MODE_CHECKIN_CTRL_ON = 2,
  MODE_CHECKIN_CTRL_OFF = 3
  };


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


EFI_STATUS
SetPciDevList (
  IN OUT EFI_LIST_ENTRY *ListHead
  );
  
VOID
FreePciDevList (
  IN EFI_LIST_ENTRY *ListHead
  );

EFI_STATUS
InitializePciDevsMonitor (
  VOID
  );

VOID
RunPciDevsMonitor (
  VOID
  );

EFI_STATUS
PciDevsMonitorCheckConfiguration (
  VOID
  );

#endif  /* #ifndef __PCI__DEVS__MONITOR__LIB__H */

