/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __STORAGE__H
#define __STORAGE__H

#include <Library/DebugLib.h>
#include <Guid/VariableFormat.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Protocol/Runtime.h>
#include <Library/PciDevsMonitorLib.h>


#define STORAGE_VARIABLE_NAME                  L"PciDevsMonitor"
#define STORAGE_VARIABLE_NAME_WITH_NUM         L"PciDevsMonitor_00000000"
#define STORAGE_VARIABLE_MAX_NAME_LEN          (sizeof(STORAGE_VARIABLE_NAME_WITH_NUM))

#define STORAGE_VARIABLE_MAX_CARD_SIZE         (PcdGet32(PcdMaxVariableSize) - \
                                                  sizeof (VARIABLE_HEADER) - \
                                                  STORAGE_VARIABLE_MAX_NAME_LEN)
#define STORAGE_VARIABLE_MAX_STORAGE_SIZE      (1024 * 10)
#define STORAGE_GUID                           { 0xd3642e3f, 0xa088, 0x4c46, \
                                                { 0x9f, 0x92, 0xf5, 0x14, 0xcb,\
                                                  0x7b, 0xe7, 0x98 \
                                                } }          

typedef struct {
  UINT32 DataLen;
  UINT32 Mode;
  UINT8  Data[1];
} PCI_DEVS_COMMON_DATA;

EFI_STATUS
PciDevsMonStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );

EFI_STATUS
PciDevsMonSaveData(
  IN EFI_LIST_ENTRY *PciDevsList,
  IN UINT32 Mode
  );

EFI_STATUS
PciDevsMonStorageGetData(
  IN OUT EFI_LIST_ENTRY *PciDevsList,
  IN OUT UINT32 *Mode
  );

EFI_STATUS
PciDevsMonStorageInitEmpty (
  IN UINT32 Mode
  );


#endif /* #ifndef __STORAGE__H */

