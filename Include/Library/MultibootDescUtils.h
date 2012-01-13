/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __MULTIBOOT__DESC__UTILS__H
#define __MULTIBOOT__DESC__UTILS__H


#include <MultibootDesc.h>


BOOLEAN
PciDaAlloweed(
  IN UINT8 Bus,
  IN UINT8 Dev,
  IN UINT8 Func
  );

EFI_STATUS
CreatePciDaTable(
  IN UINT16 *PciDaStr
  );

VOID
DestroyObjectsDescTable(
  VOID
  );

EFI_STATUS
CreateObjectsDescTable(
  IN CHAR16 *ObjDescStr
  );
  
CHAR16 *
FindObjDescByGuid(
  IN EFI_GUID *Guid
  );

MULTIBOOT_ENTRY *
FindEntryOnCurrentFormByIndex(
  MULTIBOOT_CONFIG *Config,
  UINTN Index
  );

MULTIBOOT_ENTRY *
FindEntryOnFormByIndex(
  MULTIBOOT_CONFIG *Config,
  MULTIBOOT_FORM *Form,
  UINTN Index
  );

MULTIBOOT_ENTRY *
FindEntryByIndex(
  MULTIBOOT_CONFIG* Config,
  UINTN Index
  );
  
MULTIBOOT_ENTRY*
FindEntryByName(
  MULTIBOOT_CONFIG* Config,
  CHAR16 *Name
  );

MULTIBOOT_FORM *
GetFormById(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN FormId
  );

VOID
ClearForm(
  IN MULTIBOOT_FORM *Form
);

VOID
DeleteEntry(
  IN MULTIBOOT_ENTRY   *Entry
);

CHAR16*
GetDevicePathFromCfg(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN EntryIndex
  );

DEV_PATH_ADV *
GetNextDevPathAdv(
  IN MULTIBOOT_MODULE *ModuleEntry,
  IN BOOLEAN bReset
  );

VOID
ShowAllDevPathAdv(
  IN MULTIBOOT_CONFIG *Config
  );

CHAR16*
GetDevicePathAdvFromCfg(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN EntryIndex,
  IN BOOLEAN bReset
  );

MULTIBOOT_FORM *
GetFormByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pFormGuid
  );

VOID
DeleteFormByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pFormGuid
  );

EFI_GUID *
GetNextObjDescGuid(
  IN BOOLEAN bRestart
  );

UINTN
GetObjDescCount(
  VOID
  );

MULTIBOOT_MODULE *
FindModuleByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pGuid
  );

MULTIBOOT_ENTRY*
FindEntryByGuid(
  MULTIBOOT_CONFIG* Config,
  EFI_GUID *pGuid
  );

#endif /* #ifndef __MULTIBOOT__DESC__UTILS__H */

