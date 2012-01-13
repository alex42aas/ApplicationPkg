/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/** @file

**/

#ifndef _EFI_CHIPSET_CONFIG_H_
#define _EFI_CHIPSET_CONFIG_H_

#include <Library/ChipsetCfgLib.h>
#include <Library/CommonUtils.h>
#include "../../Loader/Bds/Bds.h"
#include <Library/MultibootDescUtils.h>
#include <Protocol/GlobalConfigType.h>
#include <Protocol/BdsHelperProtocol.h>
#include <Guid/PcAnsi.h>

#define MAIN_CHIPSET_CONFIG_ID              0x0501
#define MAIN_USB_LEGACY_SUPPORT_ID          0x0503
#define MAIN_SATA_MODE_ID                   0x0504

#define MAIN_CHIPSET_UNDEF                  0x05FF

#define USB_LEGACY_SUPPORT_ID               0xCC02
#define SATA_MODE_SELECT_ID                 0xCC03
#define PS2_PORT_CFG_ID                     0xCC04
#define USB_PORTS_CFG_START_ID              0xCC07
#define USB_PORTS_CFG_END_ID                0xCC24
#define AMT_LOCK_KEYBORD_ID                 0xCC30
#define DISABLE_SERIAL_CONSOLE_ID           0xCC31
#define SERIAL_CONSOLE_TYPE                 0xCC32
#define PXE_OPROM_SWITCH_ID                 0xCC33
#define SATA_AHCI_SLOW_SELECT_ID            0xCC34
#define USB30_MODE_ENABLE_ID                0xCC35


#define LABEL_SETUP_OPTION                      0x0000
#define LABEL_SETUP_OPTION_END                  0x0001

//
// These are defined as the same with vfr file
//
#define CHIPSET_CONFIG_FORMSET_GUID \
  { \
  0x543cd5fe, 0x1276, 0x443d, {0x41, 0x42, 0x34, 0xc2, 0x32, 0xef, 0xa1, 0xe4}\
  }

#define CHIPSET_CONFIG_FORM_ID              0xCC00

#define LABEL_BOOT_OPTION                   0x00
#define LABEL_BOOT_OPTION_END               0x01



#define ARRAY_ITEMS(Array_) \
  (sizeof (Array_) / sizeof (*Array_))

#define MAXIMUM_BOOT_OPTIONS                5

//
// These are the VFR compiler generated data representing our VFR data.
//
extern UINT8 ChipsetConfigVfrBin[];

extern GUID gVendorGuid;

#define VarConsoleInp           L"ConIn"
#define VarConsoleOut           L"ConOut"
#define VarErrorOut             L"ErrOut"


#define CHIPSET_CONFIG_CALLBACK_DATA_SIGNATURE  SIGNATURE_32 ('C', 'C', 'C', 'B')

typedef struct {
  UINTN                           Signature;

  //
  // HII relative handles
  //
  EFI_HII_HANDLE                  HiiHandle;
  EFI_HANDLE                      DriverHandle;

  //
  // Produced protocols
  //
  EFI_HII_CONFIG_ACCESS_PROTOCOL   ConfigAccess;
} CHIPSET_CONFIG_CALLBACK_DATA;


EFI_STATUS
EFIAPI
ChipsetConfigCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  );

CONFIG_ERROR_T
SetChipsetConfigFromINIFile (
  CHAR8 *filePath
  );

BOOLEAN
IsNeedToConfigFirstTime (
  VOID
);

EFI_STATUS
ObtainUsbSetupEfiVar(
  IN OUT USB_SETUP **UsbSetupPtr
  );

EFI_STATUS
GetCurrentConsoleType(
  UINT8 *ConsoleType
  );

EFI_STATUS
SetCurrentConsoleType(
  UINT8 ConsoleType
  );

EFI_STATUS
ResetCurrentConsoleType(
  UINT8 *DefaultConsoleType
  );

EFI_STATUS
GetCurrentConsoleTypeGuid(
  EFI_GUID *pGUIdConsType
  );

#endif

