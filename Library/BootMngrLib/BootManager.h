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

#ifndef _EFI_BOOT_MANAGER_H_
#define _EFI_BOOT_MANAGER_H_

#include "../../Loader/Bds/Bds.h"
#include "Common.h"
#include <Library/ExtHdrUtils.h>
#include <Guid/VariableFormat.h>
#include <Library/FeLib.h>
#include <Library/VarStorageUtils.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/AcpiS3Save.h>
#include <Library/PcdLib.h>
#include <MultibootDesc.h>
#include <Library/BootMngrLib.h>


#define MAIN_BOOT_MANAGER_ID                0x0501
#define MAIN_BOOT_CONFIG_ID                 0x0502
#define MAIN_BOOT_INTEGRITY_ID              0x0503
#define MAIN_BOOT_IMPORT_ID                 0x0504
#define MAIN_BOOT_EXPORT_ID                 0x0505
#define MAIN_BOOT_ADD_FILE_ID               0x0506
#define MAIN_BOOT_SELECT_FILE_ID            0x0507
#define MAIN_BOOT_SAVE_FILES_LIST_ID        0x0508
#define MAIN_BOOT_SAVE_CURRENT_CFG_ID       0x0509
#define MAIN_BOOT_TYPE_SELECT_ID            0x050A
#define MAIN_ADD_MODULE_ID                  0x050B
#define MAIN_REMOVE_MODULES_ID              0x050C
#define MAIN_BOOT_UPDATE_DEVICES_LIST_ID    0x050D
#define MAIN_BOOT_MODE_ID                   0x050E
#define MAIN_CLEAN_FILES_LIST_ID            0x050F
#define MAIN_REFRESH_FILES_LIST_ID          0x0510
#define MAIN_BOOT_CONFIG_MN_ITEM_ID         0x0511


#define MAIN_BOOT_UNDEF                     0x05FF
#define MAIN_BOOT_MODULES_START             0x0600

#define ICFL_LIST_START                     0x0700

#define ADDITIONAL_OPT_START                0x1000

#define BOOT_MNGR_BOPT_NEED_REINIT          (1 << 0)

enum { 
  OPCODE_SAVE_USB_FULL_PATH, OPCODE_ADD_USB_PATH
};



//
// These are defined as the same with vfr file
//
#define BOOT_MANAGER_FORMSET_GUID \
  { \
  0x543cd5fe, 0x1276, 0x443d, {0x41, 0x42, 0x34, 0xc2, 0x32, 0xef, 0xa1, 0xe4}\
  }

#define BOOT_MANAGER_FORM_ID                0x1000
#define BOOT_MENU_FORM_ID                   0x3000

#define LABEL_BOOT_OPTION                   0x00
#define LABEL_BOOT_OPTION_END               0x01



#define ARRAY_ITEMS(Array_) \
  (sizeof (Array_) / sizeof (*Array_))

#define MAXIMUM_BOOT_OPTIONS                5

#define BOOTCONF_TAG_BEG                    L"<BOOTCONF>"
#define BOOTCONF_TAG_END                    L"</BOOTCONF>"
#define BOOT_CONF_GUID_TAG_BEG              L"<CONFGUID>"
#define BOOT_CONF_GUID_TAG_END              L"</CONFGUID>"
#define BOOT_CONF_TYPE_TAG_BEG              L"<CONFTYPE>"
#define BOOT_CONF_TYPE_TAG_END              L"</CONFTYPE>"
#define BOOT_TYPE_TAG_BEG                   L"<BOOTTYPE>"
#define BOOT_TYPE_TAG_END                   L"</BOOTTYPE>"
#define MODULECONF_TAG_BEG                  L"<MODULE>"
#define MODULECONF_TAG_END                  L"</MODULE>"
#define DEVPATH_TAG_BEG                     L"<DEVPATH>"
#define DEVPATH_TAG_END                     L"</DEVPATH>"
#define PARAMS_TAG_BEG                      L"<PARAMS>"
#define PARAMS_TAG_END                      L"</PARAMS>"
#define ICFL_TAG_BEG                        L"<ICFL>"
#define ICFL_TAG_END                        L"</ICFL>"
#define FILE_TAG_BEG                        L"<FILE>"
#define FILE_TAG_END                        L"</FILE>"
#define ENTRY_TAG_BEG                       L"<ENTRY>"
#define ENTRY_TAG_END                       L"</ENTRY>"
#define HASH_TAG_BEG                        L"<HASH>"
#define HASH_TAG_END                        L"</HASH>"


#define TAGS_TOTAL_LEN                      (sizeof(BOOTCONF_TAG_BEG) +\
                                             sizeof(BOOTCONF_TAG_END) +\
                                             sizeof(BOOT_CONF_GUID_TAG_BEG) +\
                                             sizeof(BOOT_CONF_GUID_TAG_END) +\
                                             sizeof(BOOT_CONF_TYPE_TAG_BEG) +\
                                             sizeof(BOOT_CONF_TYPE_TAG_END) +\
                                             sizeof(BOOT_TYPE_TAG_BEG) +\
                                             sizeof(BOOT_TYPE_TAG_END) +\
                                             sizeof(MODULECONF_TAG_BEG) +\
                                             sizeof(MODULECONF_TAG_END) +\
                                             sizeof(DEVPATH_TAG_BEG) +\
                                             sizeof(DEVPATH_TAG_END) +\
                                             sizeof(PARAMS_TAG_BEG) +\
                                             sizeof(PARAMS_TAG_END) +\
                                             sizeof(ICFL_TAG_BEG) +\
                                             sizeof(ICFL_TAG_END) +\
                                             sizeof(FILE_TAG_BEG) +\
                                             sizeof(FILE_TAG_END) +\
                                             sizeof(ENTRY_TAG_BEG) +\
                                             sizeof(ENTRY_TAG_END) +\
                                             sizeof(HASH_TAG_BEG) +\
                                             sizeof(HASH_TAG_END))

#define ONE_MODULE_TAGS_LEN                 (sizeof(DEVPATH_TAG_BEG) +\
                                             sizeof(DEVPATH_TAG_END) +\
                                             sizeof(PARAMS_TAG_BEG) +\
                                             sizeof(PARAMS_TAG_END) +\
                                             sizeof(HASH_TAG_BEG) +\
                                             sizeof(HASH_TAG_END))

#define ICFL_TAGS_LEN                       (sizeof(FILE_TAG_BEG) +\
                                             sizeof(FILE_TAG_END) +\
                                             sizeof(HASH_TAG_BEG) +\
                                             sizeof(HASH_TAG_END))

#define PRIMARY_HASH_TYPE                   (CS_TYPE_GOST)


//
// These are the VFR compiler generated data representing our VFR data.
//
extern UINT8 BootManagerVfrBin[];

extern GUID gVendorGuid;


#define BOOT_MANAGER_CALLBACK_DATA_SIGNATURE  SIGNATURE_32 ('B', 'M', 'C', 'B')

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
} BOOT_MANAGER_CALLBACK_DATA;


EFI_STATUS
EFIAPI
BootManagerCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  );


#endif

