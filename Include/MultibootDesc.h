/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __MULTIBOOT__DESC__H
#define __MULTIBOOT__DESC__H


#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiBaseType.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/CommonUtils.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Multiboot.h>
#include <CommonDefs.h>


#ifndef MAX_HASH_LEN
#define MAX_HASH_LEN        32
#endif


typedef enum {
  ModuleFormatBinary,
  ModuleFormatElfAuto,
  ModuleFormatElf32,
  ModuleFormatElf64,
  ModuleFormatPeAuto,
  ModuleFormatPe32,
  ModuleFormatPe64,
  ModuleFormatMultibootAuto,
  ModuleFormatMultibootBin,         // Multiboot kernel Binary
  ModuleFormatMultibootElf32,
  ModuleFormatMultibootElf64,
  ModuleFormatLinux,
  ModuleFormatEfi
} MODULE_FORMAT;

typedef enum {
  ModuleCompressNone,
  ModuleCompressAuto,
  ModuleCompressTiano,
  ModuleCompressGzip,
  ModuleCompressBz2,
  ModuleCompressLzma
} MODULE_COMPRESS_TYPE;

typedef enum {
  MenuItemAction,
  MenuItemListBox,
  MenuItemCheckbox,
  MenuItemNumericString,
  MenuItemString,
  MenuItemPassword,
  MenuItemDotString,
  MenuItemLabel,
  MenuItemEmptyAction,
} MENU_ITEM_TYPE;

typedef struct _OBJDESC {
  EFI_GUID GuidVal;
  CHAR16 *ObjDesc;
} OBJDESC;

typedef struct _DEV_PATH_ADV {
  LIST_ENTRY             ListEntry;
  CHAR16                 *DevPath;
} DEV_PATH_ADV;

typedef struct {
  LIST_ENTRY             ListEntry;
  EFI_FILE*              Root;
  MODULE_FORMAT          Format;
  MODULE_COMPRESS_TYPE   CompressType;
  EFI_PHYSICAL_ADDRESS   BaseAddreess;
  EFI_PHYSICAL_ADDRESS   EntryPoint;
  LIST_ENTRY             DevPathAdvHead;
  UINT16                 DevPath[MULTIBOOT_MAX_STRING];
  UINT16                 Args[MULTIBOOT_MAX_STRING];
  BOOLEAN                bHashPresent;
  UINT8                  HashType;
  CHAR8                  *GuidStr;
  UINT8                  Hash[MAX_HASH_LEN];
} MULTIBOOT_MODULE;

typedef struct _MULTIBOOT_ENTRY {
  LIST_ENTRY ListEntry;  // Entries list
  LIST_ENTRY ModuleHead; // Head of the modules list
  UINTN Index;
  MODULE_FORMAT Format;
  MENU_ITEM_TYPE MenuItemType;
  UINT16 Name[MULTIBOOT_MAX_STRING];
  CHAR16 *FilterStr;
  CHAR8  *GuidStr;
  CHAR16 *MenuInfo;
  CHAR16 *Help;
  EFI_STRING_ID NameToken; // Token of the Name in the Hii data base
  EFI_GUID *SecureGrayGuid; // Security attribute for menu item: GRAY IF NOT SECURE(GUID)
  EFI_HII_HANDLE HiiHandle; // Handle for hii resources for external modules usage
} MULTIBOOT_ENTRY;

typedef struct _MULTIBOOT_FORM {
  LIST_ENTRY ListForm;  // Forms list
  LIST_ENTRY EntryHead;
  MULTIBOOT_ENTRY *CurrentEntry;
  MULTIBOOT_MODULE *CurrentModule;
  UINTN Id;
  CHAR8 *GuidStr;  
  UINT16 Title[MULTIBOOT_MAX_STRING];
} MULTIBOOT_FORM;

typedef struct _DEF_USER_DESC {
  CHAR16 *UserName;
  CHAR16 *UserFIO;
  CHAR16 *UserContactInfo;
  CHAR16 *PassHash;
  CHAR16 *Digest;
} DEF_USER_DESC;

enum {
  MB_WORK_MODE_UNDEF,
  MB_WORK_MODE_WIFI,
  MB_WORK_MODE_WIFI_NB
};

typedef struct _MULTIBOOT_CONFIG {
  UINT32              State;
  UINTN               Interactive;
  UINTN               Timeout;
  UINTN               Default;
  CHAR8               Language[16];
  UINTN               ErrorLine;
  UINTN               ErrorPos;
  //LIST_ENTRY          EntryHead;
  //MULTIBOOT_ENTRY     *CurrentEntry;
  //MULTIBOOT_MODULE    *CurrentModule;
  CHAR16              *DevDescStr;
  CHAR16              *TokenDevPathStr;
  CHAR16              *PciDaStr;
  CHAR16              *ObjDescStr;
  CHAR8               *PlatformGuidStr;
  CHAR8               *PlatformNameStr;
  LIST_ENTRY          FormHead;
  MULTIBOOT_FORM      *CurrentForm;
  DEF_USER_DESC       *DefUserDesc;
  UINT16              WorkMode;
  CHAR16               FwVerStr[255];
  UINT8               *XmlConfigData;
  UINTN               XmlConfigDataSize;
} MULTIBOOT_CONFIG;

typedef struct _MULTIBOOT_DATA {
  UINT32                          Signature;
  LIST_ENTRY                      ModulesHead;
  MULTIBOOT_PROTOCOL              Multiboot;
  EFI_HII_CONFIG_ACCESS_PROTOCOL  ConfigAccess;
  EFI_FORM_BROWSER2_PROTOCOL      *FormBrowser2;
  EFI_HII_DATABASE_PROTOCOL       *HiiDatabase;
  EFI_HII_STRING_PROTOCOL         *HiiString;
  EFI_HANDLE                      DriverHandle;
  EFI_HANDLE                      HiiHandle;
  MULTIBOOT_CONFIG                Config;
} MULTIBOOT_DATA;

typedef struct _PCI_DA_DESC {
  UINT8 Bus;
  UINT8 BusMask;
  UINT8 Dev;
  UINT8 DevMask;
  UINT8 Func;
  UINT8 FuncMask;
} PCI_DA_DESC;


#endif  /*  #ifndef __MULTIBOOT__DESC__H */
