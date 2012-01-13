/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "XmlConfig.h"


CONFIG_STATE_TABLE gConfigStateTable[] = {
  { ST_BASE,        "global",      6, EVENT_START, ST_GLOBAL,      0 },
  { ST_GLOBAL,      "default",     7, EVENT_NAME,  ST_DEFAULT,     0 },
  { ST_GLOBAL,      "timeout",     7, EVENT_NAME,  ST_TIMEOUT,     0 },
  { ST_GLOBAL,      "language",    8, EVENT_NAME,  ST_LANGUAGE,    0 },

  { ST_TIMEOUT,     0,             0, EVENT_VAL,   ST_GLOBAL,      1 },
  { ST_DEFAULT,     0,             0, EVENT_VAL,   ST_GLOBAL,      1 },
  { ST_LANGUAGE,    0,             0, EVENT_VAL,   ST_GLOBAL,      1 },

  { ST_GLOBAL,      "/global",     7, EVENT_END,   ST_BASE,        0 },

  { ST_BASE,        "defusr",      6, EVENT_START, ST_DEF_USER,    0 },
  
  { ST_DEF_USER,    "usrname",     7, EVENT_START, ST_USR_NAME,    0 },
  { ST_USR_NAME,    0,             0, EVENT_TEXT,  ST_USR_NAME,    1 },
  { ST_USR_NAME,    "/usrname",    8, EVENT_END,   ST_DEF_USER,    0 },

  { ST_DEF_USER,    "usrfio",      6, EVENT_START, ST_USR_FIO,     0 },
  { ST_USR_FIO,     0,             0, EVENT_TEXT,  ST_USR_FIO,     1 },
  { ST_USR_FIO,     "/usrfio",     7, EVENT_END,   ST_DEF_USER,    0 },

  { ST_DEF_USER,    "usrinfo",      7, EVENT_START, ST_USR_INFO,   0 },
  { ST_USR_INFO,     0,             0, EVENT_TEXT,  ST_USR_INFO,   1 },
  { ST_USR_INFO,     "/usrinfo",    8, EVENT_END,   ST_DEF_USER,   0 },

  { ST_DEF_USER,    "passhash",     8, EVENT_START, ST_PASSHASH,   0 },
  { ST_PASSHASH,     0,             0, EVENT_TEXT,  ST_PASSHASH,   1 },
  { ST_PASSHASH,     "/passhash",   9, EVENT_END,   ST_DEF_USER,   0 },

  { ST_DEF_USER,    "dgst",         4, EVENT_START, ST_DGST,       0 },
  { ST_DGST,        0,              0, EVENT_TEXT,  ST_DGST,       1 },
  { ST_DGST,        "/dgst",        5, EVENT_END,   ST_DEF_USER,   0 },

  { ST_DEF_USER,    "/defusr",      7, EVENT_END,   ST_BASE,       0 },

  
  { ST_BASE,        "form",        4, EVENT_START, ST_FORM,        0 },
  { ST_FORM,        "title",       5, EVENT_NAME,  ST_TITLE,       0 },
  { ST_TITLE,       0,             0, EVENT_VAL,   ST_FORM,        1 },
  { ST_FORM,        "id",          2, EVENT_NAME,  ST_FORM_ID,     0 },
  { ST_FORM_ID,     0,             0, EVENT_VAL,   ST_FORM,        1 },

  { ST_GLOBAL,      "/global",     7, EVENT_END,   ST_BASE,        0 },
  
  { ST_FORM,        "entry",       5, EVENT_START, ST_ENTRY,       0 },
  { ST_ENTRY,       "name",        4, EVENT_NAME,  ST_NAME,        0 },
  { ST_NAME,        0,             0, EVENT_VAL,   ST_ENTRY,       1 },
  { ST_ENTRY,       "id",          2, EVENT_NAME,  ST_ID,          0 },
  { ST_ID,          0,             0, EVENT_VAL,   ST_ENTRY,       1 },
  { ST_ENTRY,       "type",        4, EVENT_NAME,  ST_TYPE,        0 },
  { ST_TYPE,        0,             0, EVENT_VAL,   ST_ENTRY,       1 },
  { ST_ENTRY,       "mnitem",      6, EVENT_NAME,  ST_MNITEM,      0 },
  { ST_MNITEM,      0,             0, EVENT_VAL,   ST_ENTRY,       1 },
  
  { ST_FORM,        "guid",        4, EVENT_START, ST_FGUID,       0 },
  { ST_FGUID,       0,             0, EVENT_TEXT,  ST_FGUID,       1 },
  { ST_FGUID,       "/guid",       5, EVENT_END,   ST_FORM,        0 },
  
  { ST_ENTRY,       "guid",        4, EVENT_START, ST_EGUID,       0 },
  { ST_EGUID,       0,             0, EVENT_TEXT,  ST_EGUID,       1 },
  { ST_EGUID,       "/guid",       5, EVENT_END,   ST_ENTRY,       0 },

  { ST_ENTRY,       "filterstr",   9, EVENT_START, ST_FILTER_STR,       0 },
  { ST_FILTER_STR,  0,             0, EVENT_TEXT,  ST_FILTER_STR,       1 },
  { ST_FILTER_STR,  "/filterstr",  10, EVENT_END,  ST_ENTRY,       0 },

  { ST_ENTRY,       "securegray",  10, EVENT_START, ST_SECURE_GRAY, 0 },
  { ST_SECURE_GRAY,  0,             0, EVENT_TEXT,  ST_SECURE_GRAY, 1 },
  { ST_SECURE_GRAY, "/securegray", 11, EVENT_END,   ST_ENTRY,       0 },

  { ST_ENTRY,       "mnlist",      6, EVENT_START, ST_MN_LIST,     0 },
  { ST_MN_LIST,     0,             0, EVENT_TEXT,  ST_MN_LIST,     1 },
  { ST_MN_LIST,     "/mnlist",     7, EVENT_END,   ST_ENTRY,       0 },  

  { ST_ENTRY,       "help",        4, EVENT_START, ST_HELP,        0 },
  { ST_HELP ,       0,             0, EVENT_TEXT,  ST_HELP,        1 },
  { ST_HELP,        "/help",       5, EVENT_END,   ST_ENTRY,       0 },

  { ST_GLOBAL,      "fsdev",       5, EVENT_START, ST_FSDEV,       0 },
  { ST_FSDEV,       0,             0, EVENT_TEXT,  ST_FSDEV,       1 },
  { ST_FSDEV,       "/fsdev",      6, EVENT_END,   ST_GLOBAL,      0 },

  { ST_GLOBAL,      "tokendevpath", 12, EVENT_START, ST_TOKENDEVPATH,0 },
  { ST_TOKENDEVPATH,0,              0,  EVENT_TEXT,  ST_TOKENDEVPATH,1 },
  { ST_TOKENDEVPATH,"/tokendevpath",13, EVENT_END,   ST_GLOBAL,      0 },

  

  { ST_GLOBAL,      "pcida",       5, EVENT_START, ST_PCIDA,       0 },
  { ST_PCIDA,       0,             0, EVENT_TEXT,  ST_PCIDA,       1 },
  { ST_PCIDA,       "/pcida",      6, EVENT_END,   ST_GLOBAL,      0 },
  
  { ST_GLOBAL,      "objdesc",     7, EVENT_START, ST_OBJDESC,     0 },
  { ST_OBJDESC,     0,             0, EVENT_TEXT,  ST_OBJDESC,     1 },
  { ST_OBJDESC,     "/objdesc",    8, EVENT_END,   ST_GLOBAL,      0 },
  
  { ST_GLOBAL,        "platformguid",  12, EVENT_START, ST_PLATFORM_GUID, 0 },
  { ST_PLATFORM_GUID, 0,                0,  EVENT_TEXT,  ST_PLATFORM_GUID, 1 },
  { ST_PLATFORM_GUID, "/platformguid", 13, EVENT_END,   ST_GLOBAL,        0 },

  { ST_GLOBAL,        "platformname",  12, EVENT_START, ST_PLATFORM_NAME, 0 },
  { ST_PLATFORM_NAME, 0,                0,  EVENT_TEXT,  ST_PLATFORM_NAME, 1 },
  { ST_PLATFORM_NAME, "/platformname", 13, EVENT_END,   ST_GLOBAL,        0 },

  { ST_GLOBAL,      "workmode",       8, EVENT_START, ST_WORK_MODE,    0 },
  { ST_WORK_MODE,   0,                0, EVENT_TEXT,  ST_WORK_MODE,    1 },
  { ST_WORK_MODE,   "/workmode",      9, EVENT_END,   ST_GLOBAL,       0 },

  { ST_ENTRY,       "module",      6, EVENT_START, ST_MODULE,      0 },
  { ST_MODULE,      "baseaddress",11, EVENT_NAME,  ST_BASEADDRESS, 0 },
  { ST_BASEADDRESS, 0,             0, EVENT_VAL,   ST_MODULE,      1 },
  { ST_MODULE,      "uncompress", 10, EVENT_NAME,  ST_UNCOMPRESS,  0 },
  { ST_UNCOMPRESS,  0,             0, EVENT_VAL,   ST_MODULE,      1 },

  { ST_ENTRY,       "kernel",      6, EVENT_START, ST_KERNEL,      0 },
  { ST_KERNEL,      "baseaddress",11, EVENT_NAME,  ST_KBASEADDRESS,0 },
  { ST_KBASEADDRESS,0,             0, EVENT_VAL,   ST_KERNEL,      1 },
  { ST_KERNEL,      "entry",       5, EVENT_NAME,  ST_KENTRYPOINT, 0 },  
  { ST_KENTRYPOINT, 0,             0, EVENT_VAL,   ST_KERNEL,      1 },
  { ST_KERNEL,      "uncompress", 10, EVENT_NAME,  ST_KUNCOMPRESS, 0 },
  { ST_KUNCOMPRESS, 0,             0, EVENT_VAL,   ST_KERNEL,      1 },
  
  { ST_KERNEL,      "devpath",     7, EVENT_START,  ST_KDEVPATH,   0 },
  { ST_KDEVPATH,     0,             0, EVENT_TEXT,  ST_KDEVPATH,   1 },
  { ST_KDEVPATH,     "/devpath",    8, EVENT_END,   ST_KERNEL,     0 },

  { ST_KERNEL,      "params",      6, EVENT_START, ST_KPARAMS,     0 },
  { ST_KPARAMS,     0,             0, EVENT_TEXT,  ST_KPARAMS,     1 },
  { ST_KPARAMS,     "/params",     7, EVENT_END,   ST_KERNEL,      0 },

  { ST_KERNEL,      "guid",         4, EVENT_START, ST_KGUID,      0 },
  { ST_KGUID,        0,             0, EVENT_TEXT,  ST_KGUID,      1 },
  { ST_KGUID,        "/guid",       5, EVENT_END,   ST_KERNEL,     0 },
  
  { ST_KERNEL,      "hash",         4, EVENT_START, ST_KHASH,      0 },
  { ST_KHASH,        0,             0, EVENT_TEXT,  ST_KHASH,      1 },
  { ST_KHASH,       "/hash",        5, EVENT_END,   ST_KERNEL,     0 },
  
  { ST_MODULE,      "devpath",     7, EVENT_START, ST_DEVPATH,     0 },
  { ST_DEVPATH,     0,             0, EVENT_TEXT,  ST_DEVPATH,     1 },
  { ST_DEVPATH,     "/devpath",    8, EVENT_END,   ST_MODULE,      0 },
  
  { ST_MODULE,      "params",      6, EVENT_START, ST_PARAMS,      0 },
  { ST_PARAMS,      0,             0, EVENT_TEXT,  ST_PARAMS,      1 },
  { ST_PARAMS,      "/params",     7, EVENT_END,   ST_MODULE,      0 },

  { ST_MODULE,      "hash",         4, EVENT_START, ST_HASH,       0 },
  { ST_HASH,        0,              0, EVENT_TEXT,  ST_HASH,       1 },
  { ST_HASH,        "/hash",        5, EVENT_END,   ST_MODULE,     0 },
  
  { ST_MODULE,      "guid",         4, EVENT_START, ST_GUID,       0 },
  { ST_GUID,        0,              0, EVENT_TEXT,  ST_GUID,       1 },
  { ST_GUID,        "/guid",        5, EVENT_END,   ST_MODULE,     0 },
  
  { ST_MODULE,      "/module",     7, EVENT_END,    ST_ENTRY,      0 },
  { ST_KERNEL,      "/kernel",     7, EVENT_END,    ST_ENTRY,      0 },
  { ST_ENTRY,       "/entry",      6, EVENT_END,    ST_FORM,       0 },
  { ST_FORM,        "/form",       5, EVENT_END,    ST_BASE,       0 },
  { ST_ERROR_TAG,   0,             0, EVENT_NONE,   ST_ERROR_TAG,  0 }
};
static CHAR16 *ParserText = NULL;




VOID
XmlConfigShowState(
  IN UINT32 State
  )
{
  switch(State) {
  case ST_TIMEOUT:
    MsgDebugPrint("state: ST_TIMEOUT\n");
    break;

  case ST_DEFAULT:
    MsgDebugPrint("state: ST_DEFAULT\n");
    break;

  case ST_LANGUAGE:
    MsgDebugPrint("state: ST_LANGUAGE\n");
    break;

  case ST_TITLE:
    MsgDebugPrint("state: ST_TITLE\n");
    break;

  case ST_NAME:
    MsgDebugPrint("state: ST_NAME\n");
    break;

  case ST_ID:
    MsgDebugPrint("state: ST_ID\n");
    break;
    
  case ST_FORM_ID:
    MsgDebugPrint("state: ST_FORM_ID\n");
    break;

  case ST_TYPE:
    MsgDebugPrint("state: ST_TYPE\n");
    break;

  case ST_MNITEM:
    MsgDebugPrint("state: ST_MNITEM\n");
    break;

  case ST_HELP:
    MsgDebugPrint("state: ST_HELP\n");
    break;

  case ST_KDEVPATH:
    MsgDebugPrint("state: ST_KDEVPATH\n");
    break;
    
  case ST_DEVPATH:
    MsgDebugPrint("state: ST_DEFAULT\n");
    break;

  case ST_PARAMS:
    MsgDebugPrint("state: ST_DEVPATH\n");
    break;
    
  case ST_KPARAMS:
    MsgDebugPrint("state: ST_KPARAMS\n");
    break;

  case ST_HASH:
    MsgDebugPrint("state: ST_HASH\n");
    break;
    
  case ST_KHASH:
    MsgDebugPrint("state: ST_KHASH\n");
    break;

  case ST_KGUID:
    MsgDebugPrint("state: ST_KGUID\n");
    break;
    
  case ST_GUID:
    MsgDebugPrint("state: ST_GUID\n");
    break;
  
  case ST_FGUID:
    MsgDebugPrint("state: ST_FGUID\n");
    break;
    
  case ST_EGUID:
    MsgDebugPrint("state: ST_EGUID\n");
    break;

  case ST_SECURE_GRAY:
    MsgDebugPrint("state: ST_SECURE_GRAY");
    break;

  case ST_DEF_USER:
    MsgDebugPrint("state: ST_SECURE_GRAY");
    break;

  case ST_USR_NAME:
    MsgDebugPrint("state: ST_USR_NAME");
    break;

  case ST_USR_FIO:
    MsgDebugPrint("state: ST_USR_FIO");
    break;

  case ST_USR_INFO:
    MsgDebugPrint("state: ST_USR_INFO");
    break;

  case ST_PASSHASH:
    MsgDebugPrint("state: ST_PASSHASH");
    break;

  case ST_MN_LIST:
    MsgDebugPrint("state: ST_MN_LIST\n");
    break;
    
  case ST_OBJDESC:
    MsgDebugPrint("state: ST_OBJDESC\n");
    break;
    
  case ST_PLATFORM_GUID:
    MsgDebugPrint("state: ST_PLATFORM_GUID\n");
    break;

  case ST_PLATFORM_NAME:
    MsgDebugPrint("state: ST_PLATFORM_NAME\n");
    break;

  case ST_WORK_MODE:
    MsgDebugPrint("state: ST_WORK_MODE\n");
    break;

  case ST_FSDEV:
    MsgDebugPrint("state: ST_FSDEV\n");
    break;

  case ST_TOKENDEVPATH:
    MsgDebugPrint("state: ST_TOKENDEVPATH\n");
    break;    

  case ST_PCIDA:
    MsgDebugPrint("state: ST_PCIDA\n");
    break;

  case ST_BASEADDRESS:
    MsgDebugPrint("state: ST_BASEADDRESS\n");
    break;
    
  case ST_KENTRYPOINT:
    MsgDebugPrint("state: ST_KENTRYPOINT\n");
    break;
    
  case ST_KBASEADDRESS:
    MsgDebugPrint("state: ST_KBASEADDRESS\n");
    break;
    
  case ST_UNCOMPRESS:
    MsgDebugPrint("state: ST_UNCOMPRESS\n");
    break;
    
  case ST_KUNCOMPRESS:
    MsgDebugPrint("state: ST_KUNCOMPRESS\n");
    break;
    
  case ST_FORM:
    MsgDebugPrint("state: ST_FORM\n");
    break;
    
  case ST_ENTRY:
    MsgDebugPrint("state: ST_ENTRY\n");
    break;
    
  default:
    MsgDebugPrint("State: unknown %x\n", State);
  }
}


/**
  Function to compare 2 strings without regard to case of the characters.

  @param[in] Buffer1            Pointer to String to compare.
  @param[in] Buffer2            Pointer to second String to compare.

  @retval 0                     Buffer1 equal to Buffer2.
  @return < 0                   Buffer1 is less than Buffer2.
  @return > 0                   Buffer1 is greater than Buffer2.                 
**/

INTN
EFIAPI
StringNoCaseCompare (
  IN  CHAR16             *Buffer1,
  IN  CHAR16             *Buffer2
  )
{
  EFI_STATUS Status;
  static EFI_UNICODE_COLLATION_PROTOCOL *mUnicodeCollation;
  
  if (mUnicodeCollation == NULL) {
    Status = gBS->LocateProtocol(
      &gEfiUnicodeCollation2ProtocolGuid,
      NULL,
      (VOID**)&mUnicodeCollation
      );

    ASSERT_EFI_ERROR(Status);
  }

  return (mUnicodeCollation->StriColl(
    mUnicodeCollation,
    Buffer1,
    Buffer2));
}


EFI_STATUS 
ParseConfig( 
    CHAR8            *Text8, 
    UINT32           Length,
    UINT32           State,
    UINT32           NextState, 
    UINT32           Emit,
    MULTIBOOT_CONFIG *Config
    )
{
  MULTIBOOT_ENTRY   *Entry;
  MULTIBOOT_MODULE  *Module;
  MULTIBOOT_FORM    *Form;
  //EFI_STATUS         Status;
  //CHAR16 Text[MULTIBOOT_MAX_STRING];
  CHAR16 *Text;

  Text = ParserText;

  AsciiStrToUnicodeStr( Text8, Text );

  if( State == ST_GLOBAL ) {

  }

  if (State == ST_BASE && NextState == ST_DEF_USER) {
    if (Config->DefUserDesc != NULL) {
      return EFI_ABORTED;
    }
    Config->DefUserDesc = AllocateZeroPool(sizeof(*Config->DefUserDesc));
    if(Config->DefUserDesc == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
  }
  
  if( State == ST_BASE && NextState == ST_FORM ) {
    Form = AllocateZeroPool(sizeof(MULTIBOOT_FORM));
    if(Form == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    InitializeListHead( &Form->EntryHead );
    InsertTailList( &Config->FormHead, &Form->ListForm );
    Config->CurrentForm = Form;
  }

  if( State == ST_FORM && NextState == ST_ENTRY ) {
    ASSERT(Config->CurrentForm != NULL);
    Entry = AllocateZeroPool(sizeof(MULTIBOOT_ENTRY));
    if(Entry == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    InitializeListHead( &Entry->ModuleHead );
    InsertTailList( &Config->CurrentForm->EntryHead, &Entry->ListEntry );
    Config->CurrentForm->CurrentEntry = Entry;
  }

  if( State == ST_ENTRY && (NextState == ST_MODULE || NextState == ST_KERNEL)) {
    ASSERT(Config->CurrentForm != NULL);
    ASSERT(Config->CurrentForm->CurrentEntry != NULL);
    Module = AllocateZeroPool(sizeof(MULTIBOOT_MODULE));
    if(Module == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
      
    InsertTailList( &Config->CurrentForm->CurrentEntry->ModuleHead,
      &Module->ListEntry );
    Config->CurrentForm->CurrentModule = Module;
    Config->CurrentForm->CurrentModule->Format = 
      Config->CurrentForm->CurrentEntry->Format;
  }

  if (!Emit) {
    return EFI_SUCCESS;
  }

  EncodeCP1251Str(Text);

  switch(State) {
  case ST_TIMEOUT:
    Config->Timeout = StrDecimalToUintn(Text);
    break;

  case ST_DEFAULT:
    Config->Default = StrDecimalToUintn(Text);
    break;

  case ST_LANGUAGE:
    AsciiSPrint(Config->Language, sizeof(Config->Language), "%a", Text8);
    break;
    
  case ST_TITLE:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(Config->CurrentForm->Title,
      sizeof(Config->CurrentForm->Title), L"%s", Text);
    //EncodeCP1251Str(Config->CurrentForm->Title);
    break;

  case ST_NAME:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(Config->CurrentForm->CurrentEntry->Name,
      sizeof(Config->CurrentForm->CurrentEntry->Name), L"%s", Text);
    //EncodeCP1251Str(Config->CurrentForm->CurrentEntry->Name);
    break;

  case ST_ID:
  case ST_FORM_ID:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    } else {
      UINTN Id;
      
      if (StrLen(Text) >= 3 && (Text[1] == 'x' || Text[1] == 'X')) {
        Id = StrHexToUintn(Text);
      } else {
        Id = StrDecimalToUintn(Text);
      }
      
      if (NextState == ST_ENTRY) {
        Config->CurrentForm->CurrentEntry->Index = Id;
      } else if (NextState == ST_FORM) {
        Config->CurrentForm->Id = Id;
      } else {
        return EFI_INVALID_PARAMETER;
      }
    }
    break;

  case ST_TYPE:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    if(StringNoCaseCompare(Text, L"multiboot") == 0) {
      Config->CurrentForm->CurrentEntry->Format = ModuleFormatMultibootAuto;
      //Config->CurrentForm->CurrentModule->Format = ModuleFormatMultibootAuto;
    } else if(StringNoCaseCompare(Text, L"linux") == 0) {
      Config->CurrentForm->CurrentEntry->Format = ModuleFormatLinux;
      //Config->CurrentForm->CurrentModule->Format = ModuleFormatLinux;
    } else if(StringNoCaseCompare(Text, L"efi") == 0) {
      Config->CurrentForm->CurrentEntry->Format = ModuleFormatEfi;
      //Config->CurrentForm->CurrentModule->Format = ModuleFormatEfi;
    }
    break;

  case ST_MNITEM:
    if (Config->CurrentForm == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    if(StringNoCaseCompare(Text, L"action") == 0) {
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemAction;
    } else if(StringNoCaseCompare(Text, L"listbox") == 0) {
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemListBox;
    } else if(StringNoCaseCompare(Text, L"checkbox") == 0) {
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemCheckbox;
    } else if (StringNoCaseCompare(Text, L"numericstring") == 0){  
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemNumericString;
    } else if (StringNoCaseCompare(Text, L"string") == 0){  
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemString;
    } else if (StringNoCaseCompare(Text, L"password") == 0){  
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemPassword;
    } else if (StringNoCaseCompare(Text, L"dotstring") == 0){  
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemDotString;
    } else if (StringNoCaseCompare(Text, L"label") == 0){  
      Config->CurrentForm->CurrentEntry->MenuItemType = MenuItemLabel;
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    break;

  case ST_HELP:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    if (Config->CurrentForm->CurrentEntry->Help != NULL) {
      break;
    } else {
      UINTN Len;
      Len = StrSize(Text);
      Config->CurrentForm->CurrentEntry->Help = AllocateZeroPool(Len);
      if (NULL == Config->CurrentForm->CurrentEntry->Help) {
        return EFI_OUT_OF_RESOURCES;
      }
      StrCpy(Config->CurrentForm->CurrentEntry->Help, Text);
    }
    break;

  case ST_KDEVPATH:
  case ST_DEVPATH:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    if (StrLen(Config->CurrentForm->CurrentModule->DevPath) == 0) {
      InitializeListHead(&Config->CurrentForm->CurrentModule->DevPathAdvHead);
      UnicodeSPrint(Config->CurrentForm->CurrentModule->DevPath,
        sizeof(Config->CurrentForm->CurrentModule->DevPath), L"%s", Text);
    } else {
      DEV_PATH_ADV *DevPathAdv;
      DevPathAdv = (DEV_PATH_ADV*)AllocateZeroPool(sizeof(DEV_PATH_ADV));
      if (NULL == DevPathAdv) {
        return EFI_OUT_OF_RESOURCES;
      }
      DevPathAdv->DevPath = (CHAR16*)AllocateZeroPool(
        (StrLen(Text) + 1) * sizeof(CHAR16));
      if (NULL == DevPathAdv->DevPath) {
        FreePool(DevPathAdv);
        return EFI_OUT_OF_RESOURCES;
      }
      StrCpy(DevPathAdv->DevPath, Text);
      InsertTailList(&Config->CurrentForm->CurrentModule->DevPathAdvHead, 
        &DevPathAdv->ListEntry);
    }
    //EncodeCP1251Str(Config->CurrentForm->CurrentModule->DevPath);
    break;

  case ST_PARAMS:
  case ST_KPARAMS:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(Config->CurrentForm->CurrentModule->Args,
      sizeof(Config->CurrentForm->CurrentModule->Args), L"%s", Text);
    //EncodeCP1251Str(Config->CurrentForm->CurrentModule->Args);
    break;

  case ST_HASH:
  case ST_KHASH:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    Config->CurrentForm->CurrentModule->bHashPresent = TRUE;
    UnicodeHashToBin(Config->CurrentForm->CurrentModule->Hash, Text);
    break;

  case ST_DEF_USER:
    break;

  case ST_USR_NAME:
    if (Config->DefUserDesc == NULL || Config->DefUserDesc->UserName != NULL) {
      return EFI_ABORTED;
    }
    Config->DefUserDesc->UserName = AllocateZeroPool(StrSize(Text));
    if (Config->DefUserDesc->UserName == NULL) {
      return EFI_ABORTED;
    }
    UnicodeSPrint(Config->DefUserDesc->UserName, StrSize(Text), L"%s", Text);
    break;

  case ST_USR_FIO:
    if (Config->DefUserDesc == NULL || Config->DefUserDesc->UserFIO != NULL) {
      return EFI_ABORTED;
    }
    Config->DefUserDesc->UserFIO = AllocateZeroPool(StrSize(Text));
    if (Config->DefUserDesc->UserFIO == NULL) {
      return EFI_ABORTED;
    }
    UnicodeSPrint(Config->DefUserDesc->UserFIO, StrSize(Text), L"%s", Text);
    break;

  case ST_USR_INFO:
    if (Config->DefUserDesc == NULL || 
        Config->DefUserDesc->UserContactInfo != NULL) {
      return EFI_ABORTED;
    }
    Config->DefUserDesc->UserContactInfo = AllocateZeroPool(StrSize(Text));
    if (Config->DefUserDesc->UserContactInfo == NULL) {
      return EFI_ABORTED;
    }
    UnicodeSPrint(Config->DefUserDesc->UserContactInfo, 
      StrSize(Text), L"%s", Text);
    break;

  case ST_PASSHASH:
    if (Config->DefUserDesc == NULL || 
        Config->DefUserDesc->PassHash != NULL) {
      return EFI_ABORTED;
    }
    Config->DefUserDesc->PassHash = AllocateZeroPool(StrSize(Text));
    if (Config->DefUserDesc->PassHash == NULL) {
      return EFI_ABORTED;
    }
    UnicodeSPrint(Config->DefUserDesc->PassHash, 
      StrSize(Text), L"%s", Text);
    break;

  case ST_SECURE_GRAY:
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (Config->CurrentForm == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    } else {
      EFI_STATUS Status;
      CHAR8 *GuidStr;
      GuidStr = AllocateZeroPool(Length + 1);
      if (NULL == GuidStr) {
        DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(GuidStr, Text8, Length);
      Config->CurrentForm->CurrentEntry->SecureGrayGuid = 
        AllocateZeroPool (sizeof(EFI_GUID));
      Status = StringToGuid_L(GuidStr, 
        Config->CurrentForm->CurrentEntry->SecureGrayGuid);
      FreePool (GuidStr);
      DEBUG ((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    }
    break;

  case ST_KGUID:
  case ST_GUID:
  case ST_EGUID:
  case ST_FGUID:
    if (Config->CurrentForm == NULL) {
      return EFI_INVALID_PARAMETER;
    } else {
      CHAR8 *GuidStr;
      GuidStr = AllocateZeroPool(Length + 1);
      if (NULL == GuidStr) {
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(GuidStr, Text8, Length);
      if (State == ST_EGUID) {
        Config->CurrentForm->CurrentEntry->GuidStr = GuidStr;
      } else if (State == ST_FGUID) {
        Config->CurrentForm->GuidStr = GuidStr;
      } else {
        Config->CurrentForm->CurrentModule->GuidStr = GuidStr;
      }
    }
    break;

  case ST_FILTER_STR:
    if (Config->CurrentForm == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    } else {
      CHAR16 *FilterStr = NULL;
      CHAR16 *NextStr, *CurPtr;
      UINTN RestLen, Offs;
      CHAR16 *FilterRes;
            
      FilterStr = AllocateZeroPool(sizeof (*FilterStr) * (Length + 1));
      if (FilterStr == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
      FilterRes = AllocateZeroPool(sizeof (*FilterRes) * (Length + 1));
      if (FilterRes == NULL) {
        FreePool (FilterStr);
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(FilterStr, &Text[1], sizeof (*FilterStr) * (Length - 2));
      RestLen = Length;

      for (NextStr = FilterStr, CurPtr = FilterStr;;) {
        if (RestLen <= 1) {
          break;
        }
        NextStr = StrStr(CurPtr, L"\\");
        if (NextStr == NULL) {
          break;
        }
        Offs = (NextStr - CurPtr);
        DEBUG ((EFI_D_INFO, "Offs=%d\n", Offs));
        CurPtr += Offs;
        CopyMem (CurPtr, &NextStr[1], (RestLen - 1) * sizeof (*FilterStr));
        RestLen -= Offs;        
      }

      DEBUG ((EFI_D_INFO, "\"%s\"\n", FilterStr));
      HexString16ToByteBuf(FilterStr,(UINT8*)FilterRes, Length);
      DEBUG ((EFI_D_INFO, "\"%s\"\n", FilterRes));
      FreePool (FilterStr);
      Config->CurrentForm->CurrentEntry->FilterStr = FilterRes;
    }
    break;

  case ST_MN_LIST:
    if (Config->CurrentForm == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    } else {      
      CHAR8 *StrMatch, *StrStart;
      UINTN Len;
      if (Config->CurrentForm->CurrentEntry->MenuInfo != NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      StrMatch = AsciiStrStr(Text8, "\"");
      if (NULL == StrMatch) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      StrStart = StrMatch + 1;
      StrMatch = AsciiStrStr(StrStart, "\"");
      if (NULL == StrMatch) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      *StrMatch = '\0';
      Len = AsciiStrLen(StrStart)*sizeof(CHAR16) + sizeof(CHAR16);
      Config->CurrentForm->CurrentEntry->MenuInfo = AllocateZeroPool(Len);
      if (NULL == Config->CurrentForm->CurrentEntry->MenuInfo) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
      }
      AsciiStrToUnicodeStr( StrStart, Text );
      EncodeCP1251Str(Text);
      
      CopyMem(Config->CurrentForm->CurrentEntry->MenuInfo, Text, Len);
    }
    break;

  case ST_FSDEV:
    if (Config->DevDescStr != NULL) {
      break;
    }
    Config->DevDescStr = AllocateZeroPool((Length << 1) + sizeof(CHAR16));
    if (NULL == Config->DevDescStr) {
      break;
    }
    StrCpy(Config->DevDescStr, Text);
    break;

  case ST_TOKENDEVPATH:
    {
      CHAR16 *StrBeg, *StrEnd;
      if (Config->TokenDevPathStr != NULL) {
        break;
      }            
      StrBeg = StrStr(Text, L"\"");
      if (NULL == StrBeg) {
        break;
      }
      StrBeg++;
      StrEnd = StrStr(StrBeg, L"\"");
      if (NULL == StrEnd) {
        break;
      }
      *StrEnd = L'\0';
      Config->TokenDevPathStr = AllocateZeroPool(
        (Length << 1) + sizeof(CHAR16));
      if (NULL == Config->TokenDevPathStr) {
        break;
      }
      StrCpy(Config->TokenDevPathStr, StrBeg);
    }
    break;

  case ST_PCIDA:
    if (Config->PciDaStr != NULL) {
      break;
    }
    Config->PciDaStr = AllocateZeroPool((Length << 1) + sizeof(CHAR16));
    if (NULL == Config->PciDaStr) {
      break;
    }
    StrCpy(Config->PciDaStr, Text);
    break;
    
  case ST_OBJDESC:
    if (Config->ObjDescStr != NULL) {
      break;
    }
    Config->ObjDescStr = AllocateZeroPool((Length << 1) + sizeof(CHAR16));
    if (NULL == Config->ObjDescStr) {
      break;
    }
    //StrCpy(Config->ObjDescStr, Text);
    UnicodeSPrint(Config->ObjDescStr, (Length << 1) + sizeof(CHAR16),
      L"%s", Text);
    //EncodeCP1251Str(Config->ObjDescStr);
    break;
    
  case ST_WORK_MODE:
    if (Config->WorkMode != MB_WORK_MODE_UNDEF) {
      return EFI_ABORTED;
    }
    if (StrCmp (Text, L"WIFI") == 0) {
      Config->WorkMode = MB_WORK_MODE_WIFI;
    } else {
      Config->WorkMode = MB_WORK_MODE_WIFI_NB;
    }
    break;
    
  case ST_PLATFORM_GUID:
    if (Config->PlatformGuidStr != NULL) {
      break;
    }
    {
      Config->PlatformGuidStr = AllocateZeroPool(Length + 1);
      if (NULL == Config->PlatformGuidStr) {
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(Config->PlatformGuidStr, Text8, Length);
    }
    break;

  case ST_PLATFORM_NAME:
    if (Config->PlatformNameStr != NULL) {
      break;
    }
    {
      Config->PlatformNameStr = AllocateZeroPool(Length + 1);
      if (NULL == Config->PlatformNameStr) {
        return EFI_OUT_OF_RESOURCES;
      }
      CopyMem(Config->PlatformNameStr, Text8, Length);
    }
    break;

  case ST_BASEADDRESS:
  case ST_KENTRYPOINT:
  case ST_KBASEADDRESS:
  case ST_UNCOMPRESS:
  case ST_KUNCOMPRESS:
    break;

  default:
    return EFI_INVALID_PARAMETER;
  }
    
  return EFI_SUCCESS;
}

/* simpler than dealing with strcasecmp and more efficient as we only
   need to fold the incoming text */
#define FOLD(c) ((c < 'A' || c > 'Z') ? c : (c + 'a' - 'A'))

static int
ConfigCallback(
  IN int event,
  IN const char* txt,
  IN int len,
  IN OUT void* user
  )
{
  EFI_STATUS Status;
  MULTIBOOT_CONFIG *Config = (MULTIBOOT_CONFIG*) user;
  const char* name;
  UINT32 i, j, match = 0, Next, Length = (UINT32) len;

  Next = Config->State; /* stay in same state */
#if 0
  MsgDebugPrint("At enter: ");
  XmlConfigShowState(Config->State);
#endif

  for(i=0; gConfigStateTable[i].State != ST_ERROR_TAG; i++) {
    if(gConfigStateTable[i].State == Config->State &&
        gConfigStateTable[i].Event == (UINT32) event) {
      if(gConfigStateTable[i].Name) {          /* if we have a name */

        if(gConfigStateTable[i].Length == (UINT32) len) {  /* same length? */
          match = 1; /* assume match */
          name = gConfigStateTable[i].Name;
          for(j=0; j < Length; j++) {
            /* only case fold the the incoming txt tags */
            //            DEBUG((EFI_D_ERROR, "%x:%x", name[j], txt[j]));
            if(name[j] != FOLD(txt[j])) {
              match = 0; /* doesn't match */
              break;
            }
          }
        }
      } else {
        match = 1; /* no name, match implicitly */
      }

      if(match) {        
        ParserText = AllocateZeroPool((Length + 1) << 1);
        if (ParserText == NULL) {
          DEBUG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
          return 0;
        }
        Status = ParseConfig( 
            (CHAR8*) txt,
            Length,
            Config->State, 
            gConfigStateTable[i].Next,
            gConfigStateTable[i].Emit, 
            Config
            );
        FreePool(ParserText);
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "%a.%d error! Status=0x%X\n", 
            __FUNCTION__, __LINE__, Status));
          return 0;
        }

        Next = gConfigStateTable[i].Next;
        break;
      } 
    }
  }

  Config->State = Next;
#if 0
  MsgDebugPrint("At exit: ");
  XmlConfigShowState(Config->State);
#endif

  return match;
}

/**
  Read the EFI variable (VendorGuid/Name) and return a dynamically allocated
  buffer, and the size of the buffer. If failure return NULL.

  @param  Name                  String part of EFI variable name
  @param  VendorGuid            GUID part of EFI variable name
  @param  VariableSize          Returns the size of the EFI variable that was read

  @return                       Dynamically allocated memory that contains a copy of the EFI variable
  Caller is responsible freeing the buffer.
  @retval NULL                  Variable was not read

 **/
VOID *
EFIAPI
MultibootGetVariableAndSize (
    IN  CHAR16              *Name,
    IN  EFI_GUID            *VendorGuid,
    OUT UINTN               *VariableSize
    )
{
  EFI_STATUS  Status;
  UINTN       BufferSize;
  VOID        *Buffer;

  Buffer = NULL;

  //
  // Pass in a zero size buffer to find the required buffer size.
  //
  BufferSize  = 0;
  Status      = gRT->GetVariable (Name, VendorGuid, NULL, &BufferSize, Buffer);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    //
    // Allocate the buffer to return
    //
    Buffer = AllocateZeroPool (BufferSize);
    if (Buffer == NULL) {
      return NULL;
    }
    //
    // Read variable into the allocated buffer.
    //
    Status = gRT->GetVariable (Name, VendorGuid, NULL, &BufferSize, Buffer);
    if (EFI_ERROR (Status)) {
      BufferSize = 0;
    }
  }

  *VariableSize = BufferSize;
  return Buffer;
}


static VOID
SaveErrorPosition(
  IN tinyxml_t *tinyxml,
  IN CHAR8 *ConfigTest,
  MULTIBOOT_CONFIG *Config)
{
  UINTN i;
  UINTN Line;
  UINTN Position;

  for (i = 0, Line = 1, Position = 1; i <= (UINTN) tinyxml->haltix; i++) {
    if(ConfigTest[i] == 0xA) {
      Line++;
      Position=1;
      continue;
    }

    if(ConfigTest[i] == 0xD) {
      continue;
    }
    Position++;
  }
  
  Config->ErrorPos = Position;
  Config->ErrorLine = Line;
#if 1
  DEBUG((EFI_D_ERROR, "ErrorPos=%d ErrorLine=%d\n\n", Position, Line));
#endif
}


static VOID
ConfigWriteTest(
  IN CHAR8 *FilePath
  )
{
  EFI_FILE_HANDLE Pf = NULL;
  UINT8 FileData[80];
  UINTN FileDataLen;
  EFI_STATUS Status;

  Pf = LibFsOpenFile(FilePath, EFI_FILE_MODE_READ, 0);
  if (NULL == Pf) {
    return;
  }
  
  FileDataLen = sizeof(FileData);
  Status = LibFsReadFile(Pf, &FileDataLen, FileData);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  FileData[0] = 'T';
  FileData[1] = 'E';
  FileData[2] = 'S';
  FileData[3] = 'T';
  FileData[4] = 'E';
  FileData[5] = 'S';
  
  Status = LibFsWriteFile(Pf, &FileDataLen, FileData);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
_exit:
  if (Pf != NULL) {
    LibFsCloseFile(Pf);
  }
}


EFI_STATUS
XmlConfigRead(
  IN OUT MULTIBOOT_CONFIG *Config,
  IN CHAR8 *ConfigTest,
  IN UINTN Size
  )
{

  tinyxml_t *tinyxml;

//  tinyxml = tinyxml_new(DEF_XMLBUFSZ, ConfigCallback, Config);
  tinyxml = tinyxml_new((int)Size, ConfigCallback, Config);
  tinyxml_feed(tinyxml, ConfigTest, (int) Size);

  if(tinyxml->halt) {
    SaveErrorPosition(tinyxml, ConfigTest, Config);
    return EFI_INVALID_PARAMETER;
  }

  tinyxml_free(tinyxml);
  return EFI_SUCCESS;
}

