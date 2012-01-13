/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/MainPage.h>
#include <Library/Lib/PciDevList.h>


extern UINT8 MainPagevfrBin[];


static MULTIBOOT_CONFIG *CurrentConfig;
static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
static EFI_HII_HANDLE CurrentHiiHandle;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;
static BOOLEAN bMainPageFormExitFlag;
static UINTN CurrentEvent;
static BOOLEAN bFailureModeEnable, bBlockingMode;
STATIC BOOLEAN bAdmModeRdOnly;
extern VOID InitApmdz(VOID);

VOID
MainPageSetAdminModeRdOnly (
  IN BOOLEAN bFlag
  )
{
  bAdmModeRdOnly = bFlag;
}

EFI_STATUS
MainPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  static int TimeOut;
  static BOOLEAN bDisabledTimeOut;
  EFI_STATUS Status;
  
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  switch (Action)  {
  case EFI_BROWSER_ACTION_FORM_CLOSE:
    bMainPageFormExitFlag = TRUE;
    return EFI_SUCCESS;
  
  case EFI_BROWSER_ACTION_CHANGING:
    if (QuestionId == MP_LEGACY_BIOS_ITEM1_ID) {
      InitApmdz();
      return EFI_SUCCESS;
    }
    if (QuestionId == MP_TIME_OUT_ID) {
      break;
    }
    bMainPageFormExitFlag = TRUE;
    if (CurrentEvent != MP_TIME_OUT_ID) {
      CurrentEvent = QuestionId;
    }
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  }

  switch (QuestionId) {
  case MP_ADDITIONAL_LOADING_MODE_1_ID:
  case MP_ADDITIONAL_LOADING_MODE_2_ID:
  case MP_ADDITIONAL_LOADING_MODE_3_ID:
    break;
    
  case MP_REGULAR_LOADING_MODE_ID:
    if (Action != EFI_BROWSER_ACTION_FORM_OPEN) {
      HistoryAddRecord(HEVENT_REGULAR_LOADING_MODE, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
    }
    break;
  
  case MP_ADMIN_MODE_ID:
    break;
  
  case MP_FAILURE_MODE_ID:
    break;
  
  case MP_RECOVER_MODE_ID:
    break;
  
  case MP_TIME_OUT_ID:
   if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
      TimeOut = MP_DEFAULT_TIME_OUT;
      bDisabledTimeOut = FALSE;
    } else {
      Status = gBS->CheckEvent(gST->ConIn->WaitForKey);
     if (!EFI_ERROR(Status)) {
        bDisabledTimeOut = TRUE;
      }
    }
    
    if (TimeOut == 0 && !bDisabledTimeOut) {
      CurrentEvent = MP_TIME_OUT_ID;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      gBS->SignalEvent (gST->ConIn->WaitForKey);
      bMainPageFormExitFlag = TRUE;
      break;
    }
    if (Action == EFI_BROWSER_ACTION_CHANGING && Type == 0) {
      if (!bDisabledTimeOut) {
        TimeOut--;
      }
      if (Value != NULL) {
        Value->u8 = (UINT8)(TimeOut & 0xFF);
      }
    }
    break;

  default:
    bMainPageFormExitFlag = FALSE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    CurrentEvent = 0;
    break;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
CreateMainPageStrings(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_MAIN_PAGE_GUID;
  EFI_FORM_ID FormId = MAIN_PAGE_ID;
  UINT8 *VfrData;
  UINT8 OtherFlags = 0;
  STATIC BOOLEAN bTitleUpdate = FALSE;

  CurrentForm = GetFormById(CurrentConfig, FormId);
  if (NULL == CurrentForm) {
    return EFI_INVALID_PARAMETER;
  }

  if (!bTitleUpdate) {
    VfrFwVersionString(HiiHandle, L"", STRING_TOKEN(STR_FW_VERSION), L"");
    bTitleUpdate = TRUE;
  }
  
  ListEntry = CurrentForm->EntryHead.ForwardLink;
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  while (ListEntry != &CurrentForm->EntryHead) {
    Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );
    
    if (Entry->Index == MP_LEGACY_BIOS_ITEM1_ID) {
      if (!PciDevPresent(0xF005, 0x1172)) {
        goto _next_item;
      }
    }
    
    Token = HiiSetString (HiiHandle, 0, Entry->Name, NULL);
    QuestionId = (EFI_QUESTION_ID) (Entry->Index);
    if (Entry->GuidStr && 
        AsciiStrCmp(Entry->GuidStr, MP_LOADING_FROM_USB_GUID) == 0) {        
      goto _next_item;
    }


    DEBUG((EFI_D_ERROR, "%s\n", Entry->Name));
    
    OtherFlags = 0;
    
    if (bBlockingMode || MainMenuAdmModeLocked()) {
      if (Entry->GuidStr && 
          AsciiStrCmp(Entry->GuidStr, MP_ADMIN_MODE_GUID) != 0) {
        OtherFlags |= EFI_IFR_FLAG_READ_ONLY;
      }
    }

    if (bAdmModeRdOnly && 
        AsciiStrCmp(Entry->GuidStr, MP_ADMIN_MODE_GUID) == 0) {
      OtherFlags |= EFI_IFR_FLAG_READ_ONLY;
    }
    
    if (Entry->GuidStr && 
        AsciiStrCmp(Entry->GuidStr, MP_TIME_OUT_GUID) == 0) {
      if (bBlockingMode) {
        goto _next_item;
      }
      
      VfrData = VfrCreateRefreshNumericTimeOut(StartOpCodeHandle,
        MP_DEFAULT_TIME_OUT, (EFI_QUESTION_ID) MP_TIME_OUT_ID, 
        Token, HelpToken);
    } else {
    
      if (Entry->GuidStr && 
          AsciiStrCmp(Entry->GuidStr, MP_FAILURE_MODE_GUID) == 0) {
        if (!bFailureModeEnable) {
          goto _next_item;
        }
      }
      
      VfrData = HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK | OtherFlags, 0);
    }

    if (NULL == VfrData) {
      return EFI_OUT_OF_RESOURCES;
    }

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
_next_item:
    ListEntry  = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}


UINTN
ShowMainPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_MAIN_PAGE_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (StartOpCodeHandle == NULL) {
    goto _exit;
  }

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (EndOpCodeHandle == NULL) {
    goto _exit;
  }

  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      StartOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_MAIN_PAGE_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_MAIN_PAGE_LIST_END;

  Status = CreateMainPageStrings(HiiHandle);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    goto _exit;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, MAIN_PAGE_ID, NULL, &ActionRequest);
    
    if (bMainPageFormExitFlag) {
      break;
    }
  } while (CurrentEvent == 0);
  
_exit:  
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }

  return CurrentEvent;
}


VOID
MainPageBlockingMode(
  IN BOOLEAN Enable
  )
{
  bBlockingMode = Enable;
}

VOID
MainPageFailureMode(
  IN BOOLEAN Enable
  )
{
  bFailureModeEnable = Enable;
}


VOID
MainPageSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}



UINTN
MainPageStart(
  IN EFI_HANDLE DriverHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_MAIN_PAGE_GUID;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  CleanKeyBuffer();

  ASSERT(CurrentConfig != NULL);
  
  bMainPageFormExitFlag = FALSE;
  CurrentEvent = 0;
  
  if (NULL == CurrentHiiHandle) {
    CurrentHiiHandle = HiiAddPackages (&FormSetGuid, DriverHandle,
      MainPagevfrBin, LibStrings, NULL);
  }
  
  return ShowMainPage(CurrentHiiHandle);
}
