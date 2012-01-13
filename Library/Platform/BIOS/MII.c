/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/MII.h>
#include <Library/DeviceManager/DeviceManagerInterface.h>

static MULTIBOOT_CONFIG *CurrentConfig;
static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
static EFI_HII_HANDLE CurrentHiiHandle;
static int CurrentEvent;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;
static struct tMainFvInfo *pMainFv;
static BOOLEAN bMiiFormExitFlag, bGlobalExitFlag;
static enum {
             MII_MODE_EXIT, 
             MII_MODE_DATE_TIME_SETUP, 
             MII_MODE_RESTORE_FROM_USB, 
             MII_MODE_CREATE_ADM_USR,
             MII_MODE_CERTIFICATE_CTRL,
             MII_MODE_DEV_MANAGER_ID
  } eMiiSelectedMode = MII_MODE_EXIT;
static CHAR8 **FilesList;
static UINT32 FilesListCount;
static CHAR8 RestoreFromUsbBaseDir[255];


static VOID
FreeHiiResources(
  VOID
  )
{
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle(StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle(EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }
}

int
MIICheckPass(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN PassLen, TmpLen;
  CHAR8 PassBuf[21];
  int retval = -1;
  CHAR16 *HiiString;
  
  ConOut = gST->ConOut;

  HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_ADM_PASSWD_PROMPT),
          Language);
  ShowPassWindow(HiiGetString(HiiHandle, STRING_TOKEN(STR_MII_TITLE), Language), 
          HiiString);

  TmpLen = ReadLineAndHide(PassBuf, sizeof(PassBuf) - 1, TRUE);
  if (TmpLen == 0) {
    goto _exit;
  }
  PassLen = TmpLen;
  
  if (-1 == CheckDataWithGuid(BIOS_PASS_GUID, PassBuf, PassLen, pMainFv)) {
    goto _exit;
  }

  retval = 0;
_exit:
  ConOut->ClearScreen(ConOut);
  if (retval) {
    HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_WRONG_PASSWD),
      Language);
    ShowErrorPopup(HiiHandle, HiiString);
  }
  return retval;
}


VOID
MIISetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}

EFI_STATUS
MIIPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;
  CHAR8 TmpStr[512];
  
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bMiiFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  
  if (Action == EFI_BROWSER_ACTION_CHANGING && 
      QuestionId >= RESTORE_USERS_FROM_USB_START_QUID && 
      QuestionId <= RESTORE_USERS_FROM_USB_END_QUID) {
    UINT32 Index;

    Index = (UINT32)(QuestionId - RESTORE_USERS_FROM_USB_START_QUID - 2);
    if (FilesListCount == 0 || FilesList == NULL || Index >= FilesListCount) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    
    AsciiSPrint(TmpStr, sizeof(TmpStr), "%a%a", RestoreFromUsbBaseDir, 
      FilesList[Index]);
    Status = UsersRestoreAllFromCsvFile(TmpStr);
    if (EFI_ERROR(Status)) {
      UsersStorageInitEmpty();
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_USER_CARDS_RESTORE_ERROR), NULL));
    } else {
      if (EFI_SUCCESS != UserFindRecordByAuthType(AUTH_TYPE_LOG_PASS) &&
          GetMiiMode()) {
        UsersStorageInitEmpty();
        ShowErrorPopup(CurrentHiiHandle, 
          HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_USER_CARDS_RESTORE_ERROR), NULL));
        return EFI_ABORTED;
      }
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bGlobalExitFlag = TRUE;
      ShowSuccessPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_USER_CARDS_RESTORE_SUCCESS), NULL));
    }
    return Status;
  }

  switch (QuestionId) {
  case MII_CREATE_ADMIN_CARD:
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      eMiiSelectedMode = MII_MODE_CREATE_ADM_USR;
      bMiiFormExitFlag = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    break;

  case MII_RESTORE_FROM_USB:
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      eMiiSelectedMode = MII_MODE_RESTORE_FROM_USB;
      bMiiFormExitFlag = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    break;
    
  case MII_DATE_TIME_SETUP:
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      eMiiSelectedMode = MII_MODE_DATE_TIME_SETUP;
      bMiiFormExitFlag = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    break;
    
  case MII_CERTIFICATE_CTRL:
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      eMiiSelectedMode = MII_MODE_CERTIFICATE_CTRL;
      bMiiFormExitFlag = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    break;

  case MII_DEV_MANAGER_ID:
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      eMiiSelectedMode = MII_MODE_DEV_MANAGER_ID;
      bMiiFormExitFlag = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }  
    break;
    
  default:
    break;
  }
  return EFI_SUCCESS;
}


static int
MIICreateStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN VOID *EndOpCodeHandle
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_MII_GUID;
  EFI_FORM_ID FormId = MII_PAGE_ID;

  CurrentForm = GetFormById(CurrentConfig, FormId);
  if (NULL == CurrentForm) {
    return -1;
  }
  
  ListEntry = CurrentForm->EntryHead.ForwardLink;

  while (ListEntry != &CurrentForm->EntryHead) {
    Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

    Token = HiiSetString (HiiHandle, 0, Entry->Name, NULL);
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    QuestionId = (EFI_QUESTION_ID) (Entry->Index);

    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);

    ListEntry  = ListEntry->ForwardLink;
  }

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);
  
  return 0;
}


static int
MIIShowPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_MII_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status;
  int retval = -1;
  
  FreeHiiResources();

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
  StartLabel->Number       = LABEL_MII_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_MII_LIST_END;

  if (-1 == MIICreateStrings(HiiHandle, StartOpCodeHandle, EndOpCodeHandle)) {
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
      &FormSetGuid, MII_PAGE_ID, NULL, &ActionRequest);
    
    if (bMiiFormExitFlag) {
      break;
    }
  } while (CurrentEvent == 0);
  
  retval = 0;

_exit:  
  return retval;
}

static int ObtainFnameParams(
  IN CHAR16 *PatternPath,
  IN OUT CHAR8 *Fname,
  IN OUT CHAR8 *Pattern
  )
{
  UINTN Len;
  CHAR16 *StrPtr, SaveSymbol;
  
  Len = StrLen(PatternPath);
  if (Len == 0) {
    return -1;
  }
  
  StrPtr = PatternPath + Len - 1;
  
  while (Len) {
    if (*StrPtr == L'\\') {
      C16ToC8StrCpy(StrPtr + 1, Pattern);
      SaveSymbol = *StrPtr;
      *StrPtr = L'\0';
      C16ToC8StrCpy(PatternPath, Fname);
      *StrPtr = SaveSymbol;
      return 0;
    }
    Len--;
    StrPtr--;
  }
  return -1;
}

static int
MIIRestoreFromUsbStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN VOID *EndOpCodeHandle
  )
{
  LIST_ENTRY *ListEntry, *ListEntryModules;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_MII_GUID;
  EFI_FORM_ID FormId = RESTORE_USERS_FROM_USB_PAGE_ID;
  MULTIBOOT_MODULE *pModule;
  CHAR8 Fname[255], Pattern[255];
  UINT32 i;
  CHAR16 Str16[256], *HiiStr1, HiiStr2[] = L")";
  static BOOLEAN bUpdated;
  
  FilesList = NULL;

  CurrentForm = GetFormById(CurrentConfig, FormId);
  if (NULL == CurrentForm) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return -1;
  }
  
  if (!bUpdated) {
    HiiStr1 = HiiGetString(HiiHandle, STR_FW_VERSION, NULL);
    HiiStr1[0] = L'(';
    VfrFwVersionString(HiiHandle, HiiStr1, STR_RECOVER_USERS_FROM_USB_TITLE, 
      HiiStr2);
    bUpdated = TRUE;
  }
  
  ListEntry = CurrentForm->EntryHead.ForwardLink;
  Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

  ListEntryModules = Entry->ModuleHead.ForwardLink;
  if(IsListEmpty(&Entry->ModuleHead)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return -1;
  }
  pModule = _CR( ListEntryModules, MULTIBOOT_MODULE, ListEntry );
  if (pModule->DevPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return -1;
  }
  if (-1 == ObtainFnameParams(pModule->DevPath, Fname, Pattern)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return -1;
  }
  
  FilesList = LibFsObtainFileListByMask(Fname, Pattern, &FilesListCount);
  if (NULL == FilesList) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    FilesListCount = 0;
  }
  
  Token = HiiSetString (HiiHandle, 0, Entry->Name, NULL);
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  QuestionId = (EFI_QUESTION_ID) (Entry->Index);

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
      HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

  ListEntry  = ListEntry->ForwardLink;

  QuestionId++;
  
  AsciiSPrint(RestoreFromUsbBaseDir, sizeof(RestoreFromUsbBaseDir), 
    "%a\\", Fname);
  UnicodeSPrint(Str16, sizeof(Str16), L"%a\\", Fname);
  Token = HiiSetString (HiiHandle, 0, Str16, NULL);
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);

  QuestionId++;

  if (FilesListCount) {
    for (i = 0; i < FilesListCount; i++) {
     UnicodeSPrint(Str16, sizeof(Str16), L"    %a", FilesList[i]);
      Token = HiiSetString (HiiHandle, 0, Str16, NULL);
      HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

      HiiCreateActionOpCode(StartOpCodeHandle, 
        (EFI_QUESTION_ID)(QuestionId + i), Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);
    }
  } else {
    HiiStr1 = HiiGetString(HiiHandle, STRING_TOKEN(STR_FILES_ABSENT_SPEC1), 
      NULL);
    UnicodeSPrint(Str16, sizeof(Str16), L"%s %a", HiiStr1, Pattern);
    Token = HiiSetString (HiiHandle, 0, Str16, NULL);
    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
      HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  }

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);

  return 0;
}

static int
MIIRestoreFromUsb(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_MII_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status;
  int retval = -1;

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
  StartLabel->Number       = LABEL_RECOVER_USERS_FROM_USB_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_RECOVER_USERS_FROM_USB_LIST_END;

  if (-1 == MIIRestoreFromUsbStrings(HiiHandle, StartOpCodeHandle, 
      EndOpCodeHandle)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
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
      &FormSetGuid, RESTORE_USERS_FROM_USB_PAGE_ID, NULL, &ActionRequest);
    
    if (bMiiFormExitFlag) {
      break;
    }
  } while (CurrentEvent == 0);
  
  retval = 0;

_exit:
  FreeHiiResources();

  DEBUG((EFI_D_ERROR, "%a.%d: done!\n", __FUNCTION__, __LINE__));
  
  return retval;
}


VOID
MIIStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Config,
  IN struct tMainFvInfo *pmfvi,
  IN CHAR8 *Language
  )
{
  EFI_STATUS Status;

  SetMiiMode(TRUE);
  
  if (CurrentConfig == NULL) {
    goto _exit;
  }
  CurrentEvent = 0;
  pMainFv = pmfvi;  
  
 CurrentHiiHandle = HiiHandle;
  
  if (-1 == MIICheckPass(CurrentHiiHandle, Language)) {
    goto _exit;
  }
  
  gBS->SetWatchdogTimer (0, 0x0000, 0x00, NULL);
  
  do {
    bMiiFormExitFlag = bGlobalExitFlag = FALSE;
    eMiiSelectedMode = MII_MODE_EXIT;
    
    MIIShowPage(CurrentHiiHandle);
    
    switch (eMiiSelectedMode) {
    case MII_MODE_RESTORE_FROM_USB:
      MIIRestoreFromUsb(CurrentHiiHandle);
      if (FilesList) {
        DestroyStringsArray(FilesList, FilesListCount);
      }
      FilesList = NULL;
      FilesListCount = 0;
      break;

    case MII_MODE_CREATE_ADM_USR:
      if (EFI_SUCCESS != UsersStart(CurrentHiiHandle, Language, 
          USERS_PAGE_TYPE_CREATE)) {
        break;
      }
      DEBUG((EFI_D_ERROR, "GetUserPageCurrentEvent()=0x%X\n", 
        GetUserPageCurrentEvent()));
      if (USER_CREATE_BUTTON_ID == GetUserPageCurrentEvent()) {        
        bGlobalExitFlag = TRUE;
      }
      break;
      
    case MII_MODE_DATE_TIME_SETUP:
      DateTimePageStart(CurrentHiiHandle, Language);
      break;

    case MII_MODE_DEV_MANAGER_ID:      
      DeviceManagerStart ();
      break;

    default:
      Status = AreYouSureWarning(CurrentHiiHandle, 
        STRING_TOKEN(STR_EXIT_AND_REBOOT), 
        STRING_TOKEN(STR_YOUR_CHOISE));
      if (!EFI_ERROR(Status)) {
        bGlobalExitFlag = TRUE;
      }
      break;
    }
  } while (!bGlobalExitFlag);
  
  FreeHiiResources();
_exit:  
  SetMiiMode(FALSE);
}
