/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/LdapAuthDxe.h>
#include <Library/Lib/PlatformCommon.h>
#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/ChipsetCfgLib.h>
#include <Protocol/GlobalConfigDxe.h>
#include <Library/PciLib.h>
#include <Library/BootMngrLib.h>
#include <Library/UserManagerLib.h>
#include <Protocol/DrmHelperProtocol.h>
#include <Protocol/HistoryHandlerProto.h>

//#include "ProcessingErrors.h"

USER_INFO_LOG_PASS *pCurrUserLoginPass;
extern MULTIBOOT_DATA *gMultibootData;
extern struct tMainFvInfo MainFvInfo;

static LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;
STATIC HISTORY_HANDLER_PROTOCOL *gHistoryHandlerProtocol;
STATIC UINT8 EndRemoteSessionMode = END_MODE_WAIT_FOR_CMD;
STATIC BOOLEAN bBlockMbRemoteAccess = FALSE;


VOID
BlockMultibootRemoteAccess (
  IN BOOLEAN bBlock
  )
{
  bBlockMbRemoteAccess = bBlock;
}

static
VOID
ProceedUserNameFail(
  VOID
  )
{
  UpdateUserNameFailCounter();
  CheckForUserNameFail();
  ResetUserPasswordFailCounter();
}

CHAR16*
GetEntryNameByIndex(
  UINTN Index
  )
{
  MULTIBOOT_ENTRY *MbEntry;
  
  MbEntry = FindEntryByIndex(&gMultibootData->Config, Index);
  if (MbEntry == NULL) {
    return NULL;
  }
  return MbEntry->Name;
}


EFI_STATUS
GetPciBackHideStr(
  IN UINTN ModeIndex,
  IN OUT CHAR16 *Str,
  IN UINTN Len
  )
{
  UINT8 *BufStart;
  UINTN Amount, i;
  EFI_STATUS Status;
  DA_DEV_REC *Dev;
  UINTN Tmp;
  CHAR16 TmpStr16[40], *SrcStr;

  Status = GetSetupPciDevListByIndex(ModeIndex, &BufStart, &Amount);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status = 0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (Amount == 0) {
    return EFI_NOT_FOUND;
  }

  SrcStr = Str;

  UnicodeSPrint(Str, Len, L"xen-pciback.hide=");
  Tmp = StrLen(L"xen-pciback.hide=");
  Str += Tmp;
  Len -= Tmp;

  for (i = 0; i < Amount; i++) {
    Dev = (DA_DEV_REC*)BufStart;

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"(%02x:%02x.%x)", 
      Dev->Bus, Dev->Dev, Dev->Func);
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      Dev->Bus, Dev->Dev, Dev->Func));

    UnicodeSPrint(Str, Len, L"%s", TmpStr16);
    Tmp = StrLen(TmpStr16);
    Str += Tmp;
    Len -= Tmp;
    
    BufStart += sizeof(DA_DEV_REC);
  }
  DEBUG((EFI_D_ERROR, "Result=%s\n", SrcStr));
  return EFI_SUCCESS;
}

EFI_STRING_ID
GetStringErrUnknownModuleFmt(
  VOID
  )
{
  return STRING_TOKEN(STR_ERR_UNKNOWN_MODULE_FORMAT);
}


EFI_STRING_ID
GetStringErrorIntegrity(
  VOID
  )
{
  return STRING_TOKEN (STR_ERR_INTEGRITY);
}


EFI_STRING_ID
GetStringSuccess(
  VOID
  )
{
  return STRING_TOKEN (STR_SUCCESS);
}


EFI_STRING_ID
GetStringError(
  VOID
  )
{
  return STRING_TOKEN (STR_ERROR);
}


EFI_STRING_ID
GetStringFileHashCheck(
  VOID
  )
{
  return STRING_TOKEN (STR_FILE_HASH_CHECK);
}


EFI_STRING_ID
GetStringLoadingOsModuleError(
  VOID
  )
{
  return STRING_TOKEN(STR_LOADING_OS_MODULE_ERR);
}

EFI_STRING_ID
GetStringWaitForLoadingOs(
  VOID
  )
{
  return STRING_TOKEN(STR_WAIT_FOR_LOADING_OS);
}

//------------------------------------------------------------------------------
/*! \brief Check a user name */
//------------------------------------------------------------------------------
int
CheckUserName8(
  IN UINTN NameLen,
  IN CHAR8 *LoginBuf,
  IN CHAR16 *UserName,
  IN UINTN UserNameMaxLen,
  IN EFI_HII_HANDLE CurrentHiiHandle
  )
{
  USER_INFO *pUserInfo;
  EFI_STATUS Status;
  int retval = USER_NOT_EXIST_OR_BLOCK;
  
  DEBUG((EFI_D_ERROR, "%a.%d: NameLen=%d\n", __FUNCTION__, __LINE__, NameLen));
  
  if (NameLen == 0) {
    goto _exit;
  }
  
  LoginBuf[NameLen] = 0;
  UnicodeSPrint(UserName, UserNameMaxLen, L"%a", LoginBuf);

  Status = UserFindRecordByNameWithThisAuth(AUTH_TYPE_LOG_PASS, UserName);
  
  if (EFI_NOT_FOUND == Status) {    
    HistoryAddRecord(HEVENT_USER_NAME_FAIL, USER_UNKNOWN_ID, SEVERITY_LVL_ERROR, 0);
    goto _exit;
  }
  
  if (EFI_SUCCESS != Status) {
    MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
  }
  
  pUserInfo = UserGetLastFoundedInfo();
  
  if (NULL == pUserInfo) {
    MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
  }
  
  if (SuOnlyMode() && ((pUserInfo->Flags & USER_SU_FLAG) == 0)) {
    goto _exit;
  }
  
  if (pUserInfo->AuthType == AUTH_TYPE_LOG_PASS) {
    pCurrUserLoginPass = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
    if (pCurrUserLoginPass == NULL) {
      MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
    }
    ResetUserNameFailCounter();

    retval = USER_AUTH_TYPE_LOG_PASS;
  }
  
_exit:
  if (USER_NOT_EXIST_OR_BLOCK == retval) {
    UpdateUserNameFailCounter();
  }
  CheckForUserNameFail();
  
  return retval;
}
//------------------------------------------------------------------------------


EFI_STATUS
EFIAPI
FormCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  switch(QuestionId) {
  case MII_CREATE_ADMIN_CARD:
  case MII_RESTORE_FROM_USB:
  case MII_DATE_TIME_SETUP:
  case MII_CERTIFICATE_CTRL:
  case MII_DEV_MANAGER_ID:
    MIIPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    break;
  
  case MP_REGULAR_LOADING_MODE_ID:
  case MP_ADMIN_MODE_ID:
  case MP_FAILURE_MODE_ID:
  case MP_RECOVER_MODE_ID:
  case MP_TIME_OUT_ID:
  case MP_LEGACY_BIOS_ITEM1_ID:
  case MP_ADDITIONAL_LOADING_MODE_1_ID:
  case MP_ADDITIONAL_LOADING_MODE_2_ID:
  case MP_ADDITIONAL_LOADING_MODE_3_ID:
    MainPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    break;
  
  case ADM_MAIN_PAGE_SERT_CTRL_ID:
  case ADM_MAIN_PAGE_USRS_CTRL_ID:
  case ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID:
  case ADM_MAIN_PAGE_INTEGRITY_CTRL_ID:
  case ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID:
  case ADM_MAIN_PAGE_COMPLEX_INSTALL_ID:
  case ADM_MAIN_PAGE_DATE_TIME_SETUP_ID:
  case ADM_MAIN_PAGE_ADM_VIRTUAL_ID:
  case ADM_MAIN_PAGE_BIOS_UPDATE_ID:
  case ADM_MAIN_PAGE_LOCAL_ADMIN_ID:
  case ADM_MAIN_PAGE_SU_PASS_ID:
  case ADM_MAIN_PAGE_SET_DAD_ID:
  case ADM_MAIN_PAGE_MEM_TEST_ID:
  case ADM_MAIN_PAGE_ADV_MENU_ID:
  case ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID:
  case ADM_MAIN_PAGE_DEV_MANAGER_ID:
  case ADM_MAIN_LEGACY_BIOS_ITEM1_ID:
  case ADM_MAIN_BOOT_MENU_ID:
  case ADM_MAIN_EQUIPMENT_MONITOR_ID:
  case ADM_MAIN_CHIPSET_CONFIG_ID:
  case ADM_MAIN_COMP_UNBLOCK_ID:
  case ADM_MAIN_BOOT_1_ID:
  case ADM_MAIN_BOOT_2_ID:
  case ADM_MAIN_BOOT_3_ID:
  case ADM_MAIN_AMT_FUNC:
  case ADM_MAIN_SYS_INFO:
    AdminMainPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    break;
  
  case HISTORY_VIEW_CLEAN_ID:
  case HISTORY_OUTSWAP_TO_USB_ID:
  case HISTORY_SEVERITY_LEVEL_ID:
  case HISTORY_ENABLE_AUTO_CLEAN_ID:
  case HISTORY_CLEAN_ALL_ID:
    HistoryPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    break;

  default:
    if ((QuestionId >= USERS_PAGE_ID && 
         QuestionId <= USER_TYPE_ID) ||
        QuestionId == USER_CREATE_BUTTON_ID ||
        (QuestionId >= USER_VIEW_START_ID && QuestionId < USER_DEL_START_ID) ||
        (QuestionId >= USER_DEL_START_ID && 
          QuestionId < USERS_VARSTORE_VAR_ID) ||
        (QuestionId >= USERS_CREATE_PAGE_ID && 
          QuestionId <= USERS_STORE_TO_CVS_FILE_ID) ||
        (QuestionId >= USERS_FILES_START_ID && 
          QuestionId <= USERS_FILES_END_ID) ||
        (QuestionId >= USERS_REMOTE_ACCESS_ID &&
          QuestionId <= USERS_LOAD_LIST_FROM_LDAP_ID)) {
      UsersPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    } else if (QuestionId >= RESTORE_USERS_FROM_USB_START_QUID && 
               QuestionId <= RESTORE_USERS_FROM_USB_END_QUID) {
      MIIPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    } else if (QuestionId >= HISTORY_VIEW_DEL_REC_START && 
               QuestionId <= HISTORY_VIEW_DEL_REC_END) {
      HistoryPageCallback(This, Action, QuestionId, Type, Value, ActionRequest);
    } else if ((QuestionId >= ADM_BIOS_UPDATE_FILES_START_ID && 
               QuestionId <= ADM_BIOS_UPDATE_FILES_END_ID) ||
               (QuestionId >= ADVANCED_MODE_START_QID && 
                QuestionId < LABEL_ADVANCED_MODE_PAGE_LIST_START)) {
      AdminMainPageCallback(This, Action, QuestionId, Type, 
        Value, ActionRequest);
    } else if (QuestionId >= PCI_DEV_LIST_LOAD_DEFAULTS_ID && 
               QuestionId <= LABEL_PCI_DEV_LIST_MODE_PAGE_LIST_START) {
      PciDevListCallback(This, Action, QuestionId, Type, 
        Value, ActionRequest);
    } else if (QuestionId >= INTEGRITY_VIEW_RES_START && 
               QuestionId <= INTEGRITY_VIEW_RES_END) {      
      IntegrityPageCallback(This, Action, QuestionId, Type, 
        Value, ActionRequest);
    } else if (QuestionId >= DBG_LOAD_PARAMS_START && 
               QuestionId <= DBG_LOAD_PARAMS_END) {

    } else if (QuestionId == RUN_BOOT_MANAGER) {
      AdminMainPageCallback(This, Action, QuestionId, Type, 
        Value, ActionRequest);
    }
    break;
  }

  //
  // Request to exit SendForm(), so as to switch to selected form
  //
  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
   *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  }

  return EFI_SUCCESS;
}


static
EFI_STATUS
SetupInit(
  VOID
  )
{
  EFI_STATUS Status;
  SETUP_VAR_PROTOCOL *pSetupProto;
  UINT8 *Data = NULL;
  UINTN RecordsNum;
  
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = gBS->LocateProtocol (
        &gSetupVarProtocolGuid,
        NULL,
        (VOID **)&pSetupProto
        );
  DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = pSetupProto->GetPciDaDevices(pSetupProto, &Data, &RecordsNum);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (!EFI_ERROR(Status)) {
    /* All OK */
    DEBUG((EFI_D_ERROR, "%a.%d RecordsNum=%d\n", __FUNCTION__, __LINE__, RecordsNum));
    /* Freeing data if allocated */
    if (Data) {
      FreePool(Data);
    }
    /* if pci da present we are done */
    //if (RecordsNum) {
    return Status;
    //}
  }
  
  Status = pSetupProto->SetDefaultPciDaDevices(pSetupProto);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS 
InitProtocols(
  IN MULTIBOOT_DATA *Data
  )
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
    (VOID **) &gHistoryHandlerProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }

  Data->Multiboot.ProcessingRemoteCtrlPkt = NULL;
  Data->Multiboot.GetCurrentHiiHandle     = GetCurrentHiiHandle;
  Data->Multiboot.GetDriverHandle         = GetDriverHandle;

  Status = gBS->InstallMultipleProtocolInterfaces(
        &Data->DriverHandle,
        &gMultibootProtocolGuid,
        &Data->Multiboot,
        NULL
        );

  if (EFI_ERROR(Status))
    return Status;
    
  //
  // Locate Hii Database protocol
  //
  Status = gBS->LocateProtocol (
        &gEfiHiiDatabaseProtocolGuid,
        NULL,
        (VOID **) &Data->HiiDatabase
        );


  if (EFI_ERROR(Status))
    return Status;

  //
  // Locate HiiString protocol
  //
  Status = gBS->LocateProtocol (
        &gEfiHiiStringProtocolGuid,
        NULL,
        (VOID **) &Data->HiiString
        );

  if (EFI_ERROR(Status))
    return Status;

  //
  // Locate Formbrowser2 protocol
  //
  Data->ConfigAccess.ExtractConfig = MbFakeExtractConfig;
  Data->ConfigAccess.RouteConfig = MbFakeRouteConfig;
  Data->ConfigAccess.Callback = FormCallback;

  Status = gBS->InstallProtocolInterface (
        &Data->DriverHandle,
        &gEfiHiiConfigAccessProtocolGuid,
        EFI_NATIVE_INTERFACE,
        &Data->ConfigAccess
        );

  if (EFI_ERROR(Status))
    return Status;

  Status = SetupInit();
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }
  ASSERT_EFI_ERROR (Status);
  return Status;
}


VOID
ShowErrorObject(
  VOID
  )
{
  struct tHashRecord *pRec = GetCorruptRecord();
  CHAR16 Text16[255];
  CHAR16 *HiiString;

  if (NULL == pRec) {
    return;
  }

  HiiString = HiiGetString (gMultibootData->HiiHandle,
        STRING_TOKEN (STR_OBJECT_INFO),
        gMultibootData->Config.Language);
  UnicodeSPrint(Text16, sizeof(Text16), L"%s: %g\n", HiiString, &pRec->Guid);
  MsgTextOut(Text16);
}

int
FailSaveModeCheckPass(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN struct tMainFvInfo *pMainFv
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN PassLen, TmpLen;
  CHAR8 PassBuf[PASSWORD_MAX_LEN + 1];
  int retval = -1;
  CHAR16 *HiiString;
  
  ConOut = gST->ConOut;

  HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_FAIL_SAVE_PROMPT),
          Language);
  ShowPassWindow(HiiGetString(HiiHandle, STRING_TOKEN(STR_FAILURE_MODE), Language),
          HiiString);
  TmpLen = ReadLineAndHide(PassBuf, sizeof(PassBuf) - 1, TRUE);
  if (TmpLen == 0) {
    goto _exit;
  }
  PassLen = TmpLen;
  
  if (-1 == CheckDataWithGuid(FAIL_SAVE_PASS_GUID, PassBuf, PassLen, pMainFv)) {
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



BOOLEAN
CheckEngeneerPasswdPresent(
  IN struct tMainFvInfo *pmfvi,
  IN CHAR8 *Guid
  )
{
  EFI_STATUS Status;
  UINTN RestSize;
  EFI_GUID GuidVal;
  
  Status = StringToGuid_L(Guid, &GuidVal);
  if (EFI_ERROR(Status)) {
    return FALSE;
  }
  
  if (NULL == FindPlaceInExtHdr(&GuidVal, pmfvi, &RestSize)) {
    return FALSE;
  }
  return TRUE;
}


VOID
SoundForError(
  VOID
  )
{
  int i;
  
  for (i = 0; i < 2; i++) {
    BeepCode(MEMORY_ERR_CODE, MEMORY_ERR_CODE_LEN, ERR_BEEP_FREQ,
      LONG_ERR_BEEP_MS, SHORT_ERR_BEEP_MS, ERR_BEEP_DELAY);

    MicroSecondDelay(500000);
  }
}

VOID
ShowErrorPermissionDenied(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  CHAR16 *HiiString;
  
  HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_PERMISSION_DENIED), 
    Language);
  ShowErrorPopup(HiiHandle, HiiString);
}

VOID
ProcessingLoginError(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  USER_INFO *pUserInfo;
  EFI_STATUS Status;
  CHAR16 *HiiString;

  UpdateUserPasswordFailCounter();

  
  pUserInfo = UserGetLastFoundedInfo();
  if (pUserInfo == NULL) {    
    goto _show_error;
  }  
  if (pUserInfo->Flags & USER_SU_FLAG) {
    pUserInfo->LoginFailCnt++;
    CheckForSuPasswordFail();
    goto _show_error;
  }
  HistoryAddRecord(HEVENT_USER_LOGIN, pUserInfo->UserId, SEVERITY_LVL_ERROR, 0);
  Status = LoginFailCntUpdate();  
  if (Status == EFI_ABORTED) {
    pUserInfo->Flags |= USER_BLOCKED_FLAG;
    if (EFI_SUCCESS != UsersStorageUpdate()) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      MsgInternalError(INT_ERR_WHILE_LOGIN_FAIL_CNT_ACCESS);
    }
    {
      CHAR16 TmpStr16[1024], *UsrTypeStr16, *BlockedStr16;
      if (pUserInfo->Flags & USER_ADMIN_FLAG) {
        UsrTypeStr16 = HiiGetString(gMultibootData->HiiHandle, 
          STRING_TOKEN(STR_USERS_TYPE_ADMIN), NULL);
      } else {      
        UsrTypeStr16 = HiiGetString(gMultibootData->HiiHandle, 
          STRING_TOKEN(STR_USERS_TYPE_USER), NULL);        
      }

      BlockedStr16 = HiiGetString(gMultibootData->HiiHandle, 
          STRING_TOKEN(STR_BLOCK_FLAG_ON), NULL);
      pUserInfo->Flags |= USER_BLOCKED_FLAG;
      UsersStorageUpdate();
      HistoryAddRecord (
        HEVENT_USER_BLOCKED, 
        pUserInfo->UserId, 
        SEVERITY_LVL_ERROR, 
        HISTORY_RECORD_FLAG_RESULT_OK
        );
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s %s %s", 
          UsrTypeStr16, pUserInfo->UserName, BlockedStr16);
      BeepOn(1000);
      ShowErrorPopup(gMultibootData->HiiHandle, TmpStr16);      
      CpuDeadLoop();
    }
  } else if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    MsgInternalError(INT_ERR_WHILE_LOGIN_FAIL_CNT_ACCESS);
  }
  
_show_error:
  CheckForUserPasswordFail();
  
  HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_WRONG_PASSWD),
    Language);
  ShowErrorPopup(HiiHandle, HiiString);
}

EFI_STATUS
ChangeAdminPassword(
  IN EFI_HII_HANDLE HiiHandle,
  IN USER_INFO *pUserInfo
  )
{
  UINTN PassLen;
  CHAR8 PassBuf[PASSWORD_MAX_LEN + 1];
  CHAR16 Password16[PASSWORD_MAX_LEN + 1];
  EFI_STATUS Status;
  USER_INFO_LOG_PASS *pLogPassUsr;
  UINT32 PassCreationTime;
  UINT8 HashBuf[MAX_HASH_LEN];

  if (pUserInfo->AuthType != AUTH_TYPE_LOG_PASS) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! pUserInfo->AuthType=%d\n", 
      __FUNCTION__, __LINE__, pUserInfo->AuthType));
    return EFI_INVALID_PARAMETER;
  }
  if (pUserInfo->ExtDataLen < sizeof(USER_INFO_LOG_PASS)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! pUserInfo->ExtDataLen=%d {%d}\n", 
      __FUNCTION__, __LINE__, pUserInfo->ExtDataLen, 
      sizeof(USER_INFO_LOG_PASS)));
    return EFI_INVALID_PARAMETER;
  }

  pLogPassUsr = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
  
  while (1) {
    UINT32 PassLen32;
    
    ZeroMem(PassBuf, sizeof(PassBuf));
    ZeroMem(Password16, sizeof(Password16));

    Status = GetUsrPasswordLen (&PassLen32);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    PassLen = (UINTN)PassLen32;
    
    Status = PassswordReGen (PassBuf);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    
    Status = CalcHashCs(PASSWD_HASH_TYPE, PassBuf, PassLen,
      CALC_CS_RESET | CALC_CS_FINALIZE, HashBuf);
    if (EFI_SUCCESS != Status) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }

    if (0 == CompareMem (pLogPassUsr->PassHash, HashBuf, 
                GetHashLen(PASSWD_HASH_TYPE))) {
      ShowErrorPopup(HiiHandle, 
        HiiGetString(HiiHandle, STRING_TOKEN(STR_PASS_SAME_AS_OLD), NULL));
      return EFI_ACCESS_DENIED;
    }
    CopyMem (pLogPassUsr->PassHash, HashBuf, GetHashLen(PASSWD_HASH_TYPE));

    Status = GetU32TimeSec(&PassCreationTime);
    WriteUnaligned32((UINT32*)(UINT8*)&pLogPassUsr->PassCreateTime, 
        PassCreationTime);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));      
      break;
    }
    Status = UpdateCurrentUserCard();
    if (EFI_SUCCESS != Status) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));      
    }
    break;
  }

  HistoryAddRecord(HEVENT_USR_PASS_CHANGE, GetCurrentUserId(), 
    SEVERITY_LVL_INFO, 
    EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  
  return Status;
}


int
AdminModeCheckLoginPass(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN  PassLen, TmpLen;
  CHAR8  LoginBuf[MAX_USER_NAME_LEN + 1], PassBuf[PASSWORD_MAX_LEN + 1];
  CHAR16 UserName[MAX_USER_NAME_LEN + 1];
  INT32 retval, chkStatus;
  EFI_STATUS Status;
  EFI_INPUT_KEY Key; 
  USER_INFO *pUserInfo;
  EFI_STRING StrUserAuthPrompt = NULL;
  EFI_STRING StrLoginPassAuthHlp = NULL;
  EFI_STRING StrSystemGuid = NULL;
  EFI_STRING StrUserLoginPrompt = NULL;
  EFI_STRING StrUserPassword = NULL;
  
  EFI_GUID SysGuid = {0};
  CHAR16 SysGuidString[SYS_GUID_STR_LENG];

  StrUserAuthPrompt = HiiGetString(HiiHandle, STRING_TOKEN(STR_USER_AUTH_PROMPT), Language);
  StrLoginPassAuthHlp = HiiGetString(HiiHandle, STRING_TOKEN(STR_LOGIN_PASS_AUTH_HLP), Language);
  StrSystemGuid = HiiGetString(HiiHandle, STRING_TOKEN(STR_SYSTEM_GUID), Language);
  StrUserLoginPrompt = HiiGetString(HiiHandle, STRING_TOKEN(STR_USER_LOGIN_PROMPT), Language);
  StrUserPassword = HiiGetString(HiiHandle, STRING_TOKEN(STR_USER_PASSWORD), Language);

  gST->ConOut->ClearScreen (gST->ConOut);
  
  Status = GetSystemGuidFromVolume (&SysGuid);
  if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d: Status = %d\n",
        __FUNCTION__, __LINE__, Status));
  }

  UnicodeSPrint(SysGuidString, sizeof(SysGuidString), L"%s %g",
    StrSystemGuid, &SysGuid);

  do {
    retval = -1;
    pCurrUserLoginPass = NULL;
    ConOut = gST->ConOut;

    CleanKeyBuffer();

    do {
      CreatePopUp(EFI_BLACK | EFI_BACKGROUND_GREEN, NULL, 
        StrUserAuthPrompt,
        L"", L"", 
        StrLoginPassAuthHlp,
        L"",
        SysGuidString,
        NULL);

      Key.ScanCode = 0;
      Key.UnicodeChar = CHAR_NULL;

      WaitForKeyStroke1Sec(&Key);
    } while (Key.UnicodeChar != CHAR_CARRIAGE_RETURN);
    
    ShowPassWindow (StrUserAuthPrompt, StrUserLoginPrompt);

    TmpLen = ReadLineAndHide(LoginBuf, sizeof(LoginBuf) - 1, FALSE);

    ShowPassWindow(StrUserAuthPrompt, StrUserPassword);
      
    PassLen = ReadLineAndHide(PassBuf, sizeof(PassBuf) - 1, TRUE);    
    
    chkStatus = CheckUserName8(TmpLen, LoginBuf, UserName, sizeof(UserName),
       HiiHandle);
       
    if (chkStatus == USER_NOT_EXIST_OR_BLOCK) {
      retval = -2;
      ResetUserPasswordFailCounter();
      goto _exit;
    }

    DEBUG((EFI_D_ERROR, "%a.%d: PassLen=%d HashType=%X{%X}\n", 
      __FUNCTION__, __LINE__, PassLen, pCurrUserLoginPass->PassHashType, 
      PASSWD_HASH_TYPE));
   
    if (PassLen == 0) {
      goto _exit;
    }
    
    PassBuf[PassLen] = 0;
    DEBUG((EFI_D_ERROR, "%a.%d: PassBuf=%a\n", __FUNCTION__, __LINE__, PassBuf));
    SaveUserPassOrPin (PassBuf, NULL);
    
    retval = CheckDataWithHash(pCurrUserLoginPass->PassHashType,
        PassBuf, PassLen, pCurrUserLoginPass->PassHash);
    if (retval == -1) {
      pUserInfo = UserGetLastFoundedInfo();

      HistoryAddRecord(
        HEVENT_PASSWD_GUESSING, 
        pUserInfo ? pUserInfo->UserId : USER_UNKNOWN_ID, 
        SEVERITY_LVL_ALERT, 
        0);      
    }

_exit:
    ConOut->ClearScreen(ConOut);
    pUserInfo = UserGetLastFoundedInfo();
    if (pUserInfo && (pUserInfo->Flags & USER_BLOCKED_FLAG)) {
      CHAR16 TmpStr16[1024];
      DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
      HistoryAddRecord(HEVENT_USER_LOGIN, pUserInfo->UserId, SEVERITY_LVL_ERROR, 0);
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s: %s %s", 
          HiiGetString(HiiHandle, 
            pUserInfo->Flags & USER_ADMIN_FLAG ? 
              STRING_TOKEN(STR_USERS_TYPE_ADMIN) : 
              STRING_TOKEN(STR_USERS_TYPE_USER), NULL),
          pUserInfo->UserName,
          HiiGetString(HiiHandle, 
              STRING_TOKEN(STR_BLOCK_FLAG_ON), NULL));
      ShowErrorPopup(HiiHandle, TmpStr16);
      gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
    }
    
    if (retval == -1) {
      ProcessingLoginError(HiiHandle, Language);
    }
  } while (retval);
  if (EFI_SUCCESS != LoginFailCntClean()) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    MsgInternalError(INT_ERR_WHILE_LOGIN_FAIL_CNT_ACCESS);
  }

  gST->ConOut->ClearScreen(gST->ConOut);
  if (StrUserAuthPrompt != NULL) {
    FreePool (StrUserAuthPrompt);
  }
  if (StrLoginPassAuthHlp != NULL) {
    FreePool (StrLoginPassAuthHlp);
  }
  if (StrSystemGuid != NULL) {
    FreePool (StrSystemGuid);
  }
  if (StrUserLoginPrompt != NULL) {
    FreePool (StrUserLoginPrompt);
  }
  if (StrUserPassword != NULL) {
    FreePool (StrUserPassword);
  }
  return retval;
}

BOOLEAN
EnterToAdminMode(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_INPUT_KEY Key;
  
  while (1) {
    Status = WaitForKeyStroke1Sec( &Key );
    if (Status == EFI_TIMEOUT) {
      return FALSE;
    }

    if (DelKeyHandlerFsm(&Key)) {
      break;
    }
    if (F2KeyHandlerFsm(&Key)) {
      break;
    }
    if (Key.UnicodeChar != CHAR_NULL) {
      continue;
    }
    if (Key.ScanCode == SCAN_DELETE || Key.ScanCode == SCAN_F2) {
      break;
    }
  }
  CleanKeyBuffer();
  return TRUE;
}

EFI_STATUS
PreBootPlatfromProcessing(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Config,
  IN MULTIBOOT_ENTRY *DefaultEntry
  )
{
  EFI_STATUS Status;
  UINT16 Flags;
  
  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  if (Flags & SETUP_FLAG_DBG_LOAD_PARAMS) {
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CheckModuleHash(
  IN LIST_ENTRY *IcflList,
  IN EFI_STATUS IcflStatus,
  IN MULTIBOOT_MODULE *Module,
  IN CBCFG_RECORD *Rec
  )
{
  CHAR16 *String = NULL, *FilePath;
  CHAR16 *Ptr1, *Ptr2;
  UINTN Len;
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR16 ShortName[10], *FullName;

  DEBUG((EFI_D_ERROR, "%a.%d IcflStatus=%r\n", 
    __FUNCTION__, __LINE__, IcflStatus));

  if (Rec == NULL || Module == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  
  if (IsBufZero(Rec->Hash, sizeof(Rec->Hash))) {
    DEBUG((EFI_D_ERROR, "%a.%d Hash not set!\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }

  FilePath = &Module->DevPath[5];
  CopyMem(ShortName, Module->DevPath, 4 * sizeof(CHAR16));
  ShortName[4] = 0;

  FullName = FsDescTableGetFullName(ShortName);
  
  Len = StrSize(FullName) + StrSize(FilePath) + 
    StrSize(ICFL_SEPARATOR);
  String = AllocateZeroPool(Len);
  if (NULL == String) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Ptr1 = StrStr(Rec->DeviceFullName, FilePath);
  if (Ptr1 == NULL) {
    UnicodeSPrint(String, Len, L"%s%s%s", Rec->DeviceFullName, 
      ICFL_SEPARATOR, FilePath);
    DEBUG((EFI_D_ERROR, "%a.%d String=\"%s\"\n", 
      __FUNCTION__, __LINE__, String));
  } else {
    UINTN FullNameLen = StrLen(FullName);

    Ptr2 = NULL;
    if (FullNameLen) {
      Ptr2 = &FullName[FullNameLen - 1];
      if (*Ptr2 == L'/') {
        *Ptr2 = 0;
      }
    }
    UnicodeSPrint(String, Len, L"%s%s%s", FullName, 
      ICFL_SEPARATOR, FilePath);
    if (Ptr2 && *Ptr2 == 0) {
      *Ptr2 = L'/';
    }
    DEBUG((EFI_D_ERROR, "%a.%d String=\"%s\"\n", 
      __FUNCTION__, __LINE__, String));
  }

  DEBUG((EFI_D_ERROR, "%a.%d Module->DevPath=\"%s\"\n", 
    __FUNCTION__, __LINE__, Module->DevPath));


  /* if this module exist in the list then check hash in the list */
  if (!EFI_ERROR(IcflStatus) && IcflItemPresent(
      String, IcflList)) {
    DEBUG((EFI_D_ERROR, "%a.%d This module will be checked later...\n", 
      __FUNCTION__, __LINE__));
  } else {
    UINT8 HashData[MAX_HASH_LEN];

    if (IsLegacyBootDevPath(Module->DevPath)) {
      Status = CalcHashForMbr(Module->DevPath, CS_TYPE_CRC32, HashData);
    } else {
      Status = CalcHashCsOnFile16(Module->DevPath, CS_TYPE_CRC32, HashData);
    }
    DumpBytes(Rec->Hash, sizeof(HashData));
    DumpBytes(HashData, sizeof(HashData));
    if (CompareMem(HashData, Rec->Hash, sizeof(HashData))) {      
      Status = EFI_CRC_ERROR;
    } else {
      DEBUG((EFI_D_ERROR, "%s : HASH OK!\n", Module->DevPath));
    }
  }
  
  if (String != NULL) {
    FreePool(String);
  }
  return Status;
}

MULTIBOOT_ENTRY *
GetCurrentBootOption(
  VOID
  )
{
  CBCFG_DATA_SET *CbcfgDataSet;
  CBCFG_RECORD *Rec;
  UINTN DataSetSize, Idx;
  UINT8 *DataPtr;
  EFI_STATUS Status, IcflStatus;
  MULTIBOOT_ENTRY *MbEntry;
  MULTIBOOT_MODULE *Module;
  CHAR16 ShortName[10];
  LIST_ENTRY IcflList;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitializeListHead(&IcflList);
  IcflStatus = GetIcfl(&IcflList);
  DEBUG((EFI_D_ERROR, "%a.%d IcflStatus=%r\n", 
    __FUNCTION__, __LINE__, IcflStatus));
  
  Status = CbcfgStorageGetData(&CbcfgDataSet, &DataSetSize);  
  if (EFI_ERROR(Status) || CbcfgDataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return NULL;
  }

  if (CbcfgDataSet->BootType == BOOT_TYPE_DEFAULT || 
      CbcfgDataSet->BootType > BOOT_TYPE_EFI) {
    FreePool(CbcfgDataSet);
    return NULL;
  }

  MbEntry = AllocateZeroPool(sizeof(MULTIBOOT_ENTRY));
  if (NULL == MbEntry) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    FreePool(CbcfgDataSet);
    return NULL;
  }
  InitializeListHead( &MbEntry->ModuleHead );

  switch (CbcfgDataSet->ModulesType) {
  case MODULE_TYPE_LINUX:
    MbEntry->Format = ModuleFormatLinux;
    break;

  case MODULE_TYPE_EFI:
    MbEntry->Format = ModuleFormatEfi;
    break;

  case MODULE_TYPE_MULTIBOOT:
    MbEntry->Format = ModuleFormatMultibootAuto;
    break;

  default:
    FreePool(CbcfgDataSet);
    FreePool(MbEntry);
    return NULL;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  DataPtr = CbcfgDataSet->Data;
  for (Idx = 0; Idx < CbcfgDataSet->BootOptionsNum; Idx++) {
    Rec = (CBCFG_RECORD*)DataPtr;
    DataPtr += sizeof(CBCFG_RECORD);

    Module = AllocateZeroPool(sizeof(MULTIBOOT_MODULE));
    if(Module == NULL) {
      FreePool(CbcfgDataSet);
      return NULL;
    }

    Module->Format = MbEntry->Format;

    if (CbcfgDataSet->BootType == BOOT_TYPE_EFI) {
      CHAR16 *FileName, *StrDevPath, *EfiFileName;
      CHAR16 FilePath[255];

      StrDevPath = NULL;
      FileName = StrStr(Rec->DevPath, L"\\");
      if (FileName) {
        EfiFileName = StrStr (FileName, EFI_REMOVABLE_MEDIA_FILE_NAME);
        if (EfiFileName == NULL) {
          UnicodeSPrint(FilePath, sizeof(FilePath), 
            L"%s", FileName);
          EfiFileName = FilePath;
        }
        *FileName = 0;
        StrDevPath = GetFullDevicePathFromShortStringPath (
                        Rec->DevPath, 
                        EfiFileName ? EfiFileName : NULL
                        );
      }

      if (Idx < 100) {
        UnicodeSPrint(ShortName, sizeof(ShortName), L"%s%02d", 
          TEMP_BOOT_DEV_NAME, Idx);
      } else {
        UnicodeSPrint(ShortName, sizeof(ShortName), L"%s%d", 
          TEMP_BOOT_DEV_NAME, Idx);
      }
      
      AddFsDescTableItem(ShortName, 
        StrDevPath ? StrDevPath : Rec->DevPath, FALSE);
      if (StrDevPath) {
        *FileName = L'\\';
      }
      
      UnicodeSPrint(Module->DevPath, sizeof(Module->DevPath), 
        L"%s:%s", ShortName, FileName ? 
          FileName : EFI_REMOVABLE_MEDIA_FILE_NAME);
    } else {
      CHAR16 *TmpStr16 = FindSymbol(Rec->DevPath, L':');
      CHAR16 S;

      if (TmpStr16 != NULL) {
        S = *TmpStr16;
        *TmpStr16 = 0;
        StrCpy(ShortName, Rec->DevPath);
        *TmpStr16 = S;
        if (FsDescTableGetFullName(ShortName) == NULL) {
          AddFsDescTableItem(ShortName, Rec->DeviceFullName, FALSE);
        }
      }

      StrCpy(Module->DevPath, Rec->DevPath);
      StrCpy(Module->Args, Rec->Args);
    }

    DEBUG((EFI_D_ERROR, 
      "Module->Format=%X Module->DevPath=%s Module->Args=%s\n",
      Module->Format, Module->DevPath, Module->Args));

    Status = CheckModuleHash(&IcflList, IcflStatus, Module, Rec);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
    InsertTailList( &MbEntry->ModuleHead, &Module->ListEntry );
  }
  
  return MbEntry;
}


VOID
PlatfromLibraryInit(
  IN MULTIBOOT_DATA *Data
  )
{
  EFI_STATUS Status;
  MULTIBOOT_ENTRY *Entry;
  EFI_GUID Guid;
  UINTN Idx;
  
  MIISetCurrentConfig(&Data->Config);
  UsersSetCurrentConfig(&Data->Config);
  UsersCommonInit(Data->HiiHandle);  
  MainPageSetCurrentConfig(&Data->Config);
  AdminSetCurrentConfig(&Data->Config);
  HistorySetCurrentConfig(Data->HiiHandle, &Data->Config);
  IntegrityCheckingInit(&Data->Config);
  Status = InitializeBootManager();  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    MsgInternalError(INT_ERR_BOOT_MANAGER_INIT);
  }

  Status = InitializeChipsetConfig();  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    MsgInternalError(INT_ERR_INIT_CHIPSET_CONFIG_ERROR);
  }

  Idx = 0;
  Entry = FindEntryByIndex(&Data->Config, MP_REGULAR_LOADING_MODE_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }
  
  Entry = FindEntryByIndex(&Data->Config, ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, MP_ADDITIONAL_LOADING_MODE_1_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, MP_ADDITIONAL_LOADING_MODE_2_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, MP_ADDITIONAL_LOADING_MODE_3_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, ADM_MAIN_BOOT_1_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, ADM_MAIN_BOOT_2_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  Entry = FindEntryByIndex(&Data->Config, ADM_MAIN_BOOT_3_ID);
  if (Entry) {
    Status = StringToGuid_L(Entry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Entry->Name=%s Guid=%g\n",
        __FUNCTION__, __LINE__, Entry->Name, &Guid));
      BootMngrSetVarsGuidAndDesc(Idx++, &Guid, Entry->Name);
    }
  }

  ImportBootCfgFromFv ();
}


VOID
GotoInitialInitializationMode(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_INPUT_KEY Key;
  EFI_STATUS Status = EFI_ABORTED;
  
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(HiiHandle, STRING_TOKEN(STR_BIOS_DATA_CORRUPT), NULL),
      HiiGetString(HiiHandle, STRING_TOKEN(STR_ASK_FOR_RUN_MII), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      Status = EFI_SUCCESS;
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      Status = EFI_ABORTED;
      break;
    }
  } while (1);

  gST->ConOut->ClearScreen(gST->ConOut);

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  CleanSetupEfiVar();
  UsersStorageInitEmpty();
  HistoryStorageInitEmpty();
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
}


EFI_STATUS
CheckAllFvWithExtHdr (
  VOID
  )
{
  struct tMainFvInfo FvInfo, *pmfvi;
  UINT8 *TmpPtr;
  STATIC EFI_PEI_HOB_POINTERS FvHob;

  pmfvi = &FvInfo;
  FvHob.Raw = GetHobList();
  
  while ((FvHob.Raw = GetNextHob (EFI_HOB_TYPE_FV, FvHob.Raw)) != NULL) {
    TmpPtr = (UINT8*)(UINTN)FvHob.FirmwareVolume->BaseAddress;
    pmfvi->Fvh = (EFI_FIRMWARE_VOLUME_HEADER*) TmpPtr;
    if ( pmfvi->Fvh->Signature != EFI_FVH_SIGNATURE || 
         !pmfvi->Fvh->ExtHeaderOffset) {
      FvHob.Raw = GET_NEXT_HOB (FvHob);
      continue;
    }

    pmfvi->FvhExt = (EFI_FIRMWARE_VOLUME_EXT_HEADER*) 
      &TmpPtr[pmfvi->Fvh->ExtHeaderOffset];

    if (pmfvi->FvhExt->ExtHeaderSize > 20) {
      UpdateMainFirmwareInfo(TmpPtr, pmfvi);
      DEBUG((EFI_D_ERROR, "Checking for FV: %g   ", &pmfvi->FvhExt->FvName));
      if (-1 == CheckMainFvHashCs(MAIN_GUID_STR, pmfvi)) {
        DEBUG((EFI_D_ERROR, "Error!\n"));
        return EFI_CRC_ERROR;
      }
      DEBUG((EFI_D_ERROR, "OK!\n"));
    }
    
    FvHob.Raw = GET_NEXT_HOB (FvHob);
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS; 
}

static EFI_STATUS
CheckBiosData(
  IN UINT8 *Data,
  IN UINTN DataSize
  )
{
  struct tMainFvInfo MainFv;
  T_FIRMWARE_INFO FwInfo;
  BiosInfoRecord *pBiosInfo = NULL;
  EFI_STATUS Status;  
  EFI_GUID TmpGuid;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = FindMainFvInByteBuf(Data, DataSize, MAIN_FV_GUID_STR, &MainFv);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  if (!IsItFwUpdate(&MainFv)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  pBiosInfo = (BiosInfoRecord*)FindBiosInfoRecord(&MainFv);
  if (NULL == pBiosInfo) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  GetFirmwareInfo(&FwInfo);

  CopyMem(&TmpGuid, &pBiosInfo->PlatformGuid, sizeof(EFI_GUID));
  if (CompareGuid_L(&FwInfo.PlatformGuid, &TmpGuid)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  if (!CheckEngeneerPasswdPresent(&MainFv, BIOS_PASS_GUID)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  if (!CheckEngeneerPasswdPresent(&MainFv, FAIL_SAVE_PASS_GUID)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  if (-1 == CheckMainFvHashCs(MAIN_GUID_STR, &MainFv)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    return EFI_ABORTED;
  }
  
  return EFI_SUCCESS;
}

UINTN
GetGlobalConfigResultLen (
  IN CONFIG_RESULT_T *Result
  )
{
  UINTN Idx, Len;
  REPORT_LIST_T *RepList;

  if (Result == NULL || Result->reportList == NULL) {
    return 0;
  }

  RepList = Result->reportList;

  for (Idx = 0, Len = 0; Idx < Result->numSubsystems; Idx++) {
    Len += AsciiStrSize(RepList[Idx].configName);
    Len += sizeof (UINT8); // RepList[Idx].status
  }
  
  return Len;
}

EFI_STATUS
CopyGlobalConfigResultToByteBuf (
  IN CONFIG_RESULT_T *Result,
  IN OUT UINT8 *Data,
  IN UINTN DataLen
  )
{
  UINT8 *Ptr;
  UINTN Idx, RestLen, Len;
  REPORT_LIST_T *RepList;
  
  RepList = Result->reportList;
  Ptr = Data;
  RestLen = DataLen;
  for (Idx = 0; Idx < Result->numSubsystems; Idx++) {
    Len = AsciiStrSize(RepList[Idx].configName);
    if (Len > RestLen) {
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem (Ptr, RepList[Idx].configName, Len);
    RestLen -= Len;
    Ptr += Len;

    if (RestLen < sizeof (UINT8)) {
      return EFI_OUT_OF_RESOURCES;
    }
    *Ptr++ = (UINT8)(RepList[Idx].status & 0xFF);
    RestLen -= sizeof (UINT8);
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
LoginPassProcessing (
  IN UINT8 AuthType,
  IN CHAR8 *UserName,
  IN CHAR8 *PassStr
  )
{
  EFI_STATUS Status;
  CHAR16 UserName16[255];
  USER_INFO *pUserInfo = NULL;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (UserName == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (AsciiStrLen(UserName) >= 255) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  SaveUserPassOrPin (PassStr, NULL);

  UnicodeSPrint(UserName16, sizeof(UserName16), L"%a", UserName);

  DEBUG((EFI_D_ERROR, "AuthType=%X UserName16=%s PassStr=%a\n", 
    AuthType, UserName16, PassStr));

  if (AuthType == USER_AUTH_TYPE_LOG_PASS) {
    Status = UserFindRecordByNameWithThisAuth(AUTH_TYPE_LOG_PASS, UserName16);
    if (EFI_ERROR(Status)) {
      HistoryAddRecord(HEVENT_USER_NAME_FAIL, GetCurrentUserId(), 
        SEVERITY_LVL_ERROR, 0);  
      return Status;
    }
  
    pUserInfo = UserGetLastFoundedInfo();
    if (NULL == pUserInfo) {
      return EFI_ABORTED;
    }
  
    if (pUserInfo->AuthType != AUTH_TYPE_LOG_PASS) {
      return EFI_ACCESS_DENIED;
    }

    if (pUserInfo->Flags & USER_HIDDEN_FLAG) {
      HistoryAddRecord(HEVENT_USER_NAME_FAIL, GetCurrentUserId(), 
        SEVERITY_LVL_ERROR, 0);
      return EFI_NOT_FOUND;
    }

    if (pUserInfo->Flags & USER_BLOCKED_FLAG) {
      HistoryAddRecord(HEVENT_USER_LOGIN, 
        pUserInfo->UserId, SEVERITY_LVL_ERROR, 0);
      return EFI_ACCESS_DENIED;
    }

    if (PassStr == NULL) {
      goto Done;
    }
    
    pCurrUserLoginPass = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
    if (pCurrUserLoginPass == NULL) {
      return EFI_ABORTED;
    }
    if (-1 == CheckDataWithHash(pCurrUserLoginPass->PassHashType,
          PassStr, AsciiStrLen(PassStr), pCurrUserLoginPass->PassHash)) {
      HistoryAddRecord(
        HEVENT_PASSWD_GUESSING, 
        pUserInfo->UserId, 
        SEVERITY_LVL_ALERT, 
        0);      
      return EFI_ACCESS_DENIED;
    }
    
  } else {
    return EFI_INVALID_PARAMETER;
  }

Done:
  Status = EFI_ACCESS_DENIED;
  pUserInfo = UserGetLastFoundedInfo();
  if (pUserInfo != NULL) {
    if ((pUserInfo->Flags & USER_ADMIN_FLAG) == 0) {
    }
    if (pUserInfo->UserId == USER_SU_ID) {
      SetCurrentUser(pUserInfo);
      return EFI_SUCCESS;
    }
    
    {
      UINT8 AccessInfo = 0;
      Status = GetUserAccessInfo (pUserInfo->UserId, &AccessInfo);
      if (!EFI_ERROR(Status) && 
          (AccessInfo == USER_ACCESS_REMOTE_AUDIT ||
           AccessInfo == USER_ACCESS_REMOTE_FULL_CTRL ||
           AccessInfo == USER_ACCESS_REMOTE_START_OS)) {
        SetCurrentUser(pUserInfo);
        DEBUG((EFI_D_ERROR, "%a.%d pUserInfo->UserId=%X\n", 
          __FUNCTION__, __LINE__, pUserInfo->UserId));
        Status = EFI_SUCCESS;
      } else {
        Status = EFI_ACCESS_DENIED;
      }
    }
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }
  return Status;  
}

STATIC
UINTN
StrictAsciiStrLen (
  IN CHAR8 *Str,
  IN UINTN MaxLen
  )
{
  UINTN Len;
  
  for (Len = 0; Str[Len]; Len++) {
    if (Len >= MaxLen) {
      return 0;
    }
  }
  return Len;
}


STATIC
VOID
ResetToMii (
  VOID
  )
{
  EFI_STATUS Status;
  USER_INFO *pUser;
  UINT8 UserId = USER_UNKNOWN_ID;
  
  CleanSetupEfiVar();
  UsersStorageInitEmpty();
  HistoryStorageInitEmpty();

  pUser = UserGetLastFoundedInfo();
  if (pUser != NULL) {
    UserId = pUser->UserId;
  }

  Status = HistoryAddRecord(
    HEVENT_RESET_BIOS_TO_MII, 
    UserId, 
    SEVERITY_LVL_EMERGENCY, 
    HISTORY_RECORD_FLAG_RESULT_OK);
  DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
}

STATIC
UINT8
GetSeverityVal (
  IN UINT8 PktData
  )
{
  UINT8 Shift, CurSeverity;

  Shift = PktData;//Buf[RCFG_PKT_DATA_OFFS + 1];
  if (Shift > 7) {
    Shift = 7;
  }
  CurSeverity = (UINT8)(0xFF << Shift);
  CurSeverity = ~CurSeverity;
  CurSeverity <<= 1;
  CurSeverity++;
  return CurSeverity;
}

EFI_STATUS
Delay (
  IN UINTN Ms
  )
{
  UINTN Index;
  EFI_STATUS Status;
  EFI_EVENT TimerEvent, WaitList[2];

  Status = gBS->CreateEvent (EVT_TIMER, 0, NULL, NULL, &TimerEvent);
  if (EFI_ERROR(Status)) {
    return EFI_TIMEOUT;
  }
  
  Status = gBS->SetTimer (TimerEvent, TimerRelative, Ms * 10000);
  if (EFI_ERROR(Status)) {
    return EFI_TIMEOUT;
  }

  //
  // Wait for the keystroke event or the timer
  //  
  WaitList[0] = TimerEvent;
  Status      = gBS->WaitForEvent (1, WaitList, &Index); 
  return Status;
}


VOID
ShowAllConsoles (
  VOID
  )
{
  UINTN                     Index;
  EFI_DEVICE_PATH_PROTOCOL  *ConDevicePath;
  UINTN                     HandleCount;
  EFI_HANDLE                *HandleBuffer = NULL;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  gBS->LocateHandleBuffer (
          ByProtocol,
          &gEfiSimpleTextOutProtocolGuid,
          NULL,
          &HandleCount,
          &HandleBuffer
          );
  for (Index = 0; Index < HandleCount; Index++) {
    CHAR16 *Str16;
    
    gBS->HandleProtocol (
            HandleBuffer[Index],
            &gEfiDevicePathProtocolGuid,
            (VOID **) &ConDevicePath
            );
    Str16 = DevPathToString(ConDevicePath, FALSE, TRUE);
    if (Str16) {
      DEBUG ((EFI_D_ERROR, "%d %s\n", Index, Str16));      
    }
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }
}


EFI_STATUS
ResetBiosSetupByRtcRst (
  IN EFI_HII_HANDLE HiiHandle,
  IN UINT8 State
  )
{
  UINT8 *RtcRst;
  EFI_HOB_GUID_TYPE *GuidHob;
  EFI_INPUT_KEY Key;
  EFI_STATUS Status = EFI_ABORTED;
  
  GuidHob = GetFirstGuidHob (PcdGetPtr(PcdRtcRstGuid));
  if (GuidHob == NULL)  {
    return EFI_NOT_FOUND;
  }


  RtcRst = (UINT8*)GET_GUID_HOB_DATA(GuidHob);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (RtcRst == NULL) {
    return EFI_NOT_FOUND;
  }
  
  if ((*RtcRst & BIT2) == 0)  {
    return EFI_NOT_FOUND;
  }
  
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(HiiHandle, STRING_TOKEN(STR_MSG_RTC_RST), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      Status = EFI_SUCCESS;
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      Status = EFI_ABORTED;
      break;
    }
  } while (1);

  gST->ConOut->ClearScreen(gST->ConOut);

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  

  DEBUG((EFI_D_ERROR, "%a.%d *RtcRst=%02X %02X\n", __FUNCTION__, __LINE__, 
    *RtcRst, PciRead8(PCI_LIB_ADDRESS (0, 31, 0, 0xA4))));

  PciWrite8(PCI_LIB_ADDRESS (0, 31, 0, 0xA4), 
    PciRead8(PCI_LIB_ADDRESS (0, 31, 0, 0xA4)) & ~BIT2);
  DEBUG((EFI_D_ERROR, "%a.%d %02X\n", __FUNCTION__, __LINE__, 
    PciRead8(PCI_LIB_ADDRESS (0, 31, 0, 0xA4))));

  ResetToMii ();

  if (State == 1) {
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }
  
  return Status;
}


EFI_STATUS
SaveLoadingModeEvent (
  UINTN Mode
  )
{
  EFI_STATUS Status;
  UINT16 EventCode;
  
  switch (Mode) {
  case MP_REGULAR_LOADING_MODE_ID:
  case MP_TIME_OUT_ID:
    EventCode = (UINT16)HEVENT_REGULAR_BOOT;
    break;

  case MP_ADMIN_MODE_ID:
  case ADM_MAIN_PAGE_ADM_VIRTUAL_ID:
    EventCode = (UINT16)HEVENT_ADMIN_BOOT;
    break;

  case MP_RECOVER_MODE_ID:
  case ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID:
    EventCode = (UINT16)HEVENT_RECOVER_BOOT;
    break;

  case ADM_MAIN_PAGE_COMPLEX_INSTALL_ID:
    EventCode = (UINT16)HEVENT_INSTALL_BOOT;
    break;

  default:
    return EFI_NOT_FOUND;
  }

  Status = HistoryAddRecord(
              EventCode, 
              GetCurrentUserId(),
              SEVERITY_LVL_INFO,
              HISTORY_RECORD_FLAG_RESULT_OK);
  return Status;
}

EFI_STATUS
CreateDefaultUser (
  IN DEF_USER_DESC *pDefUser
  )
{
  USER_LOGIN_PASS_DATA LoginPassUserData;
  EFI_STATUS Status;
  
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (pDefUser == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (pDefUser->UserContactInfo == NULL || pDefUser->UserFIO == NULL ||
      pDefUser->UserName == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (pDefUser->Digest == NULL && pDefUser->PassHash == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (pDefUser->Digest != NULL && pDefUser->PassHash != NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (pDefUser->Digest != NULL) {
    Status = EFI_UNSUPPORTED;
  } else {
    ZeroMem (&LoginPassUserData, sizeof (LoginPassUserData));
    LoginPassUserData.UserName = pDefUser->UserName;
    LoginPassUserData.ContactInfo = pDefUser->UserContactInfo;
    LoginPassUserData.UserFIO = pDefUser->UserFIO;
    LoginPassUserData.Hash = pDefUser->PassHash;
    LoginPassUserData.Permission = ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE;
    Status = AddLoginPassUser(&LoginPassUserData);
  }
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  
  return Status;
}

EFI_HANDLE
GetCurrentHiiHandle (
  VOID
)
{
  return gMultibootData->HiiHandle;
}

EFI_HANDLE
GetDriverHandle (
  VOID
)
{
  return gMultibootData->DriverHandle;
}
