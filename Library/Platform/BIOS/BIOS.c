/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib.h>
#include <Library/DeviceManager/DeviceManagerInterface.h>
#include <Library/PciDevsMonitorLib.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include <Library/CDPSupportLib/CDPSupport.h>
#include <Library/UserManagerLib.h>
#include <Protocol/RemoteCfgPktProtocol.h>
#include <Protocol/RemoteCfgSolProtocol.h>

#define LOG(MSG)            DEBUG(MSG)

static EFI_GUID mFormSetGuid = FORMSET_BIOS_GUID;
static VOID *mEfiDevPathNotifyReg;
static EFI_EVENT mEfiDevPathEvent;
static EFI_HII_HANDLE CurrentHiiHandle;

extern EFI_GUID gSmartCardReaderProtocolGuid;
extern EFI_GUID gEfiDevicePathProtocolGuid;
extern struct tMainFvInfo MainFvInfo;
extern MULTIBOOT_DATA *gMultibootData;
extern UINT8 LibBin[];


static MULTIBOOT_ENTRY *
PreLoad(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_HII_HANDLE HiiHandle,
  IN UINTN Choise,
  IN BOOLEAN bArgsAdded
  )
{
  MULTIBOOT_ENTRY *MbootDefaultEntry = NULL;
  EFI_STATUS Status;
  INTN AdmChoise;
  
  switch (Choise) {
  case MP_ADDITIONAL_LOADING_MODE_1_ID:
  case MP_ADDITIONAL_LOADING_MODE_2_ID:
  case MP_ADDITIONAL_LOADING_MODE_3_ID:
    MbootDefaultEntry = FindEntryByIndex(Config, Choise);
    break;
    
  case MP_TIME_OUT_ID:
  case MP_REGULAR_LOADING_MODE_ID:
    MbootDefaultEntry = FindEntryByIndex(Config, MP_REGULAR_LOADING_MODE_ID);
    break;

  case MP_ADMIN_MODE_ID:
    if (UserTypeAdmin(UserGetLastFoundedInfo())) {
      gBS->SetWatchdogTimer (0, 0x0000, 0x00, NULL);
      SetCurrentUser(UserGetLastFoundedInfo());
      AdminMainPageStart(HiiHandle, Config->Language);
    } else {
      ShowErrorPermissionDenied(HiiHandle, Config->Language);
      HistoryAddRecord (
        HEVENT_ADMIN_MODE,
        GetCurrentUserId (),
        SEVERITY_LVL_ERROR,
        0);
    }
  
    AdmChoise = GetAdminAdditionalFunction();
    LOG ((EFI_D_ERROR, "%a.%d AdmChoise=%X\n", __FUNCTION__, __LINE__, AdmChoise));  
    switch (AdmChoise) {
    case ADM_MAIN_PAGE_COMPLEX_INSTALL_ID:
      MbootDefaultEntry = FindEntryByIndex(Config, MP_LOAD_FROM_USB_ID);
      break;
    case ADM_MAIN_AMT_FUNC:
    case ADM_MAIN_PAGE_ADM_VIRTUAL_ID:
      MbootDefaultEntry = FindEntryByIndex(Config, 
        ADM_MAIN_PAGE_ADM_VIRTUAL_ID);
      break;

    case ADM_MAIN_BOOT_1_ID:
    case ADM_MAIN_BOOT_2_ID:
    case ADM_MAIN_BOOT_3_ID:
      MbootDefaultEntry = FindEntryByIndex(Config, 
        AdmChoise);
      break;
    
    case ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID:      
      MbootDefaultEntry = FindEntryByIndex(Config, 
        ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID);
      break;

    case ADM_MAIN_PAGE_MEM_TEST_ID:
      Status = SetSetupMemoryTest(1);
      HistoryAddRecord(HEVENT_START_MEM_TEST, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      
      HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
      break;
      
    default:
      if (BootMngrGetSelectedOptGuid()) {
        MbootDefaultEntry = FindEntryByIndex(Config, 
          GetAdminAdditionalFunction());
        if (MbootDefaultEntry) {
          break;
        }
      }
      
      HistoryAddRecord(HEVENT_ADM_MODE_EXIT, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, 0);
      HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
    }
    break;

  case MP_FAILURE_MODE_ID:
    if (-1 == FailSaveModeCheckPass(HiiHandle, Config->Language, &MainFvInfo)) {
      SoundForError();
      MsgInternalError(INT_ERR_INVALID_FAILSAVE_PASS);
    }
    MbootDefaultEntry = FindEntryByIndex(Config, MP_FAILURE_MODE_ID);
    break;


  default:
    MbootDefaultEntry = NULL;
    MsgInternalError(INT_ERR_INVALID_MP_CHOISE);
    break;
  }
  
  return MbootDefaultEntry;
}


static VOID
HistoryTest(
  VOID
  )
{
  UINTN i;
  EFI_STATUS Status;
  HISTORY_STORAGE HistStorage;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  for (i = 0; i < 16; i++) {
    Status = HistoryAddRecord(HEVENT_USER_LOGIN, GetCurrentUserId(), 
      SEVERITY_LVL_INFO, HISTORY_RECORD_FLAG_RESULT_OK);    
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    HistoryStorageGetData(&HistStorage);
    LOG((EFI_D_ERROR, "%a.%d HistStorage.DataLen=%d\n", 
    __FUNCTION__, __LINE__, HistStorage.DataLen));
  }
}

BOOLEAN
IsChoiseIsLoadingWithParams (
  IN UINTN Choise
  )
{
  if (Choise == MP_REGULAR_LOADING_MODE_ID || 
      Choise == MP_TIME_OUT_ID ||
      Choise == MP_RECOVER_MODE_ID || 
      Choise == MP_ADDITIONAL_LOADING_MODE_1_ID ||
      Choise == MP_ADDITIONAL_LOADING_MODE_2_ID ||
      Choise == MP_ADDITIONAL_LOADING_MODE_3_ID ||
      Choise == MP_ADMIN_MODE_ID ||
      Choise == ADM_MAIN_BOOT_1_ID ||
      Choise == ADM_MAIN_BOOT_2_ID ||
      Choise == ADM_MAIN_BOOT_3_ID) {
    return TRUE;
  }
  return FALSE;
}

STATIC
EFI_STATUS
EFIAPI
ReadyToBootCallback (
  IN EFI_EVENT    Event,
  IN VOID         *Context
  )
{
  UsersListUpdate ();
  return EFI_SUCCESS;
}


MULTIBOOT_ENTRY *
BIOSSetup(
  VOID
  )
{
  EFI_STATUS Status;
  MULTIBOOT_DATA *Data;
  MULTIBOOT_CONFIG *Config;
  MULTIBOOT_ENTRY *MbootDefaultEntry = NULL;
  UINTN Choise;
  INT32 RetVal;
  BOOLEAN IntegrityFailFlag1 = FALSE, IntegrityFailFlag2 = FALSE;
  BOOLEAN bArgsAdded = FALSE;
  UINT8 PakStatus, LoadCounter;
  USERS_STORAGE UsrStrorage;
  HISTORY_STORAGE HistStorage;
  USER_INFO *pUserInfo;
  BOOLEAN bNeedMii = TRUE;
  STATIC BOOLEAN bFirtsIn = TRUE;
  T_FIRMWARE_INFO FwInfo;
  EFI_EVENT ReadyToBootEvt;

  Data = gMultibootData;
  Config = &gMultibootData->Config;
  if (!bFirtsIn) {
    bNeedMii = FALSE;
    PakStatus = LoadCounter = 0;
    goto _login;
  }

  Status = EfiCreateEventReadyToBootEx (
            TPL_CALLBACK,
            ReadyToBootCallback,
            NULL,
            &ReadyToBootEvt
            );
  DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  bFirtsIn = FALSE;
 
  Status = InitializeDeviceManager();
    if (EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_INIT_DEVICE_MANAGER_ERROR);
  }

  MsgSetInernalErrStringId(STRING_TOKEN(STR_ERR_INTERNAL));    

  Status = InitProtocols(Data);
  if (EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_INIT_PROTOCOLS_ERROR);
  }

  //
  // Publish our HII data
  //
  Data->HiiHandle = HiiAddPackages (
          &mFormSetGuid,
          Data->DriverHandle,
          LibBin,
          LibStrings, 
          NULL
          );

  if(Data->HiiHandle == NULL) {
    MsgInternalError(INT_ERR_HII_ADD_PKG_ERROR);
  }

  InitReadDataHelper(
    Data->HiiHandle,
    STRING_TOKEN(STR_INFO_READ_DATA),
    STRING_TOKEN(STR_INFO_READED),
    STRING_TOKEN(STR_INFO_FROM)
    );

  if (-1 == MsgInit(Data->HiiHandle, Config->Language)) {
    MsgInternalError(INT_ERR_INIT_MSG_MODULE_ERROR);
  }

  Status = SetupBestLanguage(Data->HiiHandle, Config->Language);
  if(EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_SETUP_BEST_LANG_ERROR);
  }

  GetFirmwareInfo(&FwInfo);

  LOG((EFI_D_ERROR, "%a.%d Config->Default=0x%X\n",
    __FUNCTION__, __LINE__, Config->Default));
  MbootDefaultEntry = FindEntryByIndex( 
    Config,
    Config->Default
    );
  if (MbootDefaultEntry) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_ERROR, "MbootDefaultEntry->Name=%s\n",
      MbootDefaultEntry->Name));
    return MbootDefaultEntry;
  }

  MsgInfo(STRING_TOKEN(STR_BIOS_HASH_CHECK));
  if (-1 == FindMainFv(MAIN_FV_GUID_STR, &MainFvInfo)) {
    MsgSendError( STRING_TOKEN(STR_HASH_NOT_PRESENT) );
  }

  if (!CheckEngeneerPasswdPresent(&MainFvInfo, BIOS_PASS_GUID)) {
    MsgInternalError(INT_ERR_ENGENEER_PASS_NOT_PRESENT);
  }
  if (!CheckEngeneerPasswdPresent(&MainFvInfo, FAIL_SAVE_PASS_GUID)) {
    MsgInternalError(INT_ERR_FAILSAVE_PASS_NOT_PRESENT);
  }

  Status = CheckAllFvWithExtHdr ();
  if (EFI_ERROR(Status)) {
    IntegrityFailFlag1 = TRUE;
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }

  if (IntegrityFailFlag1) {
    MsgInfo(STRING_TOKEN(STR_ERR_BIOS_INTEGRITY));
    FtSetStatus(FT_BIOS_INTEGRITY_ERR);
  }  

  MsgInfo(STRING_TOKEN(STR_FILE_HASH_CHECK));
  if (-1 == CheckAllObjWithPath(&MainFvInfo)) {
    ShowErrorObject();
    if (!IntegrityFailFlag1) {
      FtSetStatus(FT_BIOS_INTEGRITY_ERR);
      IntegrityFailFlag2 = TRUE;
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    }
  }
  if (!IntegrityFailFlag1 && !IntegrityFailFlag2) {
    FtSetStatus(0);
  }

  CurrentHiiHandle = Data->HiiHandle;
  MainMenuLockOff();
  PlatfromLibraryInit(Data);   

  if (EFI_NOT_FOUND == HistoryStoragePresent()) {
    LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    if (EFI_SUCCESS != HistoryStorageInitEmpty()) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      MsgInternalError(INT_ERR_WHILE_INIT_HISTORY_STORAGE);
    }
  }
  if (EFI_SUCCESS != HistoryStorageGetData(&HistStorage)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    GotoInitialInitializationMode(Data->HiiHandle);
    MsgInternalError(INT_ERR_WHILE_READ_HISTORY_STORAGE);
  }

  LOG((EFI_D_ERROR, "%a.%d HistStorage.DataLen=%d\n", 
    __FUNCTION__, __LINE__, HistStorage.DataLen));

  if (EFI_NOT_FOUND == UsersStoragePresent()) {
    LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    if (EFI_SUCCESS != UsersStorageInitEmpty()) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      MsgInternalError(INT_ERR_WHILE_INIT_USERS_STORAGE);
    }
  }  
  ZeroMem(&UsrStrorage, sizeof(USERS_STORAGE));
  if (EFI_SUCCESS != UsersStorageGetData(&UsrStrorage)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    GotoInitialInitializationMode(Data->HiiHandle);
    MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
  }

  bNeedMii = GetFormById (Config, MII_PAGE_ID) == NULL ? FALSE : TRUE;
  LOG((EFI_D_ERROR, "%a.%d bNeedMii=%d UsrStrorage.DataLen=%d\n", 
    __FUNCTION__, __LINE__,
    bNeedMii,
    UsrStrorage.DataLen
    ));
  if (UsrStrorage.DataLen == 0 && bNeedMii) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));

    UsersSetUserTypesFlags(USER_TYPE_ADMIN);    

    LocksInit(CurrentHiiHandle);
    if (Config->DefUserDesc != NULL) {
      Status = CreateDefaultUser (Config->DefUserDesc);
      if (EFI_ERROR (Status)) {
        LOG ((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      }
    } else {
      MIIStart(Data->HiiHandle, Config, &MainFvInfo, Config->Language);
      HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
    }
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);

  } else if (UsrStrorage.DataLen < sizeof(USER_INFO)) {
    LOG((EFI_D_ERROR, "%a.%d Error UsrStrorage.DataLen=%d!\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
  } else if (EFI_SUCCESS != UsersStorageCheckIntegrity()) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      GotoInitialInitializationMode(Data->HiiHandle);
      MsgInternalError(INT_ERR_CORRUPT_USERS_STORAGE);
  }

  Status = LocksInit(CurrentHiiHandle);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    MsgInternalError(INT_ERR_WHILE_LOGIN_FAIL_CNT_ACCESS);
  }
  
  if (EFI_SUCCESS != FtGetStatus(&PakStatus)) {
    MsgInternalError(INT_ERR_STATUS_VAR_READ_ERROR);
  }
  if (EFI_SUCCESS != FtGetLoadCounter(&LoadCounter)) {
    MsgInternalError(INT_ERR_LOAD_COUNTER_VAR_READ_ERROR);
  }

  if (IntegrityFailFlag1 || IntegrityFailFlag2 || 
    PakStatus == FT_BIOS_INTEGRITY_ERR) {
    while (1) {
      SoundForError();
      GotoInitialInitializationMode(Data->HiiHandle);
    }
  }

  if (GetCurrentUserId() == 0) {
    /* we are not logged in */
    SetCurrentUser (NULL);
  }
  
  // Clean all messages and logo here
  gST->ConOut->ClearScreen(gST->ConOut);

_login:
  
  BlockMultibootRemoteAccess (FALSE);

  Choise = MP_TIME_OUT_ID;

  Status = UsrVarClean();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    MsgInternalError(INT_ERR_WHILE_USR_VAR_ACCESS_RD);
  }

  if (PcdGetBool(bEnableRtcRst)) {
    ResetBiosSetupByRtcRst(Data->HiiHandle, 1);
  }

  {
    USER_INFO *pUserInfo = GetCurrentUser();
	LOG ((EFI_D_ERROR, "%a.%d pUserInfo=%p\n", __FUNCTION__, __LINE__, pUserInfo));
    if (pUserInfo == NULL || pUserInfo->UserId == USER_UNKNOWN_ID) {
      RetVal = AdminModeCheckLoginPass(Data->HiiHandle, 
        Config->Language);
    } else {
      /* just for updating last founded information */
      UserFindRecordById(pUserInfo->UserId);
      RetVal = -3;
    }
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    gST->ConOut->ClearScreen (gST->ConOut);
  }
  BlockMultibootRemoteAccess (TRUE);
  if (-1 == RetVal) {
      gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  } else {
    pUserInfo = UserGetLastFoundedInfo();
    SetCurrentUser(pUserInfo);
    UpdateCurrentUserInfo ();
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    Status = AdminCheckCurrentUserPassExpiration(Data->HiiHandle);
    if (EFI_ERROR(Status)) {
      if ((pUserInfo->Flags & USER_ADMIN_FLAG) == 0) {  
        gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
      } else {
        Status = ChangeAdminPassword(Data->HiiHandle, pUserInfo);
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(Data->HiiHandle,
            HiiGetString(Data->HiiHandle, 
              STRING_TOKEN(STR_PASS_UPDATE_FAIL), NULL));
        } else {
          ShowSuccessPopup(Data->HiiHandle,
            HiiGetString(Data->HiiHandle, 
              STRING_TOKEN(STR_PASS_UPDATE_SUCCESS), NULL));
        }
        gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
      }
    }
    Status = UsrVarUpdate();
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
      MsgInternalError(INT_ERR_WHILE_USR_VAR_ACCESS_WR);
    }

    HistoryAddRecord(HEVENT_USER_LOGIN, 
        GetCurrentUserId(), SEVERITY_LVL_INFO, HISTORY_RECORD_FLAG_RESULT_OK);
    
    if (!UserTypeAdmin(UserGetLastFoundedInfo())) {
      USER_INFO *pUsrInfo;
      UINT8 UsrAccess = 0;
      pUsrInfo = UserGetLastFoundedInfo();
      if (pUsrInfo) {
        GetUserAccessInfo(pUsrInfo->UserId, &UsrAccess);
      }
      
      if (PciDevPresent(0xF005, 0x1172) || 
          UsrAccess == USER_ACCESS_REMOTE_START_OS) {
        MainPageSetAdminModeRdOnly (TRUE);
        Choise = MainPageStart(Data->DriverHandle, Config->Language);
        MainPageSetAdminModeRdOnly (FALSE);
      } else {
        Choise = MP_REGULAR_LOADING_MODE_ID;
      }
    } else {      
       Choise = MainPageStart(Data->DriverHandle, Config->Language);
    }
  }  

  LOG((EFI_D_ERROR, "%a.%d Choise=%X\n", __FUNCTION__, __LINE__, Choise));

_load:
  
  MbootDefaultEntry = PreLoad(Config, Data->HiiHandle, Choise, bArgsAdded);
  if (IsNeedAmt()) {
    return MbootDefaultEntry;
  }

  if (IsChoiseIsLoadingWithParams (Choise)) {
    MULTIBOOT_ENTRY *MbEntry;
    EFI_GUID Guid;

    Status = StringToGuid_L(MbootDefaultEntry->GuidStr, &Guid);
    if (!EFI_ERROR(Status)) {
      Status = BootMngrSetVarsGuidIdxByGuid(&Guid);
    }
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Cfg not found!\n", 
        __FUNCTION__, __LINE__));
      goto CfgNotFound;
    }
    MsgInfo(STRING_TOKEN(STR_WAIT_FOR_CHECKING_MODULES));
    
    MbEntry = GetCurrentBootOption();
    if (MbEntry) {
      MbootDefaultEntry = MbEntry;
      LOG((EFI_D_ERROR, "%a.%d Found Entry:\n", 
        __FUNCTION__, __LINE__));
      LOG((EFI_D_ERROR, "MbEntry->Format=0x%X\n", 
        MbEntry->Format));
    }
    Status = IcflCheckIntegrity();
    if (EFI_ERROR(Status)) {
      HistoryAddRecord(
        HEVENT_CHECK_MODULE, 
        GetCurrentUserId(), 
        SEVERITY_LVL_ERROR, 0);

      MsgInfo(STRING_TOKEN(STR_ERR_OS_MODULE_INTEGRITY));
      LOG((EFI_D_ERROR, "%a.%d Wrong hash!\n", 
        __FUNCTION__, __LINE__));
      SoundForError();
      CpuDeadLoop();
    }
    MsgInfo(STRING_TOKEN(STR_LOADING_MODULES_CHECKING_DONE));
  }
  
CfgNotFound:
  if (Choise == MP_TIME_OUT_ID || Choise == MP_REGULAR_LOADING_MODE_ID) {
    HistoryCheckOverflow();
  }

  if (EFI_SUCCESS != FtUpdateLoadCounter()) {
    MsgInternalError(INT_ERR_UPDATE_LOAD_COUNTER);
  }
  if (PakStatus == FT_CTRL_APP_RUN_ERR) {
    if (EFI_SUCCESS != FtUpdateLoadCounter()) {
      MsgInternalError(INT_ERR_UPDATE_LOAD_COUNTER);
    }
  }
  
  FtSetStatus(FT_OS_RUN_ERR);

  PreBootPlatfromProcessing(Data->HiiHandle, Config, MbootDefaultEntry);

  Status = PciDevsMonitorCheckConfiguration();
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {    
    MsgInfo(STRING_TOKEN(STR_ERR_EQUIPMENT_MONITORING_FAIL));
    SoundForError();
    CpuDeadLoop();
  }
  
  SaveLoadingModeEvent (Choise);
  
  return MbootDefaultEntry;
}
