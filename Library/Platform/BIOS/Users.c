/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/Users.h>
#include <Library/Lib/History.h>
#include <Library/Lib/SuperUser.h>
#include <Library/UserManagerLib.h>
#include "Password.h"

#define LOG(MSG)            DEBUG(MSG)

extern UINT8 BIOSvfrBin[];

STATIC MULTIBOOT_CONFIG *CurrentConfig;
STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
STATIC BOOLEAN bUsersFormExitFlag, bRecreateForm, bUserCreated, bRefreshForm;
STATIC UINT8 AuthTypeOptions[2], CurAuthType, CurUsrType, BlockingOpt[2];

STATIC USER_INFO gUserInfo;
STATIC USER_INFO_LOG_PASS gUserInfoPass;
STATIC UINT32 InputDataFlags;
STATIC UINT8 gComparisonFlags;
STATIC CHAR16 *PasswdMenuStr;
STATIC EFI_STRING_ID PasswdMenuStrId;
STATIC CHAR16 *PasswdCreationTimeStr;
STATIC EFI_STRING_ID PasswdCreationTimeStrId;
STATIC UINT8 CurrentUserId;
STATIC UINT8 CurrentUserTypesFlags = USER_TYPE_ADMIN;
STATIC int CurrentEvent;
STATIC int CurrentMode = USERS_PAGE_TYPE_NONE;
extern USERS_STORAGE UsrStrorage;
STATIC UINT8 gUserId, ValU8;
STATIC UINTN gEditedUserNum;
STATIC BOOLEAN bCreateAccountQuite;
STATIC UINT8 *AdminRolesMapping;
STATIC EFI_STRING_ID AdminRolesStrId[] = {
    STRING_TOKEN(STR_ADMIN_ROLE_AUDIT),
    STRING_TOKEN(STR_ADMIN_ROLE_FULL_ACCESS)
  };
enum {
  ADM_ROLE_AUDIT_ID,
  ADM_ROLE_FULL_ACCESS_ID,
  ADM_ROLE_UNKNOWN
};
STATIC UINTN AdminRolesMappingSize;
STATIC USERS_ACCESS_INFO gUsrAccessInfo;
STATIC BOOLEAN bDontChangeAuthType;
STATIC CHAR16 *CurrentPinPass;

BOOLEAN
isHiddenUser (
  IN USER_INFO *pUserInfo
  )
{
  if (pUserInfo == NULL) {
    return FALSE;
  }
  if ((pUserInfo->Flags & USER_HIDDEN_FLAG) == USER_HIDDEN_FLAG) {
    return TRUE;
  }
  return FALSE;
}

STATIC
EFI_STATUS
UpdateGlobalUsrAccessInfo (
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  
  gUsrAccessInfo.UsrId = UserId;
  Status = GetUserAccessInfo (UserId, &gUsrAccessInfo.AccessType);  
  if (EFI_ERROR(Status)) {
    gUsrAccessInfo.AccessType = USER_ACCESS_AUDIT;
  }
  return EFI_SUCCESS;
}

STATIC
UINT8
ConvertLdapPermission (
  IN UINTN Permission
  )
{
  switch (Permission) {
  case ALLOW_TO_LOGIN_ADMIN_FULL:
    return USER_ACCESS_FULL_CTRL;

  case ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE:
    return USER_ACCESS_REMOTE_FULL_CTRL;

  case ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE:
    return USER_ACCESS_REMOTE_AUDIT;

  case ALLOW_TO_LOGIN_ADMIN_AUDIT:    
    return USER_ACCESS_AUDIT;

  case ALLOW_TO_LOGIN_USER_REMOTE:
    return USER_ACCESS_REMOTE_START_OS; 
  }
  return USER_ACCESS_START_OS;
}


STATIC
EFI_STATUS
CreateDefaultAdminRolesMap (
  VOID
  )
{
  UINTN Idx;
  
  AdminRolesMappingSize = 2;
  AdminRolesMapping = AllocateZeroPool(
    sizeof(*AdminRolesMapping) * AdminRolesMappingSize);
  if (AdminRolesMapping == NULL) {
    AdminRolesMappingSize = 0;
    return EFI_OUT_OF_RESOURCES;
  }

  for (Idx = 0; Idx < AdminRolesMappingSize; Idx++) {
    AdminRolesMapping[Idx] = (UINT8)Idx;
  }
  
  return EFI_SUCCESS;
}

STATIC
VOID
RefreshCurrentAdminRolesMapByIdx (
  IN UINTN CurIdx
  )
{
  UINT8 Val;

  if (CurIdx > AdminRolesMappingSize) {
    return;
  }
  if (CurIdx == 0) {
    return;
  }

  Val = AdminRolesMapping[0];
  AdminRolesMapping[0] = AdminRolesMapping[CurIdx];
  AdminRolesMapping[CurIdx] = Val;
}

STATIC
VOID
RefreshCurrentAdminRolesMapByType (
  IN UINTN Type
  )
{
  UINTN CurIdx;

  if (Type > ADM_ROLE_UNKNOWN) {
    return;
  }

  for (CurIdx = 1; CurIdx < AdminRolesMappingSize; CurIdx++) {
    if (AdminRolesMapping[CurIdx] == Type) {
      RefreshCurrentAdminRolesMapByIdx (CurIdx);
      break;
    }
  }
}


STATIC
EFI_STATUS
UsersAdminAccessInfoMenu (
  IN VOID *OpCodeHandle,
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID QuestionId 
  )
{
  EFI_STRING_ID Token, HelpToken;
  UINT8 CheckBoxFlags = 0;
  VOID *OptionsOpCodeHandle;
  UINTN Idx, Idx2;
  USER_INFO *pUserInfo;
  EFI_STATUS Status;

  ZeroMem (&gUsrAccessInfo, sizeof (gUsrAccessInfo));

  if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
    UINT8 AccessInfo;

    pUserInfo = UserGetLastFoundedInfo();
    DEBUG ((EFI_D_ERROR, "%a.%d pUserInfo->UserId=%X\n", 
      __FUNCTION__, __LINE__, pUserInfo->UserId));
    Status = GetUserAccessInfo (pUserInfo->UserId, &AccessInfo);
    if (!EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d AccessInfo=%X\n", 
        __FUNCTION__, __LINE__, AccessInfo));
      if (AccessInfo & 0x1) {
        CheckBoxFlags |= EFI_IFR_CHECKBOX_DEFAULT;
        AccessInfo--;
      }

      if (AccessInfo == USER_ACCESS_AUDIT) {
        RefreshCurrentAdminRolesMapByType (ADM_ROLE_AUDIT_ID);
        gUsrAccessInfo.AccessType = CheckBoxFlags & EFI_IFR_CHECKBOX_DEFAULT ? 
          USER_ACCESS_REMOTE_AUDIT : USER_ACCESS_AUDIT;
      } else if (AccessInfo == USER_ACCESS_FULL_CTRL) {
        RefreshCurrentAdminRolesMapByType (ADM_ROLE_FULL_ACCESS_ID);
        gUsrAccessInfo.AccessType = CheckBoxFlags & EFI_IFR_CHECKBOX_DEFAULT ? 
          USER_ACCESS_REMOTE_FULL_CTRL : USER_ACCESS_FULL_CTRL;
      }
    }
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (NULL == OptionsOpCodeHandle) {
    return EFI_OUT_OF_RESOURCES;
  }

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  if (GetMiiMode()) {
    RefreshCurrentAdminRolesMapByType (ADM_ROLE_FULL_ACCESS_ID);
    gUsrAccessInfo.AccessType = USER_ACCESS_FULL_CTRL;
  }

  for (Idx = 0; Idx < AdminRolesMappingSize; Idx++) {
    Idx2 = AdminRolesMapping[Idx];
    if (Idx2 >= sizeof(AdminRolesStrId)/ sizeof(*AdminRolesStrId)) {
      return EFI_ABORTED;
    }
    if (GetMiiMode() && Idx2 == ADM_ROLE_AUDIT_ID) {
      continue;
    }
    Token = AdminRolesStrId[Idx2];
    HiiCreateOneOfOptionOpCode (
        OptionsOpCodeHandle,
        Token,
        0,
        EFI_IFR_NUMERIC_SIZE_1,
        Idx);
  }
  Token = STRING_TOKEN(STR_USERS_ADMIN_ROLE);
  HiiCreateOneOfOpCode (
    OpCodeHandle, 
    QuestionId, 
    0,  
    0, 
    Token, 
    HelpToken, 
    EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
    EFI_IFR_NUMERIC_SIZE_1, 
    OptionsOpCodeHandle, 
    NULL
    );
  return EFI_SUCCESS;
}


EFI_STATUS
UsrVarClean(
  VOID
  )
{
  UINTN Size;
  EFI_STATUS Status;
    
  Size = 0;
  Status = gRT->GetVariable(USR_VAR_NAME, &gUsrVarGuid,
      NULL, &Size, NULL);

  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }

  LOG((EFI_D_ERROR, "%a.%d Data={%s}\n", __FUNCTION__, __LINE__, Data));
  Size = (StrLen(Data) + 1) << 1;

  Status = gRT->SetVariable(USR_VAR_NAME, &gUsrVarGuid,
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
       EFI_VARIABLE_RUNTIME_ACCESS), Size, Data);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
CHAR16 *
UsrGetAccessStr (
  IN USER_INFO *pUser
  )
{
  EFI_STATUS Status;
  UINT8 AccessInfo = 0;
  
  Status = GetUserAccessInfo (pUser->UserId, &AccessInfo);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    return L"0";
  }

  if ((pUser->Flags & USER_ADMIN_FLAG) == 0) {
    if (AccessInfo != USER_ACCESS_REMOTE_START_OS) {
      return L"0";
    }
    return L"1";
  }

  switch (AccessInfo) {
  case USER_ACCESS_AUDIT:
    return L"0";
    
  case USER_ACCESS_REMOTE_AUDIT:
    return L"1";
    
  case USER_ACCESS_FULL_CTRL:
    return L"2";
    
  case USER_ACCESS_REMOTE_FULL_CTRL:
    return L"3";
    
  case USER_ACCESS_START_OS:
  case USER_ACCESS_REMOTE_START_OS:
    return L"0";
  }
  return L"0";
}

STATIC CHAR16 *
UsrVarString(
  VOID
  )
{
  USER_INFO *pUser;
  STATIC CHAR16 Buffer[1024] = {0};
  
  pUser = GetCurrentUser();
  if (NULL == pUser) {
    return NULL;
  }
  UnicodeSPrint(Buffer, sizeof(Buffer), L"%d;%s;%s;%s",
    pUser->AuthType, pUser->UserName, pUser->UserFIO, pUser->UserContactInfo);
  switch (pUser->AuthType) {
    case AUTH_TYPE_LOG_PASS:
      UnicodeSPrint(Buffer + StrLen(Buffer), 
        sizeof(Buffer) - StrLen(Buffer), L";;;;;;");
      break;

    default:
      return NULL;
    }

  UnicodeSPrint(Buffer + StrLen(Buffer), 
      sizeof(Buffer) - StrLen(Buffer), L";%s;%s", 
      (pUser->Flags & USER_ADMIN_FLAG) == 0 ? L"0" : L"1",
      UsrGetAccessStr (pUser));

  return Buffer;
}

EFI_STATUS
UsrVarUpdate(
  VOID
  )
{
  UINTN Size;
  EFI_STATUS Status;
  CHAR16 *Data;
    
  Size = 0;
  Data = NULL;
  Status = gRT->GetVariable(USR_VAR_NAME, &gUsrVarGuid,
      NULL, &Size, Data);

  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }

  Data = UsrVarString();

  if (Data == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  LOG((EFI_D_ERROR, "%a.%d Data={%s}\n", __FUNCTION__, __LINE__, Data));
  Size = (StrLen(Data) + 1) << 1;

  Status = gRT->SetVariable(USR_VAR_NAME, &gUsrVarGuid,
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
       EFI_VARIABLE_RUNTIME_ACCESS), Size, Data);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


int
GetUserPageCurrentEvent(
  VOID
  )
{
  return CurrentEvent;
}


STATIC VOID
UpdateGlobalUserInfo(
  VOID
  )
{
  USER_INFO *pCurUserInfo;

  pCurUserInfo = UserGetLastFoundedInfo();
  if (NULL == pCurUserInfo) {
    LOG((EFI_D_ERROR, "%a.%d No user selected!\n", __FUNCTION__, __LINE__));
    return;
  }
  
  CopyMem(&gUserInfo, pCurUserInfo, sizeof(USER_INFO) - 1);

  InputDataFlags = (FILL_FLAG_USER_NAME | FILL_FLAG_USER_FIO | 
    FILL_FLAG_USER_CONTACT_INFO);
  
  CurAuthType = gUserInfo.AuthType;
  if (gUserInfo.AuthType == AUTH_TYPE_LOG_PASS) {    
    CopyMem(&gUserInfoPass, pCurUserInfo->ExtData, sizeof(USER_INFO_LOG_PASS));
    InputDataFlags |= FILL_FLAG_USER_PASSWD;
  } else {
    return;
  }  
}


STATIC
BOOLEAN
CheckPaddingData (
  IN UINTN Len1,
  IN UINTN Len2,
  IN UINT8 *Data1,
  IN UINT8 *Data2
  )
{
  UINTN OriginLen1, OriginLen2;
  
  if (Data1 == NULL || Data2 == NULL || Len1 == 0 || Len2 == 0) {
    return FALSE;
  }

  OriginLen1 = Len1;
  OriginLen2 = Len2;

  if ((Len1 & 0x1) == 0 && (Len2 & 0x1) == 0) {
    Len1 >>= 1;
    Len2 >>= 1;
  }
  if (Len1 > Len2) {
    if (Len1 - Len2 == 1) {
      return IsBufZero(&Data1[OriginLen2], OriginLen1 - OriginLen2);
    }
  } else {
    if (Len2 - Len1 == 1) {
      return IsBufZero(&Data2[OriginLen1], OriginLen2 - OriginLen1);
    }
  }
  return FALSE;
}


STATIC EFI_STATUS
UsersDeleteAction(
  IN EFI_QUESTION_ID QuestionId
  );

STATIC EFI_STATUS
UsersStoreToCvsFileAction(
  VOID
  );


BOOLEAN
UserTypeAdmin(
  IN USER_INFO *pUser
  )
{
  if (NULL == pUser) {
    LOG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return FALSE;
  }
  if (pUser->Flags & USER_ADMIN_FLAG) {
    return TRUE;
  }
  return FALSE;
}


USER_INFO *
GetCurrentUser(
  VOID
  )
{
  if (CurrentUserId == USER_SU_ID) {    
    return ObtainSuRecord();
  }
  if (EFI_SUCCESS != UserFindRecordById(CurrentUserId)) {
    return NULL;
  }
  return UserGetLastFoundedInfo();
}

UINT8
GetCurrentUserId(
  VOID
  )
{
  return CurrentUserId == 0 ? USER_UNKNOWN_ID : CurrentUserId;
}


VOID
SetCurrentUser(
  IN USER_INFO *pUser
  )
{
  EFI_STATUS Status;
  
  if (NULL == pUser) {
    CurrentUserId = USER_UNKNOWN_ID;
    return;
  }
  CurrentUserId = pUser->UserId;  
  SetCurrentUserVar (&CurrentUserId, sizeof(CurrentUserId));
  if (pUser->UserId == USER_SU_ID) {
    gUsrAccessInfo.UsrId = USER_SU_ID;
    gUsrAccessInfo.AccessType = USER_ACCESS_REMOTE_FULL_CTRL;
    Status = CheckUserAccessInfoPresent (gUsrAccessInfo.UsrId);
    if (EFI_ERROR(Status)) {
      Status = AddUserAccessInfo (gUsrAccessInfo.UsrId, 
        gUsrAccessInfo.AccessType);
    }
    ZeroMem (&gUsrAccessInfo, sizeof(gUsrAccessInfo));
  }
}


STATIC EFI_STATUS
ObtainNewUserId(
  IN UINT8 *pUserId
  )
{
  UINT8 i;
  BOOLEAN bHaveNewId;
  
  for (i = 0, bHaveNewId = FALSE; i <= 255; i++) {
    while( gUserId == 0 || 
            gUserId == USER_SU_ID ||
            gUserId == USER_UNKNOWN_ID ||
            gUserId == USER_AMT_ID)
    {
      gUserId++;
    }
    
    if (EFI_SUCCESS == UserFindRecordById(gUserId)) {
      gUserId++;
    } else {
      bHaveNewId = TRUE;
      break;
    }
  }
  if (!bHaveNewId) {
    return EFI_OUT_OF_RESOURCES;
  }

  LOG((EFI_D_ERROR, "%a.%d: gUserId=0x%02X\n", 
    __FUNCTION__, __LINE__, gUserId));
  
  *pUserId = gUserId;
  gUserId++;
  return EFI_SUCCESS;
}


STATIC UINT32
PassCountUcSymbols(
  CHAR16 *Password,
  UINT32 PassLen
  )
{
  UINT32 Cnt, i;
  
  for (i = 0, Cnt = 0; i < PassLen; i++) {
    if (Password[i] >= L'A' && Password[i] <= L'Z') {
      Cnt++;
    }
  }
  
  return Cnt;
}

STATIC UINT32
PassCountLcSymbols(
  CHAR16 *Password,
  UINT32 PassLen
  )
{
  UINT32 Cnt, i;
  
  for (i = 0, Cnt = 0; i < PassLen; i++) {
    if (Password[i] >= L'a' && Password[i] <= L'z') {
      Cnt++;
    }
  }
  
  return Cnt;
}


STATIC UINT32
PassCountDigitSymbols(
  CHAR16 *Password,
  UINT32 PassLen
  )
{
  UINT32 Cnt, i;
  
  for (i = 0, Cnt = 0; i < PassLen; i++) {
    if (Password[i] >= L'0' && Password[i] <= L'9') {
      Cnt++;
    }
  }
  
  return Cnt;
}


STATIC UINT32 
PassCountSpecsymbols(
  CHAR16 *Password,
  UINT32 PassLen
  )
{
  UINT32 Cnt, i, j, SpecArrLen;
  
  SpecArrLen = sizeof(SpecSymbols) / sizeof(SpecSymbols[0]);
  
  for (i = 0, Cnt = 0; i < PassLen; i++) {
    for (j = 0; j < SpecArrLen; j++) {
      if (Password[i] == SpecSymbols[j]) {
        Cnt++;
      }
    }
  }
  return Cnt;
}


EFI_STATUS
CheckPasswordSymbols(
  CHAR16 *Password,
  UINT32 PassLen
  )
{
  UINT32 SpecCnt, UcCnt, LcCnt, DigCnt;
  
  UcCnt = PassCountUcSymbols(Password, PassLen);
  LcCnt = PassCountLcSymbols(Password, PassLen);
  SpecCnt = PassCountSpecsymbols(Password, PassLen);
  DigCnt = PassCountDigitSymbols(Password, PassLen);
  
  LOG((EFI_D_ERROR, "TotalLen=%d; UcCnt=%d; LcCnt=%d; SpecCnt=%d; DigCnt=%d;\n",
    PassLen, UcCnt, LcCnt, SpecCnt, DigCnt));
  
  if (UcCnt < 1) {
    return EFI_ACCESS_DENIED;
  }
  if (LcCnt < 1) {
    return EFI_ACCESS_DENIED;
  }
  if (SpecCnt < 1) {
    return EFI_ACCESS_DENIED;
  }
  if (DigCnt < 1) {
    return EFI_ACCESS_DENIED;
  }
  
  return EFI_SUCCESS;
}


STATIC VOID
DestroyHiiResources(
  VOID
  )
{
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }
}


STATIC EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = USERS_PAGE_ID;
  
  DestroyHiiResources();
  
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
  StartLabel->Number       = LABEL_USERS_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_USERS_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


STATIC EFI_STATUS
BlockFlagOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  USER_INFO *pCurUserInfo;

  
  
LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
  __FUNCTION__, __LINE__, QuestionId));

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    goto _exit;
  }

  Str16_1 = STRING_TOKEN (STR_BLOCK_FLAG_OFF);
  Str16_2 = STRING_TOKEN (STR_BLOCK_FLAG_ON);
  
  BlockingOpt[USER_NON_BLOCKED_STATE] = 0;
  BlockingOpt[USER_BLOCKED_STATE] = 1;
  
  if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
    pCurUserInfo = UserGetLastFoundedInfo();
    if (NULL == pCurUserInfo) {
      LOG((EFI_D_ERROR, "%a.%d No user selected!\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    if (pCurUserInfo->Flags & USER_BLOCKED_FLAG) {
      BlockingOpt[USER_NON_BLOCKED_STATE] = 1;
      Str16_1 = STRING_TOKEN (STR_BLOCK_FLAG_ON);
      Str16_2 = STRING_TOKEN (STR_BLOCK_FLAG_OFF);
    }
  }

  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0)) {
     LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1)) {
    LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  Status =  HiiCreateOneOfOpCode (StartOpCodeHandle, QuestionId, 
    0,  0, Caption,
    STRING_TOKEN (STR_NULL_STRING), 
    EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
    EFI_IFR_NUMERIC_SIZE_1, OptionsOpCodeHandle, NULL
    ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
  
_exit:  
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


STATIC EFI_STATUS
SuspendFlagOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
  __FUNCTION__, __LINE__, QuestionId));  

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    STRING_TOKEN (STR_SUSPEND_FLAG_OFF), 0, EFI_IFR_NUMERIC_SIZE_1, 0)) {
LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    STRING_TOKEN (STR_SUSPEND_FLAG_ON), 0, EFI_IFR_NUMERIC_SIZE_1, 1)) {
LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, STRING_TOKEN (STR_NULL_STRING),
      EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
      EFI_IFR_NUMERIC_SIZE_1,
      OptionsOpCodeHandle,
      NULL
      ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;

_exit:
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


STATIC 
EFI_STATUS
UsersTypeOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 UserType
  )
{
  VOID *OptionsOpCodeHandle = NULL; // *Opt1, *Opt2;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  
  LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));  

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  LOG((EFI_D_ERROR, "OptionsOpCodeHandle=%p\n", OptionsOpCodeHandle));

  if (CurUsrType == USER_TYPE_USER) {
    LOG((EFI_D_ERROR, "%a.%d CurUsrType == USER_TYPE_USER\n", 
      __FUNCTION__, __LINE__));
    Str16_1 = STRING_TOKEN (STR_USERS_TYPE_USER);
    Str16_2 = STRING_TOKEN (STR_USERS_TYPE_ADMIN);
  } else {
    LOG((EFI_D_ERROR, "%a.%d CurUsrType == USER_TYPE_ADMIN\n", 
      __FUNCTION__, __LINE__));
    Str16_1 = STRING_TOKEN (STR_USERS_TYPE_ADMIN);
    Str16_2 = STRING_TOKEN (STR_USERS_TYPE_USER);
  }
  
  if (UserType == USER_TYPE_USER) {
    LOG((EFI_D_ERROR, "%a.%d UserType == USER_TYPE_USER\n", 
      __FUNCTION__, __LINE__));
    if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
                  STRING_TOKEN (STR_USERS_TYPE_USER), 0, 
                    EFI_IFR_NUMERIC_SIZE_1, 0)) {
      LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
  } else if (UserType == USER_TYPE_ADMIN) {
    LOG((EFI_D_ERROR, "%a.%d UserType == USER_TYPE_ADMIN\n", 
      __FUNCTION__, __LINE__));
    if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
                  STRING_TOKEN (STR_USERS_TYPE_ADMIN), 0, 
                    EFI_IFR_NUMERIC_SIZE_1, 0)) {
      LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
  } else {
    LOG((EFI_D_ERROR, "%a.%d >>><<<\n", 
      __FUNCTION__, __LINE__));
    if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
                  Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0)) {
      LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
    if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
                  Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1)) {
      LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
  }

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, STRING_TOKEN (STR_NULL_STRING),
      EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
      EFI_IFR_NUMERIC_SIZE_1,
      OptionsOpCodeHandle,
      NULL
      ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;

_exit:
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


STATIC VOID
UpdateFrameTitle(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  CHAR16 *HiiStr1, HiiStr2[] = L")";
  STATIC BOOLEAN bUpdated;
  
  if (bUpdated) {
    return;
  }
  bUpdated = TRUE;
  
  HiiStr1 = HiiGetString(HiiHandle, STR_FW_VERSION, NULL);
  HiiStr1[0] = L'(';
  VfrFwVersionString(HiiHandle, HiiStr1, STRING_TOKEN(STR_USERS_TITLE), HiiStr2);
}


STATIC 
EFI_STATUS
CreateUsersPageStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN UINT8 AuthType,
  IN UINT8 UserType
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_FORM_ID FormId = USERS_PAGE_ID;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
    UserFindRecordByNum(gEditedUserNum);
  }
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }

  CurrentForm = GetFormById(CurrentConfig, FormId);
  if (NULL == CurrentForm) {
    return EFI_INVALID_PARAMETER;
  }
  ListEntry = CurrentForm->EntryHead.ForwardLink;
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  while (ListEntry != &CurrentForm->EntryHead) {
    Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

    Token = HiiSetString (HiiHandle, 0, Entry->Name, NULL);
    QuestionId = (EFI_QUESTION_ID) (Entry->Index);
    
    LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", __FUNCTION__, __LINE__, 
      QuestionId));

    if (Entry->GuidStr && 
        AsciiStrCmp(Entry->GuidStr, USER_AUTHORIZATION_TYPE_GUID) == 0) {
      
    } else if (Entry->GuidStr && 
        AsciiStrCmp(Entry->GuidStr, USER_TYPE_GUID) == 0) {
      UsersTypeOneOfString(HiiHandle, StartOpCodeHandle, 
        Token, QuestionId, UserType);
    } else if (Entry->GuidStr && 
        AsciiStrCmp(Entry->GuidStr, USER_BLOCK_FLAG_GUID) == 0) {
      BlockFlagOneOfString(HiiHandle, StartOpCodeHandle, Token, QuestionId);
    } else if (Entry->GuidStr && 
               AsciiStrCmp(Entry->GuidStr, USER_NAME_GUID) == 0) {
      HiiCreateStringOpCode (StartOpCodeHandle, QuestionId, 0, 0, 
          Token, HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          0 /*StringFlags*/,
          MIN_USER_NAME_LEN, MAX_USER_NAME_LEN, 
          NULL);
    } else if (Entry->GuidStr && 
               AsciiStrCmp(Entry->GuidStr, USER_FIO_GUID) == 0) {
      HiiCreateStringOpCode (StartOpCodeHandle, QuestionId, 0, 0, 
          Token, HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          0 /*StringFlags*/,
          MIN_USER_FIO_LEN, MAX_USER_FIO_LEN, NULL);
    } else if (Entry->GuidStr && 
              AsciiStrCmp(Entry->GuidStr, USER_CONTACT_INFO_GUID) == 0) {      
      HiiCreateStringOpCode (StartOpCodeHandle, QuestionId, 0, 0, 
          Token, HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          0 /*StringFlags*/,
          MIN_USER_CONTACT_INFO, MAX_USER_CONTACT_INFO, NULL);
    } else if (Entry->GuidStr && 
              AsciiStrCmp(Entry->GuidStr, USER_PASS_GUID) == 0) {
      CHAR16 TmpStr[255];
      if (AuthType != AUTH_TYPE_LOG_PASS) {
        goto _next_item;
      }
      (VOID)TmpStr;
      UnicodeSPrint(TmpStr, sizeof(TmpStr) >> 1, L"%s: %s", Entry->Name,
        HiiGetString(HiiHandle, STRING_TOKEN(STR_USER_PASSWORD_NOT_SET), NULL));

      HiiSetString(HiiHandle, Token, TmpStr, NULL);

      PasswdMenuStr = Entry->Name;
      PasswdMenuStrId = Token;
      HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    } else if (Entry->GuidStr && 
              AsciiStrCmp(Entry->GuidStr, USER_COMPARE_TYPE_GUID) == 0) {
      
    } else if (Entry->GuidStr && 
              AsciiStrCmp(Entry->GuidStr, USER_PASS_CREATE_TIME_GUID) == 0) {
      if (AuthType != AUTH_TYPE_LOG_PASS) {
        goto _next_item;
      }
      PasswdCreationTimeStr = Entry->Name;
      PasswdCreationTimeStrId = Token;
      HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);
    } else {
      LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X!\n", 
        __FUNCTION__, __LINE__, QuestionId));
      
      if (Entry->GuidStr && 
              AsciiStrCmp(Entry->GuidStr, USER_COMPARE_DATA_GUID) == 0) {
         goto _next_item;
      }
      
      HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    }

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
_next_item:
    ListEntry  = ListEntry->ForwardLink;
  }

  if (CurUsrType == USER_TYPE_ADMIN || 
      CurrentUserTypesFlags ==  USER_TYPE_ADMIN) {
    UsersAdminAccessInfoMenu (
      StartOpCodeHandle, 
      HiiHandle, 
      USERS_REMOTE_ACCESS_ID);
  }
  if (CurrentUserTypesFlags ==  USER_TYPE_ADMIN) {
    CurUsrType = USER_TYPE_ADMIN;
  }
  
  HiiCreateActionOpCode(StartOpCodeHandle, USER_CREATE_BUTTON_ID, 
    CurrentMode == USERS_PAGE_TYPE_CREATE ? 
      STRING_TOKEN(STR_USERS_CREATE) : STRING_TOKEN(STR_USERS_UPDATE), 
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);  
  
  return EFI_SUCCESS;
}


STATIC VOID 
AuthType1UserNotFilledMsg(
  VOID
  )
{
  CHAR16 *StrPtr16[4], StrBuf[255];
  EFI_INPUT_KEY Key;
  
  ZeroMem(StrPtr16, sizeof(StrPtr16));
  
  if ((InputDataFlags & USER_AUTH_TYPE1_FLAGS_MASK) == 
      USER_AUTH_TYPE1_FLAGS_MASK) {
    return;
  }
  
  if ((InputDataFlags & FILL_FLAG_USER_NAME) != FILL_FLAG_USER_NAME) {
    StrPtr16[0] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_NAME), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_FIO) != FILL_FLAG_USER_FIO) {
    StrPtr16[1] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_FIO), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_CONTACT_INFO) != 
      FILL_FLAG_USER_CONTACT_INFO) {
    StrPtr16[2] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_CONTACT_INFO), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_PASSWD) != FILL_FLAG_USER_PASSWD) {
    StrPtr16[3] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_PASSWORD), NULL);
  }
  UnicodeSPrint(StrBuf, sizeof(StrBuf) >> 1, L"%s:", 
    HiiGetString(CurrentHiiHandle,STRING_TOKEN(STR_NOT_SET), NULL));
  CleanKeyBuffer();
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, StrBuf, 
    L"---------------------------", 
    StrPtr16[0] ? StrPtr16[0] : L"", 
    StrPtr16[1] ? StrPtr16[1] : L"", 
    StrPtr16[2] ? StrPtr16[2] : L"", 
    StrPtr16[3] ? StrPtr16[3] : L"", 
    NULL);
}


STATIC VOID 
AuthType2UserNotFilledMsg(
  VOID
  )
{
  CHAR16 *StrPtr16[4], StrBuf[255];
  EFI_INPUT_KEY Key;
  
  ZeroMem(StrPtr16, sizeof(StrPtr16));
  
  if ((InputDataFlags & USER_AUTH_TYPE2_FLAGS_MASK) == 
      USER_AUTH_TYPE2_FLAGS_MASK) {
    return;
  }
  
  if ((InputDataFlags & FILL_FLAG_USER_NAME) != FILL_FLAG_USER_NAME) {
    StrPtr16[0] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_NAME), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_FIO) != FILL_FLAG_USER_FIO) {
    StrPtr16[1] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_FIO), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_CONTACT_INFO) != 
      FILL_FLAG_USER_CONTACT_INFO) {
    StrPtr16[2] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_CONTACT_INFO), NULL);
  }
  if ((InputDataFlags & FILL_FLAG_USER_COMPARISON) != FILL_FLAG_USER_COMPARISON) {
    StrPtr16[3] = HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USER_COMPARISON), NULL);
  }
  UnicodeSPrint(StrBuf, sizeof(StrBuf) >> 1, L"%s:", 
    HiiGetString(CurrentHiiHandle,STRING_TOKEN(STR_NOT_SET), NULL));
  CleanKeyBuffer();
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, StrBuf, 
    L"---------------------------", 
    StrPtr16[0] ? StrPtr16[0] : L"", 
    StrPtr16[1] ? StrPtr16[1] : L"", 
    StrPtr16[2] ? StrPtr16[2] : L"", 
    StrPtr16[3] ? StrPtr16[3] : L"", 
    NULL);
}


EFI_STATUS
UserFindRecordByAuthType(
  IN UINT8 AuthType
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  
  UserCleanLastFoundedInfo ();
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pUserInfo->AuthType == AuthType) {
      UserSetLastFoundedInfo(pUserInfo);
      return EFI_SUCCESS;
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  
  return EFI_NOT_FOUND;
}


EFI_STATUS
UserFindRecordByName(
  IN CHAR16 *UserName
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  CHAR8 TmpName8[255];
  
  UserCleanLastFoundedInfo ();
  
  if (UserName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  AsciiSPrint(TmpName8, sizeof(TmpName8), "%s", UserName);
  if (SuCheckName(TmpName8)) {
    return UserFindRecordById(USER_SU_ID);
  }
  
  LOG((EFI_D_ERROR, "%a.%d: UserName=%s\n", __FUNCTION__, __LINE__, UserName));
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (StrNoCaseCompare(pUserInfo->UserName, UserName) == 0) {
      UserSetLastFoundedInfo(pUserInfo);
      return EFI_SUCCESS;
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  
  return EFI_NOT_FOUND;
}


EFI_STATUS
UserFindRecordByNameWithThisAuth(
  IN UINT8 AuthType,
  IN CHAR16 *UserName
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  CHAR8 TmpName8[255];
  
  UserCleanLastFoundedInfo ();
  
  if (UserName == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  AsciiSPrint(TmpName8, sizeof(TmpName8), "%s", UserName);
  if (SuCheckName(TmpName8)) {
    return UserFindRecordById(USER_SU_ID);
  }
  
  LOG((EFI_D_ERROR, "%a.%d: UserName=%s AuthType=%X\n", 
    __FUNCTION__, __LINE__, UserName, AuthType));
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pUserInfo->AuthType == AuthType) {
      if (StrNoCaseCompare(pUserInfo->UserName, UserName) == 0) {
        UserSetLastFoundedInfo(pUserInfo);
        return EFI_SUCCESS;
      }
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  
  return EFI_NOT_FOUND;
}



EFI_STATUS
UserFindRecordByNum(
  IN UINTN RecordNum
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize, Index;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  
  UserCleanLastFoundedInfo ();
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  Index = 0;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, 
        "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (RecordNum == Index) {
      UserSetLastFoundedInfo(pUserInfo);
      return EFI_SUCCESS;
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    Index++;
  }
  
  return EFI_NOT_FOUND;
}


USER_INFO *
UserGetNextUserInfo(
  IN BOOLEAN bRestart
  )
{
  EFI_STATUS Status;
  STATIC UINTN i;

  if (bRestart) {
    i = 0;
  }
  Status = UserFindRecordByNum(i);
  if (EFI_ERROR(Status)) {
    i = 0;
    return NULL;
  } else {
    i++;
  }
  return UserGetLastFoundedInfo();
}


EFI_STATUS
UsersStorageUpdate(
  VOID
  )
{
  if (UsrStrorage.DataLen == 0) {
    return EFI_SUCCESS;
  }
  return UsersStorageSetRawData(UsrStrorage.Data, UsrStrorage.DataLen);
}


STATIC VOID
ErrorCurrentUserDelete(
  VOID
  )
{
  EFI_INPUT_KEY Key;
  CHAR16 *HiiString;
  
  HiiString = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_ERR_CURRENT_USER_DELETE), NULL);
  CleanKeyBuffer();
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, HiiString, NULL);
}


STATIC VOID
ErrorWhileUserDeleteBecauseHistory(
  VOID
  )
{
  EFI_INPUT_KEY Key;
  CHAR16 *HiiString1, *HiiString2;
  
  HiiString1 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USER_DELETE_ERR_1), NULL);
  HiiString2 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_HISTORY_NEED_TO_OUTSWAP), NULL);
  CleanKeyBuffer();
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
    HiiString1, HiiString2, NULL);
}

STATIC VOID
ErrorWhileUserDeleteBecauseHistory2(
  VOID
  )
{
  EFI_INPUT_KEY Key;
  CHAR16 *HiiString1, *HiiString2, *HiiString3;
  
  HiiString1 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USER_DELETE_ERR_1), NULL);
  HiiString2 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USER_DELETE_ERR_2_1), NULL);
  HiiString3 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USER_DELETE_ERR_2_2), NULL);
  CleanKeyBuffer();
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
    HiiString1, HiiString2, HiiString3, NULL);
}


EFI_STATUS
DeleteLastFoundedRecord(
  VOID
  )
{
  USER_INFO *pUserInfo;
  USERS_STORAGE *pBeginStorage;
  UINT8 *RestDataPtr;
  HISTORY_RECORD *pHistoryRec;
  UINTN RecordLen, RestDataLen;
  BOOLEAN bFirst;
  EFI_STATUS Status;
  UINT8 UserId;

  pUserInfo = UserGetLastFoundedInfo();
  if (NULL == pUserInfo) {
    return EFI_NOT_FOUND;
  }

/* save last founded user id for deleting user access info */
  UserId = pUserInfo->UserId;
  
/* We can't delete ourself */
  if (pUserInfo->UserId == CurrentUserId) {
    LOG((EFI_D_ERROR, "%a.%d we can't delete current user!\n", 
      __FUNCTION__, __LINE__));
    ErrorCurrentUserDelete();
    return EFI_INVALID_PARAMETER;
  }

  bFirst = TRUE;
/* We can't delete if History storage not outswap to USB */
/* And we are must clean all outswapped records for this user if autoclean is enabled */
  while (1) {
    if (EFI_SUCCESS == HistoryFindRecordByUserId(pUserInfo->UserId)) {
      pHistoryRec = HistoryGetLastFoundedRecord();
      if ((pHistoryRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) == 0) {
        LOG((EFI_D_ERROR, "%a.%d Error we can't delete this user!\n",
          __FUNCTION__, __LINE__));
        ErrorWhileUserDeleteBecauseHistory();
        return EFI_INVALID_PARAMETER;
      }
      if (!HistoryAutoCleanEnabled()) {
        ErrorWhileUserDeleteBecauseHistory2();
        return EFI_ABORTED;
      }

      HistoryDeleteLastFoundedRecord(FALSE);
    } else {
      if (!bFirst) {
        HistoryFlush();
      }
      break;
    }
    bFirst = FALSE;
  }

  pBeginStorage = &UsrStrorage;
  RecordLen = pUserInfo->ExtDataLen + sizeof(USER_INFO) - 1;
  
  if (pBeginStorage->DataLen < RecordLen || RecordLen == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  RestDataPtr = (UINT8*)pUserInfo + RecordLen;
  RestDataLen = pBeginStorage->DataLen - 
    ((UINT8*)pUserInfo - pBeginStorage->Data) - RecordLen;
  if (RestDataLen) {
    CopyMem(pUserInfo, RestDataPtr, RestDataLen);
  }
  pBeginStorage->DataLen -= (UINT32) RecordLen;
  Status = UsersStorageSetRawData(pBeginStorage->Data, pBeginStorage->DataLen);

  LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  LOG((EFI_D_ERROR, "%a.%d UserId=0x%X\n", 
      __FUNCTION__, __LINE__, UserId));
  DeleteUserAccessInfo (UserId);
  return Status;
}

EFI_STATUS
UserDeletePopUp(
  VOID
  )
{
  USER_INFO *pUserInfo;
  EFI_INPUT_KEY Key;
  
  pUserInfo = UserGetLastFoundedInfo();
  if (NULL == pUserInfo) {
    return EFI_NOT_FOUND;
  }
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_USERS_DELETE_SURE), NULL), 
      pUserInfo->UserName,
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_USERS_DELETE_YES_NO), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      return EFI_ABORTED;
    }
  } while (1);
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
UserDeleteRecordByNumber(
  IN UINTN RecordNum
  )
{
  EFI_STATUS Status;
  
  Status = UserFindRecordByNum(RecordNum);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Status = UserDeletePopUp();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Status = DeleteLastFoundedRecord();
  HistoryAddRecord(HEVENT_DELETE_USER, CurrentUserId, 
    EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
    EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  return Status;
}


STATIC EFI_STATUS
UserDeleteRecordByName(
  IN CHAR16 *UserName
  )
{
  EFI_STATUS Status;
  
  Status = UserFindRecordByName(UserName);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Status = UserDeletePopUp();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Status = DeleteLastFoundedRecord();
  HistoryAddRecord(HEVENT_DELETE_USER, CurrentUserId, 
    EFI_ERROR(Status) ? SEVERITY_LVL_ERROR: SEVERITY_LVL_INFO,
    EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  return Status;
}

STATIC EFI_STATUS
UserAddRecord(
  IN UINT8 *NewUsrId
  )
{
  EFI_STATUS Status;
  UINTN RecordSize; //, i, Offset;
  UINT8 *Data;

  LOG((EFI_D_ERROR, "%a.%d: gComparisonFlags=0x%X\n", 
      __FUNCTION__, __LINE__, gComparisonFlags));
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  if (NewUsrId) {
    gUserInfo.UserId = *NewUsrId;
  } else {
    Status = ObtainNewUserId(&gUserInfo.UserId);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }
  
  RecordSize = sizeof(USER_INFO) - 1;
  if (gUserInfo.AuthType == AUTH_TYPE_LOG_PASS) {
    RecordSize += sizeof(USER_INFO_LOG_PASS);
    gUserInfo.ExtDataLen = sizeof(USER_INFO_LOG_PASS);
  } else {    
    return EFI_INVALID_PARAMETER;
  }
  if (RecordSize & 0x1) {
    RecordSize++;
    gUserInfo.ExtDataLen++;
  }

  LOG((EFI_D_ERROR, "%a.%d RecordSize=%d\n", 
    __FUNCTION__, __LINE__, RecordSize));

  if (USERS_STORAGE_MAX_DATA_LEN - UsrStrorage.DataLen < RecordSize) {
    LOG((EFI_D_ERROR, "%a.%d Error! UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_BUFFER_TOO_SMALL;
  }
  
  Data = AllocateZeroPool(RecordSize + UsrStrorage.DataLen);
  if (NULL == Data) {
    LOG((EFI_D_ERROR, "%a.%d Error! EFI_OUT_OF_RESOURCES\n", 
      __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  CopyMem(Data, UsrStrorage.Data, UsrStrorage.DataLen);

  CopyMem(Data + UsrStrorage.DataLen, &gUserInfo, 
    sizeof(USER_INFO) - 1);
  
  if (gUserInfo.AuthType == AUTH_TYPE_LOG_PASS) {
    LOG((EFI_D_ERROR, "%a.%d: gUserInfoPass.PassHashType=0x%X\n", 
      __FUNCTION__, __LINE__, gUserInfoPass.PassHashType));
    CopyMem(Data + UsrStrorage.DataLen + sizeof(USER_INFO) - 1, &gUserInfoPass, 
      sizeof(USER_INFO_LOG_PASS));
  } else {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = UsersStorageSetRawData(Data, UsrStrorage.DataLen + RecordSize);
  if (!EFI_ERROR(Status)) {
   gUsrAccessInfo.UsrId = gUserInfo.UserId;
    if (gUserInfo.Flags & USER_ADMIN_FLAG) {      
      
    } else {
      gUsrAccessInfo.AccessType = gUsrAccessInfo.AccessType & 1 ?
            USER_ACCESS_REMOTE_START_OS : USER_ACCESS_START_OS;
    }
    Status = CheckUserAccessInfoPresent (gUsrAccessInfo.UsrId);
    if (EFI_ERROR(Status)) {
      Status = AddUserAccessInfo (gUsrAccessInfo.UsrId, 
        gUsrAccessInfo.AccessType);
    } else {
      Status = ChangeUserAccessInfo (gUsrAccessInfo.UsrId, 
        gUsrAccessInfo.AccessType);
    }
  }
  
  HistoryAddRecord(HEVENT_ADD_NEW_USER, CurrentUserId, 
    EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
    EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  FreePool(Data);
  return Status;
}


EFI_STATUS
AddLoginPassUser(
  IN USER_LOGIN_PASS_DATA *LoginPassUserData
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  USER_INFO *pUserInfo;
  UINT8 SaveUserId;
  BOOLEAN bUserPresent = FALSE;
  UINT32 PassCreationTime;
  UINT8 HashBuf[MAX_HASH_LEN];

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  if (LoginPassUserData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }
  if (LoginPassUserData->Permission == NOT_ALLOW_TO_LOGIN) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }
  if (LoginPassUserData->UserName == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "User name: %s {%02X}\n", 
    LoginPassUserData->UserName, 
    LoginPassUserData->Permission));

  ZeroMem (&gUserInfo, sizeof(gUserInfo));
  ZeroMem (&gUsrAccessInfo, sizeof(gUsrAccessInfo));

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
  gUserInfo.AuthType = AUTH_TYPE_LOG_PASS;
  StrnCpy(gUserInfo.UserName, LoginPassUserData->UserName, 
    sizeof(gUserInfo.UserName));
  if (LoginPassUserData->UserFIO) {
    StrnCpy(gUserInfo.UserFIO, LoginPassUserData->UserFIO, 
      sizeof(gUserInfo.UserFIO));
  }
  if (LoginPassUserData->ContactInfo) {
    StrnCpy(gUserInfo.UserContactInfo, LoginPassUserData->ContactInfo, 
      sizeof(gUserInfo.UserContactInfo));
  }

  if (LoginPassUserData->Permission == ALLOW_TO_LOGIN_GUEST ||
      LoginPassUserData->Permission == ALLOW_TO_LOGIN_USER ||
      LoginPassUserData->Permission == ALLOW_TO_LOGIN_USER_REMOTE) {

  } else {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    gUserInfo.Flags |= USER_ADMIN_FLAG;
    gUsrAccessInfo.UsrId = gUserInfo.UserId;
    gUsrAccessInfo.AccessType = ConvertLdapPermission (
              LoginPassUserData->Permission);
    DEBUG((EFI_D_ERROR, "%a.%d gUsrAccessInfo.AccessType=%X\n", 
      __FUNCTION__, __LINE__, gUsrAccessInfo.AccessType));  
  }

  UnicodeHashToBin (HashBuf, LoginPassUserData->Hash);
  ReverseByteBuf(HashBuf, sizeof (HashBuf));

  gUserInfoPass.PassHashType = PASSWD_HASH_TYPE;
  CopyMem(gUserInfoPass.PassHash, HashBuf, GetHashLen(PASSWD_HASH_TYPE));

  Status = GetU32TimeSec(&PassCreationTime);
  WriteUnaligned32((UINT32*)(UINT8*)&gUserInfoPass.PassCreateTime, 
    PassCreationTime);

  Status = UserFindRecordByNameWithThisAuth(AUTH_TYPE_LOG_PASS, 
    LoginPassUserData->UserName);
  if (!EFI_ERROR(Status)) {
    bUserPresent = TRUE;
  }

  if (bUserPresent) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    pUserInfo = UserGetLastFoundedInfo ();
    SaveUserId = pUserInfo->UserId;
    pUserInfo->UserId = USER_SPECIAL_ID;
    UsersStorageUpdate ();
    Status = UserFindRecordById(USER_SPECIAL_ID);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
      return Status;
    }
  
    Status = DeleteLastFoundedRecord();
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));  
      return Status;
    }
  }
  Status = UserAddRecord(bUserPresent ? &SaveUserId : NULL);  
  DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));  

  return Status;
}


EFI_STATUS
CreateAccount(
  VOID
  )
{
  EFI_STATUS Status;
  USER_INFO *pUsrToReplace = NULL, *pUserNew = NULL;
  UINT8 AuthType;

  gUserInfo.AuthType = CurAuthType;
  AuthType = gUserInfo.AuthType;
  if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
    UserFindRecordByNum(gEditedUserNum);
    pUserNew = UserGetLastFoundedInfo ();
    if (pUserNew) {
      AuthType = pUserNew->AuthType;
    }
  }

  Status = UserFindRecordByNameWithThisAuth(AuthType, 
    gUserInfo.UserName);
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (EFI_NOT_FOUND != Status) {
    if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
      pUsrToReplace = UserGetLastFoundedInfo();      
    } else {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
  }
  
  if (CurrentMode == USERS_PAGE_TYPE_VIEW && NULL == pUsrToReplace) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  if (CurAuthType != AUTH_TYPE_LOG_PASS) {
    return EFI_INVALID_PARAMETER;
  } else {
    if ((InputDataFlags & USER_AUTH_TYPE1_FLAGS_MASK) != 
        USER_AUTH_TYPE1_FLAGS_MASK) {
      AuthType1UserNotFilledMsg();
      return EFI_INVALID_PARAMETER;
    }
  }
  
  Status = UserAddRecord(NULL);
  LOG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));  
  if (EFI_SUCCESS == Status && CurrentMode == USERS_PAGE_TYPE_VIEW) {
    UINT8 Tmp;
    
    LOG((EFI_D_ERROR, "%a.%d pUsrToReplace->UserId=0x%X\n", 
      __FUNCTION__, __LINE__, pUsrToReplace->UserId));
    LOG((EFI_D_ERROR, "%a.%d gUserInfo.UserId=0x%X\n", 
      __FUNCTION__, __LINE__, gUserInfo.UserId));
    /* Update storage data */ 
    Status = UsersStorageGetData(&UsrStrorage);
    if (EFI_ERROR(Status)) {
      MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
      return Status;
    }
    
    Status = UserFindRecordById(gUserInfo.UserId);    
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    pUserNew = UserGetLastFoundedInfo();
    if (NULL == pUserNew) {
      LOG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    Tmp = pUsrToReplace->UserId;
    pUsrToReplace->UserId = pUserNew->UserId;
    pUserNew->UserId = Tmp;
    UserSetLastFoundedInfo(pUsrToReplace);
    { 
      UINT8 AccessInfo;
      GetUserAccessInfo (pUsrToReplace->UserId, &AccessInfo);      
      Status = CheckUserAccessInfoPresent (pUserNew->UserId);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        Status = AddUserAccessInfo (pUserNew->UserId, AccessInfo);
      } else {
        LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        Status = ChangeUserAccessInfo (pUserNew->UserId, AccessInfo);
      }
    }
    
    Status = DeleteLastFoundedRecord();
    HistoryAddRecord(HEVENT_DELETE_USER, CurrentUserId, 
      EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
    LOG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      /* Delete this user */
      LOG((EFI_D_ERROR, "%a.%d: <<<DELETE THIS>>>\n", __FUNCTION__, __LINE__));
      UserFindRecordById(gUserInfo.UserId);
      DeleteLastFoundedRecord();
      MsgInternalError(INT_ERR_WHILE_UPDATE_CUR_USR);
    } else {
      gUserInfo.UserId = pUserNew->UserId;
    }
  }
  if (EFI_SUCCESS == Status) {
    if (!bCreateAccountQuite)
    ShowSuccessPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_USER_CARD_CREATE_SUCCESS), NULL));
  } else if (EFI_BUFFER_TOO_SMALL == Status || EFI_ABORTED == Status) {
    ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_USERS_STORAGE_FULL), NULL));
  } else if (EFI_INVALID_PARAMETER == Status) {
    LOG((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  }else {
    gST->ConOut->ClearScreen(gST->ConOut);
    MsgInternalError(INT_ERR_CANT_CREATE_USER);
  }
  return Status;
}


STATIC VOID
UserStringsAction(
  IN EFI_STRING_ID StrId,
  IN OUT CHAR16 *DstStr,
  IN UINT32 Flag
  )
{
  CHAR16 *Str16;
  
  if (StrId == (EFI_STRING_ID)0) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }
  Str16 = HiiGetString(CurrentHiiHandle, StrId, NULL);
  if (Str16 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }
  StrCpy(DstStr, Str16);
  InputDataFlags |= Flag;
}


STATIC VOID
UpdateMenuPasswordStr(
  VOID
  )
{
  struct tHashRecord *pTmpRec;
  CHAR16 PassHashStr[255];
  CHAR8 Password8[255];
  
  pTmpRec = AllocateZeroPool(sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN);
  if (NULL == pTmpRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }

  if (IsArrayAllZero(gUserInfoPass.PassHash, 
                      sizeof(gUserInfoPass.PassHash))) {   
    return;
  }
  
  pTmpRec->HashType = PASSWD_HASH_TYPE;
  CopyMem(pTmpRec->HashData, gUserInfoPass.PassHash, 
    GetHashLen(PASSWD_HASH_TYPE));
  GetDigestStr(Password8, pTmpRec);
  FreePool(pTmpRec);

  UnicodeSPrint(PassHashStr, sizeof(PassHashStr) >> 1, L"%s: <%a>", 
    PasswdMenuStr, Password8);
  HiiSetString(CurrentHiiHandle, PasswdMenuStrId, PassHashStr, NULL);

{
  EFI_TIME EfiTime;
  
  ConvU32ToEfiTime(gUserInfoPass.PassCreateTime, &EfiTime);
  
  UnicodeSPrint(PassHashStr, sizeof(PassHashStr) >> 1, 
    L"%s: %02d/%02d/%04d %02d.%02d.%02d", 
    PasswdCreationTimeStr, 
    EfiTime.Month, 
    EfiTime.Day,
    EfiTime.Year,
    EfiTime.Hour,
    EfiTime.Minute,
    EfiTime.Second
    );
  HiiSetString(CurrentHiiHandle, PasswdCreationTimeStrId, PassHashStr, NULL);
}
}


EFI_STATUS
GetUsrPasswordLen (
  IN OUT UINT32 *PasswordLen
  )
{
  UINTN Size;
  EFI_STATUS Status;

  Size = sizeof (*PasswordLen);
  Status = gRT->GetVariable(
        L"UsrPasswordLen", 
        &gVendorGuid,
        NULL, 
        &Size, 
        PasswordLen
        );
  return Status;
}


EFI_STATUS
SetUsrPasswordLen (
  IN UINT32 PasswordLen
  )
{
  EFI_STATUS Status;

  Status = gRT->SetVariable(
      L"UsrPasswordLen", 
      &gVendorGuid,
      (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS), 
       sizeof (PasswordLen), 
       &PasswordLen
       );
  return Status;
}


EFI_STATUS
PassswordReGen (
  CHAR8 Password8[]
  )
{
  EFI_STATUS Status;
  UINTN PassLen = 8;
  UINTN PassStrLen;
  CHAR16 TmpStr16[255]; 

  for (;;) {
    UINT32 PassLen32;
    Status = GetUsrPasswordLen (&PassLen32);
    if (!EFI_ERROR (Status)) {
      PassLen = (UINTN)PassLen32;
      break;
    }
    
    ShowPassWindow (
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(MSG_SET_PASSWORD_LEN_HEADER), NULL),
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(MSG_SET_PASSWORD_LEN_PROMPT), NULL)
      );

    ZeroMem (Password8, PASSWORD_MAX_LEN);
    PassStrLen = ReadLineAndHide(Password8, PASSWORD_MAX_LEN, FALSE);
    if (PassStrLen) {
      PassLen = AsciiStrDecimalToUintn(Password8);
    }
    if (PassStrLen == 0 || PassLen < PASSWORD_MIN_LEN || 
        PassLen > PASSWORD_MAX_LEN) {
      ShowErrorPopup (CurrentHiiHandle, 
        HiiGetString (
            CurrentHiiHandle,
            STRING_TOKEN (MSG_SET_PASSWORD_LEN_ERROR),
            NULL
            )
            );
      continue;
    } else {
      PassLen32 = (UINT32)PassLen ;
      SetUsrPasswordLen (PassLen32);
      break;
    }
  }
    
  ZeroMem (Password8, PASSWORD_MAX_LEN);
  GenPassword (PassLen, Password8);
  if (Password8 == NULL) {
    ShowErrorPopup (
      CurrentHiiHandle, 
        HiiGetString (
            CurrentHiiHandle,
            STRING_TOKEN (MSG_GENERATE_PASSWORD_ERROR),
            NULL
            )
      );
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((EFI_D_ERROR, "Pass: \"%a\"\n", Password8));
  UnicodeSPrint (TmpStr16, sizeof (TmpStr16), L"%a",
    Password8
    );

  CleanKeyBuffer();
  CreatePopUp(EFI_BLACK | EFI_BACKGROUND_GREEN, NULL, 
      L"", 
      HiiGetString (
        CurrentHiiHandle,
        STRING_TOKEN (MSG_USER_PASSWORD_SAVE_PROMPT),
        NULL
        ),
      TmpStr16, 
      L"", NULL);
  WaitForEscOrEnter();
  gST->ConOut->ClearScreen(gST->ConOut);  
  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
PasswordAction(
  VOID
  )
{
  UINT8 HashBuf[MAX_HASH_LEN];
  EFI_STATUS Status;
  UINT32 PassCreationTime;
  CHAR8 Password8[32];

  Status = PassswordReGen (Password8);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  if (EFI_SUCCESS != CalcHashCs(PASSWD_HASH_TYPE, (UINT8*)Password8, 
                       AsciiStrLen(Password8), CALC_CS_RESET | CALC_CS_FINALIZE, 
                       HashBuf)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_CRC_ERROR;
  }

  gUserInfoPass.PassHashType = PASSWD_HASH_TYPE;
  CopyMem(gUserInfoPass.PassHash, HashBuf, GetHashLen(PASSWD_HASH_TYPE));

  Status = GetU32TimeSec(&PassCreationTime);
  WriteUnaligned32((UINT32*)(UINT8*)&gUserInfoPass.PassCreateTime, 
    PassCreationTime);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  LOG((EFI_D_ERROR, "UserCreateTimeStamp: 0x%X\n", 
    gUserInfoPass.PassCreateTime));
  InputDataFlags |= FILL_FLAG_USER_PASSWD;
  
  UpdateMenuPasswordStr();
  return EFI_SUCCESS;
}


STATIC EFI_STATUS
UsersViewAction(
  IN EFI_QUESTION_ID QuestionId,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  return EFI_SUCCESS;
}

STATIC VOID
UpdateAuthTypeValue(
  IN EFI_IFR_TYPE_VALUE *Value
  )
{  
  if (Value == NULL) {
    return;
  }

  if (Value->u8 != AUTH_TYPE_LOG_PASS && GetMiiMode()) {
    ValU8 = AUTH_TYPE_LOG_PASS;    
  } else {
    ValU8 = Value->u8;
  }
}


EFI_STATUS
UsersRetriveFormData(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  CHAR16 *Str16;

  Str16 = (CHAR16*)Value;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  switch (QuestionId) {
  case USER_NAME_ID:
    UnicodeSPrint(Str16, sizeof(gUserInfo.UserName), L"%s",
      gUserInfo.UserName);
    break;

  case USER_FIO_ID:   
    UnicodeSPrint(Str16, sizeof(gUserInfo.UserFIO), L"%s",
      gUserInfo.UserFIO);
    break;
  
  case USER_CONTACT_INFO_ID:
    UnicodeSPrint(Str16, sizeof(gUserInfo.UserContactInfo), L"%s", 
      gUserInfo.UserContactInfo);
    break;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
UsersPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;  

  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (QuestionId >= USERS_FILES_START_ID && QuestionId <= USERS_FILES_END_ID) {
    return FeCallback(This, Action, QuestionId, Type, Value, ActionRequest);
  }

  if (EFI_BROWSER_ACTION_RETRIEVE == Action) {
    return UsersRetriveFormData(This, Action, QuestionId, Type, Value, 
      ActionRequest);
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bUsersFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    if (QuestionId == USER_PASSWD_ID) {
      UpdateMenuPasswordStr();
    }
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }

  CurrentEvent = QuestionId;
  
  if (QuestionId >= USER_VIEW_START_ID && QuestionId < USER_DEL_START_ID) {
    LOG((EFI_D_ERROR, "%a.%d >= USER_VIEW_START_ID...\n", __FUNCTION__, __LINE__));
    bUsersFormExitFlag = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  } else if (QuestionId >= USER_DEL_START_ID && QuestionId < USERS_VARSTORE_VAR_ID) {
    LOG((EFI_D_ERROR, "%a.%d >= USER_DEL_START_ID...\n", __FUNCTION__, __LINE__));
    UsersDeleteAction(QuestionId);
  } else if (QuestionId == USERS_CREATE_PAGE_ID || 
             QuestionId == USERS_VIEW_PAGE_ID ||
             QuestionId == USERS_DELETE_PAGE_ID) {
    bUsersFormExitFlag = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  } else if (QuestionId == USERS_STORE_TO_CVS_FILE_ID) {
    if (EFI_SUCCESS == UsersStoreToCvsFileAction()) {
      ShowSuccessPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_DATA_STORE_SUCCESS), NULL));
    }
  } else if (QuestionId > USER_COMPARE_TYPE_ID && 
             QuestionId < USER_COMPARE_DATA_ID) {
    UINT8 Shift;
    Shift = (UINT8)((QuestionId - USER_COMPARE_TYPE_ID - 1) & 0xFF);
    if (Value && Value->u8) {
      gComparisonFlags |= (1 << Shift);
    } else if (Value && Value->u8 == 0) {
      gComparisonFlags &= ~(1 << Shift);
    }
    LOG((EFI_D_ERROR, "--> gComparisonFlags = 0x%02X\n", gComparisonFlags));
  }

  switch (QuestionId) {
  case USER_TYPE_ID:
    if (Value == NULL) {
      break;
    }
    LOG((EFI_D_ERROR, "%a.%d: Value->u8=%d CurUsrType=0x%X\n", 
      __FUNCTION__, __LINE__, Value->u8, CurUsrType));
    switch (CurUsrType) {
    case USER_TYPE_USER:
      if (Value->u8 == 1) {
        gUserInfo.Flags |= USER_ADMIN_FLAG;
      } else {
        gUserInfo.Flags &= ~USER_ADMIN_FLAG;
      }
      break;
      
    case USER_TYPE_ADMIN:
      if (Value->u8 == 1) {
        gUserInfo.Flags &= ~USER_ADMIN_FLAG;
      } else {        
        gUserInfo.Flags |= USER_ADMIN_FLAG;
      }
      break;
    }
    CurUsrType = gUserInfo.Flags & USER_ADMIN_FLAG ? 
      USER_TYPE_ADMIN : USER_TYPE_USER;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bDontChangeAuthType = TRUE;
    bRecreateForm = TRUE;
    LOG((EFI_D_ERROR, "%a.%d: CurUsrType=0x%X\n", 
      __FUNCTION__, __LINE__, CurUsrType));
    break;

  case USER_NAME_ID:
    LOG((EFI_D_ERROR, "%a: USER_NAME_ID\n", __FUNCTION__));
    if (Value == NULL) {
      break;
    }
    if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_CHANGE_FOR_USR_NAME_DISABLED), NULL));
      break;
    }
    Status = UserFindRecordByNameWithThisAuth(CurAuthType, 
      HiiGetString(CurrentHiiHandle, Value->string, NULL));
    
    if (EFI_NOT_FOUND == Status) {
      UserStringsAction(Value->string, gUserInfo.UserName, FILL_FLAG_USER_NAME);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_SUBMIT;
    } else if (EFI_SUCCESS == Status) {
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_ERR_USER_ALLREADY_PRESENT), NULL));      
      return Status;
    } else {
      gST->ConOut->ClearScreen(gST->ConOut);
      MsgInternalError(INT_ERR_WHILE_SET_USER_NAME);
      return Status;
    }
    break;

  case USER_PASSWD_ID:
    LOG((EFI_D_ERROR, "%a: USER_PASSWD_ID\n", __FUNCTION__));    
    Status = PasswordAction ();
    HistoryAddRecord(HEVENT_USR_PASS_CHANGE, GetCurrentUserId(), 
      SEVERITY_LVL_INFO, 
      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
    break;

  case USER_FIO_ID:
    LOG((EFI_D_ERROR, "%a: USER_FIO_ID\n", __FUNCTION__));
    if (Value == NULL) {
      break;
    }
    UserStringsAction(Value->string, gUserInfo.UserFIO, FILL_FLAG_USER_FIO);
    break;
  
  case USER_CONTACT_INFO_ID:
    LOG((EFI_D_ERROR, "%a: USER_CONTACT_INFO_ID\n", __FUNCTION__));
    if (Value == NULL) {
      break;
    }
    UserStringsAction(Value->string, gUserInfo.UserContactInfo, 
      FILL_FLAG_USER_CONTACT_INFO);
    break;
  
  case USER_BLOCK_FLAG_ID:
    LOG((EFI_D_ERROR, "%a: USER_BLOCK_FLAG_ID\n", __FUNCTION__));
    if (Value == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    if (Value->u8 == BlockingOpt[USER_NON_BLOCKED_STATE]) {
      gUserInfo.Flags &= ~USER_BLOCKED_FLAG;
    } else if (Value->u8 == BlockingOpt[USER_BLOCKED_STATE]) {
      gUserInfo.Flags |= USER_BLOCKED_FLAG;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    }
    break;
  
  case USER_SUSPEND_FLAG_ID:
    LOG((EFI_D_ERROR, "%a: USER_SUSPEND_FLAG_ID\n", __FUNCTION__));
    break;
  
  case USER_COMPARE_TYPE_ID:
    LOG((EFI_D_ERROR, "%a: USER_COMPARE_TYPE_ID\n", __FUNCTION__));
    break;
  
  case USER_COMPARE_DATA_ID:
    LOG((EFI_D_ERROR, "%a: USER_COMPARE_DATA_ID\n", __FUNCTION__));
    bRefreshForm = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    CurUsrType = gUserInfo.Flags & USER_ADMIN_FLAG ? 
      USER_TYPE_ADMIN : USER_TYPE_USER;
    break;

  case USERS_LOAD_LIST_FROM_LDAP_ID:
    if (Value == NULL) {
      break;
    }
    SetIsLoadUsersFromLdapFlag(Value->u8 ? TRUE : FALSE);
    break;
  
  case USER_CREATE_BUTTON_ID:
    LOG((EFI_D_ERROR, "%a: USER_CREATE_BUTTON_ID\n", __FUNCTION__));
    if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
      UsersStorageSetSpecialFlag(TRUE); 
    }
    if (EFI_SUCCESS == (Status = CreateAccount())) {
      bUsersFormExitFlag = TRUE;
      bUserCreated = TRUE;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    if (CurrentMode == USERS_PAGE_TYPE_VIEW) {
      UsersStorageSetSpecialFlag(FALSE);
      HistoryAddRecord(HEVENT_USER_UPDATE_DATA, GetCurrentUserId(), 
        EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      if (Status == EFI_SUCCESS && gUserInfo.UserId == CurrentUserId) {
        ShowTimeoutPopup(CurrentHiiHandle,
          HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(STR_REBOOT_WHILE_CUR_USR_UPDATE), NULL), 5, 
          EFI_LIGHTGRAY | EFI_BACKGROUND_RED);
        HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
        gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
      }
    }
    break;
  
  case USER_AUTHORIZATION_TYPE_ID:
    LOG((EFI_D_ERROR, "%a: USER_AUTHORIZATION_TYPE_ID\n", __FUNCTION__));
    if (Action == EFI_BROWSER_ACTION_CHANGING) {
      if (Value == NULL) {
        break;
      }
      UpdateAuthTypeValue(Value);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
      bRecreateForm = TRUE;
    }
    break;

  case USERS_REMOTE_ACCESS_ID:
    if (Value == NULL) {
      break;
    }
    if (Value->u8) {
      gUsrAccessInfo.AccessType++;
    } else {
      gUsrAccessInfo.AccessType--;
    }
    DEBUG ((EFI_D_ERROR, "%a.%d gUsrAccessInfo.AccessType=%X\n",
      __FUNCTION__, __LINE__, gUsrAccessInfo.AccessType));
    break;  

  case USERS_ADMIN_ROLE_ID:
    {
      BOOLEAN bRemote = FALSE;

      if (Value == NULL) {
        break;
      }
      
      if (Value->u8 >= AdminRolesMappingSize) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error!\n",
          __FUNCTION__, __LINE__));
        break;
      }
      if (gUsrAccessInfo.AccessType & 0x1) {
        bRemote = TRUE;
      }
      if (AdminRolesMapping[Value->u8] == ADM_ROLE_AUDIT_ID) {
        gUsrAccessInfo.AccessType = USER_ACCESS_AUDIT;
      } else if (AdminRolesMapping[Value->u8] == ADM_ROLE_FULL_ACCESS_ID) {
        gUsrAccessInfo.AccessType = USER_ACCESS_FULL_CTRL;
      } else {
        break;
      }
      if (bRemote) {
        gUsrAccessInfo.AccessType++;
      }
    }
    DEBUG ((EFI_D_ERROR, "%a.%d gUsrAccessInfo.AccessType=%X\n",
      __FUNCTION__, __LINE__, gUsrAccessInfo.AccessType));
    break;
  
  default:
    break;
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
CreateUsersPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_FORM_ID FormId = USERS_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  gComparisonFlags = 0;
  
  CurUsrType = USER_TYPE_USER;
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (CurrentMode == USERS_PAGE_TYPE_VIEW) {    
    UpdateGlobalUserInfo();
    CurUsrType = gUserInfo.Flags & USER_ADMIN_FLAG ? 
      USER_TYPE_ADMIN : USER_TYPE_USER; 
  }

  do {
    bRefreshForm = FALSE;
    UpdateFrameTitle(HiiHandle);
    
    Status = CreateUsersPageStrings(HiiHandle, CurAuthType, 
      CurrentUserTypesFlags);
    if (EFI_ERROR(Status)) {
      goto _exit;
    }
    
    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      goto _exit;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, FormId, NULL, &ActionRequest);
      
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      
      switch (CurrentEvent) {
      case USER_COMPARE_DATA_ID:
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        break;
      
      default:
        break;
      }
      if (bRecreateForm) {
        bRecreateForm = FALSE;
        CreateUsersPageStrings (
          CurrentHiiHandle, 
          CurAuthType, 
          CurrentUserTypesFlags
        );
        bUsersFormExitFlag = FALSE;
      }
      if (bUsersFormExitFlag) {
        break;
      }
    } while (1);
  
  } while (bRefreshForm);

exit:  
  DestroyHiiResources();

  return Status;
}


STATIC EFI_STATUS
UsersListPageStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STRING_ID Title,
  EFI_QUESTION_ID StartQId
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_FORM_ID FormId = USERS_PAGE_ID;
  CHAR16 TmpStr16[255];
  
  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  HelpToken = (Title == STRING_TOKEN(STR_USERS_VIEW_TITLE)) ?
    STRING_TOKEN(STR_USERS_PRESS_ENTER_TO_EDIT) : 
    STRING_TOKEN(STR_USERS_PRESS_ENTER_TO_DELETE);
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  LOG((EFI_D_ERROR, "%a.%d TotalLen = %d\n", 
    __FUNCTION__, __LINE__, TotalLen));
  
  QuestionId = (EFI_QUESTION_ID)StartQId; //USER_VIEW_START_ID;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Title,
        HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  QuestionId++;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "--> RecordSize=%d\n", RecordSize));
    RecordSize += pUserInfo->ExtDataLen;
    
    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }
    LOG((EFI_D_ERROR, "%a.%d UserName = %s AuthType=0x%X\n", 
      __FUNCTION__, __LINE__, pUserInfo->UserName, pUserInfo->AuthType));
    
    if ((pUserInfo->Flags & USER_HIDDEN_FLAG) != USER_HIDDEN_FLAG) {
      USER_INFO_LOG_PASS *pUserLogPass;
      EFI_TIME TimeStamp;
      
      pUserLogPass = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
      ConvU32ToEfiTime(pUserLogPass->PassCreateTime, &TimeStamp);
      
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s", 
        pUserInfo->UserName
        );

      Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);

      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), 
        L"%s:\n%s\n%s:\n%s\n%s:\n%02d/%02d/%02d %02d.%02d.%02d", 
        HiiGetString (CurrentHiiHandle, 
            STRING_TOKEN(STR_USR_TYPE), NULL),
        pUserInfo->Flags & USER_ADMIN_FLAG ?
          HiiGetString (CurrentHiiHandle, 
            STRING_TOKEN(STR_USERS_TYPE_ADMIN), NULL) :
          HiiGetString (CurrentHiiHandle, 
            STRING_TOKEN(STR_USERS_TYPE_USER), NULL),
        HiiGetString (CurrentHiiHandle, 
            STRING_TOKEN(STR_USER_FIO), NULL),          
        pUserInfo->UserFIO,
        HiiGetString (CurrentHiiHandle, 
            STRING_TOKEN(STR_PASSWORD_SET_TIME), NULL),          
        TimeStamp.Month,
        TimeStamp.Day,
        TimeStamp.Year,
        TimeStamp.Hour,
        TimeStamp.Minute,
        TimeStamp.Second
        );

      HelpToken = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
  
      HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
  
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);
    }
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    QuestionId++;
    LOG((EFI_D_ERROR, "TotalLen=%d, QuestionId=0x%X\n", TotalLen, QuestionId));
  }
  
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
UsersDeleteAction(
  IN EFI_QUESTION_ID QuestionId
  )
{
  EFI_STATUS Status;
  if (QuestionId == USER_DEL_START_ID || QuestionId >= USERS_VARSTORE_VAR_ID) {
    return EFI_INVALID_PARAMETER;
  }
  Status = UserDeleteRecordByNumber(QuestionId - USER_DEL_START_ID - 1);  
  if (Status == EFI_SUCCESS) {
    /* Update Page */
    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }
    Status = UsersListPageStrings(CurrentHiiHandle, 
      STRING_TOKEN(STR_USERS_DELETE_TITLE), USER_DEL_START_ID);
  }
  return Status;
}

STATIC EFI_STATUS
ViewUsersPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;

LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  UpdateFrameTitle(HiiHandle);
  while (1) {
    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = UsersListPageStrings(HiiHandle, STRING_TOKEN(STR_USERS_VIEW_TITLE),
      USER_VIEW_START_ID);
    if (EFI_ERROR(Status)) {
      goto _exit;
    }

    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      goto _exit;
    }

    CurrentEvent = 0;
    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, USERS_PAGE_ID, NULL, &ActionRequest);
          
      LOG((EFI_D_ERROR, "%a.%d: bUsersFormExitFlag=%d bRecreateForm=%d\n",
        __FUNCTION__, __LINE__, bUsersFormExitFlag, bRecreateForm));
      if (bUsersFormExitFlag) {
        break;
      }
      
    } while (1);
  
    if (CurrentEvent >= USER_VIEW_START_ID && 
        CurrentEvent < USER_DEL_START_ID) {
      gEditedUserNum = CurrentEvent - USER_VIEW_START_ID - 1;
      Status = UserFindRecordByNum(gEditedUserNum);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));        
        break;
      }
      CreateUsersPage(HiiHandle);
      continue;
    }
    break;
  }
  
_exit:  
  DestroyHiiResources();
  
  if (CurrentEvent >= USER_VIEW_START_ID && 
      CurrentEvent < USER_DEL_START_ID) {
    CreateUsersPage(HiiHandle);
  }
  
  return Status;
}


STATIC EFI_STATUS
DeleteUsersPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  UpdateFrameTitle(HiiHandle);
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = UsersListPageStrings(HiiHandle, 
    STRING_TOKEN(STR_USERS_DELETE_TITLE), USER_DEL_START_ID);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    goto _exit;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, USERS_PAGE_ID, NULL, &ActionRequest);
    
    LOG((EFI_D_ERROR, "%a.%d: bUsersFormExitFlag=%d bRecreateForm=%d\n",
      __FUNCTION__, __LINE__, bUsersFormExitFlag, bRecreateForm));
    if (bUsersFormExitFlag) {
      break;
    }
  } while (1);

_exit:  
  DestroyHiiResources();
  return Status;
}


VOID
UsersSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}


VOID
UsersSetUserTypesFlags(
  IN UINT8 Flags
  )
{
  CurrentUserTypesFlags = Flags;
}


STATIC EFI_STATUS
SaveUserLogPassToCvs(
  IN EFI_FILE_HANDLE File,
  IN USER_INFO_LOG_PASS *pUserLogPass
  )
{
  EFI_STATUS Status;
  UINTN Size;
  CHAR8 Str8[255], Password8[255];
  EFI_TIME EfiTime;
  struct tHashRecord *pTmpRec;
  
  if (pUserLogPass == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ConvU32ToEfiTime(pUserLogPass->PassCreateTime, &EfiTime);
  pTmpRec = AllocateZeroPool(sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN);
  if (NULL == pTmpRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  pTmpRec->HashType = PASSWD_HASH_TYPE;
  CopyMem(pTmpRec->HashData, pUserLogPass->PassHash, 
    GetHashLen(PASSWD_HASH_TYPE));
  GetDigestStr(Password8, pTmpRec);
  FreePool(pTmpRec);

  AsciiSPrint(Str8, sizeof(Str8), "%02X;%04d-%02d-%02d_%02d:%02d:%02d;%a", 
    pUserLogPass->PassHashType,
    EfiTime.Year, EfiTime.Month, 
    EfiTime.Day, EfiTime.Hour, 
    EfiTime.Minute, EfiTime.Second,
    Password8);
  
  Size = AsciiStrLen(Str8);
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  return EFI_SUCCESS;
}


STATIC EFI_STATUS
SaveUserLogPassToCvs16(
  IN EFI_FILE_HANDLE File,
  IN USER_INFO_LOG_PASS *pUserLogPass
  )
{
  EFI_STATUS Status;
  UINTN Size;
  CHAR16 Str16[255];
  CHAR8 Password8[255];
  EFI_TIME EfiTime;
  struct tHashRecord *pTmpRec;
  
  if (pUserLogPass == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  ConvU32ToEfiTime(pUserLogPass->PassCreateTime, &EfiTime);
  pTmpRec = AllocateZeroPool(sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN);
  if (NULL == pTmpRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  pTmpRec->HashType = PASSWD_HASH_TYPE;
  CopyMem(pTmpRec->HashData, pUserLogPass->PassHash, 
    GetHashLen(PASSWD_HASH_TYPE));
  GetDigestStr(Password8, pTmpRec);
  FreePool(pTmpRec);

  UnicodeSPrint(Str16, sizeof(Str16), L"%02X;%04d-%02d-%02d_%02d:%02d:%02d;%a", 
    pUserLogPass->PassHashType,
    EfiTime.Year, EfiTime.Month, 
    EfiTime.Day, EfiTime.Hour, 
    EfiTime.Minute, EfiTime.Second,
    Password8);
  
  Size = StrLen(Str16) << 1;
  Status = LibFsWriteFile(File, &Size, Str16);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  return EFI_SUCCESS;
}



STATIC
EFI_STATUS
SaveUserAccessInfoToCsv16 (
  IN EFI_FILE_HANDLE File,
  IN USER_INFO *pUserInfo
  )
{
  EFI_STATUS Status;
  CHAR16 Str16[255];
  UINTN Size;

  UpdateGlobalUsrAccessInfo (pUserInfo->UserId);
  UnicodeSPrint(Str16, sizeof(Str16), L";%02X", gUsrAccessInfo.AccessType);
  Size = StrLen(Str16) << 1;
  Status = LibFsWriteFile(File, &Size, Str16);
  return Status;
}



STATIC EFI_STATUS
SaveUserInfoToCvs(
  IN EFI_FILE_HANDLE File,
  IN USER_INFO *pUserInfo
  )
{
  EFI_STATUS Status;
  UINTN Size;
  CHAR8 Str8[255], AuthStr8[25], UsrTypeStr8[25];
  USER_INFO_LOG_PASS *pUserLogPass;
  
  if (pUserInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  AsciiSPrint(AuthStr8, sizeof(AuthStr8), "%s", 
    pUserInfo->AuthType == AUTH_TYPE_LOG_PASS ?
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_AUTH_LOGIN_PASS), NULL) :
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_AUTH_TOKEN), NULL));
  
  LOG((EFI_D_ERROR, "%a.%d: AuthStr8=%a\n", 
      __FUNCTION__, __LINE__, AuthStr8));
  
   AsciiSPrint(UsrTypeStr8, sizeof(UsrTypeStr8), "%s", 
     pUserInfo->Flags & USER_ADMIN_FLAG ?
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USERS_TYPE_ADMIN), NULL) :
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_USERS_TYPE_USER), NULL));
  
  LOG((EFI_D_ERROR, "%a.%d: UsrTypeStr8=%a\n", 
      __FUNCTION__, __LINE__, AuthStr8));
  
  AsciiSPrint(Str8, sizeof(Str8), "%a;%a;%s;%s;%s;", 
    AuthStr8, UsrTypeStr8,
    pUserInfo->UserName,
    pUserInfo->UserFIO,
    pUserInfo->UserContactInfo);
    
  LOG((EFI_D_ERROR, "%a.%d: Str8=%a\n", 
      __FUNCTION__, __LINE__, Str8));
  
  Size = AsciiStrLen(Str8);
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  if (pUserInfo->AuthType == AUTH_TYPE_LOG_PASS) {
    LOG((EFI_D_ERROR, "%a.%d: Save login pass user info...\n", 
      __FUNCTION__, __LINE__));
    pUserLogPass = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
    Status = SaveUserLogPassToCvs(File, pUserLogPass);
  } else {
    return EFI_ABORTED;
  }
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  AsciiSPrint(Str8, sizeof(Str8), "%a", "\n");
  Size = AsciiStrLen(Str8);
  return LibFsWriteFile(File, &Size, Str8);
}

STATIC EFI_STATUS
SaveUserInfoToCvs16(
  IN EFI_FILE_HANDLE File,
  IN USER_INFO *pUserInfo
  )
{
  EFI_STATUS Status;
  UINTN Size, ErrCnt;
  CHAR16 Str16[255];
  USER_INFO_LOG_PASS *pUserLogPass;
  CHAR16 *UserName, *UserFIO, *UserContactInfo;
  
  
  if (pUserInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  UserName = UserFIO = UserContactInfo = NULL;
  ErrCnt = 0;
  Status = ObtainProperCSVString16(pUserInfo->UserName, &UserName);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ErrCnt++;
  }
  Status = ObtainProperCSVString16(pUserInfo->UserFIO, &UserFIO);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ErrCnt++;
  }
  Status = ObtainProperCSVString16(pUserInfo->UserContactInfo, 
    &UserContactInfo);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ErrCnt++;
  }
  
  if (ErrCnt == 0) {
    UnicodeSPrint(Str16, sizeof(Str16), L"%d;%d;%s;%s;%s;", 
      pUserInfo->AuthType, pUserInfo->Flags & USER_ADMIN_FLAG ? 1 : 0,
      UserName,
      UserFIO,
      UserContactInfo);    
    LOG((EFI_D_ERROR, "%a.%d: Str16=%s\n", 
        __FUNCTION__, __LINE__, Str16));
  }

  if (UserName) {
    FreePool(UserName);
  }
  if (UserFIO) {
    FreePool(UserFIO);
  }
  if (UserContactInfo) {
    FreePool(UserContactInfo);
  }

  if (ErrCnt) {    
    return EFI_ABORTED;
  }
  
  Size = StrLen(Str16) << 1;
  Status = LibFsWriteFile(File, &Size, Str16);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  if (pUserInfo->AuthType == AUTH_TYPE_LOG_PASS) {
    LOG((EFI_D_ERROR, "%a.%d: Save login pass user info...\n", 
      __FUNCTION__, __LINE__));
    pUserLogPass = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
    Status = SaveUserLogPassToCvs16(File, pUserLogPass);
  } else {
    return EFI_ABORTED;
  }
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = SaveUserAccessInfoToCsv16 (File, pUserInfo);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  UnicodeSPrint(Str16, sizeof(Str16), L"\n");
  Size = StrLen(Str16) << 1;
  return LibFsWriteFile(File, &Size, Str16);
}


STATIC 
EFI_STATUS
UsersStoreAllToCsvFile(
  IN CHAR8 *FileName
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_FILE_HANDLE File = NULL;
  USER_INFO *pUserInfo;
  
  File = LibFsCreateFile(FileName);
  if (File == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error while LibFsOpenFile!!!!\n", 
      __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
    goto _exit;
  }
  
  pUserInfo = UserGetNextUserInfo(TRUE);
  if (!pUserInfo) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_NOT_FOUND;
    goto _exit;
  }
  
  do {
    Status = SaveUserInfoToCvs16(File, pUserInfo);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    pUserInfo = UserGetNextUserInfo(FALSE);
  } while (pUserInfo != NULL);
  
_exit:
  if (File != NULL) {
    LibFsCloseFile(File);
  }
  HistoryAddRecord(HEVENT_USERS_TO_CSV, GetCurrentUserId(), 
    EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
    EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  return Status;
}


STATIC EFI_STATUS
UpdateFnameTimeStamp(
  IN OUT CHAR8 *Fname
  )
{
  EFI_STATUS Status;
  CHAR8 *EndName, TmpStr8[5];
  EFI_TIME EfiTime;
  enum {FIND_DAY, FIND_MONTH, FIND_YEAR} State = FIND_DAY;

  EndName = Fname + AsciiStrLen(Fname);

  if (Fname == EndName) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->GetTime(&EfiTime, NULL);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  while (Fname < EndName) {
    if (*Fname != PATTERN_SYMBOL) {
      Fname++;
      continue;
    }
    if (Fname[1] != PATTERN_SYMBOL) {
      return EFI_INVALID_PARAMETER;
    }
    if (EndName - Fname < 4) {
      return EFI_INVALID_PARAMETER;
    }

    switch (State) {
    case FIND_DAY:
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%02d", EfiTime.Day);
      CopyMem(Fname, TmpStr8, 2);
      State = FIND_MONTH;
      break;

    case FIND_MONTH:
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%02d", EfiTime.Month);
      CopyMem(Fname, TmpStr8, 2);
      State = FIND_YEAR;
      break;

    case FIND_YEAR:
      if (Fname[1] != PATTERN_SYMBOL || Fname[2] != PATTERN_SYMBOL || 
          Fname[3] != PATTERN_SYMBOL) {
        return EFI_INVALID_PARAMETER;
      }
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%04d", EfiTime.Year);
      CopyMem(Fname, TmpStr8, 4);
      Fname += 2;
      return EFI_SUCCESS;

    default:
      return EFI_INVALID_PARAMETER;
    }
    Fname += 2;
  }

  return EFI_INVALID_PARAMETER;
}


STATIC EFI_STATUS
UsersStoreToCvsFileAction(
  VOID
  )
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  CHAR8 FileName[255];
  LIST_ENTRY *ListEntry, *ListEntryModules;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_MODULE *pModule;

  CurrentForm = GetFormById(CurrentConfig, RESTORE_USERS_FROM_USB_PAGE_ID);
  if (NULL == CurrentForm) {
    goto _exit;
  }

  ListEntry = CurrentForm->EntryHead.ForwardLink;
  Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

  ListEntryModules = Entry->ModuleHead.ForwardLink;
  if(IsListEmpty(&Entry->ModuleHead)) {
    goto _exit;
  }
  
  pModule = _CR( ListEntryModules, MULTIBOOT_MODULE, ListEntry );
  if (pModule->DevPath == NULL) {
    goto _exit;
  }
  
  AsciiSPrint(FileName, sizeof(FileName), "%s", pModule->DevPath);
  LOG((EFI_D_ERROR, "%a.%d: FileName=%a\n", 
    __FUNCTION__, __LINE__, FileName));
  Status = UpdateFnameTimeStamp(FileName);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  LOG((EFI_D_ERROR, "%a.%d: FileName=%a\n", 
    __FUNCTION__, __LINE__, FileName));
  
  Status = UsersStoreAllToCsvFile(FileName);
  
_exit:
  if (EFI_ERROR(Status)) {
    ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_ERR_DATA_STORE), NULL));
  }
  return Status;
}

STATIC VOID
PrepareObtainedString16(
  IN CHAR16 *InData,
  IN CHAR16 *NextData
  )
{
  
  if (NextData) {
    *(NextData - 1) = 0;    
  }
  LOG((EFI_D_ERROR, "%a.%d InData={%s}\n", __FUNCTION__, __LINE__, InData));
  LOG((EFI_D_ERROR, "StrLen(InData) = %d\n", StrLen(InData)));
  DumpBytes((UINT8*) InData, StrLen(InData) << 1);
  TrimString16FromEnd(InData, FALSE);
  LOG((EFI_D_ERROR, "%a.%d InData=%s\n", __FUNCTION__, __LINE__, InData));
}


BOOLEAN 
UsersCheckPresent(
  VOID
  )
{
  if (EFI_SUCCESS == UserFindRecordByNameWithThisAuth(gUserInfo.AuthType, 
                                                      gUserInfo.UserName)) {
    return TRUE;
  }
  return FALSE;
}

EFI_STATUS
UsersImportCsvData (
  IN UINT8 *FileData,
  IN UINTN FileSize,
  IN OUT BOOLEAN *bAdminUserPresent
  )
{
  EFI_STATUS Status;
  CHAR16 *InData, *EndData, *NextData;
  int retval;
  CHAR16 TmpStr16[25];
  UINT32 PassCreationTime;
  BOOLEAN bAccessInfo = FALSE;
  
  if (FileSize == 0 || FileData == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    UsrStrorage.DataLen = 0;
  }
  
  EndData = (CHAR16*)(FileData + FileSize);
  InData = NextData = (CHAR16*)FileData;
  *EndData = '\0';
  
  do {
    retval = Csv16GetNextField(InData, EndData, &NextData);
    if (NextData == NULL) {
      LOG((EFI_D_ERROR, "%a.%d End of file!!!\n", __FUNCTION__, __LINE__));
      break;
    }
    if (CSV_FIELDS_SEPARATOR16 != retval ) {
      LOG((EFI_D_ERROR, "%a.%d Error: %d\n", __FUNCTION__, __LINE__, retval));
      return EFI_NOT_FOUND;
    }
    PrepareObtainedString16(InData, NextData);

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%d", AUTH_TYPE_LOG_PASS);    

    if (StrCmp(InData, TmpStr16) == 0) {
      gUserInfo.AuthType = AUTH_TYPE_LOG_PASS;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    InData = NextData;
    if (CSV_FIELDS_SEPARATOR16 != Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    PrepareObtainedString16(InData, NextData);

    if (StrCmp(InData, L"1") == 0) {
      gUserInfo.Flags |= USER_ADMIN_FLAG;
      *bAdminUserPresent = TRUE;
    } else if (StrCmp(InData, L"0") == 0) {
        gUserInfo.Flags &= ~USER_ADMIN_FLAG;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    InData = NextData;
    if (CSV_FIELDS_SEPARATOR16 != Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    PrepareObtainedString16(InData, NextData);
    
    if (StrLen(InData) > MAX_USER_NAME_LEN) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(gUserInfo.UserName, sizeof(gUserInfo.UserName), 
      L"%s", InData);
    LOG((EFI_D_ERROR, "gUserInfo.UserName=%s {%s}\n", 
      gUserInfo.UserName, InData));
    InData = NextData;
    if (CSV_FIELDS_SEPARATOR16 != Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    PrepareObtainedString16(InData, NextData);
    
    if (StrLen(InData) > MAX_USER_FIO_LEN) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(gUserInfo.UserFIO, sizeof(gUserInfo.UserFIO), L"%s", InData);
    LOG((EFI_D_ERROR, "gUserInfo.UserFIO=%s {%s}\n", 
      gUserInfo.UserFIO, InData));
    InData = NextData;
    if (CSV_FIELDS_SEPARATOR16 !=  Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    PrepareObtainedString16(InData, NextData);
    
    if (StrLen(InData) > MAX_USER_CONTACT_INFO) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
    UnicodeSPrint(gUserInfo.UserContactInfo, sizeof(gUserInfo.UserContactInfo), 
      L"%s", InData);
    LOG((EFI_D_ERROR, "gUserInfo.UserContactInfo=%s {%s}\n", 
      gUserInfo.UserContactInfo, InData));
    InData = NextData;
    Status = ObtainNewUserId(&gUserInfo.UserId);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }

    if (gUserInfo.AuthType == AUTH_TYPE_LOG_PASS) {
      if (CSV_FIELDS_SEPARATOR16 != Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
        LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return EFI_NOT_FOUND;
      }
      PrepareObtainedString16(InData, NextData);
      gUserInfoPass.PassHashType = (UINT8)(StrHexToUintn(InData) & 0xFF);
      if (0 == GetHashLen(gUserInfoPass.PassHashType)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return EFI_INVALID_PARAMETER;
      }
      InData = NextData;
      if (CSV_FIELDS_SEPARATOR16 != Csv16GetNextField(InData, EndData, 
                                                    &NextData)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return EFI_NOT_FOUND;
      }
      PrepareObtainedString16(InData, NextData);

      Status = TimeString16ToU32Time(InData, &PassCreationTime );
      WriteUnaligned32((UINT32*)(UINT8*)&gUserInfoPass.PassCreateTime, 
        PassCreationTime);

      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));        
        return Status;
      }
      InData = NextData;
      retval = Csv16GetNextField(InData, EndData, &NextData);
      if (CSV_FIELDS_SEPARATOR16 == retval) {
        LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        bAccessInfo = TRUE;
      }
      PrepareObtainedString16(InData, NextData);
      LOG((EFI_D_ERROR, "Hash: %s\n", InData));
      Status = HexString16ToByteBuf(InData, gUserInfoPass.PassHash, 
        sizeof(gUserInfoPass.PassHash));
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return Status;
      }
      InData = NextData;
    
      ReverseByteBuf(gUserInfoPass.PassHash, sizeof(gUserInfoPass.PassHash));
      
      DumpBytes(gUserInfoPass.PassHash, sizeof(gUserInfoPass.PassHash));
      gUsrAccessInfo.UsrId = 0;
      gUsrAccessInfo.AccessType = 0;
      if (bAccessInfo) {
        retval = Csv16GetNextField(InData, EndData, &NextData);
        gUsrAccessInfo.AccessType = (UINT8)(StrHexToUintn (InData) & 0x00FF);
        InData = NextData;
        bAccessInfo = FALSE;
      }
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }

    if (UsersCheckPresent()) {
      LOG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }    
    
    Status = UserAddRecord(NULL);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
    LOG((EFI_D_ERROR, "Added new record: UserName=%s\n", gUserInfo.UserName));
  } while (NextData != NULL && InData != EndData);
    
  return EFI_SUCCESS;
}


EFI_STATUS
UsersRestoreAllFromCsvFile(
  IN CHAR8 *FileName
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  EFI_FILE_HANDLE File;
  UINTN FileSize;
  UINT8 *FileData = NULL;
  BOOLEAN bAdminUserPresent = FALSE;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));  
  
  File = LibFsOpenFile(FileName, EFI_FILE_MODE_READ /*| EFI_FILE_MODE_WRITE*/, 0);
  if (File == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error while LibFsOpenFile!!!!\n",
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  FileSize = LibFsSizeFile(File);
  if (FileSize) {
    FileData = AllocateZeroPool(FileSize + 1);
    if (FileData) {
      Status = LibFsReadFile(File, &FileSize, FileData);
    }
  }
  
  LibFsCloseFile(File);

  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  if (FileSize == 0 || FileData == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = UsersImportCsvData(FileData, FileSize, &bAdminUserPresent);
  
  if (!bAdminUserPresent) {
    ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_ERR_NO_ADM_USER_PRESENT), NULL));
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
UsersCommonInit(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  if (CurrentConfig == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  bUsersFormExitFlag = FALSE;
  bRecreateForm = FALSE;
  CurAuthType = AUTH_TYPE_LOG_PASS;
  
  CurrentEvent = 0;
  CurrentMode = USERS_PAGE_TYPE_NONE;
  
  PasswdMenuStr = NULL;
  
  InputDataFlags = 0;
  ZeroMem(&gUserInfo, sizeof(USER_INFO));
  ZeroMem(&gUserInfoPass, sizeof(USER_INFO_LOG_PASS));
  
  CurrentHiiHandle = HiiHandle;
  
  if (CurrentUserTypesFlags == USER_TYPE_ADMIN) {
    gUserInfo.Flags |= USER_ADMIN_FLAG;
  }

  CreateDefaultAdminRolesMap();
  UsersInfoInit ();
  return EFI_SUCCESS;
}


EFI_STATUS
UsersControlPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_USERS_GUID;
  EFI_FORM_ID FormId = USERS_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken, Token;
  CHAR16 TmpStr16[255];
  UINTN Offs;
  UINT32 PasswordLen;

  do {  
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    if (EFI_SUCCESS != UsersCommonInit(HiiHandle)) {
      return EFI_INVALID_PARAMETER;
    }
  
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    UpdateFrameTitle(HiiHandle);

    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)USERS_CREATE_PAGE_ID, STRING_TOKEN(STR_USER_CREATE),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)USERS_DELETE_PAGE_ID, STRING_TOKEN(STR_USER_DELETE),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)USERS_VIEW_PAGE_ID, STRING_TOKEN(STR_USER_VIEW),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
      
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)USERS_STORE_TO_CVS_FILE_ID, 
      STRING_TOKEN(STR_USERS_STORE_TO_CVS_FILE),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    
    Offs = UnicodeSPrint(
      TmpStr16, 
      sizeof (TmpStr16),
      L"%s",
      HiiGetString (HiiHandle, STRING_TOKEN(STR_USERS_PASSWORD_LEN), NULL)
      );
    Status = GetUsrPasswordLen(&PasswordLen);
    if (EFI_ERROR (Status)) {
      UnicodeSPrint(
        &TmpStr16[Offs], 
        sizeof (TmpStr16) - Offs * sizeof (*TmpStr16),
        L"%s",
        HiiGetString (HiiHandle, STRING_TOKEN(STR_NOT_SET), NULL)
        );
    } else {
      UnicodeSPrint(
        &TmpStr16[Offs], 
        sizeof (TmpStr16) - Offs * sizeof (*TmpStr16),
        L"%d",
        PasswordLen
        );
    }

    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)USERS_STORE_TO_CVS_FILE_ID, 
      Token,
      HelpToken, 
      EFI_IFR_FLAG_READ_ONLY, 
      0
      );
    
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      goto _exit;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, USERS_PAGE_ID, NULL, &ActionRequest);
      
      LOG((EFI_D_ERROR, "%a.%d: bUsersFormExitFlag=%d\n",
        __FUNCTION__, __LINE__, bUsersFormExitFlag));
      if (bUsersFormExitFlag) {
        Status = EFI_SUCCESS;
        break;
      }
    } while (1);

  _exit:  
    DestroyHiiResources();
    
    switch (CurrentEvent) {
    case USERS_CREATE_PAGE_ID:
      CurrentMode = USERS_PAGE_TYPE_CREATE;
      Status = CreateUsersPage(HiiHandle);
      break;

    case USERS_DELETE_PAGE_ID:
      CurrentMode = USERS_PAGE_TYPE_DELETE;
      DeleteUsersPage(HiiHandle);
      break;
    
    case USERS_VIEW_PAGE_ID:
      CurrentMode = USERS_PAGE_TYPE_VIEW;
      Status = ViewUsersPage(HiiHandle);
      break;

    default:
      return Status;
    }
  } while (!EFI_ERROR(Status));
  
  return Status;
}

EFI_STATUS
UsersStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN UINT8 Type
  )
{
  EFI_STATUS Status;

  if (EFI_SUCCESS != UsersCommonInit(HiiHandle)) {
    return EFI_INVALID_PARAMETER;
  }
  
  CurrentMode = Type;
  switch (Type) {
  case USERS_PAGE_TYPE_CREATE:
    Status = CreateUsersPage(CurrentHiiHandle);
    break;
  
  case USERS_PAGE_TYPE_DELETE:
    Status = DeleteUsersPage(CurrentHiiHandle);
    break;
  
  case USERS_PAGE_TYPE_VIEW:
    Status = ViewUsersPage(CurrentHiiHandle);
    break;
  
  default:
    CurrentMode = USERS_PAGE_TYPE_NONE;
    Status = EFI_INVALID_PARAMETER;
  }
  return Status;
}


EFI_STATUS
UpdateCurrentUserCard(
  VOID
  )
{
  int SaveCurrentMode;
  EFI_STATUS Status;
  USER_INFO *pCurUserInfo;  

  SaveCurrentMode = CurrentMode;
  CurrentMode = USERS_PAGE_TYPE_VIEW;
  UpdateGlobalUserInfo();
  pCurUserInfo = UserGetLastFoundedInfo();
  if (pCurUserInfo != NULL) {
    UpdateGlobalUsrAccessInfo (pCurUserInfo->UserId);
  }
  bCreateAccountQuite = TRUE;
  Status = CreateAccount();
  bCreateAccountQuite = FALSE;
  LOG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  CurrentMode = SaveCurrentMode;
  return Status;
}

STATIC
EFI_STATUS
FindHiddenUser (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  
  UserCleanLastFoundedInfo ();
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pUserInfo->Flags & USER_HIDDEN_FLAG) {
      UserSetLastFoundedInfo(pUserInfo);
      return EFI_SUCCESS;
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  
  return EFI_NOT_FOUND;
}


UINTN
GetUsersCount (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  UINTN Count;
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return 0;
  }
  
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return 0;
  }
  
  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return 0;
  }

  Count = 0;
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {      
      break;
    }

    Count++;
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  return Count;
}


#define MAX_USR_LIST_VAR_CHUNKS     30
#define MAX_USR_LIST_VAR_SIZE       (PcdGet32(PcdMaxVariableSize) - \
                                      sizeof (VARIABLE_HEADER) - 20)

EFI_STATUS
UsersListVarDelete (
  IN UINTN StartChunk
  )
{
  CHAR16 Vname[40];
  UINTN Idx, Size;
  EFI_STATUS Status = EFI_SUCCESS;
  

  for (Idx = StartChunk; Idx < MAX_USR_LIST_VAR_CHUNKS; Idx++) {
    UnicodeSPrint(Vname, sizeof (Vname), L"%s%03d", USR_LIST_VAR_NAME, Idx);
      
    Status = gRT->GetVariable(
        Vname, 
        &gUsrVarGuid,
        NULL, 
        &Size, 
        NULL);
    if (Status == EFI_NOT_FOUND) {
      break;
    }
    
    gRT->SetVariable(
      Vname, 
      &gUsrVarGuid,
      (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
         EFI_VARIABLE_RUNTIME_ACCESS), 
       0, 
       NULL);  
  }
  return Status;
}


EFI_STATUS
UsersListVarUpdate (
  IN USERS_LIST_VAR *VarData
  )
{
    UINTN Size, Idx, Amount, ChunkSize, RestLen;
    EFI_STATUS Status = EFI_SUCCESS;
    BOOLEAN bNeedUpdate;
    CHAR16 Vname[40];
    UINT8 *PrevData, *CurData;

    if (VarData == NULL) {
      Status = UsersListVarDelete (0);
      DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }

    Amount = VarData->VarLen / MAX_USR_LIST_VAR_SIZE;
    if (VarData->VarLen % MAX_USR_LIST_VAR_SIZE) {
      Amount++;
    }
    RestLen = VarData->VarLen + sizeof (*VarData) - 1;
    CurData = (UINT8*)VarData;
    DEBUG ((EFI_D_ERROR, "%a.%d Amount=%d\n", __FUNCTION__, __LINE__, Amount));

    for (Idx = 0; Idx < Amount; Idx++) {
      UnicodeSPrint(Vname, sizeof (Vname), L"%s%03d", USR_LIST_VAR_NAME, Idx);
      bNeedUpdate = TRUE;
      Size = 0;
      ChunkSize = RestLen > MAX_USR_LIST_VAR_SIZE ? 
                    MAX_USR_LIST_VAR_SIZE : RestLen;
      Status = gRT->GetVariable(Vname, &gUsrVarGuid, NULL, &Size, NULL);
      if (Size && Size == ChunkSize) {        
        PrevData = AllocateZeroPool (Size);
        
        Status = gRT->GetVariable(Vname, &gUsrVarGuid, NULL, &Size, PrevData);
        if (!EFI_ERROR (Status)) {
          if (CompareMem(PrevData, CurData, ChunkSize) == 0) {
            bNeedUpdate = FALSE;
          }
        }

        if (PrevData) {
          FreePool (PrevData);
        }
      }

      if (bNeedUpdate) {
        DEBUG ((EFI_D_ERROR, "!! UsrListVarUpdate !!\n"));
        Status = gRT->SetVariable (
                        Vname, 
                        &gUsrVarGuid,
                        (EFI_VARIABLE_NON_VOLATILE | 
                         EFI_VARIABLE_BOOTSERVICE_ACCESS | 
                         EFI_VARIABLE_RUNTIME_ACCESS), 
                         ChunkSize, 
                         CurData
                         );
        if (EFI_ERROR (Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
            __FUNCTION__, __LINE__, Status));
          break;
        }
      }
      CurData += ChunkSize;
      RestLen -= ChunkSize;
    }
      
    DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      UsersListVarDelete (0);
    } else {
      if (Amount) {
        UsersListVarDelete (Amount);
      }
    }
    return Status;
}


EFI_STATUS
UsersListUpdate (
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  USER_INFO *pUserInfo;  
  UINTN UsersCnt, VarLen, RestLen, Rv;
  USERS_LIST_VAR *VarData = NULL;
  CHAR16 *CurStr;

  UsersCnt = GetUsersCount ();
  if (UsersCnt == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_NOT_FOUND;
    goto _exit;
  }

  RestLen = VarLen = UsersCnt * (sizeof (pUserInfo->UserName) + 
    4 * sizeof (CHAR16));
  VarData = AllocateZeroPool (VarLen + sizeof (USERS_LIST_VAR));
  if (VarData == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_NOT_FOUND;
    goto _exit;
  }
  VarData->RecordsCnt = 0;
  VarData->VarLen = 0;
  CurStr = VarData->VarData;
  
  pUserInfo = UserGetNextUserInfo(TRUE);
  if (!pUserInfo) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_NOT_FOUND;
    goto _exit;
  }
  
  do {
    if ((pUserInfo->Flags & USER_BLOCKED_FLAG) == 0) {
      Rv = UnicodeSPrint(CurStr, RestLen, L"%s;%s\n", 
        pUserInfo->UserName,
        (pUserInfo->Flags & USER_ADMIN_FLAG) == 0 ? 
          L"0" : L"1"
        );
      if (RestLen < Rv) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        Status = EFI_ABORTED;
        goto _exit;
      }
      RestLen -= Rv;
      CurStr += Rv;
      VarData->VarLen += (UINT32)Rv * sizeof (CHAR16);
      VarData->RecordsCnt++;
    }
    pUserInfo = UserGetNextUserInfo(FALSE);
  } while (pUserInfo != NULL);

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  VarData->VarLen += sizeof (CHAR16); // end of line
  DEBUG ((EFI_D_ERROR, "VarData->VarData=%s\n", VarData->VarData));

  Status = UsersListVarUpdate (VarData);

_exit:
  if (VarData != NULL) {
    FreePool (VarData);
  }
  return Status;
}


VOID
DestroyCurrentUserInfo (
  CURRENT_USER_INFO *pCurUsrInfo
  )
{
  if (pCurUsrInfo == NULL) {
    return;
  }
  if (pCurUsrInfo->Pass) {
    FreePool (pCurUsrInfo->Pass);
  }
  if (pCurUsrInfo->Username) {
    FreePool (pCurUsrInfo->Username);
  }
  if (pCurUsrInfo->ServerNameOrIP) {
    FreePool (pCurUsrInfo->ServerNameOrIP);
  }
  FreePool (pCurUsrInfo);
}


EFI_STATUS
SaveUserPassOrPin (
  IN CHAR8 *PinPass8,
  IN CHAR16 *PinPass16
  )
{
  UINTN BufSize;

  if (CurrentPinPass) {
    FreePool (CurrentPinPass);
    CurrentPinPass = NULL;
  }
  
  if (PinPass8 == NULL && PinPass16 == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (PinPass8) {
    BufSize = sizeof (CHAR16) * AsciiStrSize (PinPass8);
    CurrentPinPass = AllocatePool (BufSize);
    if (CurrentPinPass == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    UnicodeSPrint(CurrentPinPass, BufSize, L"%a", PinPass8);
  } else if (PinPass16) {
    BufSize = StrSize (PinPass16);
    CurrentPinPass = AllocatePool (BufSize);
    if (CurrentPinPass == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    UnicodeSPrint(CurrentPinPass, BufSize, L"%s", PinPass16);
  }

  return EFI_SUCCESS;
}


EFI_STATUS
UpdateCurrentUserInfo (
  VOID
  )
{
  STATIC CURRENT_USER_INFO_PROTOCOL CurrentUsrInfoProtocol, *pUsrInfoProto;
  CURRENT_USER_INFO *pCurrUsrInfo;
  EFI_STATUS Status;
  USER_INFO *pUserInfo;
  MULTIBOOT_PROTOCOL *MultibootProto;

  Status = gBS->LocateProtocol (
              &gMultibootProtocolGuid, 
              NULL, 
              (VOID **) &MultibootProto
              );
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (MultibootProto == NULL) {
    return EFI_ABORTED;
  }

  Status = gBS->LocateProtocol (&gCurrentUserInfoProtocolGuid, NULL,
        (VOID **) &pUsrInfoProto);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR (Status)) {
    EFI_HANDLE DriverHandle;
    
    if (Status != EFI_NOT_FOUND) {
      return Status;
    }
    DriverHandle = MultibootProto->GetDriverHandle();
    Status = gBS->InstallProtocolInterface( 
      &DriverHandle, 
      &gCurrentUserInfoProtocolGuid,
      EFI_NATIVE_INTERFACE,
      &CurrentUsrInfoProtocol
      );
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }
  DestroyCurrentUserInfo (CurrentUsrInfoProtocol.CurrentUserInfo);
  CurrentUsrInfoProtocol.CurrentUserInfo = NULL;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  pUserInfo = GetCurrentUser ();
  if (pUserInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (pUserInfo->UserId == USER_UNKNOWN_ID ||
      pUserInfo->UserId == USER_SPECIAL_ID ||
      pUserInfo->UserId == USER_AMT_ID) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }

  pCurrUsrInfo = AllocateZeroPool (sizeof (*pCurrUsrInfo));
  if (pCurrUsrInfo == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  pCurrUsrInfo->Username = AllocateCopyPool (
    StrSize (pUserInfo->UserName), pUserInfo->UserName);
  if (pCurrUsrInfo->Username == NULL) {
    DestroyCurrentUserInfo (pCurrUsrInfo);
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  if (CurrentPinPass) {
    pCurrUsrInfo->Pass = AllocateCopyPool (StrSize (CurrentPinPass), 
      CurrentPinPass);
    if (pCurrUsrInfo->Pass == NULL) {
      DestroyCurrentUserInfo (pCurrUsrInfo);
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
  }  
  
  CurrentUsrInfoProtocol.CurrentUserInfo = pCurrUsrInfo;

  return EFI_SUCCESS;
}


