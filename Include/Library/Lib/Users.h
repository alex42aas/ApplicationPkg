/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __USERS__H
#define __USERS__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/GlobalConfigDxe.h>
#include <Library/MultibootDescUtils.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VfrCommon.h>
#include <Library/FeLib.h>
#include <InternalErrDesc.h>
#include "Locks.h"
#include "UsersStorage.h"
#include "vfrdata.h"
#include <Protocol/CurrentUserInfo.h>


#define USER_NAME_GUID                    "90EC25EC-3D8D-426c-AFB4-891D59CF00B1"
#define USER_PASS_GUID                    "6D922D36-8148-4711-8FF4-B5277EC7F6B9"
#define USER_FIO_GUID                     "D8CB9B42-B6CF-4981-A7A5-EC968FF64F59"
#define USER_CONTACT_INFO_GUID            "3FC4ADAA-3629-40f1-AE4D-F79BAE873E24"
#define USER_BLOCK_FLAG_GUID              "EBDC703F-9FF2-49ce-8304-F90B54761E1D"
#define USER_SUSPEND_FLAG_GUID            "1DCF1193-BB37-4aac-98EB-CA31F6350F0F"
#define USER_COMPARE_TYPE_GUID            "243E2312-DF93-41bd-8B9C-CB198B025201"
#define USER_COMPARE_DATA_GUID            "18063AC1-D963-4088-B10E-2B03637C7829"
#define USER_AUTHORIZATION_TYPE_GUID      "349FC025-016D-4edf-B34F-8911ED95BDBB"
#define USER_TYPE_GUID                    "FBD5A67C-32C2-4b4d-B8A1-D387CD73C855"
#define USER_PASS_CREATE_TIME_GUID        "6D922D36-8148-4711-8FF4-B5277EC7F6BA"


#define MAX_TOKEN_USR_INFO                8

#define PASSWORD_MIN_LEN                  8
#define PASSWORD_MAX_LEN                  16


#define NUM_AUTH_METHODS                  2  //!< Number of authorizations metods, dont allow to create ldap auth user manually

enum {
  USERS_PAGE_TYPE_NONE, USERS_PAGE_TYPE_CREATE, USERS_PAGE_TYPE_DELETE, 
  USERS_PAGE_TYPE_VIEW, USERS_PAGE_TYPE_UNKNOWN
};

enum {AUTH_TYPE_LOG_PASS, AUTH_TYPE_UNKNOWN};

enum {USER_NON_BLOCKED_STATE, USER_BLOCKED_STATE};

#define USER_ADMIN_FLAG                   (1 << 7)
#define USER_BLOCKED_FLAG                 (1 << 6)
#define USER_SU_FLAG                      (1 << 5)
#define USER_HIDDEN_FLAG                  (1 << 4)
#define USER_TOKEN_LDAP                   (1 << 3)

#define USER_SU_ID                        0x55
#define USER_SPECIAL_ID                   0xFD
#define USER_AMT_ID                       0xFE
#define USER_UNKNOWN_ID                   0xFF

#define MIN_USER_NAME_LEN                 3
#define MAX_USER_NAME_LEN                 25
#define MIN_USER_FIO_LEN                  1
#define MAX_USER_FIO_LEN                  25
#define MIN_USER_CONTACT_INFO             1
#define MAX_USER_CONTACT_INFO             50
#define PASSWD_HASH_TYPE                  (CS_TYPE_CRC32)

#define USER_MAX_COMPARISON_DATA_SIZE     20

#define FILL_FLAG_USER_NAME               (1 << 0)
#define FILL_FLAG_USER_FIO                (1 << 1)
#define FILL_FLAG_USER_CONTACT_INFO       (1 << 2)
#define FILL_FLAG_USER_PASSWD             (1 << 3)
#define FILL_FLAG_USER_COMPARISON         (1 << 4)

#define USER_TYPE_USER                    (1 << 0)
#define USER_TYPE_ADMIN                   (1 << 1)

#define USER_AUTH_TYPE1_FLAGS_MASK        (FILL_FLAG_USER_NAME | \
      FILL_FLAG_USER_FIO | FILL_FLAG_USER_CONTACT_INFO | FILL_FLAG_USER_PASSWD)

#define USER_AUTH_TYPE2_FLAGS_MASK        (FILL_FLAG_USER_NAME | \
      FILL_FLAG_USER_FIO | FILL_FLAG_USER_CONTACT_INFO | \
      FILL_FLAG_USER_COMPARISON)

#define USR_VAR_NAME                      L"UsrVar"
#define USR_CONFIG_VAR_NAME               L"UsrConfig"
#define USR_LIST_VAR_NAME                 L"UsrListVar"


#define USER_CONFIG_VERSION  1

#define USERS_LIST_FROM_LDAP      (1 << 0)
#define USERS_SETUP_FLAG_STATUS   (1 << 7)

#pragma pack(1)
typedef struct T_USER_INFO {
  UINT8 AuthType;  
  UINT8 Flags;
  CHAR16 UserName[MAX_USER_NAME_LEN + 1];
  CHAR16 UserFIO[MAX_USER_FIO_LEN + 1];
  CHAR16 UserContactInfo[MAX_USER_CONTACT_INFO + 1];
  UINT8 UserId;
  UINT8 LoginFailCnt;
  UINT32 ExtDataLen;
  UINT8 ExtData[1];
} USER_INFO;

typedef struct T_USER_INFO_LOG_PASS {
  UINT8 PassHashType;
  UINT32 PassCreateTime;
  //UINT64 PassCreateTime;
  UINT8 PassHash[MAX_HASH_LEN];
} USER_INFO_LOG_PASS;

/* total length of token info present by ExtDataLen in USER_INFO */
typedef struct T_USER_INFO_TOKEN {
  UINT8 DataLen;
  UINT8 DataType;
  UINT8 Data[1];
} USER_INFO_TOKEN;

typedef struct T_USER_TOKEN_DATA {
  CHAR16 *userName;
  CHAR16 *digest;
  CHAR16 *commonName;
  CHAR16 *subject;
  CHAR16 *mail;
  CHAR16 *uid;
  CHAR16 *UserFIO;
  CHAR16 *ContactInfo;
  UINTN  permission;
} USER_TOKEN_DATA;

typedef struct T_USER_LOGIN_PASS_DATA {
  CHAR16 *UserName;
  CHAR16 *UserFIO;
  CHAR16 *ContactInfo;
  CHAR16 *Hash;
  UINTN  Permission;
} USER_LOGIN_PASS_DATA;


typedef struct T_USER_CONFIG_DATA {
  UINT32 varVersion;
  CHAR16 flags;
} USER_CONFIG_DATA;

typedef struct T_USERS_LIST_VAR {
  UINT32 VarVersion;
  UINT32 VarLen;
  UINT32 RecordsCnt;
  UINT32 Crc32;
  CHAR16 VarData[1];
} USERS_LIST_VAR;

#pragma pack()


extern EFI_GUID gUsrVarGuid;


EFI_STATUS
UsersStorageUpdate(
  VOID
  );


int
GetUserPageCurrentEvent(
  VOID
  );

USER_INFO_TOKEN**
UsersGetLastFoundedTokenUser(
  VOID
  );

EFI_STATUS
UsersGetNextTokenUser(
  BOOLEAN bRestart
  );

USER_INFO *
GetStaticUserInfo(
  VOID
  );

BOOLEAN
UserTypeAdmin(
  IN USER_INFO *pUser
  );

USER_INFO *
GetCurrentUser(
  VOID
  );

UINT8
GetCurrentUserId(
  VOID
  );


VOID
SetCurrentUser(
  IN USER_INFO *pUser
  );

EFI_STATUS
UsersControlPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

EFI_STATUS
UsersStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN UINT8 Type
  );

VOID
UsersSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  );
  
VOID
UsersSetUserTypesFlags(
  IN UINT8 Flags
  );
  
USER_INFO *
UserGetLastFoundedInfo(
  VOID
  );


VOID
UserCleanLastFoundedInfo(
  VOID
  );


EFI_STATUS
UserFindRecordById(
  IN UINT8 UserId
  );

EFI_STATUS
UserFindRecordByName(
  IN CHAR16 *UserName
  );
  
USER_INFO *
UserGetNextUserInfo(
  IN BOOLEAN bRestart
  );
  
EFI_STATUS
UsersPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );
  
EFI_STATUS
UsersRestoreAllFromCsvFile(
  IN CHAR8 *FileName
  );
  
EFI_STATUS
UsersCommonInit(
  IN EFI_HII_HANDLE HiiHandle
  );

EFI_STATUS
UsrVarUpdate(
  VOID
  );

EFI_STATUS
UsrVarClean(
  VOID
  );

EFI_STATUS
CheckPasswordSymbols(
  CHAR16 *Password,
  UINT32 PassLen
  );

EFI_STATUS
UserFindRecordByAuthType(
  IN UINT8 AuthType
  );

BOOLEAN
CheckIfMiiTokenUsrAndCANotLoaded(
  VOID
  );

EFI_STATUS
UpdateCurrentUserCard(
  VOID
  );
  
EFI_STATUS
AddLdapUser( 
  IN  CHAR16 *userName,
  IN  CHAR8  *distinguishedName,
  IN  BOOLEAN isAdmin,
  IN  BOOLEAN isToken,
  IN  UINTN   permission,
  OUT UINT8  *userID
  );
  
EFI_STATUS
AddTokenGuestUser(
  IN  CHAR16 *userName,
  IN  const CHAR16  *ComparisonData,
  OUT UINT8  *userID
  );

EFI_STATUS
UserFindRecordByNameWithThisAuth(
  IN UINT8 AuthType,
  IN CHAR16 *UserName
  );
  
EFI_STRING
UsersGetTypeString16(
  IN UINT8 UsrType,
  IN EFI_HII_HANDLE HiiHandle
  );

UINT8*
GetUserTokenExtData(
  IN UINT8     dataType,
  IN USER_INFO *pUser
  );
  
EFI_STATUS
DeleteLastFoundedRecord(
  VOID
  );

EFI_STATUS
RemoveAllHiddenUsers (
  VOID
  );

BOOLEAN
isHiddenUser (
  IN USER_INFO *pUserInfo
  );

USER_INFO *
GetAmtUsrInfo(
  VOID
  );

USER_INFO *
ObtainSuRecord(
  VOID
  );

EFI_STATUS
UsersImportCsvData (
  IN UINT8 *FileData,
  IN UINTN FileSize,
  IN OUT BOOLEAN *bAdminUserPresent
  );

UINTN
GetUsersCount (
  VOID
  );

BOOLEAN
CheckTokenUserDataPresent (
  IN USER_INFO_TOKEN *pUserInfoToken[]
  );

EFI_STATUS
GetUsersFromLdapAndSave (
  VOID
  );

EFI_STATUS
IsTokenUserDataPresentAndSame (
  IN USER_TOKEN_DATA *tokenUserData,
  IN OUT BOOLEAN *bPresentSame,
  IN OUT BOOLEAN *bPresent
  );

EFI_STATUS
AddTokenUser(
  IN USER_TOKEN_DATA *tokenUserData
  );

EFI_STATUS
AddLoginPassUser(
  IN USER_LOGIN_PASS_DATA *LoginPassUserData
  );


EFI_STATUS
UsersParseComparisonData16(
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN USER_INFO_TOKEN *pUserInfoToken[]
  );

EFI_STATUS
SetIsLoadUsersFromLdapFlag (
  BOOLEAN isLoadFromLdap
  );

BOOLEAN
IsLoadUsersFromLdap (
  VOID
  );

EFI_STATUS
SetUsersConfigFirstTimeConfigured (
  VOID
  );

BOOLEAN
IsNeedToUsersConfigFirstTime (
  VOID
  );

CONFIG_ERROR_T
SetUsersConfigFromINIFile (
  CHAR8 *filePath
  );

EFI_STATUS
InitializeUsersConfig (
  VOID
  );

EFI_STATUS
UserFindRecordByNum(
  IN UINTN RecordNum
  );

VOID
UserSetLastFoundedInfo (
  IN USER_INFO *pInfo
  );

UINT8*
UserTokenExtData (
  IN UINT8     dataType,
  IN USER_INFO *pUser
  );

VOID
FreeTokenData(
  IN USER_INFO_TOKEN **pTokenData
  );


EFI_STATUS
UsersListUpdate (
  VOID
  );

VOID
DestroyCurrentUserInfo (
  CURRENT_USER_INFO *pCurUsrInfo
  );

EFI_STATUS
SaveUserPassOrPin (
  IN CHAR8 *PinPass8,
  IN CHAR16 *PinPass16
  );

EFI_STATUS
UpdateCurrentUserInfo (
  VOID
  );

EFI_STATUS
GetUsrPasswordLen (
  IN OUT UINT32 *PasswordLen
  );

EFI_STATUS
SetUsrPasswordLen (
  IN UINT32 PasswordLen
  );

EFI_STATUS
PassswordReGen (
  CHAR8 Password8[]
  );


#endif  /* #ifndef __USERS__H */

