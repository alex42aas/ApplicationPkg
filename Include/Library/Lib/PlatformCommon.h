/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PLATFORM__COMMON__H
#define __PLATFORM__COMMON__H

#include <Library/CommonUtils.h>
#include <Library/MultibootDescUtils.h>
#include <Library/Lib/Drm.h>
#include <Library/Lib/MII.h>
#include <Library/Lib/MainPage.h>
#include <Library/VfrCommon.h>
#include <Library/FaultTolerance.h>
#include <Library/ExtHdrUtils.h>
#include <Library/Lib/AdminMainPage.h>
#include <Library/Lib/UsersStorage.h>
#include <Library/Lib/Users.h>
#include <InternalErrDesc.h>
#include <Library/FeLib.h>
#include <Library/Lib/PciDevList.h>
#include <Library/Lib/SuperUser.h>
#include <Library/Lib/PciDevList.h>
#include <Protocol/SetupVarProto.h>
#include <Library/BootMngrLib.h>

#define USER_NOT_EXIST_OR_BLOCK  -1  //!< Not allow to login this username
#define USER_AUTH_TYPE_LOG_PASS   0  //!< User with AUTH_TYPE_LOG_PASS
#define USER_AUTH_TYPE_LDAP       1  //!< User with AUTH_TYPE_LDAP

#define TEMP_BOOT_DEV_NAME            L"fd"

#define SYS_GUID_STR_LENG             60


extern USER_INFO_LOG_PASS *pCurrUserLoginPass;


typedef 
EFI_STATUS
(EFIAPI *SEND_ANS_FNC) (
  IN UINT8 Addr,
  IN UINT8 Func,
  IN UINT8 Sc,
  IN UINTN DataLen,
  IN UINT8 *Data,
  IN UINT8 CrcType
  );

typedef struct _ECP_DATA {
  UINT8 Cmd;
  UINTN EcpDataLen;
  UINT8 EcpData[1];
} ECP_DATA;


CHAR16*
GetEntryNameByIndex(
  UINTN Index
  );

EFI_STATUS
UpdateTrrModuleParam(
  IN MULTIBOOT_ENTRY *MbootDefaultEntry
  );

EFI_STATUS
UpdateModulePciBackHideParams(
  IN MULTIBOOT_ENTRY *MbootDefaultEntry
  );

EFI_STRING_ID
GetStringErrUnknownModuleFmt(
  VOID
  );

EFI_STRING_ID
GetStringErrorIntegrity(
  VOID
  );

EFI_STRING_ID
GetStringSuccess(
  VOID
  );

EFI_STRING_ID
GetStringError(
  VOID
  );

EFI_STRING_ID
GetStringFileHashCheck(
  VOID
  );

EFI_STRING_ID
GetStringLoadingOsModuleError(
  VOID
  );

EFI_STRING_ID
GetStringWaitForLoadingOs(
  VOID
  );

int
CheckUserName16(
  IN UINTN NameLen,
  IN CHAR16 *LoginBuf
  );

int
CheckUserName8(
  IN UINTN NameLen,
  IN CHAR8 *LoginBuf,
  IN CHAR16 *UserName,
  IN UINTN UserNameMaxLen,
  IN EFI_HII_HANDLE CurrentHiiHandle
  );

EFI_STATUS
EFIAPI
BIOSFormCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  );

EFI_STATUS 
InitProtocols(
  IN MULTIBOOT_DATA *Data
  );

VOID
ShowErrorObject(
  VOID
  );

BOOLEAN
CheckEngeneerPasswdPresent(
  IN struct tMainFvInfo *pmfvi,
  IN CHAR8 *Guid
  );

VOID
SoundForError(
  VOID
  );

int
FailSaveModeCheckPass(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN struct tMainFvInfo *pMainFv
  );

VOID
ShowErrorPermissionDenied(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

VOID
FileListTest_func(
  IN CHAR8 *Fname,
  IN BOOLEAN bVolume
  );

VOID
ProcessingLoginError(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

int
AdminModeCheckLoginPass(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

int
AdminModeCheckTokenUser(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

BOOLEAN
EnterToAdminMode(
  VOID
  );

EFI_STATUS
PreBootPlatfromProcessing(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Config,
  IN MULTIBOOT_ENTRY *DefaultEntry
  );

EFI_STATUS
ChangeAdminPassword(
  IN EFI_HII_HANDLE HiiHandle,
  IN USER_INFO *pUserInfo
  );

VOID
PlatfromLibraryInit(
  IN MULTIBOOT_DATA *Data
  );

MULTIBOOT_ENTRY *
GetCurrentBootOption(
  VOID
  );

VOID
GotoInitialInitializationMode(
  IN EFI_HII_HANDLE HiiHandle
  );

EFI_STATUS
CheckAllFvWithExtHdr (
  VOID
  );

BOOLEAN
CheckForCompLocks (
  VOID
  );

EFI_STATUS
UnlockComp (
  VOID
  );

EFI_STATUS
CheckingForRemoteAccess (
  IN EFI_HII_HANDLE HiiHandle
  );

VOID
ShowAllConsoles (
  VOID
  );

EFI_STATUS
ResetBiosSetupByRtcRst (
  IN EFI_HII_HANDLE HiiHandle,
  IN UINT8 State
  );

EFI_STATUS
SaveLoadingModeEvent (
  UINTN Mode
  );

EFI_STATUS
CreateDefaultUser (
  IN DEF_USER_DESC *pDefUser
  );

UINT8
GetEndRemoteSessionEndMode (
  VOID
  );

VOID
StopRemoteCfgTlsIfPresent (
  VOID
  );

EFI_STATUS
ProcessingRemoteCtrlPkt (
    IN     MULTIBOOT_PROTOCOL* This,
    IN     UINT8 *RxBuf,
    IN     UINTN RxBufLen,
    IN     REMOTE_CFG_PKT_PROTOCOL *ThisRCPkt,
    IN     EFI_HANDLE ThisRCPktHandle
    );

EFI_STATUS
TlsRemoteAccess (
  IN MULTIBOOT_DATA *Data
  );

EFI_STATUS
TlsRemoteAccessFsm (
  IN EFI_HII_HANDLE HiiHandle
  );

VOID
BlockMultibootRemoteAccess (
  IN BOOLEAN bBlock
  );

EFI_HANDLE
GetCurrentHiiHandle (
  VOID
  );
EFI_HANDLE
GetDriverHandle (
  VOID
  );


EFI_STATUS
InitX509Storage (
  IN BOOLEAN EnableIntErr
  );

EFI_STATUS
SetupEcp (
  IN UINT8 Cmd,
  IN UINT8 *EcpData,
  IN UINTN EcpDataLen
  );

EFI_STATUS
CheckEcp (
  IN UINT8 Cmd,
  IN UINT8 *Data,
  IN UINTN DataLen
  );


#endif /* #ifndef __PLATFORM__COMMON__H */

