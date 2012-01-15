/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __TOKEN__FUNCTIONS__H
#define __TOKEN__FUNCTIONS__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <Library/VfrCommon.h>
#include <InternalErrDesc.h>
#include <Protocol/SmartCard.h>
#include <Library/Pkcs11Lib.h>
#include <Library/Lib/AdminMainPage.h>
#include <Library/Lib/Users.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/Locks.h>


#define GOST_DIGEST_LEN               64
#define MAX_PIN_CODE_LEN              64


typedef struct _ET_OBJ_DESC {
  UINT16 Id;
  UINT16 Type;
} ET_OBJ_DESC;

VOID
SetResetAfterLogOff (
  IN BOOLEAN bFlag
  );


EFI_STATUS
TokenGetCertificateById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT UINT8 **Cdata,
  IN OUT UINTN *CdataLen
  );


EFI_STATUS
TokenCheckCASign(
  VOID
  );


EFI_STATUS
TokenCheckPin(
  VOID
  );

BOOLEAN
TokenPresent(
  VOID
  );

VOID 
TokenRegisterCallback(
  VOID
  );

EFI_STATUS
TokenFunctionsInit(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Cfg
  );


VOID
TokenNotifyTest(
  VOID
  );

VOID
TokenSimpleTest(
  VOID
  );

EFI_STATUS
TokenComparisonDataById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  );

UINT16 *
GetTokenUserVarsString16(
  VOID
  );

SMART_CARD_PROTOCOL *
TokenGetSmartCardProtocol(
  VOID
  );

BOOLEAN
CheckForWrongPinLocks (
  VOID
  );

EFI_STATUS
LdapAuthWithCertData (
  IN UINT8 *UsrCertData,
  IN UINTN UsrCertDataLen
  );

BOOLEAN
eTokenLikeSmartCard(
  VOID
  );

CHAR8 *
GetUserPIN (
  VOID
  );



#endif  /* #ifndef __TOKEN__FUNCTIONS__H */
