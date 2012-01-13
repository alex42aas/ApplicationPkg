/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __RUTOKEN_ECP_H__
#define __RUTOKEN_ECP_H__

#include <Protocol/SmartCard.h>

#include "Apdu.h"

typedef enum {
  RUTOKEN_MODE_PRO,
  RUTOKEN_MODE_GOST_2001,
  RUTOKEN_MODE_GOST_2012,
  RUTOKEN_MODE_UNKNOWN
} RUTOKEN_MODES;

typedef enum {
  DiagnoseOS = 0x00,
  DiagnoseGOST28147_89 = 0x10,
  DiagnoseGOST3410_2001 = 0x11,
  DiagnoseGOST3411_94 = 0x12,
  DiagnoseCryptoProVKO = 0x13
} DIAGNOSE_TEST;

/* Smart card low-level API */

EFI_STATUS
RutokenNsdLock (
  IN SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
RutokenReset (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8           *AtrString,
  IN UINT16              Length
  );

EFI_STATUS
RutokenVerify (
  IN SMART_CARD_PROTOCOL *This,
  IN PIN_USER            UserId,
  IN LOCAL_RIGHTS        Rights,
  IN UINT8               *PinCode,
  IN UINTN               PinCodeLen,
  OUT UINTN              *RetryLeft
  );

EFI_STATUS
RutokenResetAccessRights (
  IN SMART_CARD_PROTOCOL *This,
  IN RESET_USER          UserId,
  IN LOCAL_RIGHTS        Rights
  );

EFI_STATUS
RutokenDiagnoseCard (
  IN SMART_CARD_PROTOCOL *This
  );

/* Cryptoki higher-level API */

EFI_STATUS
RutokenTokenSystemStatus (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT TOKEN_SYSTEM_STATUS *Status
  );

EFI_STATUS
RutokenTokenIdentifyingData (
  IN     SMART_CARD_PROTOCOL    *This,
  IN OUT TOKEN_IDENTIFYING_DATA *Data
  );

EFI_STATUS
RutokenLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  );

EFI_STATUS
RutokenLogout (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin
  );

EFI_STATUS
RutokenDigestInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet,
  IN     UINT8              workmode
  );

EFI_STATUS
RutokenDigest (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest
  );

EFI_STATUS
RutokenSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  );

EFI_STATUS
RutokenReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  );


EFI_STATUS
RutokenWriteBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  );

EFI_STATUS
RutokenCreateFile (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  );

EFI_STATUS
RutokenDecryptInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               RSFRef,
  IN     UINT8              workmode
  );

EFI_STATUS
RutokenDecrypt (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Cipher,
  IN OUT UINTN               *CipherLen
  );

EFI_STATUS
RutokenVerifySignatureInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8              workmode
  );

EFI_STATUS
RutokenVerifySignature (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3410_PARAM_SET ParamSet,
  IN     UINT8               *Hash,
  IN     UINTN               HashLen,
  IN     UINT8               *Sign,
  IN     UINTN               SignLen,
  IN     UINT8               *Key,
  IN     UINTN               KeyLen,
  IN OUT UINT8               *Success
  );

EFI_STATUS
RutokenGetSN (
  IN SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
RutokenGetObjectList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
RutokenGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS 
ScTransmit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *TxBuffer,
  IN     UINTN TxBufferLen,
  IN OUT UINT8 *RxBuffer,
  IN OUT UINTN *RxBufferLen,
  IN     TX_PROTO TxProto
  );

EFI_STATUS
RutokenEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
RutokenEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  );

#endif /* __RUTOKEN_ECP_H__ */

