/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/*
 */

#ifndef __ETOKEN__H__
#define __ETOKEN__H__

#include <Protocol/SmartCard.h>

#include "Apdu.h"

#define BULK_BUFFER_SIZE                    300

#define PCB_R_BIT             (1 << 7)
#define PCB_NS_BIT            (1 << 6)
#define PCB_M_BIT             (1 << 5)
#define PCB_NR_BIT            (1 << 4)

typedef enum {
  ETOKEN_MODE_PRO,
  ETOKEN_MODE_GOST_2001,
  ETOKEN_MODE_GOST_2012,
  ETOKEN_MODE_UNKNOWN
} ETOKEN_MODES;

typedef enum {
  ETOKEN_JAVPRO_A = 0x1000,
  ETOKEN_JAVPRO_B,
  ETOKEN_PROV42B,
  ETOKEN_UNKNOWN
} ETOKEN_VERSIONS;

typedef enum {
  DiagnoseOS = 0x00,
  DiagnoseGOST28147_89 = 0x10,
  DiagnoseGOST3410_2001 = 0x11,
  DiagnoseGOST3411_94 = 0x12,
  DiagnoseCryptoProVKO = 0x13
} DIAGNOSE_TEST;

#define MAX_SIGN_DATA     2048

typedef struct _ETOKEN_OBJ_DATA {
  UINT16 ObjId;
  UINT16 ObjType;
} ETOKEN_OBJ_DATA;

/* Smart card low-level API */

VOID
UpdatePcbNsBit(
  IN OUT UINT8 *Cmd
  );

UINTN 
CsumLrcCompute(
  IN UINT8 *In, 
  IN UINTN Len, 
  IN OUT UINT8 *Rc
  );

VOID
eTokenCheckBusy(
  IN SMART_CARD_READER_PROTOCOL *Reader,
  IN OUT UINT8 *CheckBuff,
  IN UINTN CheckBuffLen
  );

EFI_STATUS
SendRBlock(
  IN USB_CCID_DEV *Device,
  IN BOOLEAN bNr,
  IN OUT UINT8 *RecvBuffer,
  IN OUT UINTN *RecvSize
  );

EFI_STATUS
eTokenNsdLock (
  IN SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenReset (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8           *AtrString,
  IN UINT16              Length
  );

EFI_STATUS
eTokenVerify (
  IN SMART_CARD_PROTOCOL *This,
  IN PIN_USER            UserId,
  IN LOCAL_RIGHTS        Rights,
  IN UINT8               *PinCode,
  IN UINTN               PinCodeLen,
  OUT UINTN              *RetryLeft
  );

EFI_STATUS
eTokenEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  );

EFI_STATUS
eTokenResetAccessRights (
  IN SMART_CARD_PROTOCOL *This,
  IN RESET_USER          UserId,
  IN LOCAL_RIGHTS        Rights
  );

EFI_STATUS
eTokenDiagnoseCard (
  IN SMART_CARD_PROTOCOL *This
  );

/* Cryptoki higher-level API */

EFI_STATUS
eTokenTokenSystemStatus (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT TOKEN_SYSTEM_STATUS *Status
  );

EFI_STATUS
eTokenTokenIdentifyingData (
  IN     SMART_CARD_PROTOCOL    *This,
  IN OUT TOKEN_IDENTIFYING_DATA *Data
  );

EFI_STATUS
eTokenLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  );

EFI_STATUS
eTokenLogout (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin
  );

EFI_STATUS
eTokenDigestInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet,
  IN     UINT8              workmode
  );

EFI_STATUS
eTokenDigest (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest
  );

EFI_STATUS
eTokenSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  );

EFI_STATUS
eTokenReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  );

EFI_STATUS
eTokenDecryptInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               RSFRef,
  IN     UINT8              workmode
  );

EFI_STATUS
eTokenDecrypt (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Cipher,
  IN OUT UINTN               *CipherLen
  );

EFI_STATUS
eTokenVerifySignatureInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8              workmode
  );

EFI_STATUS
eTokenVerifySignature (
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
eTokenGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenPrintObjectsList (
  IN     SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataCnt
  );

EFI_STATUS
T1_SelectMaxBlock(
  IN USB_CCID_DEV *Device
  ); 

UINT32
eTokenGetFwVersion (
  IN UINT8 *Atr,
  IN UINTN AtrLen
  );

EFI_STATUS
eTokenGetSN (
  IN SMART_CARD_PROTOCOL *This
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


VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  );

EFI_STATUS
eTokenDigestOpenSSL (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest /* Assumed not less than 32 bytes long */
  );



#endif /* __ETOKEN___H__ */

