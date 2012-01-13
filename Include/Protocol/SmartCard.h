/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef USB_SMARTCARD_H
#define USB_SMARTCARD_H

#define SMART_CARD_READER_PROTOCOL_GUID \
  { 0x42451e4e, 0xe278, 0x4212, {0x93, 0x40, 0xf5, 0x8f, 0xfe, 0xee, 0x51, 0x44 }}

#define SMART_CARD_PROTOCOL_GUID \
  { 0xE4514441, 0xE371, 0x4214, {0x93, 0x40, 0xf5, 0x8f, 0xfe, 0xee, 0x51, 0x44 }}


#define ETOKEN_PROD_ID            0x0620
#define ETOKEN_VENDOR_ID          0x0529

#define ATHENA_VENDOR_ID          0x0DC3  // Athena Smartcard Solutions, Inc.
#define ATHENA_PROD_ID            0x1004  //0x0802 // ASEDrive IIIe

enum {
    UNKNOWN_ID_TYPE = 0,
    PUBKEY_ID_TYPE = 1,
    PKEY_ID_TYPE = 2, // private key
    CERT_ID_TYPE = 3,
    DATA_ID_TYPE = 4
};


extern EFI_GUID gSmartCardReaderProtocolGuid;
extern EFI_GUID gSmartCardProtocolGuid;

typedef struct _SMART_CARD_READER_PROTOCOL SMART_CARD_READER_PROTOCOL;

typedef struct _APDU APDU;

typedef struct _SMART_CARD_READER_SLOT_INFO {
  UINTN Dummy;
} SMART_CARD_READER_SLOT_INFO;

typedef EFI_STATUS (EFIAPI *SMART_CARD_READER_INIT) (
  IN SMART_CARD_READER_PROTOCOL *This,
  IN VOID **Param 
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_FINISH) (
  IN SMART_CARD_READER_PROTOCOL *This
  );


typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_RELEASE) (
  IN SMART_CARD_READER_PROTOCOL *This 
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_CONNECT) (
  IN SMART_CARD_READER_PROTOCOL *This,
  IN SMART_CARD_READER_SLOT_INFO *Slot
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_DISCONNECT) (
  IN SMART_CARD_READER_PROTOCOL *This,
  IN SMART_CARD_READER_SLOT_INFO *Slot
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_TRANSMIT) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8 *SendBuffer,
  IN     UINTN SendSize,
  IN OUT UINT8 *RecvBuffer,
  IN OUT UINTN *RecvSize,
  IN     UINT32 Control
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_LOCK) (
  IN     SMART_CARD_READER_PROTOCOL *This
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_UNLOCK) (
  IN     SMART_CARD_READER_PROTOCOL *This
  );


typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_GET_STATUS) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8 Slot,
  IN     UINT8 *ScStatus
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_RESET) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8  Slot,
  IN OUT UINT8* Atr,
  IN     UINTN* AtrLength);

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_SEND) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8 Slot,
  IN     UINT8 *SendBuffer,
  IN     UINTN SendSize,
  OUT    UINT8 *ScStatus     
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_RECEIVE) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8 Slot,
  IN     UINT8 *RecvBuffer,
  IN     UINTN *RecvSize,
  IN     UINTN Timeout,
  OUT    UINT8 *ScStatus
  );

typedef EFI_STATUS (EFIAPI * SMART_CARD_READER_SEND_TPDU) (
  IN     SMART_CARD_READER_PROTOCOL *This,
  IN     UINT8 Slot,
  IN     APDU* Tpdu
  );


struct _SMART_CARD_READER_PROTOCOL {
  SMART_CARD_READER_INIT Init;
  SMART_CARD_READER_FINISH Finish;
  SMART_CARD_READER_RELEASE Release;
//  SMART_CARD_READER_DETECT_CARD_PRESENSE DetectCard;
  SMART_CARD_READER_CONNECT Connect;
  SMART_CARD_READER_DISCONNECT Disconnect;
  SMART_CARD_READER_TRANSMIT Transmit;
  SMART_CARD_READER_GET_STATUS GetStatus;
  SMART_CARD_READER_RESET Reset;
  SMART_CARD_READER_SEND Send;
  SMART_CARD_READER_RECEIVE Receive;
  SMART_CARD_READER_SEND_TPDU SendTpdu;
//  SMART_CARD_READER_LOCK Lock;
//  SMART_CARD_READER_UNLOCK Unlock;
};

//

typedef struct _SMART_CARD_PROTOCOL SMART_CARD_PROTOCOL;

typedef enum {
  LocalRightsNone = 0,
  LocalRights0 = 0x83,
  LocalRights1 = 0x84,
  LocalRights2 = 0x85,
  LocalRights3 = 0x86,
  LocalRights4 = 0x87,
  LocalRights5 = 0x88,
  LocalRights6 = 0x89,
  LocalRights7 = 0x8A,
  LocalRights8 = 0x8B,
  LocalRights9 = 0x8C,
  LocalRightsA = 0x8D,
  LocalRightsB = 0x8E,
  LocalRightsC = 0x8F,
  LocalRightsD = 0x90,
  LocalRightsE = 0x91,
  LocalRightsF = 0x92,
  LocalRights10 = 0x93,
  LocalRights11 = 0x94,
  LocalRights12 = 0x95,
  LocalRights13 = 0x96,
  LocalRights14 = 0x97,
  LocalRights15 = 0x98,
  LocalRights16 = 0x99,
  LocalRights17 = 0x9A,
  LocalRights18 = 0x9B,
  LocalRights19 = 0x9C,
  LocalRights1A = 0x9D,
  LocalRights1B = 0x9E,
  LocalRights1C = 0x9F
} LOCAL_RIGHTS;

typedef enum {
  ScCredentialByCHV,
  ScCredentialAdministrator,
  ScCredentialUser,
  ScCredentialLocal
} PIN_USER;

typedef enum {
  ScResetAll,
  ScResetAdministrator,
  ScResetUser,
  ScResetLocal
} RESET_USER;

typedef enum {
  TssFullyFunctional,
  TssFormatIncomplete,
  TssNotInited,
  TssJustPreinited,
  TssNewOrBroken,
  TssOutOfUse
} TOKEN_SYSTEM_STATUS;

typedef enum {
  RUTOKEN_ECP = 0x01
} TOKEN_TYPE;

typedef struct {
#if defined __GNUC__
#if __BYTE_ORDER == __LITTLE_ENDIAN
  UINT8 Minor:4;
  UINT8 Major:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  UINT8 Major:4;
  UINT8 Minor:4;
#else
#error "Please fix <bits/endian.h>"
#endif
#elif defined _MSC_VER
  UINT8 Minor:4;
  UINT8 Major:4;
#else
/* FIXME: Endian-aware code for non-GCC compilers is to be placed here */
//#error "Endian-aware code is needed in TOKEN_VERSION for this compiler"
  UINT8 Minor:4;
  UINT8 Major:4;
#endif

} TOKEN_HW_VERSION;

typedef struct {
  UINT8 Major;
  UINT8 Minor;
} TOKEN_OS_VERSION;

typedef struct {
  UINT8            Type;
  TOKEN_HW_VERSION HwVer;
  UINT8            FileMemory;
  UINT8            ProtoNum;
  UINT8            FirmwareNum;
  UINT8            OrderNum;
  UINT8            Flags;
  TOKEN_OS_VERSION OSVer;
  UINT8            Reserved[3];
} TOKEN_IDENTIFYING_DATA;

enum { PATH_MAX_LEN  = 16,           /* Path maximal length (select file)    */
       TRANS_MAX_LEN = (1 << 8) - 1, /* Single transmission maximal length   */
       TRANS_ARB_LEN = (1 << 8),     /* Single transmission arbitrary length */
       MAX_OFFSET    = (1 << 15) - 1 /* Maximal offset value (read binary)   */
};

/* Smart card Low-level native API types */

typedef EFI_STATUS (EFIAPI *SMART_CARD_LOCK) (
  IN SMART_CARD_PROTOCOL *This
  );

typedef EFI_STATUS (EFIAPI* SMART_CARD_RESET) (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8           *AtrString,
  IN UINT16              Length
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_VERIFY) (
  IN SMART_CARD_PROTOCOL *This,
  IN PIN_USER            UserId,
  IN LOCAL_RIGHTS        LocalRights,
  IN UINT8               *PinCode,
  IN UINTN               PinCodeLen,
  OUT UINTN              *RetryLeft
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_RESET_ACCESS_RIGHTS) (
  IN SMART_CARD_PROTOCOL *This,
  IN RESET_USER          UserId,
  IN LOCAL_RIGHTS        Rights
  );

typedef EFI_STATUS (EFIAPI* SMART_CARD_DIAGNOSE) (
  IN SMART_CARD_PROTOCOL *This
  );

/* Cryptoki-specific higher-level-API types */

typedef EFI_STATUS (EFIAPI *SMART_CARD_TOKEN_SYSTEM_STATUS) (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT TOKEN_SYSTEM_STATUS *Status
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_TOKEN_IDENTIFYING_DATA) (
  IN     SMART_CARD_PROTOCOL    *This,
  IN OUT TOKEN_IDENTIFYING_DATA *Data
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_LOGIN) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN              Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_LOGOUT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN              Admin
  );

typedef enum {
  TEST_H,
  CRYPTO_PRO_H
} GOSTR3411_PARAM_SET;

typedef EFI_STATUS (EFIAPI *SMART_CARD_DIGEST_INIT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet,
  IN     UINT8              workmode
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_DIGEST) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_SELECT_FILE_BY_PATH) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_READ_BINARY) (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_WRITE_BINARY) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_CREATE_FILE) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_DECRYPT_INIT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               RSFRef,
  IN     UINT8              workmode
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_DECRYPT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Cipher,
  IN OUT UINTN               *CipherLen
  );

typedef enum {
  TEST_C,
  CRYPTO_PRO_A,
  CRYPTO_PRO_B,
  CRYPTO_PRO_C
} GOSTR3410_PARAM_SET;

typedef EFI_STATUS (EFIAPI *SMART_CARD_VERIFY_SIGNATURE_INIT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8              workmode
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_VERIFY_SIGNATURE) (
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

typedef EFI_STATUS (EFIAPI *SMART_CARD_EJECT_NOTIFY) (
  IN     SMART_CARD_PROTOCOL *This
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_GET_OBJECT_VAL_BY_ID) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *Id,
  IN     UINTN IdLen,
  OUT    UINT8 **ObjData,
  OUT    UINTN *ObjDataLen
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_GET_OBJECTS_LIST) (
  IN     SMART_CARD_PROTOCOL *This,
  OUT    UINT8 **ObjListData,
  OUT    UINTN *ObjListDataLen
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_GET_SN) (
  IN     SMART_CARD_PROTOCOL *This
  );

typedef enum {
  TX_PROTO_T0,
  TX_PROTO_T1,
  TX_PROTO_RAW
} TX_PROTO;

typedef EFI_STATUS (EFIAPI *SMART_CARD_TRANSMIT) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *TxBuffer,
  IN     UINTN TxBufferLen,
  IN OUT UINT8 *RxBuffer,
  IN OUT UINTN *RxBufferLen,
  IN     TX_PROTO TxProto
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_ECP_INIT) (
  IN     SMART_CARD_PROTOCOL *This
  );

typedef EFI_STATUS (EFIAPI *SMART_CARD_ECP) (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  );


/* Smart card protocol */
struct _SMART_CARD_PROTOCOL {
  /* Smart card Low-level native API */
  SMART_CARD_LOCK                Lock;
  SMART_CARD_RESET               Reset;
  SMART_CARD_VERIFY              Verify;
  SMART_CARD_RESET_ACCESS_RIGHTS ResetAccessRights;
  SMART_CARD_DIAGNOSE            Diagnose;

  SMART_CARD_TRANSMIT            ScTransmit;

  /* Cryptoki-specific higher-level-API using native one (above) */
  SMART_CARD_TOKEN_SYSTEM_STATUS    TokenSystemStatus;
  SMART_CARD_TOKEN_IDENTIFYING_DATA TokenIdentifyingData;
  SMART_CARD_LOGIN                  Login;
  SMART_CARD_LOGOUT                 Logout;
  SMART_CARD_DIGEST_INIT            DigestInit;
  SMART_CARD_DIGEST                 Digest;
  SMART_CARD_SELECT_FILE_BY_PATH    SelectFileByPath;
  SMART_CARD_READ_BINARY            ReadBinary;
  SMART_CARD_WRITE_BINARY           WriteBinary;
  SMART_CARD_CREATE_FILE            CreateFile;
  SMART_CARD_DECRYPT_INIT           DecryptInit;
  SMART_CARD_DECRYPT                Decrypt;
  SMART_CARD_VERIFY_SIGNATURE_INIT  VerifySignatureInit;
  SMART_CARD_VERIFY_SIGNATURE       VerifySignature;
  SMART_CARD_ECP_INIT               EcpInit;
  SMART_CARD_ECP                    Ecp;
  SMART_CARD_GET_SN                 GetSn;

  /* smartcard eject notify */
  SMART_CARD_EJECT_NOTIFY           EjectNotify;
  VOID                              *EjectNotifyContext;
  SMART_CARD_GET_OBJECT_VAL_BY_ID   GetObjectValById;
  SMART_CARD_GET_OBJECTS_LIST       GetObjectsList;
  /* smartcard device path */
  EFI_DEVICE_PATH_PROTOCOL          *DevicePath;
  /*  */
  UINT16                            VendorId;
  UINT16                            ProdId;
  UINT16                            WorkingCertId;
  UINT32                            FwVersion;
  UINT8                             WorkMode;
  CHAR8                             SerialNumberStr8[20];
  UINT8                             *Atr;
  UINTN                             AtrLen;
  UINT8                             RSFRef;
  VOID                              *CurContext;
  UINTN                             CurContextLen;
};

typedef struct _USB_CCID_DEV USB_CCID_DEV;

EFI_STATUS
SmartCardInstallProtocol(
  IN OUT EFI_HANDLE* Controller,
  IN USB_CCID_DEV *Device
  );

#endif
