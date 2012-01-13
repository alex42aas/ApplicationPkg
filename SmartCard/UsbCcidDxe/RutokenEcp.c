/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/DebugLib.h>
#include "RutokenEcp.h"
#include "SmartCard.h"
#include <Protocol/PciIo.h>

#define DUMP_APDU(X)

/* Properties of the GOST 34.10-2001 algorithm parameters */
enum {
  GOSTR3410_HASH_LEN      = 32,
  GOSTR3410_SIGN_LEN      = 64,
  GOSTR3410_KEY_LEN       = 64,
  GOSTR3410_PARAM_SET_LEN = 1
};


CARD_PROTO proto = ProtoT1;

VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  )
{
  UINTN i;

  for (i = 0; i < Len; i++) {
    if (i && !(i & 0xF)) {
      DEBUG(( EFI_D_INFO, "\n"));
    }
    DEBUG(( EFI_D_INFO, "%02x ", Bytes[i]));
  }
  DEBUG(( EFI_D_INFO, "\n"));
};


VOID
DumpApduEx (
  IN     CHAR16 CONST *Func,
  IN     UINTN        Line,
  IN     APDU CONST   *Apdu
  )
{
  if (Apdu != NULL) {
    DEBUG ((EFI_D_ERROR,
      "%s(): line %d: Apdu:\nType: %d Class: 0x%02X Ins: 0x%02X P1: 0x%02X P2: 0x%02X \n",
      Func,
      Line,
      Apdu->Type,
      Apdu->Cla,
      Apdu->Ins,
      Apdu->P1,
      Apdu->P2
      ));

    DEBUG ((EFI_D_ERROR,
      "Data: %p DL: %lld Lc: %d RData: %p RLen: %lld Le: %d\n",
      Apdu->Data,
      Apdu->DataLen,
      Apdu->Lc,
      Apdu->ResponseData,
      Apdu->ResponseLen,
      Apdu->Le
      ));
    DEBUG ((EFI_D_ERROR, "OutBufferLen: %d\n", ApduLength (Apdu, proto)));
    DEBUG ((EFI_D_ERROR, "ResBufferLen: %d\n", Apdu->Le + 2));
  }
}

EFI_STATUS
SmartCardInstallProtocol (
  IN OUT EFI_HANDLE   *Controller,
  IN     USB_CCID_DEV *Device
  )
{
  /* Smart card low-level native API */
  Device->SmartCard.Lock                 = &RutokenNsdLock;
  Device->SmartCard.Reset                = &RutokenReset;
  Device->SmartCard.Verify               = &RutokenVerify;
  Device->SmartCard.ResetAccessRights    = &RutokenResetAccessRights;
  Device->SmartCard.Diagnose             = &RutokenDiagnoseCard;
  Device->SmartCard.ScTransmit           = &ScTransmit;

  /* Cryptoki-specific higher-level-API */
  Device->SmartCard.TokenSystemStatus    = &RutokenTokenSystemStatus;
  Device->SmartCard.TokenIdentifyingData = &RutokenTokenIdentifyingData;
  Device->SmartCard.Login                = &RutokenLogin;
  Device->SmartCard.Logout               = &RutokenLogout;
  Device->SmartCard.DigestInit           = &RutokenDigestInit;
  Device->SmartCard.Digest               = &RutokenDigest;
  Device->SmartCard.SelectFileByPath     = &RutokenSelectFileByPath;
  Device->SmartCard.ReadBinary           = &RutokenReadBinary;
  Device->SmartCard.CreateFile           = &RutokenCreateFile;
  Device->SmartCard.WriteBinary          = &RutokenWriteBinary;
  Device->SmartCard.DecryptInit          = &RutokenDecryptInit;
  Device->SmartCard.Decrypt              = &RutokenDecrypt;
  Device->SmartCard.VerifySignatureInit  = &RutokenVerifySignatureInit;
  Device->SmartCard.VerifySignature      = &RutokenVerifySignature;
  Device->SmartCard.DevicePath           = Device->DevicePath;
  Device->SmartCard.GetSn                = &RutokenGetSN;
  Device->SmartCard.GetObjectsList       = &RutokenGetObjectList;
  Device->SmartCard.GetObjectValById     = &RutokenGetObjectValById;
  Device->SmartCard.EcpInit              = &RutokenEcpInit;
  Device->SmartCard.Ecp                  = &RutokenEcp;
  Device->SmartCard.RSFRef               = 0xFF; // non init
  //if (Device->SmartCard.WorkMode == ETOKEN_MODE_GOST_2001)

  return gBS->InstallMultipleProtocolInterfaces (
                Controller,
                &gSmartCardProtocolGuid,
                &Device->SmartCard,
                NULL
                );
}

static inline void emit (CHAR16 const *s) { DEBUG ((EFI_D_ERROR, "%s\n", s)); }

EFI_STATUS
SmartCardTransmit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     APDU                *Apdu
  )
{
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;

  UINT8 *Buffer;
  UINTN BufferLen;
  UINT8 *ResBuffer;
  UINTN ResBufferLen;

  Buffer    = NULL;
  ResBuffer = NULL;

  if (Apdu == NULL || This == NULL) {
    EFI_ERROR_REALRET (EFI_INVALID_PARAMETER, "");
  }

  DUMP_APDU (Apdu);

  Device = CR (This, USB_CCID_DEV, SmartCard, USB_CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  BufferLen = ApduLength (Apdu, proto);
  ResBufferLen = Apdu->Le + 2;

  if (BufferLen == 0) {
    EFI_ERROR_REALRET (EFI_INVALID_PARAMETER, "");
  }

  if ((Buffer = AllocateZeroPool(BufferLen)) == NULL) {
    EFI_ERROR_REALRET (EFI_OUT_OF_RESOURCES, "");
  }

  if ((ResBuffer = AllocateZeroPool (ResBufferLen)) == NULL) {
    FreePool (Buffer);
    EFI_ERROR_REALRET (EFI_OUT_OF_RESOURCES, "");
  }

  Status = Apdu2Buffer (
             Apdu,
             proto,
             Buffer,
             &BufferLen
             );

  EFI_ERROR_RET (Status, "");

  Status = Reader->Transmit (
                     Reader,
                     Buffer,
                     BufferLen,
                     ResBuffer,
                     &ResBufferLen,
                     0
                     );

  EFI_ERROR_RET (Status, "");

  if (Apdu->ResponseData != NULL) {
    UINT16 CopyLen;
    CopyLen = Apdu->Le > (UINT16)(ResBufferLen - 2) ? 
      (UINT16)(ResBufferLen - 2) : Apdu->Le;
    CopyMem (Apdu->ResponseData, ResBuffer, CopyLen);
  }

  Apdu->u.s.Sw1 = ResBuffer[ResBufferLen - 2];
  Apdu->u.s.Sw2 = ResBuffer[ResBufferLen - 1];

  DEBUG((EFI_D_ERROR, "SW1:SW2 = %02X:%02X\n", Apdu->u.s.Sw1, Apdu->u.s.Sw2));
  FreePool (ResBuffer);
  FreePool (Buffer);

  return Status;

OnError:
  FreePool (ResBuffer);
  FreePool (Buffer);

  Apdu->Le = 0;

  return Status;
}

#pragma pack(1)
typedef struct _SMM_INFO_AREA {
  UINT32 Port:8;
  UINT32 ControllerType:2;
  UINT32 Reserved0:21;
  UINT32 OnFlag:1;
  UINT32 Reserved1:8; // Register 00-07
  UINT32 Function:3;  // Function 08-10
  UINT32 Device:5;    // Device   11-15
  UINT32 Bus:8;       // Bus      16-23
  UINT32 Reserved2:8;
} SMM_INFO_AREA;
#pragma pack()

VOID
OhciSMIEnable (
  EFI_PCI_IO_PROTOCOL *PciIo
  )
{
#define OHCI_BAR_INDEX     0
#define OHCI_IR            (1<<8)
#define HcControl          0x4

  UINT32      Data;
  EFI_STATUS  Status;

  Status = PciIo->Mem.Read (
                        PciIo,
                        EfiPciIoWidthUint32,
                        OHCI_BAR_INDEX,
                        HcControl,
                        1,
                        &Data
                        );
  Data |= OHCI_IR;

  Status = PciIo->Mem.Write (
                        PciIo,
                        EfiPciIoWidthUint32,
                        OHCI_BAR_INDEX,
                        HcControl,
                        1,
                        &Data
                        );

#undef OHCI_BAR_INDEX
#undef OHCI_IR
#undef HcControl
}

/**
  Get the HC USB's  PCI location

**/
EFI_STATUS
SetUsbPortInfoArea (
  USB_CCID_DEV* CcidDev,
  SMM_INFO_AREA *InfoArea
  )
{
  EFI_STATUS                Status;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  EFI_HANDLE                PciIoHandle;
  //EFI_HANDLE                UsbIoHandle;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  USB_DEVICE_PATH           *UsbPath;
  UINTN                    Segment;
  UINTN                    Bus;
  UINTN                    Device;
  UINTN                    Function;
  UINTN                    PortNumber;

  Segment = Bus = Device = Function = PortNumber = 0;

  Status = gBS->HandleProtocol (
                  CcidDev->hController,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **)&DevicePath
                  );

  EFI_ERROR_RET(Status, "");


  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &DevicePath,
                  &PciIoHandle
                  );

  EFI_ERROR_RET(Status, "");

  Status = gBS->HandleProtocol (PciIoHandle, &gEfiPciIoProtocolGuid, (VOID **)&PciIo);

  EFI_ERROR_RET(Status, "");

  Status = PciIo->GetLocation (PciIo, &Segment, &Bus, &Device, &Function);

  EFI_ERROR_RET(Status, "");

  while( DevicePath->SubType != END_ENTIRE_DEVICE_PATH_SUBTYPE ) {

    DEBUG((EFI_D_ERROR,
      "Device path type:%x subtype:%x\n",
      DevicePath->Type, DevicePath->SubType
      ));

    if (DevicePath->SubType == MSG_USB_DP) {
      UsbPath = (USB_DEVICE_PATH*) DevicePath;
      PortNumber = UsbPath->ParentPortNumber;
      break;
    }

    DevicePath = (EFI_DEVICE_PATH_PROTOCOL*)(((UINT8*)DevicePath) + *(UINT16*)DevicePath->Length);
  }

  DEBUG((EFI_D_ERROR,
    "%s Bus:%x Device:%x Function:%x Port:%x\n",
    L"SetUsbPortInfoArea",
    Bus,
    Device,
    Function,
    PortNumber
    ));

  ZeroMem (InfoArea, sizeof(SMM_INFO_AREA) );
  InfoArea->Bus = (UINT32)Bus;
  InfoArea->Device = (UINT32) Device;
  InfoArea->Function = (UINT32) Function;
  InfoArea->Port = (UINT32) PortNumber;
  InfoArea->OnFlag = 1;
  InfoArea->ControllerType = 1; // XXX OHCI
  CcidDev->Locked = TRUE;

///
// (EFIAPI *EFI_USB_IO_CONTROL_TRANSFER) (
//  IN EFI_USB_IO_PROTOCOL                        * This,
//  IN EFI_USB_DEVICE_REQUEST                     * Request,
//  IN EFI_USB_DATA_DIRECTION                     Direction,
//  IN UINT32                                     Timeout,
//  IN OUT VOID                                   *Data OPTIONAL,
//  IN UINTN                                      DataLength  OPTIONAL,
//  OUT UINT32                                    *Status
//  );
  {
    EFI_USB_DEVICE_REQUEST Request;
    UINT32                 UsbStatus;

    Request.RequestType = USB_REQ_TYPE_VENDOR;

    DEBUG((EFI_D_ERROR, "%a.%d --> UsbControlTransfer\n", __FUNCTION__, __LINE__));
    CcidDev->UsbIo->UsbControlTransfer (
                      CcidDev->UsbIo,
                      &Request,
                      EfiUsbDataOut,
                      0,
                      NULL,
                      0,
                      &UsbStatus
                      );
  }

  OhciSMIEnable(PciIo);
  return EFI_SUCCESS;

OnError:
  return Status;
}

// volatile UINT32 *gsmi_nsd_flags;
SMM_INFO_AREA *gSmmInfoArea;

/* Smart card low-level native API */

EFI_STATUS
RutokenNsdLock(
  IN SMART_CARD_PROTOCOL *This
  )
{
  USB_CCID_DEV *Device;
  EFI_STATUS   Status;

  Device = CR (This, USB_CCID_DEV, SmartCard, USB_CCID_DEV_SIGNATURE);

  ASSERT (Device != NULL);

  gSmmInfoArea = (SMM_INFO_AREA*)(UINTN)(0xD0000 + 0x400 * 2); // XXX 2 Cores

  Status = SetUsbPortInfoArea (Device,(SMM_INFO_AREA*) gSmmInfoArea);

#if 0
  gSmmInfoArea->Port = Device->DevicePath.ParentPortNumber;
  gSmmInfoArea->ControllerType = CONTROLER_TYPE_OHCI; // XXX Ohci controller
  gSmmInfoArea->Function = gUserInfo[Index].UsbDevicePath.PciBusDevicePath.Function;
  gSmmInfoArea->Device = gUserInfo[Index].UsbDevicePath.PciBusDevicePath.Device;
  gSmmInfoArea->OnFlag = 1;
#endif

  return Status;
}

EFI_STATUS
RutokenReset (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *AtrString,
  IN     UINT16              Length
  )
{

  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  ApduBuild (&Apdu, APDU_TYPE_2_SHORT, APDU_CLASS_INIT_RESET, APDU_RESET, 0, 0);
  ApduSetResData (&Apdu, AtrString, Length);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG((EFI_D_ERROR, "RutokenReset: Error: 0x%04X\n", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  )
{
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  UINT8      P2 =
#ifdef _MSC_VER
  (UINT8)
#endif /* _MSC_VER */
  (UserId == ScCredentialLocal ? Rights : UserId);

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (PinCode == NULL || PinCodeLen == 0) {
    EFI_ERROR_REALRET (EFI_INVALID_PARAMETER, "");
  }

  ApduBuild (&Apdu, APDU_TYPE_1, APDU_CLASS_NORMAL, APDU_VERIFY_PIN, 0, P2);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  /* If already is logged in, then first reset access rights */
  if (Apdu.u.Status == SC_SUCCESS) {
    CHECKED_CALL (RutokenResetAccessRights, (This, UserId, Rights));
  }

  ApduBuild (&Apdu, APDU_TYPE_3_SHORT, APDU_CLASS_NORMAL, APDU_VERIFY_PIN, 0, P2);
  ApduSetData (&Apdu, PinCode, (UINT16) PinCodeLen);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  switch (Apdu.u.Status & 0xff00) {
  case SC_SUCCESS:
    break;
  case SC_AUTH_FAILED:
    if (TriesLeft != NULL) {
      ApduBuild (&Apdu, APDU_TYPE_1, APDU_CLASS_NORMAL, APDU_VERIFY_PIN, 0, P2);
      CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

      switch (Apdu.u.Status & 0xff00) {
        case SC_SUCCESS:
          break;
        case SC_AUTH_FAILED:
          *TriesLeft = Apdu.u.Status & 0x0f;
          return EFI_ACCESS_DENIED;
        default:
          return EFI_ACCESS_DENIED;
      }
    }

    break;
  default:
    return EFI_ACCESS_DENIED;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
RutokenResetAccessRights (
  IN     SMART_CARD_PROTOCOL *This,
  IN     RESET_USER          UserId,
  IN     LOCAL_RIGHTS        Rights
  )
{
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  ApduBuild (
    &Apdu,
    APDU_TYPE_1,
    APDU_CLASS_INIT_RESET,
    APDU_RESET_ACCESS_RIGHTS,
    0,
#ifdef _MSC_VER
    (UINT8)
#endif /* _MSC_VER */
    (UserId == ScResetLocal ? Rights : UserId)
    );

  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenResetAccessRights", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenDiagnoseCard (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Result[4];

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  ApduBuild (&Apdu,
             APDU_TYPE_2_SHORT,
             APDU_CLASS_INIT_RESET,
             APDU_DIAGNOSE_CARD,
             DiagnoseOS,
             0
             );

  ApduSetResData (&Apdu, Result, sizeof(Result));
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "DiagnoseOS: 0x%04X\n", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  ApduBuild (&Apdu,
             APDU_TYPE_2_SHORT,
             APDU_CLASS_INIT_RESET,
             APDU_DIAGNOSE_CARD,
             DiagnoseGOST28147_89,
             0
             );

  ApduSetResData (&Apdu, Result, sizeof(Result));
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "DiagnoseGOST28147_89: 0x%04X\n", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  ApduBuild (&Apdu,
             APDU_TYPE_2_SHORT,
             APDU_CLASS_INIT_RESET,
             APDU_DIAGNOSE_CARD,
             DiagnoseGOST3410_2001,
             0
             );

  ApduSetResData (&Apdu, Result, sizeof(Result));
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "DiagnoseGOST3410_2001: 0x%04X\n", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  ApduBuild (&Apdu,
             APDU_TYPE_2_SHORT,
             APDU_CLASS_INIT_RESET,
             APDU_DIAGNOSE_CARD,
             DiagnoseGOST3411_94,
             0
             );

  ApduSetResData (&Apdu, Result, sizeof(Result));
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "DiagnoseGOST3411_94: 0x%04X\n", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

/* Cryptoki-specific higher-level API */

EFI_STATUS
RutokenTokenSystemStatus (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT TOKEN_SYSTEM_STATUS *Status
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Res[4];

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  ApduBuild (
    &Apdu,
    APDU_TYPE_2_SHORT,
    APDU_CLASS_NORMAL,
    APDU_GET_DATA,
    APDU_OWN_DATA_BLOCK,
    APDU_ODB_TOKEN_SYSTEM_STATUS
    );

  ApduSetResData (&Apdu, &Res[0], sizeof Res);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenTokenSystemStatus", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  /* Compute returned value in endian-independent manner */
  switch (Res[0] << 24 | Res[1] << 16 | Res[2] << 8 | Res[3]) {
  case 0x32560E49:
    *Status = TssNewOrBroken;
    break;
  case 0x790F83A1:
    *Status = TssJustPreinited;
    break;
  case 0x907E0147:
    *Status = TssOutOfUse;
    break;
  default:
    switch (Res[0]) {
    case 0x19:
      switch (Res[1]) {
      case 0xA8:
        *Status = TssFormatIncomplete;
        break;
      case 0xAC:
        *Status = TssFullyFunctional;
        break;
      default:
        *Status = TssJustPreinited;
        break;
      }

      break;
    default:
      *Status = TssNotInited;
      break;
    }

    break;
  }

  return EFI_SUCCESS;
}

EFI_STATUS RutokenTokenIdentifyingData (
  IN     SMART_CARD_PROTOCOL    *This,
  IN OUT TOKEN_IDENTIFYING_DATA *Data
  )
{
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  ApduBuild (
    &Apdu,
    APDU_TYPE_2_SHORT,
    APDU_CLASS_NORMAL,
    APDU_GET_DATA,
    APDU_OWN_DATA_BLOCK,
    APDU_ODB_TOKEN_IDENTIFICATION_DATA
    );

  ApduSetResData (&Apdu, Data, sizeof *Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenTokenIdentifyingData", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  )
{
  UINTN TriesLeft;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return RutokenVerify (
           This,
           Admin ? ScCredentialAdministrator : ScCredentialUser,
           LocalRightsNone,
           Pin,
           PinLen,
           &TriesLeft
           );
}

EFI_STATUS
RutokenLogout (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return RutokenResetAccessRights (
           This,
           Admin ? ScResetAdministrator : ScResetUser,
           LocalRightsNone
           );
}

EFI_STATUS
RutokenDigestInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet,
  IN     UINT8              workmode
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Data[8] /*= {
    APDU_TLV_TAG_USAGE_QUALIFIER, 1, APDU_USAGE_QUALIFIER_HASH,
    APDU_TLV_TAG_SBOX_TABLE_INDEX, 1, Default ? CRYPTO_PRO_H : CRYPTO_TEST,
    APDU_TLV_TAG_SYNCHRO_MSG,
    (&Data[sizeof Data / sizeof *Data] - &Data[8]) * sizeof *Data
  } */;
  UINT8 SIZE  = sizeof Data;
  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  Data[0] = APDU_TLV_TAG_USAGE_QUALIFIER;
  Data[1] = 1;
  Data[2] = APDU_USAGE_QUALIFIER_HASH;
  Data[3] = APDU_TLV_TAG_SBOX_TABLE_INDEX;
  Data[4] = 1;
  Data[5] = ParamSet == TEST_H ? CRYPTO_TEST_H_CODE : CRYPTO_PRO_H_CODE;
  Data[6] = APDU_TLV_TAG_GOSTR3410_PARAM_SET;
  Data[7] = 1;
  Data[8] = 0x20;
  if(workmode!= 2)//gost-2012
	SIZE -= 3;
	
/*  Data[6] = APDU_TLV_TAG_SYNCHRO_MSG;
  Data[7] = (UINT8)((&Data[sizeof Data / sizeof *Data] - &Data[8]) * sizeof *Data);
  SetMem (&Data[8], Data[7], 0); 
*/
  if (This == NULL || (ParamSet != TEST_H && ParamSet != CRYPTO_PRO_H)) {
    return EFI_INVALID_PARAMETER;
  }

  ApduBuild (
    &Apdu,
    APDU_TYPE_3_SHORT,
    APDU_CLASS_NORMAL,
    APDU_MANAGE_SECURITY_ENVIRONMENT,
    APDU_MSE_SET_41,
    APDU_CRT_TAG_AA
    );

  ApduSetData (&Apdu, Data, sizeof Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDigestInit", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenDigest (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest /* Assumed not less than 32 bytes long */
  )
{
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This == NULL || (Data == NULL && Len > 0)) {
    return EFI_INVALID_PARAMETER;
  }

  /* Zero length data are processed only if Digest storage is specified */
  if (Len == 0 && Digest == NULL) {
    return EFI_SUCCESS;
  }

  /* Consume such amount of data that remaining amount
     is not more than TRANS_MAX_LEN */
  for (; Len > TRANS_MAX_LEN; Len -= TRANS_MAX_LEN) {
    ApduBuild (
      &Apdu,
      APDU_TYPE_3_SHORT,
      APDU_CLASS_INCOMPLETE,
      APDU_PERFORM_SECURITY_OPERATION,
      APDU_DATA_TYPE_HASH, /* Output data type */
      APDU_DATA_TYPE_PLAIN /* Input data type  */
      );

    ApduSetData (&Apdu, Data, TRANS_MAX_LEN);
    CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

    if (Apdu.u.Status != SC_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDigest", Apdu.u.Status));
      EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
    }

    Data += TRANS_MAX_LEN;
  }

  /* OK, we have now here from 1 to TRANS_MAX_LEN bytes of data to hash */

  /* Do not finalize the hash cmd if Digest is NULL and finalize it otherwise */
  ApduBuild (
    &Apdu,
    Digest != NULL ? APDU_TYPE_4_SHORT : APDU_TYPE_3_SHORT,
    Digest != NULL ? APDU_CLASS_NORMAL : APDU_CLASS_INCOMPLETE,
    APDU_PERFORM_SECURITY_OPERATION,
    APDU_DATA_TYPE_HASH, /* Output data type */
    APDU_DATA_TYPE_PLAIN /* Input data type  */
    );

  ApduSetData (&Apdu, Data, (UINT16)Len /* Because here Len <= TRANS_MAX_LEN */);

  if (Digest != NULL) {
    ApduSetResData (&Apdu, Digest, 32);
  }

  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDigest", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}
 
EFI_STATUS
RutokenSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  )
{ 
  
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This == NULL || Path == NULL || PathLen == 0 || PathLen > PATH_MAX_LEN ||
      Data == NULL || Len == NULL  || *Len < TRANS_MAX_LEN) {
    return EFI_INVALID_PARAMETER;
  }

  ApduBuild (
    &Apdu,
    APDU_TYPE_4_SHORT,
    APDU_CLASS_NORMAL,
    APDU_SELECT_FILE,
    AbsPath ? APDU_SEL_BY_PATH_FROM_MF : APDU_SEL_BY_PATH_FROM_CURRENT_DF,
    0
    );

  ApduSetData (&Apdu, Path, (UINT16)PathLen /* Because here PathLen <= PATH_MAX_LEN */);
  ApduSetResData (&Apdu, Data, TRANS_ARB_LEN);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenSelectFileByPath", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  *Len = Apdu.ResponseLen;
  return EFI_SUCCESS;
}

EFI_STATUS
RutokenWriteBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  )
{ 
  unsigned char len1 = 0;
  unsigned char len2 =0;
  unsigned short total = 0;
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;
  if (This == NULL || Len == 0 || Data == NULL) {
	  return EFI_INVALID_PARAMETER;
  }
  while(1){
	  DEBUG ((EFI_D_ERROR, "LEN==%X\n",Len));
	  ApduBuild (
		&Apdu,
		APDU_TYPE_4_SHORT,
		APDU_CLASS_NORMAL,
		APDU_WRITE_BINARY,
		len1,
		len2
		);
	if(Len>=0xff)
		ApduSetData (&Apdu, Data,(UINT16)0xFF);
	else
		ApduSetData (&Apdu, Data,(UINT16)Len);

	CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

	if (Apdu.u.Status != SC_SUCCESS) {
		DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenWriteBinary", Apdu.u.Status));
		EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
	}

	total +=0xff;
	len1=(total>>8);
	len2=(unsigned char)total;
	Data+=0xff;
	if(Len>=0xff)	
		Len-=0xFF;
	else
		break;
  }

  return EFI_SUCCESS;
}



EFI_STATUS
RutokenReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  )
{
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This == NULL || Data == NULL || Len == 0 ||
      Off + Len > MAX_OFFSET + TRANS_MAX_LEN) {
    return EFI_INVALID_PARAMETER;
  }

  while (Len > TRANS_MAX_LEN) {
    ApduBuild (
      &Apdu,
      APDU_TYPE_2_SHORT,
      APDU_CLASS_INCOMPLETE,
      APDU_READ_BINARY,
      (UINT8)(Off / 256),
      (UINT8)(Off % 256)
      );

    ApduSetResData (&Apdu, Data + Off, TRANS_MAX_LEN);
    CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

    Off  += TRANS_MAX_LEN;
    Len  -= TRANS_MAX_LEN;
  }

  ApduBuild (
    &Apdu,
    APDU_TYPE_2_SHORT,
    APDU_CLASS_NORMAL,
    APDU_READ_BINARY,
    (UINT8)(Off / 256),
    (UINT8)(Off % 256)
    );

  ApduSetResData (&Apdu, Data + Off, (UINT16)Len /* Because here Len <= TRANS_MAX_LEN */);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenReadBinary", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenCreateFile (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len
  )
{ 
  APDU Apdu /*= { APDU_TYPE_NONE }*/;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;
  if (This == NULL || Len == 0 || Data == NULL) {
	  return EFI_INVALID_PARAMETER;
  }

	ApduBuild (
		&Apdu,
		APDU_TYPE_4_SHORT,
		APDU_CLASS_NORMAL,
		APDU_CREATE_FILE,
		0,
		0
		);

	ApduSetData (&Apdu, Data,(UINT16)Len);

	CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

	if (Apdu.u.Status != SC_SUCCESS && Apdu.u.Status != SC_FILE_EXIST) {
		DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenCreateFile", Apdu.u.Status));
		EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
	}

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenDecryptInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               RSFRef,
  IN     UINT8              workmode
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/; 
  UINT8 Data[] = {
    APDU_TLV_TAG_USAGE_QUALIFIER, 1, APDU_USAGE_QUALIFIER_DECIPHER,
    APDU_TLV_TAG_AKEY_RSF_REFERENCE, 1, /* RSFRef */ 0,
	APDU_TLV_TAG_GOSTR3410_PARAM_SET, 1, /*GOST */ 0
  };
  UINT8 SIZE  = sizeof Data;
  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  /* It is because of the Microsoft C89 antique compiler */
  Data[5] = RSFRef;//2
  
  if(workmode == 2)//gost-2012
	Data[8] = 0x20;
  else
	SIZE -= 3;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ApduBuild (
    &Apdu,
    APDU_TYPE_3_SHORT,
    APDU_CLASS_NORMAL,
    APDU_MANAGE_SECURITY_ENVIRONMENT,
    APDU_MSE_SET_41,
    APDU_CRT_TAG_B8
    );

  ApduSetData (&Apdu, Data, sizeof Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDecryptInit", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenDecrypt (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Cipher,
  IN OUT UINTN               *CipherLen
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINTN L;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This   == NULL || Data      == NULL || Len              == 0 ||
      Cipher == NULL || CipherLen == NULL || (L = *CipherLen) == 0) {
    return EFI_INVALID_PARAMETER;
  }

  /* Consume such amount of data that remaining amount
     is not more than TRANS_MAX_LEN */
  for (; Len > TRANS_MAX_LEN; Len -= TRANS_MAX_LEN) {
    ApduBuild (
      &Apdu,
      APDU_TYPE_3_SHORT,
      APDU_CLASS_INCOMPLETE,
      APDU_PERFORM_SECURITY_OPERATION,
      APDU_DATA_TYPE_PLAIN, /* Output data type */
      APDU_DATA_TYPE_CIPHER /* Input data type  */
      );

    ApduSetData (&Apdu, Data, TRANS_MAX_LEN);
    CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

    if (Apdu.u.Status != SC_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDecrypt", Apdu.u.Status));
      EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
    }

    Data += TRANS_MAX_LEN;
  }

  /* OK, we have now here from 1 to TRANS_MAX_LEN bytes of data to cipher */

  ApduBuild (
    &Apdu,
    APDU_TYPE_4_SHORT,
    APDU_CLASS_NORMAL,
    APDU_PERFORM_SECURITY_OPERATION,
    APDU_DATA_TYPE_PLAIN, /* Output data type */
    APDU_DATA_TYPE_CIPHER /* Input data type  */
    );

  ApduSetData (&Apdu, Data, (UINT16)Len /* Because here Len <= TRANS_MAX_LEN */);
  ApduSetResData (&Apdu, Cipher, (UINT16)(L < TRANS_MAX_LEN ? L : TRANS_MAX_LEN));

  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDecrypt", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  *CipherLen = Apdu.ResponseLen;
  return EFI_SUCCESS;
}
 
EFI_STATUS
RutokenVerifySignatureInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8              workmode
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Data[] = {
    APDU_TLV_TAG_USAGE_QUALIFIER, 1, APDU_USAGE_QUALIFIER_SIGN_VERIFY,
    APDU_TLV_TAG_SKEY_RSF_REFERENCE, 1, 0,
	APDU_TLV_TAG_GOSTR3410_PARAM_SET, 1, /*GOST */ 0
  };
  UINT8 SIZE  = sizeof Data;
  if(workmode == 2)//gost-2012
	Data[8] = 0x20;
  else
	SIZE -= 3;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ApduBuild (
    &Apdu,
    APDU_TYPE_3_SHORT,
    APDU_CLASS_NORMAL,
    APDU_MANAGE_SECURITY_ENVIRONMENT,
    APDU_MSE_SET_81,
    APDU_CRT_TAG_B6
    );

  ApduSetData (&Apdu, Data, sizeof Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenVerifySignatureInit", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

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
  )
{  
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Data[2 + GOSTR3410_HASH_LEN +
             2 + GOSTR3410_SIGN_LEN +
             2 + GOSTR3410_KEY_LEN  +
             2 + GOSTR3410_PARAM_SET_LEN];
  UINT8       *d = &Data[0];
  UINT8 CONST *s = Sign + SignLen;
  UINTN       U;

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  /* Only the GOST 34.10-2001 algorithm is supported */
  if (This == NULL || Success == NULL               ||
      (ParamSet != TEST_C       &&
       ParamSet != CRYPTO_PRO_A &&
       ParamSet != CRYPTO_PRO_B &&
       ParamSet != CRYPTO_PRO_C)                    ||
      Hash == NULL || HashLen != GOSTR3410_HASH_LEN ||
      Sign == NULL || SignLen != GOSTR3410_SIGN_LEN ||
      Key  == NULL || KeyLen  != GOSTR3410_KEY_LEN) {
    return EFI_INVALID_PARAMETER;
  }

  /* Filling TLV-structures */

  /* Hash value */
  *d++ = APDU_TLV_TAG_HASH_DATA;
  *d++ = GOSTR3410_HASH_LEN;
  CopyMem (d, Hash, GOSTR3410_HASH_LEN);
  d += GOSTR3410_HASH_LEN;

  /* Signature value (must be reversed for the RuToken!!!) */
  *d++ = APDU_TLV_TAG_SIGNATURE_DATA;
  *d++ = GOSTR3410_SIGN_LEN;

  /* Copy Sign manually reversing on the fly */
  for (U = 0; U < GOSTR3410_SIGN_LEN; U++)
    *d++ = *--s;

  /* Key value */
  *d++ = APDU_TLV_TAG_KEY_DATA;
  *d++ = GOSTR3410_KEY_LEN;
  CopyMem (d, Key, GOSTR3410_KEY_LEN);
  d += GOSTR3410_KEY_LEN;

  /* Parameter set code value */
  *d++ = APDU_TLV_TAG_GOSTR3410_PARAM_SET;
  *d++ = GOSTR3410_PARAM_SET_LEN;
  *d++ = ParamSet == CRYPTO_PRO_A ? CRYPTO_PRO_A_CODE :
         ParamSet == CRYPTO_PRO_B ? CRYPTO_PRO_B_CODE :
         ParamSet == CRYPTO_PRO_C ? CRYPTO_PRO_C_CODE :
                                    CRYPTO_TEST_C_CODE;

  ApduBuild (
    &Apdu,
    APDU_TYPE_3_SHORT,
    APDU_CLASS_NORMAL,
    APDU_PERFORM_SECURITY_OPERATION,
    APDU_DATA_TYPE_ABSENT,
    APDU_DATA_TYPE_DS_CHK
    );

  ApduSetData (&Apdu, Data, sizeof Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  switch (Apdu.u.Status) {
  case SC_WRONG_ECP:
    *Success = FALSE; /* Siganture verification is failed */
    break;
  case SC_SUCCESS:
    *Success = TRUE;  /* Signature verification is passed */
    break;
  default:
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenVerifySignature", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}


EFI_STATUS
RutokenGetSN (
  IN SMART_CARD_PROTOCOL *This
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS 
ScTransmit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *TxBuffer,
  IN     UINTN TxBufferLen,
  IN OUT UINT8 *RxBuffer,
  IN OUT UINTN *RxBufferLen,
  IN     TX_PROTO TxProto
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
RutokenGetObjectList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
RutokenGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
RutokenEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Data[] = {
    APDU_TLV_TAG_USAGE_QUALIFIER, 1, APDU_USAGE_QUALIFIER_SIGN_CALC,
    APDU_TLV_TAG_AKEY_RSF_REFERENCE, 1, /* RSFRef */ 0
  };

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This->RSFRef == 0xFF) { //non init
    This->RSFRef = 2; // set as default
  }
  Data[5] = This->RSFRef;//2 1

  ApduBuild (
    &Apdu,
    APDU_TYPE_3_SHORT,
    APDU_CLASS_NORMAL,
    APDU_MANAGE_SECURITY_ENVIRONMENT,
    APDU_MSE_SET_41,
    APDU_CRT_TAG_B6
    );

  ApduSetData (&Apdu, Data, sizeof Data);
  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenEcpInit", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
RutokenEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINTN Idx;
  UINT8 *TmpEcp, *D, *S;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  if (This == NULL || Data      == NULL || DataLen == 0 ||
      Ecp == NULL || EcpLen == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  *Ecp = AllocateZeroPool(GOSTR3410_SIGN_LEN);
  if (*Ecp == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  /* Consume such amount of data that remaining amount
     is not more than TRANS_MAX_LEN */
  for (; DataLen > TRANS_MAX_LEN; DataLen -= TRANS_MAX_LEN) {
    ApduBuild (
      &Apdu,
      APDU_TYPE_3_SHORT,
      APDU_CLASS_INCOMPLETE,
      APDU_PERFORM_SECURITY_OPERATION,
      APDU_DATA_TYPE_ECP, /* Output data type */
      APDU_DATA_TYPE_DATA_FOR_ECP/* Input data type  */
      );

    ApduSetData (&Apdu, Data, TRANS_MAX_LEN);
    CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

    if (Apdu.u.Status != SC_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenEcp", Apdu.u.Status));
      EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
    }

    Data += TRANS_MAX_LEN;
  }

  /* OK, we have now here from 1 to TRANS_MAX_LEN bytes of data to cipher */

  ApduBuild (
    &Apdu,
    APDU_TYPE_4_SHORT,
    APDU_CLASS_NORMAL,
    APDU_PERFORM_SECURITY_OPERATION,
    APDU_DATA_TYPE_ECP, /* Output data type */
    APDU_DATA_TYPE_DATA_FOR_ECP /* Input data type  */
    );

  ApduSetData (&Apdu, Data, (UINT16)DataLen /* Because here Len <= TRANS_MAX_LEN */);
  ApduSetResData (&Apdu, *Ecp, (UINT16)GOSTR3410_SIGN_LEN);

  CHECKED_CALL (SmartCardTransmit, (This, &Apdu));

  if (Apdu.u.Status != SC_SUCCESS) {
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"RutokenDecrypt", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  DEBUG ((EFI_D_ERROR, "%a.%d Apdu.DataLen=%d\n", 
    __FUNCTION__, __LINE__, Apdu.DataLen));
  
  *EcpLen = Apdu.ResponseLen >= GOSTR3410_SIGN_LEN ? 
    GOSTR3410_SIGN_LEN : Apdu.ResponseLen;
  DEBUG ((EFI_D_ERROR, "%a.%d *EcpLen=%d\n", 
    __FUNCTION__, __LINE__, *EcpLen));

  TmpEcp = AllocateCopyPool(*EcpLen, *Ecp);
  if (TmpEcp == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (*Ecp, *EcpLen);
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  for (Idx = 0, D = *Ecp, S = &TmpEcp[GOSTR3410_SIGN_LEN]; 
       Idx < GOSTR3410_SIGN_LEN; Idx++) {
    *D++ = *--S;
  }

  FreePool (TmpEcp);
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (*Ecp, *EcpLen);
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return EFI_SUCCESS;
}



