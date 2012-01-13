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
 * eToken.c
 */
#include <Library/DebugLib.h>
#include "eToken.h"
#include "eTokenPro.h"
#include "eTokenJava.h"
#include "SmartCard.h"
#include <Protocol/PciIo.h>
#include <Library/PrintLib.h>
#include <Protocol/OpensslProtocol.h>


#define DUMP_APDU(X)


CARD_PROTO proto = ProtoT1;

STATIC UINT8 PCB_ns_bit = PCB_NS_BIT;
STATIC BOOLEAN gbNr = FALSE;

STATIC UINT8 DigestTransactID;
STATIC UINT8 eTokenPro42bAtr[] = {
  0x3B, 0xF2, 0x18, 0x00, 0x02, 0xC1, 0x0A, 0x31, 
  0xFE, 0x58, 0xC8, 0x09, 0x75
};
STATIC UINT8 eTokenProJavaVaAtr[] = {
  0x3B, 0xD5, 0x18, 0x00, 0x81, 0x31, 0xFE, 0x7D, 
  0x80, 0x73, 0xC8, 0x21, 0x10, 0xF4
};
STATIC UINT8 eTokenProJavaVbAtr[] = {
  0x3B, 0xD5, 0x18, 0x00, 0x81, 0x31, 0x3A, 0x7D, 
  0x80, 0x73, 0xC8, 0x21, 0x10, 0x30
};
STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;



VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  )
{
  UINTN i;

  for (i = 0; i < Len; i++) {
    if (i && !(i & 0xF)) {
      DEBUG(( EFI_D_ERROR, "\n"));
    }
    DEBUG(( EFI_D_ERROR, "%02x ", Bytes[i]));
  }
  DEBUG(( EFI_D_ERROR, "\n"));
}

EFI_STATUS
eTokenDigestOpenSSL (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest /* Assumed not less than 32 bytes long */
  )
{
  EFI_STATUS Status;
  UINTN HashLen = 20;
  VOID *MdCtx = NULL;
  UINTN Nid;

  if (This == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  if (pOpenSSLProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gOpenSSLProtocolGuid,
                    NULL,
                    (VOID **) &pOpenSSLProtocol
                    );
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }

  if (This->CurContext == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Nid = *(UINTN*)This->CurContext;

  DEBUG ((EFI_D_ERROR, "%a.%d Data (%d):\n\n", 
    __FUNCTION__, __LINE__, Len));
  DumpBytes (Data, Len);

  Status = pOpenSSLProtocol->EVP_New_MD_CTX (
    pOpenSSLProtocol,
    &MdCtx
    );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = pOpenSSLProtocol->EVP_DigestInit (
    pOpenSSLProtocol,
    MdCtx,
    pOpenSSLProtocol->EVP_get_digestbynid (pOpenSSLProtocol, Nid)
    );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = pOpenSSLProtocol->EVP_DigestUpdate (
    pOpenSSLProtocol,
    MdCtx,
    Data,
    Len
    );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = pOpenSSLProtocol->EVP_DigestFinal (
    pOpenSSLProtocol,
    MdCtx,
    Digest,
    &HashLen
    );
   
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


UINT32
eTokenGetFwVersion (
  IN UINT8 *Atr,
  IN UINTN AtrLen
  )
{
  if (Atr == NULL || AtrLen == 0) {
    return ETOKEN_UNKNOWN;    
  }

  if (AtrLen == sizeof(eTokenPro42bAtr)) {
    if (CompareMem(eTokenPro42bAtr, Atr, AtrLen) == 0) {
      return ETOKEN_PROV42B;
    }
  }

  if (AtrLen == sizeof(eTokenProJavaVaAtr)) {
    if (CompareMem(eTokenProJavaVaAtr, Atr, AtrLen) == 0) {
      return ETOKEN_JAVPRO_A;
    }
  }

  if (AtrLen == sizeof(eTokenProJavaVbAtr)) {
    if (CompareMem(eTokenProJavaVbAtr, Atr, AtrLen) == 0) {
      return ETOKEN_JAVPRO_B;
    }
  }

  return ETOKEN_UNKNOWN;
}


VOID
UpdatePcbNsBit(
  IN OUT UINT8 *Cmd
  )
{ 
  PCB_ns_bit ^= PCB_NS_BIT;
  if (PCB_ns_bit) {
    Cmd[1] |= PCB_NS_BIT;
  } else {
    Cmd[1] &= ~PCB_NS_BIT;
  }
}


/*
 * Compute LRC
 * In - input buffer
 * Len - length of input buffer in bytes
 * Rc - value of LRC
 * return 1 - number of checksum bytes
 */ 
UINTN 
CsumLrcCompute(
  IN UINT8 *In, 
  IN UINTN Len, 
  IN OUT UINT8 *Rc
  )
{
  UINT8 Lrc = 0;

  while (Len--) {
    Lrc ^= *In++;
  }

  if (Rc) {
    *Rc = Lrc;
  }
  return 1;
}



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
T1_IFS_Cmd(
  IN OUT UINT8 *Cmd,
  IN UINT8 BlockSize
  )
{
  Cmd[0] = 0x00; 
  Cmd[1] = 0xC1;
  Cmd[2] = 0x01; 
  Cmd[3] = BlockSize; 
  CsumLrcCompute(Cmd, 4, &Cmd[4]);
  return EFI_SUCCESS;
}

EFI_STATUS
T1_SelectMaxBlock(
  IN USB_CCID_DEV *Device
  )  
{
  UINT8 Cmd[5];
  EFI_STATUS Status;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
/* reset to initial state */
  PCB_ns_bit = PCB_NS_BIT;
  gbNr = FALSE;

  T1_IFS_Cmd(Cmd, 250);


  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);  
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0x000001);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
#if 1
  DumpBytes(RecvBuffer, RecvSize);
#endif
  return EFI_SUCCESS;  
}

EFI_STATUS
SendRBlock(
  IN USB_CCID_DEV *Device,
  IN BOOLEAN bNr,
  IN OUT UINT8 *RecvBuffer,
  IN OUT UINTN *RecvSize
  )
{
  UINT8 Cmd[] = { 0x00, 0x80, 0x00, 0x00 };
  EFI_STATUS Status;
  SMART_CARD_READER_PROTOCOL *Reader;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

//  UpdatePcbNsBit(Cmd);
//  
  if (bNr) {
    Cmd[1] |= PCB_NR_BIT;
  }

  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  Reader = &Device->SmartCardReaderIo;
  *RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  DEBUG((EFI_D_ERROR, "%a.%d Cmd=%d\n", __FUNCTION__, __LINE__, sizeof(Cmd)));
  DumpBytes(Cmd, sizeof(Cmd));
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        RecvSize,
        0x000001);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, *RecvSize));
  DumpBytes(RecvBuffer, *RecvSize);

  return EFI_SUCCESS;
}


STATIC 
EFI_STATUS
SendResync(
  IN USB_CCID_DEV *Device
  )
{
  UINT8 Cmd[] = { 0x00, 0xC0, 0x00, 0x00 };
  EFI_STATUS Status;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

//  UpdatePcbNsBit(Cmd);
//  
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);  
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0x000001);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
#if 1
  DumpBytes(RecvBuffer, RecvSize);
#endif
  return EFI_SUCCESS;
}



EFI_STATUS
SmartCardInstallProtocol (
  IN OUT EFI_HANDLE   *Controller,
  IN     USB_CCID_DEV *Device
  )
{
  T1_SelectMaxBlock(Device);
  
  /* Smart card low-level native API */
  Device->SmartCard.Lock                 = &eTokenNsdLock;
  Device->SmartCard.Reset                = &eTokenReset;
  Device->SmartCard.GetSn                = &eTokenGetSN;
  Device->SmartCard.ScTransmit           = &ScTransmit;
  
  if (Device->SmartCard.WorkMode == ETOKEN_MODE_PRO) {
    if (Device->SmartCard.FwVersion == ETOKEN_PROV42B) {
      Device->SmartCard.Verify             = &eTokenPro42bVerify;
      Device->SmartCard.Login              = &eTokenPro42bLogin;
      Device->SmartCard.ReadBinary         = &eTokenPro42bReadBinary;
      Device->SmartCard.SelectFileByPath   = &eTokenPro42bSelectFileByPath;
      Device->SmartCard.GetObjectsList     = &eTokenPro42bGetObjectsList;
      Device->SmartCard.GetObjectValById   = &eTokenPro42bGetObjectValById;
      Device->SmartCard.GetSn              = &eTokenPro42bGetSN;
      Device->SmartCard.EcpInit            = &eTokenPro42bEcpInit;
      Device->SmartCard.Ecp                = &eTokenPro42bEcp;
    } else {
      Device->SmartCard.Verify             = &eTokenJavaVerify;
      Device->SmartCard.Login              = &eTokenJavaLogin;
      Device->SmartCard.ReadBinary         = &eTokenJavaReadBinary;
      Device->SmartCard.SelectFileByPath   = &eTokenJavaSelectFileByPath;
      Device->SmartCard.GetObjectsList     = &eTokenJavaGetObjectsList;
      Device->SmartCard.GetObjectValById   = &eTokenJavaGetObjectValById;
      Device->SmartCard.GetSn              = &eTokenJavaGetSN;
      Device->SmartCard.EcpInit            = &eTokenJavaEcpInit;
      Device->SmartCard.Ecp                = &eTokenJavaEcp;
    }
  } else { 
    Device->SmartCard.Verify             = &eTokenVerify;
    Device->SmartCard.Login              = &eTokenLogin;
    Device->SmartCard.ReadBinary         = &eTokenReadBinary;
    Device->SmartCard.SelectFileByPath   = &eTokenSelectFileByPath;
    Device->SmartCard.GetObjectsList     = &eTokenGetObjectsList;
    Device->SmartCard.GetObjectValById   = &eTokenGetObjectValById;
    Device->SmartCard.EcpInit            = &eTokenEcpInit;
    Device->SmartCard.Ecp                = &eTokenEcp;
  }

  Device->SmartCard.ResetAccessRights    = &eTokenResetAccessRights;
  Device->SmartCard.Diagnose             = &eTokenDiagnoseCard;

  /* Cryptoki-specific higher-level-API */
  Device->SmartCard.TokenSystemStatus    = &eTokenTokenSystemStatus;
  Device->SmartCard.TokenIdentifyingData = &eTokenTokenIdentifyingData;
  
  Device->SmartCard.Logout               = &eTokenLogout;
  Device->SmartCard.DigestInit           = &eTokenDigestInit;
  Device->SmartCard.Digest               = &eTokenDigest;
  
  
  Device->SmartCard.DecryptInit          = &eTokenDecryptInit;
  Device->SmartCard.Decrypt              = &eTokenDecrypt;
  Device->SmartCard.VerifySignatureInit  = &eTokenVerifySignatureInit;
  Device->SmartCard.VerifySignature      = &eTokenVerifySignature;
  Device->SmartCard.DevicePath           = Device->DevicePath;

  return gBS->InstallMultipleProtocolInterfaces (
                Controller,
                &gSmartCardProtocolGuid,
                &Device->SmartCard,
                NULL
                );
}

//static inline void emit (CHAR16 const *s) { DEBUG ((EFI_D_ERROR, "%s\n", s)); }

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

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  //DumpBytes((UINT8*)Apdu, Apdu->DataLen);
  
  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
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

  Apdu->Le = (UINT16)(ResBufferLen - 2);
  Apdu->ResponseLen = (UINT16)(ResBufferLen - 2);
  CopyMem (Apdu->ResponseData, ResBuffer, Apdu->Le);

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


EFI_STATUS
eTokenSelectApp(
  IN SMART_CARD_PROTOCOL *This
  )
{
  UINT8 CmdGost[] = {
    0x00, 0x00, 0x0F, 0x00, 0xA4, 0x04, 0x00, 0x0A, 
    0xA0, 0x00, 0x00, 0x04, 0x48, 0x01, 0x01, 0x01, 
    0x06, 0x02, 0x4C
  };
  UINT8 *Cmd;
  UINTN CmdLen;
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  Reader = &Device->SmartCardReaderIo;
  ASSERT (Device != NULL);

  Cmd = CmdGost;
  CmdLen = sizeof(CmdGost);

  while (1) {
    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, CmdLen - 1, &Cmd[CmdLen - 1]);

    DEBUG((EFI_D_ERROR, "Select App: %02X %02X %02X\n",
      Cmd[0], Cmd[1], Cmd[2]));
    DumpBytes (Cmd, CmdLen);

    RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                     sizeof( CCID_RESPONSE_MSG_HEADER ) -
                     sizeof(CCID_RDR_TO_PC_DATA_BLOCK);  
    Status = Reader->Transmit(
          Reader,
          Cmd,
          CmdLen,
          RecvBuffer,
          &RecvSize,
          0);
    if (EFI_ERROR(Status)) {
      return Status;
    }

    DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
    if ((RecvBuffer[1] & PCB_R_BIT) && (RecvBuffer[1] & 0xF)) {
      SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
      gbNr = gbNr ? FALSE : TRUE;
      continue;
    }
    if (PCB_ns_bit == 0) {
      break;
    }
  };
  DumpBytes(RecvBuffer, RecvSize);
  /* check for ans */ 
  return Status;
}

EFI_STATUS
eTokenGetKeysList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x00, 0x80, 0x11, 0x10, 0x00, 0x00};
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *RcvPtr;
  UINTN RecvSize, ObjDataCnt;
  ETOKEN_OBJ_DATA *DataPtr;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  *ObjData = NULL;

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = 4; // length
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize <= 6) {
    return EFI_NOT_FOUND;
  }

  ObjDataCnt = RecvBuffer[4] << 8 | RecvBuffer[5];
  DEBUG((EFI_D_ERROR, "%a.%d Objects count=%d\n", 
    __FUNCTION__, __LINE__, ObjDataCnt));
#if 0
  (VOID)DataPtr, (VOID)RcvPtr;
#else
  *ObjDataLen = ObjDataCnt * sizeof(ETOKEN_OBJ_DATA);
  *ObjData = AllocateZeroPool(*ObjDataLen);
  DataPtr = (ETOKEN_OBJ_DATA*)*ObjData;

  DEBUG((EFI_D_ERROR, "%a.%d DataPtr=%p *ObjData=%p\n", 
    __FUNCTION__, __LINE__, DataPtr, *ObjData));
  
  if (NULL == DataPtr) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  }  

  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));
    gbNr = gbNr ? FALSE : TRUE;
    //DumpBytes(RecvBuffer, RecvSize);
    if (RecvSize < 9) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
      break;
    }
    RcvPtr = &RecvBuffer[3];
    RecvSize -= 6; // skip 3-bytes header and 2 bytes status + 1 bytes LRC
    while (RecvSize) {
      DataPtr->ObjId = RcvPtr[0] << 8 | RcvPtr[1];
      DataPtr->ObjType = RcvPtr[2];
      DEBUG((EFI_D_ERROR, "Id=%X Type=%X\n", DataPtr->ObjId, DataPtr->ObjType));
      DataPtr++;
      RecvSize -= 3;
      RcvPtr += 3;
    }
  }

  if (EFI_ERROR(Status)) {
    if (*ObjData) {
      FreePool(*ObjData);
    }
  }
#endif
  return Status;
}



EFI_STATUS
eTokenGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x00, 0x80, 0x12, 0x10, 0x00, 0x00, 0x00};
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *RcvPtr;
  UINTN RecvSize, ObjDataCnt;
  ETOKEN_OBJ_DATA *DataPtr;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  *ObjData = NULL;

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = 5; // length
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize <= 6) {
    return EFI_NOT_FOUND;
  }

  ObjDataCnt = RecvBuffer[4] << 8 | RecvBuffer[5];
  DEBUG((EFI_D_ERROR, "%a.%d Objects count=%d\n", 
    __FUNCTION__, __LINE__, ObjDataCnt));

  *ObjDataLen = ObjDataCnt * sizeof(ETOKEN_OBJ_DATA);
  *ObjData = AllocateZeroPool(*ObjDataLen);
  DataPtr = (ETOKEN_OBJ_DATA*)*ObjData;

  DEBUG((EFI_D_ERROR, "%a.%d DataPtr=%p *ObjData=%p\n", 
    __FUNCTION__, __LINE__, DataPtr, *ObjData));
  
  if (NULL == DataPtr) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  }  

  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));    
    gbNr = gbNr ? FALSE : TRUE;
    //DumpBytes(RecvBuffer, RecvSize);
    if (RecvSize < 9) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
      break;
    }
    RcvPtr = &RecvBuffer[3];
    RecvSize -= 6; // skip 3-bytes header and 2 bytes status + 1 bytes LRC
    while (RecvSize) {
      DataPtr->ObjId = RcvPtr[0] << 8 | RcvPtr[1];
      DataPtr->ObjType = RcvPtr[2];
      DEBUG((EFI_D_ERROR, "Id=%X Type=%X\n", DataPtr->ObjId, DataPtr->ObjType));
      DataPtr++;
      RecvSize -= 3;
      RcvPtr += 3;
    }
  }

  if (EFI_ERROR(Status)) {
    if (*ObjData) {
      FreePool(*ObjData);
    }
  }
  
  return Status;
}


EFI_STATUS
eTokenGetObjectAllAttributesById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **AttrData,
  OUT UINTN *AttrDataLen
  )
{
#if 0
  return EFI_SUCCESS;
#else
  UINT8 Cmd[] = {
    0x00, 0x00, 0x07, 0x80, 0x13, 0x40, 0x00, 0x02, 
    0x00, 0x00, 
    0x00
  };
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *DataPtr;
  UINTN RecvSize, TotalDataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  *AttrData = NULL;

  if (Id == NULL || IdLen == 0 || IdLen > 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d ID:\n", __FUNCTION__, __LINE__));
  //DumpBytes(Id, IdLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

#if 0
  eTokenPrintObjectsList(This);
#endif

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Cmd[9] = Id[0];
  if (IdLen > 1) {
    Cmd[8] = Id[1];
  }
  
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);  
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);
/*
  if (RecvBuffer[2] != 8) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
*/
  *AttrDataLen = 4096;
  DEBUG((EFI_D_ERROR, "%a.%d DataSize=%d\n", 
    __FUNCTION__, __LINE__, *AttrDataLen));

  *AttrData = AllocateZeroPool(*AttrDataLen);
  if (NULL == *AttrData) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  TotalDataLen = 0;
  DataPtr = *AttrData;

  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    gbNr = gbNr ? FALSE : TRUE;
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));    
    //DumpBytes(RecvBuffer, RecvSize);
    if ((UINTN)(4 + RecvBuffer[2]) != RecvSize) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    TotalDataLen += RecvBuffer[2];
    if ((RecvBuffer[1] & PCB_M_BIT) == 0) {
      TotalDataLen -= 2; // last packet contain 2-bytes result code
    } 
    
    if (TotalDataLen > *AttrDataLen) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
    DataPtr += RecvBuffer[2];
  }

  DEBUG((EFI_D_ERROR, "%a.%d AttrData (%d(%d)):\n", 
    __FUNCTION__, __LINE__, *AttrDataLen, TotalDataLen));
  //DumpBytes(*AttrData, TotalDataLen);
  if (TotalDataLen != *AttrDataLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
  }

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%08X\n", 
      __FUNCTION__, __LINE__, Status));
    if (*AttrData) {
      FreePool(*AttrData);
    }
  }

  return Status;
#endif  
}



EFI_STATUS
eTokenGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  UINT8 Cmd[] = {
    0x00, 0x00, 0x0B, 0x80, 0x13, 0x20, 0x00, 0x06, 
    0x00, 0x03, 0x11, 0x00, 0x00, 0x00, 0x00
  };
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *DataPtr;
  UINTN RecvSize, TotalDataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  *ObjData = NULL;

  if (Id == NULL || IdLen == 0 || IdLen > 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d ID:\n", __FUNCTION__, __LINE__));  
  DumpBytes(Id, IdLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

#if 0
  eTokenPrintObjectsList(This);
#endif

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Cmd[9] = Id[0];
  if (IdLen > 1) {
    Cmd[8] = Id[1];
  }
  
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);  
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvBuffer[2] != 8) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  *ObjDataLen = RecvBuffer[9] << 8 | RecvBuffer[10];
  DEBUG((EFI_D_ERROR, "%a.%d DataSize=%d\n", __FUNCTION__, __LINE__, *ObjDataLen));
  /* 
     *  3 bytes reserved for accept status code and checksum in case 
     *  last packet broken into status code field
     */
  *ObjData = AllocateZeroPool(*ObjDataLen + 3);
  if (NULL == *ObjData) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  TotalDataLen = 0;
  DataPtr = *ObjData;

  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));
    gbNr = gbNr ? FALSE : TRUE;
    
    DumpBytes(RecvBuffer, RecvSize);
    if ((UINTN)(4 + RecvBuffer[2]) > RecvSize) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }

    if (RecvBuffer[2] == 0x08 && 
        RecvBuffer[3] == 0x00 &&
        RecvBuffer[4] == Id[0] &&
        RecvBuffer[5] == 0x00 &&
        RecvBuffer[6] == 0x00 &&
        RecvBuffer[7] == 0x00 &&
        RecvBuffer[8] == 0x11) {
      continue;
    }
    
    TotalDataLen += RecvBuffer[2];
    if ((RecvBuffer[1] & PCB_M_BIT) == 0) {
      TotalDataLen -= 2; // last packet contain 2-bytes result code
    } 

    if (TotalDataLen > *ObjDataLen) {
      DEBUG((EFI_D_ERROR, "%a.%d Warning!\n", __FUNCTION__, __LINE__));
    }
    CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
    DataPtr += RecvBuffer[2];
  }

  DEBUG((EFI_D_ERROR, "%a.%d ObjectData (%d(%d)):\n", 
    __FUNCTION__, __LINE__, *ObjDataLen, TotalDataLen));
  //DumpBytes(*ObjData, TotalDataLen);
  if (TotalDataLen != *ObjDataLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
  }

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%08X\n", 
      __FUNCTION__, __LINE__, Status));
    if (*ObjData) {
      FreePool(*ObjData);
    }
  }

#if 0
{
  UINT8 *AttrData = NULL;
  UINTN AttrDataLen;
    
  eTokenGetObjectAllAttributesById(This, Id, IdLen, &AttrData, &AttrDataLen);
  if (AttrData) {
    FreePool(AttrData);
  }
}
#endif

  return Status;
}


// volatile UINT32 *gsmi_nsd_flags;
SMM_INFO_AREA *gSmmInfoArea;

/* Smart card low-level native API */

EFI_STATUS
eTokenNsdLock(
  IN SMART_CARD_PROTOCOL *This
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenReset (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *AtrString,
  IN     UINT16              Length
  )
{
  EFI_STATUS Status;
  USB_CCID_DEV *Device;
  UINTN Len;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = Device->SmartCardReaderIo.Reset(
                                  &Device->SmartCardReaderIo,
                                  0, // Slot
                                  Device->State[0].AtrBlob,
                                  &Len
                                  );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}


VOID
eTokenCheckBusy(
  IN SMART_CARD_READER_PROTOCOL *Reader,
  IN OUT UINT8 *CheckBuff,
  IN UINTN CheckBuffLen
  )
{
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0xE3, 0x01, 0x01, 0xE3};
  UINT8 BusyCnt;

  if (CheckBuffLen != 5) {
    return;
  }
  if (!(CheckBuff[0] == 0x00 && CheckBuff[1] == 0xC3 &&
      CheckBuff[2] == 0x01 && CheckBuff[3] == 0x01 &&
      CheckBuff[4] == 0xC3)) {
    return;
  }
  
  BusyCnt = 0;
  
  while (1) {
    RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                     sizeof( CCID_RESPONSE_MSG_HEADER ) -
                     sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
    Status = Reader->Transmit(Reader,
          Cmd,
          sizeof(Cmd),
          RecvBuffer,
          &RecvSize,
          0x000001);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      return;
    }

    if (RecvSize < 5) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return;    
    }
    if (!(RecvBuffer[0] == 0x00 && RecvBuffer[1] == 0xC3 &&
        RecvBuffer[2] == 0x01 && RecvBuffer[3] == 0x01 &&
        RecvBuffer[4] == 0xC3)) {
      break;
    }
    if (BusyCnt++ > 30) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return;
    }
  }
  
  CopyMem(CheckBuff, RecvBuffer, RecvSize);
}


EFI_STATUS
eTokenPrintObjectsList (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x00, 
                     0x80, 0x12, 0x10, 0x00, 0x00, 
                 0x00};
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize, TriesLeft;
  CHAR8 DefPin[] = "1234567890";

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  Status = eTokenVerify(This, 0, 0,
    DefPin,
    AsciiStrLen(DefPin),
    &TriesLeft
    );
  
  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = 5; // length
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));
    gbNr = gbNr ? FALSE : TRUE;
    //DumpBytes(RecvBuffer, RecvSize);
  }
  
  return EFI_SUCCESS;
}



EFI_STATUS
eTokenVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  )
{
  UINT8 *Cmd;
  UINTN CmdLen;
  EFI_STATUS Status;
  USB_CCID_DEV *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (PinCode == NULL || PinCodeLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (PinCodeLen < 6 || PinCodeLen > 32) {
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
#if 0
  do { 
    Status = eTokenSelectApp(This);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }while (PCB_ns_bit == 0);
#endif

  CmdLen = 11 + PinCodeLen;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    return EFI_OUT_OF_RESOURCES;
  }
  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = (UINT8)((7 + PinCodeLen) & 0xFF);
  /* APDU header */
  Cmd[3] = 0x80; // CLA
  Cmd[4] = 0x10; // INS
  Cmd[5] = 0x20; // P1
  Cmd[6] = 0x00; // P2
  Cmd[7] = (UINT8)((2 + PinCodeLen) & 0xFF); // LC
  Cmd[8] = (UserId == ScCredentialAdministrator) ? 0 : 1; // user type
  Cmd[9] = (UINT8)(PinCodeLen & 0xFF);
  
  CopyMem(Cmd + 10, PinCode, PinCodeLen);
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, 10 + PinCodeLen, &Cmd[PinCodeLen + 10]);
  //DumpBytes(Cmd, 11 + PinCodeLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(Reader,
        Cmd,
        11 + PinCodeLen,
        RecvBuffer,
        &RecvSize,
        0);
  FreePool(Cmd);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize < 5) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;    
  }
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif  
  if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[3], RecvBuffer[4]));
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}

STATIC UINT16 PrivKeyId;

EFI_STATUS
eTokenEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  UINTN ObjDataLen, ObjCnt, Idx;
  EFI_STATUS Status;
  ETOKEN_OBJ_DATA *Objects;

  PrivKeyId = 0xFFFF;

  (VOID) ObjDataLen, (VOID)ObjCnt, (VOID)Idx;
  (VOID) Objects;
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = eTokenGetKeysList(This, (UINT8**)&Objects, &ObjDataLen);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  ObjCnt = ObjDataLen / sizeof (ETOKEN_OBJ_DATA);
  DEBUG((EFI_D_ERROR, "%a.%d ObjCnt=%d\n", __FUNCTION__, __LINE__, ObjCnt));
  for (Idx = 0; Idx < ObjCnt; Idx++) {
    DEBUG((EFI_D_ERROR, "Objects[%d].Type=%d\n", Idx, Objects[Idx].ObjType));
    DEBUG((EFI_D_ERROR, "Objects[%d].ObjId=%d\n", Idx, Objects[Idx].ObjId));
    if (Objects[Idx].ObjType == 1) {
      PrivKeyId = Objects[Idx].ObjId;
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
eTokenEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  )
{
  UINT8 *Cmd;
  UINTN CmdLen, Idx;
  EFI_STATUS Status;
  USB_CCID_DEV *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  UINT8 Digest[64];

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Data == NULL || DataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenDigestInit (This, 0, 0);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  Status = eTokenDigest (
      This,
      Data,
      DataLen,
      Digest
      );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  CmdLen = 11 + 32;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    return EFI_OUT_OF_RESOURCES;
  }
  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = (UINT8)((7 + DataLen) & 0xFF);
  /* APDU header */
  Cmd[3] = 0x80; // CLA
  Cmd[4] = 0x14; // INS
  Cmd[5] = 0x10; // P1
  Cmd[6] = 0x00; // P2
  Cmd[7] = (UINT8)((2 + 32) & 0xFF); // LC
  Cmd[8] = (UINT8)(PrivKeyId >> 8 & 0xFF);
  Cmd[9] = (UINT8)(PrivKeyId & 0xFF);
  
  //CopyMem(Cmd + 10, Data, DataLen);
  for (Idx = 0; Idx < 32; Idx++) {
    Cmd[10 + Idx] = Digest[31 - Idx];
  }
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, 10 + 32, &Cmd[32 + 10]);
  DumpBytes(Cmd, 11 + DataLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(Reader,
        Cmd,
        11 + 32,
        RecvBuffer,
        &RecvSize,
        0);
  FreePool(Cmd);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize < 5) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;    
  }
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif
  if (RecvBuffer[2] != 0x42) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Wrong length %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[2]));
    return EFI_ABORTED;
  }
  if (RecvBuffer[67] != 0x90 || RecvBuffer[68] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[67], RecvBuffer[68]));
    return EFI_ABORTED;
  }

  *Ecp = AllocateZeroPool(64);
  *EcpLen = 64;
  if (*Ecp == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (*Ecp, &RecvBuffer[3 + 32], 32);
  CopyMem (*Ecp + 32, &RecvBuffer[3], 32);

  return EFI_SUCCESS;
}



EFI_STATUS
eTokenResetAccessRights (
  IN     SMART_CARD_PROTOCOL *This,
  IN     RESET_USER          UserId,
  IN     LOCAL_RIGHTS        Rights
  )
{
  UINT8 Cmd[] = {0x80, 0x15, 0x20, 0x00, 0x00, 0x00};
  EFI_STATUS Status;
  USB_CCID_DEV *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);
  //DumpBytes(Cmd, sizeof(Cmd));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d Receive size = %d\n", 
    __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize < 5) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;    
  }
  if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[3], RecvBuffer[4]));
    return EFI_ABORTED;
  }
  
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenDiagnoseCard (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

/* Cryptoki-specific higher-level API */

EFI_STATUS
eTokenTokenSystemStatus (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT TOKEN_SYSTEM_STATUS *Status
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

EFI_STATUS eTokenTokenIdentifyingData (
  IN     SMART_CARD_PROTOCOL    *This,
  IN OUT TOKEN_IDENTIFYING_DATA *Data
  )
{
  ZeroMem(Data, sizeof(TOKEN_IDENTIFYING_DATA));
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  )
{
  UINTN TriesLeft;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return eTokenVerify (
           This,
           Admin ? ScCredentialAdministrator : ScCredentialUser,
           LocalRightsNone,
           Pin,
           PinLen,
           &TriesLeft
           );
}


EFI_STATUS
eTokenLogout (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return eTokenResetAccessRights (
           This,
           Admin ? ScResetAdministrator : ScResetUser,
           LocalRightsNone
           );
}

EFI_STATUS
eTokenDigestInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet,
  IN     UINT8              workmode
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x04, 
                     0x80, 0x14, 0x31, 0x00,
                 0x00};
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  /* T1 header */
  Cmd[0] = 0;
  Cmd[1] = 0;
  Cmd[2] = 4; // length
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);

  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
  //DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize < 7) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  if (RecvBuffer[4] != 0x90 || RecvBuffer[5] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  DigestTransactID = RecvBuffer[3];

  return EFI_SUCCESS; 
}


#define MAX_T1_CHUNK_LEN        (244)
#define MAX_T1_CHUNK_LEN2       (252)


EFI_STATUS
eTokenDigest (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest /* Assumed not less than 32 bytes long */
  )
{
  UINT8 *Cmd;
  UINTN ChunkLen, RestLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *RcvPtr, *DataPtr;
  UINTN RecvSize, TotalLen;
  EFI_STATUS Status;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Digest == NULL || Data == NULL|| Len > 65536) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }  

  ChunkLen = Len > MAX_T1_CHUNK_LEN ? MAX_T1_CHUNK_LEN : Len;
  DataPtr = Data;

  Cmd = AllocateZeroPool(256);
  if (NULL == Cmd) {
    return EFI_OUT_OF_RESOURCES;
  }

  Cmd[0] = 0x00;
  Cmd[1] = 0;
  if (Len > MAX_T1_CHUNK_LEN) {
    Cmd[1] |= PCB_M_BIT;
  }  
  
  Cmd[3] = 0x80;
  Cmd[4] = 0x14;
  Cmd[5] = 0x32;
  Cmd[6] = 0x00;

  // data len + transact id byte
  if (Len + 1 > MAX_T1_CHUNK_LEN) {
    Cmd[2] = (UINT8)((ChunkLen + 8) & 0xFF); // T1 len
    Cmd[7] = 0x00; // extended APDU
    Cmd[8] = (UINT8)(((Len + 1) >> 8) & 0xFF);
    Cmd[9] = (UINT8)((Len + 1) & 0xFF);
    Cmd[10] = DigestTransactID; // transact id

    CopyMem(&Cmd[11], DataPtr, ChunkLen);
    DataPtr += ChunkLen;
  
    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, 11 + ChunkLen, &Cmd[11 + ChunkLen]);
  } else {
    Cmd[2] = (UINT8)((ChunkLen + 6) & 0xFF); // T1 len
    Cmd[7] = (UINT8)((Len + 1) & 0xFF);
    Cmd[8] = DigestTransactID; // transact id
    CopyMem(&Cmd[9], DataPtr, ChunkLen);
    DataPtr += ChunkLen;
    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, 9 + ChunkLen, &Cmd[9 + ChunkLen]);
  }
  //Cmd[8] = (UINT8)((Len >> 8) & 0xFF);
  //Cmd[9] = (UINT8)(Len & 0xFF);

  

  RestLen = Len - ChunkLen;

  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        12 + ChunkLen,
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  do {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
    //DumpBytes(RecvBuffer, RecvSize);
    ZeroMem(Cmd, 256);
    
    if (RecvSize == 6) {
      if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
          __FUNCTION__, __LINE__, Status));
        break;
      }
      if (RecvBuffer[1] & PCB_R_BIT) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
          __FUNCTION__, __LINE__, Status));
        break;
      }
      Status = EFI_SUCCESS;
      break;
    }

    if (RecvSize != 4) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      goto _exit;
    }
    if (RestLen == 0) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      goto _exit;
    }

    if ((RecvBuffer[1] & PCB_R_BIT) == 0) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }

    ChunkLen = RestLen > MAX_T1_CHUNK_LEN2 ? MAX_T1_CHUNK_LEN2 : RestLen;

    Cmd[0] = 0x00;
    Cmd[1] = 0;
    if (RestLen > MAX_T1_CHUNK_LEN2) {
      Cmd[1] |= PCB_M_BIT;
    }
    Cmd[2] = (UINT8)(ChunkLen & 0xFF);
    CopyMem(&Cmd[3], DataPtr, ChunkLen);
    DataPtr += ChunkLen;
    RestLen -= ChunkLen;

    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, 3 + ChunkLen, &Cmd[3 + ChunkLen]);

    RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                     sizeof( CCID_RESPONSE_MSG_HEADER ) -
                     sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
    Status = Reader->Transmit(
          Reader,
          Cmd,
          4 + ChunkLen,
          RecvBuffer,
          &RecvSize,
          0);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }    
  } while (1);

  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  Cmd[0] = 0x00;
  Cmd[1] = 0x00;
  Cmd[2] = 0x06;
  Cmd[3] = 0x80;
  Cmd[4] = 0x14;
  Cmd[5] = 0x33;
  Cmd[6] = 0x00;
  Cmd[7] = 0x01;
  /* Transact id */
  Cmd[8] = DigestTransactID;
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, 9, &Cmd[9]);
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        10,
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
#if 1
  DumpBytes(RecvBuffer, RecvSize);
#endif
  DataPtr = Digest;
  if (RecvBuffer[2] > 34) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
  TotalLen = RecvBuffer[2];
  DataPtr += RecvBuffer[2];
  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));
    gbNr = gbNr ? FALSE : TRUE;
    //DumpBytes(RecvBuffer, RecvSize);
    if ((UINTN)(4 + RecvBuffer[2]) != RecvSize) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    TotalLen += RecvBuffer[2];
    if ((RecvBuffer[1] & PCB_M_BIT) == 0) {
      TotalLen -= 2; // last packet contain 2-bytes result code
    } 
    
    if (TotalLen > 32) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
    DataPtr += RecvBuffer[2];
  }


  (VOID)RcvPtr;
#if 0
  if (RecvSize < 38) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  RcvPtr = &RecvBuffer[3];
  if (RecvBuffer[2] != 34 || RcvPtr[32] != 0x90 || RcvPtr[33]!= 0x00) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  CopyMem(Digest, RcvPtr, 32);
  DEBUG((EFI_D_ERROR, "%a.%d Digest:\n", 
      __FUNCTION__, __LINE__));
  DumpBytes(Digest, 32);
#endif  
_exit:
  FreePool(Cmd);
  return Status;  
}

EFI_STATUS
eTokenSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d *Len=%d, AbsPath=%d\n", 
    __FUNCTION__, __LINE__, *Len, AbsPath));
  DumpBytes(Path, PathLen);
  *Len = 0;
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenDecryptInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               RSFRef,
  IN     UINT8              workmode
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINT8 Data[] = {
    APDU_TLV_TAG_USAGE_QUALIFIER, 1, APDU_USAGE_QUALIFIER_DECIPHER,
    APDU_TLV_TAG_AKEY_RSF_REFERENCE, 1, /* RSFRef */ 0
  };

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  /* Because of Microsoft C89 antique compiler inserts and does not link with memset() */
  SetMem (&Apdu, sizeof Apdu, 0);
  Apdu.Type = APDU_TYPE_NONE;

  /* It is because of the Microsoft C89 antique compiler */
  Data[5] = RSFRef;

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
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"eTokenDecryptInit", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  return EFI_SUCCESS;
}

EFI_STATUS
eTokenDecrypt (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Cipher,
  IN OUT UINTN               *CipherLen
  )
{
  APDU  Apdu /*= { APDU_TYPE_NONE }*/;
  UINTN L;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

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
      DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"eTokenDecrypt", Apdu.u.Status));
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
    DEBUG ((EFI_D_ERROR, "%s(): Error: 0x%04X\n", L"eTokenDecrypt", Apdu.u.Status));
    EFI_ERROR_REALRET (EFI_DEVICE_ERROR, "");
  }

  *CipherLen = Apdu.ResponseLen;
  return EFI_SUCCESS;
}
 
EFI_STATUS
eTokenVerifySignatureInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8              workmode
  )
{
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
  }  

  return Status;;
}

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
  )
{
  USB_CCID_DEV *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status;
  UINT8 Cmd[170];
  UINTN Idx;

  DEBUG((EFI_D_ERROR, "%a.%d ParamSet=0x%X\n", __FUNCTION__, __LINE__, ParamSet));

  if (Hash == NULL || HashLen == 0 || Sign == NULL || 
      SignLen == 0 || Key == NULL || KeyLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (HashLen != 32 || SignLen != 64 || KeyLen != 64) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  DEBUG((EFI_D_ERROR, "%a.%d HashLen=%d\n", __FUNCTION__, __LINE__, HashLen));
  DumpBytes(Hash, HashLen);

  DEBUG((EFI_D_ERROR, "%a.%d SignLen=%d\n", __FUNCTION__, __LINE__, SignLen));
  DumpBytes(Sign, SignLen);

  DEBUG((EFI_D_ERROR, "%a.%d KeyLen=%d\n", __FUNCTION__, __LINE__, KeyLen));
  DumpBytes(Key, KeyLen);
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Cmd[0] = 0x00;
  Cmd[1] = 0x00;
  Cmd[2] = 0xA6;
  Cmd[3] = 0x80;
  Cmd[4] = 0x14;
  Cmd[5] = 0x22;
  Cmd[6] = 0x00;
  Cmd[7] = 0xA1; // len of (hash + key + sign) + paramset
  Cmd[8] = (UINT8)(ParamSet & 0xFF);  //0x01;

  /* Copy hash value */
  for (Idx = 0; Idx < 32; Idx++) {
    Cmd[9 + Idx] = Hash[31 - Idx];
  }
  
  /* Copy high 32-bytes of signature */  
  CopyMem(&Cmd[41], &Sign[32], 32);
  
  /* Copy low 32-bytes of signature */
  CopyMem(&Cmd[73], Sign, 32);

  /* Copy low 32-bytes of Key */
  for (Idx = 0; Idx < 32; Idx++) {
    Cmd[105 + Idx] = Key[31 - Idx];
  }
  /* Copy high 32-bytes of Key */
  for (Idx = 0; Idx < 32; Idx++) {
    Cmd[137 + Idx] = Key[63 - Idx];
  } 
  
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);
  
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(
        Reader,
        Cmd,
        sizeof(Cmd),
        RecvBuffer,
        &RecvSize,
        0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));
#if 1  
  DumpBytes(RecvBuffer, RecvSize);
#endif
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif  
  if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
_exit:
  if (EFI_ERROR(Status)) {
    *Success = FALSE;
  } else {
    *Success = TRUE;
  }
  return Status;
}

EFI_STATUS
eTokenGetSN (
  IN SMART_CARD_PROTOCOL *This
  )
{
#if 1
  UINT8 *Cmd;
  UINTN CmdLen, RxLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status = EFI_SUCCESS;

  if (This == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
  } 

  CmdLen = 8;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }  

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);

  Cmd[2] = 4;
  Cmd[3] = 0x80; // CLA
  Cmd[4] = 0x15; // INS
  Cmd[5] = 0x10; // P1
  Cmd[6] = 0x00; // P2

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen - 1, &Cmd[CmdLen - 1]);
  DumpBytes(Cmd, CmdLen);
  
  Status = Reader->Transmit(Reader,
      Cmd,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
  FreePool (Cmd);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize < 5) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif
  if (RecvBuffer[2] < 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  RxLen = RecvBuffer[2] - 2;
  if (RxLen == 0 || RxLen < 24) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  } else {    
    AsciiSPrint(This->SerialNumberStr8, 
      sizeof (This->SerialNumberStr8),
      "%02X%02X%02X%02X%02X%02X%02X%02X", 
                RecvBuffer[19], 
                RecvBuffer[20],
                RecvBuffer[21],
                RecvBuffer[22],
                RecvBuffer[23], 
                RecvBuffer[24],
                RecvBuffer[25],
                RecvBuffer[26]
                );
    DEBUG((EFI_D_ERROR, "%a.%d Data=%a\n", 
      __FUNCTION__, __LINE__, This->SerialNumberStr8));
  }
#endif  
  return EFI_SUCCESS;
}

EFI_STATUS 
ScTransmitRaw (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *TxBuffer,
  IN     UINTN TxBufferLen,
  IN OUT UINT8 *RxBuffer,
  IN OUT UINTN *RxBufferLen,
  IN     TX_PROTO TxProto
  )
{
  UINT8 *Cmd;
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status = EFI_SUCCESS;

  if (This == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
  }

  CmdLen = TxBufferLen;
  Cmd = TxBuffer;
  
  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  DumpBytes(Cmd, CmdLen);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  
  Status = Reader->Transmit(Reader,
      Cmd,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  DumpBytes(RecvBuffer, RecvSize);  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif
  if (RecvSize < 3) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  if (RecvBuffer[2] > *RxBufferLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! {%d %d}\n", __FUNCTION__, __LINE__,
      RecvBuffer[2], *RxBufferLen));
    *RxBufferLen = RecvBuffer[2]; 
    return EFI_BUFFER_TOO_SMALL;
  }
  *RxBufferLen = RecvBuffer[2];
  CopyMem(RxBuffer, &RecvBuffer[3], RecvBuffer[2]);
  return EFI_SUCCESS;
}


EFI_STATUS 
ScTransmitT0 (
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
ScTransmitT1 (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8 *TxBuffer,
  IN     UINTN TxBufferLen,
  IN OUT UINT8 *RxBuffer,
  IN OUT UINTN *RxBufferLen,
  IN     TX_PROTO TxProto
  )
{
  UINT8 Cmd[256], *DataPtr;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN CmdLen, RestLen, ChunkLen;
  EFI_STATUS Status = EFI_SUCCESS;
  UINTN RecvSize, TotalLen = 0;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;

  if (This == NULL || TxBuffer == NULL || 
      RxBuffer == NULL || RxBufferLen == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
#if 0  
  Status = eTokenSelectApp(This);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
  }
#endif  
  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

  DataPtr = TxBuffer;
  RestLen = TxBufferLen;
  DEBUG((EFI_D_ERROR, "%a.%d TX=%d\n", __FUNCTION__, __LINE__, TxBufferLen));  
  DumpBytes(TxBuffer, TxBufferLen);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  DEBUG((EFI_D_ERROR, "%a.%d RestLen=%d\n", __FUNCTION__, __LINE__, RestLen));

  do  {
    ChunkLen = RestLen > MAX_T1_CHUNK_LEN2 ? MAX_T1_CHUNK_LEN2 : RestLen;
    
    Cmd[0] = 0x00;
    Cmd[1] = 0;
    if (RestLen > MAX_T1_CHUNK_LEN2) {
      Cmd[1] |= PCB_M_BIT;
    }
    Cmd[2] = (UINT8)(ChunkLen & 0xFF);
    CopyMem(&Cmd[3], DataPtr, ChunkLen);
    DataPtr += ChunkLen;
    RestLen -= ChunkLen;
    CmdLen = ChunkLen + 4;

    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, CmdLen - 1, &Cmd[CmdLen - 1]);
    DEBUG((EFI_D_ERROR, "%a.%d CmdLen=%d\n", __FUNCTION__, __LINE__, CmdLen));  
    DumpBytes(Cmd, CmdLen);
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  

    RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
    
    Status = Reader->Transmit(Reader,
      Cmd,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      return Status;
    }
    DEBUG((EFI_D_ERROR, "%a.%d RecvSize=%d\n", __FUNCTION__, __LINE__, RecvSize));  
    DumpBytes(RecvBuffer, RecvSize);  
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    
    //Status = EFI_ABORTED;
    if (RecvSize == 6) {
      if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        break;
      }
      if (RecvBuffer[1] & PCB_R_BIT) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        break;
      }
      break;
    }

    if (RecvSize != 4) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      break;
    }
    
    if ((RecvBuffer[1] & PCB_R_BIT) == 0) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", 
        __FUNCTION__, __LINE__));
      break;
    }
    if (RecvBuffer[1] & PCB_NR_BIT) {
      //bNeedNr = TRUE;
    }
  }while (RestLen);

  DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  
  if (RecvBuffer[2] > *RxBufferLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_BUFFER_TOO_SMALL;
  }  
  DataPtr = RxBuffer;
  CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
  TotalLen = RecvBuffer[2];
  DataPtr += RecvBuffer[2];
  while (RecvBuffer[1] & PCB_M_BIT) {
    Status = SendRBlock(Device, gbNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));
    gbNr = gbNr ? FALSE : TRUE;

    if ((UINTN)(4 + RecvBuffer[2]) != RecvSize) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }     
    TotalLen += RecvBuffer[2];
    if (TotalLen > *RxBufferLen) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_BUFFER_TOO_SMALL;
    }
    if ((RecvBuffer[1] & PCB_M_BIT) == 0) {
      //TotalLen -= 2; // last packet contain 2-bytes result code
    } 
   
    CopyMem(DataPtr, &RecvBuffer[3], RecvBuffer[2]);
    DataPtr += RecvBuffer[2];
    
  }
  *RxBufferLen = TotalLen;
  DEBUG((EFI_D_ERROR, "%a.%d TotalLen=%d\n", __FUNCTION__, __LINE__, TotalLen));
  DumpBytes(RxBuffer, *RxBufferLen);
  DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
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
  if (This == NULL || TxBuffer == NULL || RxBuffer == NULL || 
      TxBufferLen == 0 || RxBufferLen == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  switch (TxProto) {
  case TX_PROTO_T0: 
    return ScTransmitT0 (
              This, 
              TxBuffer, 
              TxBufferLen, 
              RxBuffer, 
              RxBufferLen, 
              TxProto
              );

  case TX_PROTO_T1:
    return ScTransmitT1 (
              This, 
              TxBuffer, 
              TxBufferLen, 
              RxBuffer, 
              RxBufferLen, 
              TxProto
              );

  case TX_PROTO_RAW:
    return ScTransmitRaw (
              This, 
              TxBuffer, 
              TxBufferLen, 
              RxBuffer, 
              RxBufferLen, 
              TxProto
              );
  }
  
  return EFI_UNSUPPORTED;
}


