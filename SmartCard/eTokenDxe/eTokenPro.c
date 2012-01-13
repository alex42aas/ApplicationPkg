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
#include "eToken.h"
#include "eTokenPro.h"
#include "eTokenJava.h"
#include "SmartCard.h"
#include <Protocol/PciIo.h>
#include <Protocol/OpensslProtocol.h>
#include <Library/PrintLib.h>


STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;
STATIC UINT16 PKeyId = 0;


STATIC
EFI_STATUS
eTokenEncryptPin_v1 (
  IN UINT8 *Pin,
  IN UINTN PinSize,
  IN UINT8 *Challendge,
  IN OUT UINT8 *Response
  )
{
  STATIC VOID *Mdctx = NULL;
  VOID *Md;
  UINT8 Val = 0;
  UINT8 Hash[32];
  UINT32 HashLen;
  UINTN x = 0, y = 0, i, j;
  UINT8 Key[24];
  UINT8 Masks[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };  
  int OutLen, ResLen;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  //InitializeOpenSSL ();
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

  pOpenSSLProtocol->Init ();

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (Mdctx == NULL) {
    Status = pOpenSSLProtocol->EVP_New_MD_CTX (
                      pOpenSSLProtocol, 
                      &Mdctx);
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return Status;
    }
  }
  
  Md = (VOID*)pOpenSSLProtocol->EVP_get_digestbyname (
                    pOpenSSLProtocol,
                    "MD5"
                    );
  if (Md == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  }  

  Val = 0;
  pOpenSSLProtocol->EVP_MD_CTX_init (
                pOpenSSLProtocol,
                Mdctx
                );
        
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = pOpenSSLProtocol->EVP_DigestInit (
                pOpenSSLProtocol,
                Mdctx, 
                Md
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = pOpenSSLProtocol->EVP_DigestUpdate (
                pOpenSSLProtocol,
                Mdctx, 
                &Val, 
                1
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = pOpenSSLProtocol->EVP_DigestUpdate (
                pOpenSSLProtocol,
                Mdctx, 
                Pin, 
                PinSize
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_DigestFinal (
                pOpenSSLProtocol,
                Mdctx, 
                Hash, 
                &HashLen
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_MD_CTX_cleanup (
                pOpenSSLProtocol,
                Mdctx
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  DumpBytes(Hash, 16);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Val = 1;
  pOpenSSLProtocol->EVP_MD_CTX_init (
                pOpenSSLProtocol,
                Mdctx
                );
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_DigestInit (
                pOpenSSLProtocol,
                Mdctx, 
                Md
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_DigestUpdate (
                pOpenSSLProtocol,
                Mdctx, 
                &Val, 
                1
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_DigestUpdate (
                pOpenSSLProtocol,
                Mdctx, 
                Pin, 
                PinSize
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = pOpenSSLProtocol->EVP_DigestFinal (
                pOpenSSLProtocol,
                Mdctx, 
                Hash + 16, 
                &HashLen
                );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  pOpenSSLProtocol->EVP_MD_CTX_cleanup (
              pOpenSSLProtocol,
              Mdctx
              );
  DumpBytes(Hash + 16, 16);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ZeroMem(Key, sizeof(Key));

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 7; j++) {
      if (Hash[y] & Masks[x]) {
        Key[i] |= Masks[j];
      }
      if (++x == 8) { 
        y++; 
        x = 0; 
      }
    }
  }
  DumpBytes(Key, 24);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  {
    VOID *Cipher = NULL;
    STATIC VOID *CipherCtx = NULL;

    if (CipherCtx == NULL) {
      Status = pOpenSSLProtocol->EVP_New_CIPHER_CTX (
          pOpenSSLProtocol,
          &CipherCtx
          );
      if (EFI_ERROR (Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return Status;
      }
    }

    pOpenSSLProtocol->EVP_CIPHER_CTX_init (
        pOpenSSLProtocol,
        CipherCtx
        );
    
    Cipher = pOpenSSLProtocol->EVP_des_ede3 (
                pOpenSSLProtocol
                );
        
    Status = pOpenSSLProtocol->EVP_EncryptInit (
          pOpenSSLProtocol,
          CipherCtx,
          Cipher,
          Key,
          NULL
          );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return Status;
    }
    //EVP_EncryptInit(&Cctx, Cipher, Key, NULL);
    
    Status = pOpenSSLProtocol->EVP_EncryptUpdate (
                pOpenSSLProtocol,
                CipherCtx, 
                Response, 
                &OutLen, 
                Challendge, 
                8
                );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return Status;
    }
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = pOpenSSLProtocol->EVP_EncryptFinal_ex (
                pOpenSSLProtocol,
                CipherCtx, 
                Response + OutLen, 
                &ResLen
                );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return Status;
    }
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (Response, 16);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}


UINTN
eTokenPro42bCountCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen
  )
{
  UINT8 *Ptr;
  UINTN Len;
  UINTN eTokenObjCnt;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Ptr = DirData;
  eTokenObjCnt = 0;
  while (DirDataLen) {
    if (*Ptr != 0x6F) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return 0;
    }
    Len = *(Ptr + 1);

    DirDataLen -= 2; // skip TAG 0x6F and length
    Ptr += 2;
    
    /* 0x82 - tag of file type 0x01 - EF
           0x86 - tag of FID 2-bytes */
    if (*Ptr != 0x82 || *(Ptr + 1) != 0x01 || *(Ptr + 2) != 0x01 ||
        *(Ptr + 3) != 0x86 || *(Ptr + 4) != 0x02 || *(Ptr + 5) != 0x00) {
      
    } else {
      eTokenObjCnt++;
    }
    Ptr += Len;      
    DirDataLen -= Len;
  }
  DEBUG((EFI_D_ERROR, "%a.%d eTokenObjCnt=%d\n", 
    __FUNCTION__, __LINE__, eTokenObjCnt));
  return eTokenObjCnt;
}

EFI_STATUS
eTokenPro42bFindCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  UINT8 *Ptr;
  UINTN Len;
  ETOKEN_OBJ_DATA *eTokenObj;
  UINTN eTokenObjCnt, Idx;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (DirData, DirDataLen);

  Ptr = DirData;
  eTokenObjCnt = eTokenPro42bCountCertsInDirData (DirData, DirDataLen);
  if (eTokenObjCnt == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  eTokenObj = AllocateZeroPool(sizeof(ETOKEN_OBJ_DATA) * eTokenObjCnt);
  if (eTokenObj == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Idx = 0;

  while (DirDataLen) {
    if (*Ptr != 0x6F) {
      FreePool (eTokenObj);
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    Len = *(Ptr + 1);
    DirDataLen -= 2; // skip TAG 0x6F and length
    Ptr += 2;
        
    /* 0x82 - tag of file type 0x01 - EF
           0x86 - tag of FID 2-bytes */
    if (*Ptr != 0x82 || *(Ptr + 1) != 0x01 || *(Ptr + 2) != 0x01 ||
        *(Ptr + 3) != 0x86 || *(Ptr + 4) != 0x02 || *(Ptr + 5) != 0x00) { // 
      
    } else {
      eTokenObj[Idx].ObjId = *(Ptr + 5) << 8 | *(Ptr + 6);
      eTokenObj[Idx].ObjType = CERT_ID_TYPE; // certificate    
      Idx++;
    }
    Ptr += Len;      
    DirDataLen -= Len;
  }

  if (Idx == 0) {
    FreePool (eTokenObj);
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  *ObjData = (UINT8*)eTokenObj;
  *ObjDataLen = eTokenObjCnt * sizeof(ETOKEN_OBJ_DATA);
  return EFI_SUCCESS;
}

UINTN
eTokenPro42bCountPkeysInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen
  )
{
  UINT8 *Ptr;
  UINTN Len;
  UINTN eTokenObjCnt;
  BOOLEAN bPubKey = TRUE;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Ptr = DirData;
  eTokenObjCnt = 0;
  while (DirDataLen) {
    if (*Ptr != 0x6F) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return 0;
    }
    Len = *(Ptr + 1);

    DirDataLen -= 2; // skip TAG 0x6F and length
    Ptr += 2;
    
    /* 0x82 - tag of file type 0x01 - EF
           0x86 - tag of FID 2-bytes */
    if (*Ptr != 0x82 || *(Ptr + 1) != 0x01 || *(Ptr + 2) != 0x01 ||
        *(Ptr + 3) != 0x86 || *(Ptr + 4) != 0x02) {

    } else {
      if (!bPubKey) {
        eTokenObjCnt++;
      }
      bPubKey = !bPubKey;
    }
    Ptr += Len;      
    DirDataLen -= Len;
  }
  DEBUG((EFI_D_ERROR, "%a.%d eTokenObjCnt=%d\n", 
    __FUNCTION__, __LINE__, eTokenObjCnt));
  return eTokenObjCnt;
}


EFI_STATUS
eTokenPro42bFindPkeysInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  UINT8 *Ptr;
  UINTN Len;
  ETOKEN_OBJ_DATA *eTokenObj;
  UINTN eTokenObjCnt, Idx;
  BOOLEAN bPubKey = TRUE;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (DirData, DirDataLen);

  Ptr = DirData;
  eTokenObjCnt = eTokenPro42bCountPkeysInDirData (DirData, DirDataLen);
  if (eTokenObjCnt == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  DEBUG((EFI_D_ERROR, "%a.%d eTokenObjCnt=%d\n", 
    __FUNCTION__, __LINE__, eTokenObjCnt));

  eTokenObj = AllocateZeroPool(sizeof(ETOKEN_OBJ_DATA) * eTokenObjCnt);
  if (eTokenObj == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Idx = 0;

  while (DirDataLen) {
    if (*Ptr != 0x6F) {
      FreePool (eTokenObj);
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    Len = *(Ptr + 1);
    DirDataLen -= 2; // skip TAG 0x6F and length
    Ptr += 2;
        
    /* 0x82 - tag of file type 0x01 - EF
           0x86 - tag of FID 2-bytes */
    if (*Ptr != 0x82 || *(Ptr + 1) != 0x01 || *(Ptr + 2) != 0x01 ||
        *(Ptr + 3) != 0x86 || *(Ptr + 4) != 0x02) { // 
      
    } else {
      if (!bPubKey) {
        eTokenObj[Idx].ObjId = *(Ptr + 5) << 8 | *(Ptr + 6);
        eTokenObj[Idx].ObjType = PKEY_ID_TYPE;
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        DEBUG((EFI_D_ERROR, "*(Ptr + 5)=0x%X\n", *(Ptr + 5)));
        DEBUG((EFI_D_ERROR, "*(Ptr + 6)=0x%X\n", *(Ptr + 6)));
        DEBUG((EFI_D_ERROR, "eTokenObj[Idx].ObjId=0x%X\n", eTokenObj[Idx].ObjId));
        Idx++;
      }
      bPubKey = !bPubKey;
    }
    Ptr += Len;      
    DirDataLen -= Len;
  }

  if (Idx == 0) {
    FreePool (eTokenObj);
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  *ObjData = (UINT8*)eTokenObj;
  *ObjDataLen = eTokenObjCnt * sizeof(ETOKEN_OBJ_DATA);
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenPro42bDirectory (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x00, 0x80, 0x16, 0x02, 0x00, 0x00, 0x00};
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE], *RcvPtr;
  UINTN RecvSize, DataSize, Rest;
  UINT8 *Data, *DataPtr;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  *ObjData = NULL;

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;

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
  DumpBytes(RecvBuffer, RecvSize);

  if (RecvSize <= 6 || RecvBuffer[2] < 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  DataSize = RecvBuffer[2] - 2;
  DEBUG((EFI_D_ERROR, "%a.%d DataSize=%d\n", __FUNCTION__, __LINE__, DataSize));
  Data = DataPtr = AllocateZeroPool (DataSize);
  if (Data == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  RecvSize -= 6;
  CopyMem(DataPtr, &RecvBuffer[3], RecvSize);
  DataPtr += RecvSize;
  Rest = DataSize - RecvSize;

  while (RecvBuffer[1] & PCB_M_BIT) {    
    Status = SendRBlock(Device, FALSE, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));    
    DumpBytes(RecvBuffer, RecvSize);
    if (RecvSize < 6) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    if (Rest == 0) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    RcvPtr = &RecvBuffer[3];
    RecvSize -= 6; // skip 3-bytes header and 2 bytes status + 1 bytes LRC
    if (Rest < RecvSize) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    CopyMem(DataPtr, &RecvBuffer[3], RecvSize);
    DataPtr += RecvSize;
    Rest -= RecvSize;
  }

  if (EFI_ERROR(Status)) {
    FreePool (Data);
  } else {
    *ObjData = Data;
    *ObjDataLen = DataSize;
  }
  
  return Status;
}


EFI_STATUS
eTokenPro42bGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Path[] = {0x66, 0x66, 0x10, 0x02};
  UINT8 Data[255], *DirData = NULL;
  UINTN DataLen, DirDataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || ObjData == NULL || ObjDataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenPro42bSelectFileByPath(
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              Data,
              &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenPro42bDirectory(This, &DirData, &DirDataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenPro42bFindCertsInDirData (
                DirData, 
                DirDataLen, 
                ObjData, 
                ObjDataLen);
  if (DirData != NULL) {
    FreePool (DirData);
  }
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  return Status;
}

EFI_STATUS
eTokenPro42bPKeyId (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT16 *Id
  )
{
  EFI_STATUS Status;
  UINT8 Path[] = {0x66, 0x66, 0x10, 0x04};
  UINT8 Data[255], *DirData = NULL;
  UINTN DataLen, DirDataLen;
  UINT8 *ObjData = NULL;
  ETOKEN_OBJ_DATA *etObjs;
  UINTN *ObjDataLen = NULL;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Id == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  Status = eTokenPro42bSelectFileByPath(
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              Data,
              &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenPro42bDirectory(This, &DirData, &DirDataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenPro42bFindPkeysInDirData (
                DirData, 
                DirDataLen, 
                &ObjData, 
                ObjDataLen);
  if (DirData != NULL) {
    FreePool (DirData);
  }

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  } else {
    etObjs = (ETOKEN_OBJ_DATA*)ObjData;
    if (*ObjDataLen < sizeof(*etObjs)) {
      Status = EFI_NOT_FOUND;
    } else {
      *Id = etObjs[0].ObjId;
    }
  }
  
  return Status;
}



EFI_STATUS
eTokenPro42bGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Path[] = {0x66, 0x66, 0x10, 0x02, 0x00, 0x00};
  UINT8 Data[255], *RdData = NULL, *RdPtr;
  UINTN DataLen, TotalLen, Offs, ChunkSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL || Id == NULL || IdLen == 0 || IdLen > 2 || 
      ObjData == NULL || ObjDataLen == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Path[5] = Id[0];
  if (IdLen > 1) {
    Path[4] = Id[1];
  }

  Offs = 0;

  Status = eTokenPro42bSelectFileByPath (
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              Data,
              &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenPro42bReadBinary (
              This,
              Data,
              Offs,
              128);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  if (Data[0] != 0x04 || Data[1] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  TotalLen = Data[2] | (Data[3] << 8);
  TotalLen -= 4; // skip header

  RdData = RdPtr = AllocateZeroPool(TotalLen);
  if (RdData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
#if 1
  DataLen = TotalLen;
  ChunkSize = DataLen > 124 ? 124 : DataLen;
  CopyMem (RdPtr, &Data[4], ChunkSize);
  Offs += 128;
  RdPtr += ChunkSize;
  DataLen -= ChunkSize;

  while (DataLen) {
    ChunkSize = DataLen >= 128 ? 128 : DataLen;
    Status = eTokenPro42bReadBinary (
              This,
              Data,
              Offs,
              ChunkSize);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    CopyMem (RdPtr, Data, ChunkSize);
    Offs += ChunkSize;
    RdPtr += ChunkSize;
    DataLen -= ChunkSize;
  }
#endif

  if (EFI_ERROR(Status)) {
    if (RdData) {
      FreePool (RdData);
    }
  } else {
    *ObjData = RdData;
    *ObjDataLen = TotalLen;
  }

  return Status;
}


EFI_STATUS
eTokenPro42bChallendge (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8 *Challendge
  )
{
  UINT8 Cmd[] = {0x00, 0x00, 0x05, 0x00, 0x84, 0x00, 0x00, 0x08, 0x00};
  UINTN CmdLen;
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize, RespLen;
  UINT8 Path[] = {0x66, 0x66};
  UINT8 Data[10];
  UINTN DataLen = 0;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Challendge == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenPro42bSelectFileByPath (
      This, 
      Path, 
      sizeof(Path), 
      FALSE, 
      Data, 
      &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  Reader = &Device->SmartCardReaderIo;
  ASSERT (Device != NULL);

  CmdLen = sizeof(Cmd);
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen - 1, &Cmd[CmdLen - 1]);
  
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
  DumpBytes(RecvBuffer, RecvSize);
#if 1
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif
  RespLen = RecvBuffer[2];
  DEBUG((EFI_D_ERROR, "%a.%d RespLen=%d\n", __FUNCTION__, __LINE__, RespLen));
  if (RespLen != 0x0A) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  CopyMem(Challendge, RecvBuffer + 3, 8);
  if (RecvBuffer[11] != 0x90 || RecvBuffer[12] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[11], RecvBuffer[12]));
    return EFI_ABORTED;
  }
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenPro42bVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  )
{
  UINT8 Cmd[] = {
    0x00, 0x00, 0x0D, 0x00, 0x82, 0x00, 0x81, 0x08, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00
  };
  UINTN CmdLen;
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  UINT8 Challendge[8];
  UINT8 Resp[24];

#if 0
{
  UINT8 Ch[] = {
    0x59, 0x32, 0xD2, 0x3A, 
    0x5D, 0xFD, 0xC7, 0xF4
  };
  UINT8 Salt[] = {
    0x0F, 0x29, 0xEF, 0xC0, 0xE1, 0x39, 0xD6, 0xF1,
    0x7A, 0x19, 0xC6, 0xF2, 0xF9, 0x6E, 0xE8, 0x34,
    0xFE, 0x7D, 0xC8, 0xFC
  };

  eTokenJavaEncryptPin (
      "Qwe123$", 7,
      Salt,
      20,
      Ch,
      Resp);
}
#endif
  
  Status = eTokenPro42bChallendge(This, Challendge);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  eTokenEncryptPin_v1(PinCode, PinCodeLen, Challendge, Resp);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  Reader = &Device->SmartCardReaderIo;
  ASSERT (Device != NULL);

  CmdLen = sizeof(Cmd);

  if (UserId == ScCredentialAdministrator) {
    Cmd[6] |= 0x4;
  }
  CopyMem(&Cmd[8], Resp, 8);

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen - 1, &Cmd[CmdLen - 1]);
  
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
  DumpBytes(RecvBuffer, RecvSize);
#if 1  
  eTokenCheckBusy(Reader, RecvBuffer, RecvSize);
#endif
  
  if (RecvBuffer[3] != 0x90 || RecvBuffer[4] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[11], RecvBuffer[12]));
    return EFI_ABORTED;
  }
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenPro42bLogin (
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

  return eTokenPro42bVerify (
           This,
           Admin ? ScCredentialAdministrator : ScCredentialUser,
           LocalRightsNone,
           Pin,
           PinLen,
           &TriesLeft
           );
}

EFI_STATUS
eTokenPro42bSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  )
{
  UINT8 *Cmd;
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status;
  
  if (This == NULL || Path == NULL || PathLen == 0 || PathLen > PATH_MAX_LEN ||
      Data == NULL || Len == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d *Len=%d, AbsPath=%d\n", 
    __FUNCTION__, __LINE__, *Len, AbsPath));
  DumpBytes(Path, PathLen);
#if 0    
  eTokenPrintObjectsList (This);
#else
  CmdLen = 9 + PathLen;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Cmd[2] = (UINT8)((5 + PathLen) & 0xFF);
  Cmd[3] = 0x00; // CLA
  Cmd[4] = 0xA4; // INS
  Cmd[5] = AbsPath ? 0x09 : 0x08; //P1
  Cmd[6] = 0x04; //0x0C;  P2 (FCI)
  Cmd[7] = (UINT8)(PathLen & 0xFF);
  CopyMem(&Cmd[8], Path, PathLen);

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen, &Cmd[CmdLen - 1]);
  DumpBytes(Cmd, CmdLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(Reader,
        Cmd,
        CmdLen,
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
  *Len = 0;
  if (RecvBuffer[2] < 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  *Len = RecvBuffer[2] - 2;
  if (*Len != 0) {
    CopyMem(Data, &RecvBuffer[3], *Len);
  }

  if (RecvBuffer[3 + *Len] != 0x90 || RecvBuffer[4 + *Len] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[3], RecvBuffer[4]));
    return EFI_ABORTED;
  }

#endif
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenPro42bSelectFCI (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  )
{
  UINT8 *Cmd;
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status;
  
  if (This == NULL || Path == NULL || PathLen == 0 || PathLen > PATH_MAX_LEN ||
      Data == NULL || Len == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d *Len=%d, AbsPath=%d\n", 
    __FUNCTION__, __LINE__, *Len, AbsPath));
  DumpBytes(Path, PathLen);
#if 0    
  eTokenPrintObjectsList (This);
#else
  CmdLen = 9 + PathLen;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Cmd[2] = (UINT8)((5 + PathLen) & 0xFF);
  Cmd[3] = 0x00; // CLA
  Cmd[4] = 0xA4; // INS
  Cmd[5] = AbsPath ? 0x09 : 0x08; //P1
  Cmd[6] = 0x00; //0x0C;  P2 (FCI)
  Cmd[7] = (UINT8)(PathLen & 0xFE);
  CopyMem(&Cmd[8], Path, PathLen);

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen, &Cmd[CmdLen - 1]);
  DumpBytes(Cmd, CmdLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  Status = Reader->Transmit(Reader,
        Cmd,
        CmdLen,
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
  *Len = 0;
  if (RecvBuffer[2] < 2) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  *Len = RecvBuffer[2] - 2;
  if (*Len != 0) {
    CopyMem(Data, &RecvBuffer[3], *Len);
  }

  if (RecvBuffer[3 + *Len] != 0x90 || RecvBuffer[4 + *Len] != 0x00) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! %02X %02X\n", 
      __FUNCTION__, __LINE__, RecvBuffer[3], RecvBuffer[4]));
    return EFI_ABORTED;
  }

#endif
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenPro42bReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  )
{
  UINT8 *Cmd;
  UINTN CmdLen, RxLen, DataOff;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status = EFI_SUCCESS;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Data == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  CmdLen = 9;
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

  DataOff = 0;
  
  while (Len) {
    Cmd[2] = 5;
    Cmd[3] = 0x00; // CLA
    Cmd[4] = 0xB0; // INS
    Cmd[5] = (UINT8)(Off / 256);
    Cmd[6] = (UINT8)(Off % 256);
    Cmd[7] = (UINT8)Len;

    UpdatePcbNsBit(Cmd);
    CsumLrcCompute(Cmd, CmdLen, &Cmd[CmdLen - 1]);
    DumpBytes(Cmd, CmdLen);
    
    Status = Reader->Transmit(Reader,
        Cmd,
        CmdLen,
        RecvBuffer,
        &RecvSize,
        0);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
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
    if (Len < RxLen) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    
    if (RxLen == 0) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    } else {
      CopyMem(Data + DataOff, &RecvBuffer[3], RxLen);
    }

    Len -= RxLen;
    Off += RxLen;
    DataOff += RxLen; 
  }

  FreePool(Cmd);
  if (EFI_ERROR(Status)) {    
    return Status;
  }
  
  return EFI_SUCCESS;  
}


EFI_STATUS
eTokenPro42bGetSN (
  IN SMART_CARD_PROTOCOL *This
  )
{
  UINT8 *Cmd;
  UINTN CmdLen, RxLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status = EFI_SUCCESS;
  UINT8 Path[] = {0x66, 0x66, 0x00, 0x01};
  UINT8 PathData[255];
  UINTN PathDataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  

  if (This == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = eTokenPro42bSelectFileByPath (
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              PathData,
              &PathDataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  CmdLen = 9;
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

  Cmd[2] = 5;
  Cmd[3] = 0x00; // CLA
  Cmd[4] = 0xCA; // INS
  Cmd[5] = 0x01;
  Cmd[6] = 0x81;

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen, &Cmd[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd, CmdLen);
  
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
  if (RxLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  } else {
    if (RxLen < 19) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }

    //CopyMem(*Data, &RecvBuffer[3], RxLen);
    AsciiSPrint(This->SerialNumberStr8, 
      sizeof (This->SerialNumberStr8),
      "%02X%02X%02X%02X%02X%02X", 
                RecvBuffer[13], 
                RecvBuffer[14],
                RecvBuffer[15],
                RecvBuffer[16],
                RecvBuffer[17],
                RecvBuffer[18]
                );
    DEBUG((EFI_D_ERROR, "%a.%d Data=%a\n", 
      __FUNCTION__, __LINE__, This->SerialNumberStr8));
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenPro42bDigestInit (
  IN     SMART_CARD_PROTOCOL *This,
  IN     GOSTR3411_PARAM_SET ParamSet
  )
{
  EFI_STATUS Status;

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
      
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenPro42bDigest (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               Len,
  IN OUT UINT8               *Digest /* Assumed not less than 32 bytes long */
  )
{
  EFI_STATUS Status;

  Status = eTokenDigestOpenSSL (
              This,
              Data,
              Len,
              Digest /* Assumed not less than 32 bytes long */
              );

  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
eTokenPro42bEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  
  Status = eTokenPro42bPKeyId (This, &PKeyId);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%r PKeyId=%X\n", 
    __FUNCTION__, __LINE__, Status, PKeyId));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Status;
}

EFI_STATUS
eTokenPro42bEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  )
{
  UINT8 Cmd00[] = {
    0x00, 0x00, 0x04, 
    0x00, 0x22, 0xF3, 0xFE, 0x00
  };
  UINT8 Cmd01[] = {
    0x00, 0x00, 0x08, 
    0x00, 0x22, 0xF1, 0xB8, 0x03, 0x83, 0x01, 0x03, 0x00, 0x00
  };
  UINT8 Cmd1[] = {
    0x00, 0x00, 0xFC,
    0x00, 0x2A, 0x80, 0x86, 0x00, 0x01, 0x01, 0x00, 
    0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x30, 0x21, 0x30, 
    0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 
    0x05, 0x00, 0x04, 0x14, 0x67, 0x42, 0x3E, 0xBF, 
    0xA8, 0x45, 0x4F, 0x19, 0x00
  };
  UINT8 Cmd2[] = {
    0x00, 0x00, 0x0E,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  UINT8 Digest[255];
  EFI_STATUS Status;
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize, RxDataSize, Rest;
  UINT8 *RxData, *RxDataPtr;
  UINT8 Path[] = {0x66, 0x66, 0x10, 0x01, 0x00};
  UINT8 DirData[255];
  UINTN DirDataLen;

  Status = eTokenPro42bDigestInit (This, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = eTokenPro42bDigest(This, Data, DataLen, Digest);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = eTokenPro42bSelectFCI(
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              DirData,
              &DirDataLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);

  CmdLen = sizeof (Cmd00);
  UpdatePcbNsBit(Cmd00);
  CsumLrcCompute(Cmd00, CmdLen, &Cmd00[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d TX:\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd00, CmdLen);
  
  Status = Reader->Transmit(Reader,
      Cmd00,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d RX:\n", __FUNCTION__, __LINE__));
  DumpBytes(RecvBuffer, RecvSize);
  

  CmdLen = sizeof (Cmd01) - 1;
  UpdatePcbNsBit(Cmd01);
  CsumLrcCompute(Cmd01, CmdLen, &Cmd01[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d TX:\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd01, CmdLen);
  
  Status = Reader->Transmit(Reader,
      Cmd01,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d RX:\n", __FUNCTION__, __LINE__));
  DumpBytes(RecvBuffer, RecvSize);
  

  DEBUG((EFI_D_ERROR, "%a.%d Digest:\n", __FUNCTION__, __LINE__));
  DumpBytes (Digest, sizeof (Digest));

  CmdLen = sizeof (Cmd1);
  CopyMem (&Cmd1[CmdLen - 13], &PKeyId, 2);
  CopyMem (&Cmd1[CmdLen - 9], Digest, 8);

  Cmd1[1] |= PCB_M_BIT;
  UpdatePcbNsBit(Cmd1);
  CsumLrcCompute(Cmd1, CmdLen, &Cmd1[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d TX:\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd1, CmdLen);

  Status = Reader->Transmit(Reader,
      Cmd1,
      CmdLen,
      RecvBuffer,
      &RecvSize,
      0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d RX:\n", __FUNCTION__, __LINE__));
  DumpBytes(RecvBuffer, RecvSize);

  CmdLen = sizeof (Cmd2) - 1;
  CopyMem (&Cmd2[3], &Digest[8], 12);

  UpdatePcbNsBit(Cmd2);
  CsumLrcCompute(Cmd2, CmdLen, &Cmd2[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d TX:\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd2, CmdLen);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  
  Status = Reader->Transmit(Reader,
      Cmd2,
      CmdLen, // + 1,
      RecvBuffer,
      &RecvSize,
      0);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d RX:\n", __FUNCTION__, __LINE__));
  DumpBytes(RecvBuffer, RecvSize);

  RxDataSize = RecvBuffer[2];
  DEBUG((EFI_D_ERROR, "%a.%d RxDataSize=%d\n", 
    __FUNCTION__, __LINE__, RxDataSize));
  RxData = RxDataPtr = AllocateZeroPool (MAX_SIGN_DATA);
  if (RxData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem(RxDataPtr, &RecvBuffer[3], RecvBuffer[2]);
  RxDataPtr += RecvBuffer[2];
  Rest = MAX_SIGN_DATA - RecvBuffer[2];

  while (RecvBuffer[1] & PCB_M_BIT) {
    BOOLEAN bNr = (RecvBuffer[1] & PCB_NS_BIT) ? FALSE : TRUE;
    Status = SendRBlock(Device, bNr, RecvBuffer, &RecvSize);
    DEBUG((EFI_D_ERROR, "%a.%d Status=%08X RecvSize=%d\n", 
      __FUNCTION__, __LINE__, Status, RecvSize));    
    DumpBytes(RecvBuffer, RecvSize);
    if (RecvSize < 6) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    if (Rest == 0) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }    
    RecvSize -= 6; // skip 3-bytes header and 2 bytes status + 1 bytes LRC
    if (Rest < RecvSize) {
      Status = EFI_ABORTED;
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    if (RecvBuffer[1] & PCB_M_BIT) {
      CopyMem(RxDataPtr, &RecvBuffer[3], RecvBuffer[2]);
      RxDataPtr += RecvBuffer[2];
      RxDataSize += RecvBuffer[2];
      Rest -= RecvBuffer[2];
    } else {
      CopyMem(RxDataPtr, &RecvBuffer[3], RecvBuffer[2] - 2);
      RxDataPtr += RecvBuffer[2] - 2;
      RxDataSize += RecvBuffer[2] - 2;
      Rest -= RecvBuffer[2] - 2;
    }
  }

  if (EFI_ERROR(Status)) {
    FreePool (RxData);
  } else {
#if 0  
    if (RxDataSize > 4) {
      RxDataSize -= 4;
      CopyMem (RxData, RxData + 4, RxDataSize);      
    }
#endif    
    *Ecp = RxData;
    *EcpLen = RxDataSize;
    DEBUG((EFI_D_ERROR, "%a.%d Signature (%d):\n", 
        __FUNCTION__, __LINE__, *EcpLen));
    DumpBytes (RxData, RxDataSize);
  }

  return Status;
}


