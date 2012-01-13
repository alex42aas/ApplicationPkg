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
#include "eTokenJava.h"
#include "SmartCard.h"
#include <Protocol/PciIo.h>
#include <Protocol/OpensslProtocol.h>
#include <Library/PrintLib.h>

STATIC BOOLEAN bFci = FALSE;
STATIC UINT16 PKeyId = 0;
STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;


EFI_STATUS 
EtCryptoPbePkcs12Raw (
  IN INTN Alg, 
  IN VOID *Pass, 
  IN UINTN PassLen, 
  IN VOID *Salt, 
  IN UINTN SaltLen, 
  IN UINTN Iter,
  IN UINT8 Purpose, 
  IN VOID *Out, 
  IN UINTN OutLen
  )
{
//CryptoContext ctx = {0};
  STATIC VOID *Sha1Ctx = NULL;
//BYTE* o = (BYTE*)out;
  UINT8 *O = (UINT8*)Out;
//int blockLen, hashLen, iteration, i, j;
  UINTN BlockLen, HashLen, Iteration, Idx;
//const int v = 64;
  UINTN V = 64;
//int sLen = (saltLen + v - 1) / v * v;
  UINTN SLen = (SaltLen + V - 1) / V * V;
//int pLen = (passLen + v - 1) / v * v;
  UINTN PLen = (PassLen + V - 1) / V * V;
//BYTE iterBuf[64];
  UINT8 IterBuf[64];
//BYTE D[64];
  UINT8 D[64];
//BYTE B[64];
  UINT8 B[64];
//LPBYTE I=NULL;
  UINT8 *I = NULL;  
//LPBYTE P;
  UINT8 *P;
  EFI_STATUS Status;

//if (!alg || passLen<0 || saltLen<0 || iter<0 || outLen<0) RETURN_RV(E_INVALID_PARAMETER);
//if (passLen && !pass) RETURN_RV(E_INVALID_PARAMETER);
//if (saltLen && !salt) RETURN_RV(E_INVALID_PARAMETER);
//if (outLen && !out) RETURN_RV(E_INVALID_PARAMETER);

/*
if (sLen+pLen)
{
I=(LPBYTE)etAllocateMemory(sLen+pLen+passLen);
if (!I) RETURN_RV(E_OUT_OF_MEMORY);
}
*/

  
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

  if (Sha1Ctx == NULL) {
    Status = pOpenSSLProtocol->EVP_SHA1_New_SHA_CTX (
          pOpenSSLProtocol,
          &Sha1Ctx
          );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  DEBUG ((EFI_D_ERROR, "%a.%d SaltLen=%d\n", __FUNCTION__, __LINE__, SaltLen));
  DEBUG ((EFI_D_ERROR, "%a.%d PassLen=%d\n", __FUNCTION__, __LINE__, PassLen));
  DEBUG ((EFI_D_ERROR, "%a.%d SLen=%d\n", __FUNCTION__, __LINE__, SLen));
  DEBUG ((EFI_D_ERROR, "%a.%d PLen=%d\n", __FUNCTION__, __LINE__, PLen));

  DumpBytes (Pass, PassLen);


  I = AllocateZeroPool(SLen + PLen + PassLen);
  if (NULL == I) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

//CHECK_RV(etCryptoHashInit(&ctx, alg));

  Status = pOpenSSLProtocol->EVP_SHA1_Init (
              pOpenSSLProtocol, 
              Sha1Ctx
              );  

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));


//hashLen = ctx.hashLen;
  HashLen = 20; //FIX ME need hash length
//etCryptoFree(&ctx);
//memset(D, purpose, v);
  SetMem(D, V, Purpose);

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

//for (i=0; i<sLen; i++)  I[i] = ((LPBYTE)salt)[i % saltLen];
  for (Idx = 0; Idx < SLen; Idx++) {
    I[Idx] = ((UINT8*)Salt)[Idx % SaltLen];
  }
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
//for (i=0; i<pLen; i++)  I[sLen+i] =  ((LPBYTE)pass)[i % passLen];
  for (Idx = 0; Idx < PLen; Idx++) {
    I[SLen + Idx] = ((UINT8*)Pass)[Idx % PassLen];
  }

  DEBUG ((EFI_D_ERROR, "%a.%d Iter=%d\n", __FUNCTION__, __LINE__, Iter));

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes(I, SLen + PLen + PassLen);

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes(D, sizeof(D));

#if 1
  while (OutLen > 0) {
    for (Iteration = 0; Iteration < Iter; Iteration++) {
      //CHECK_RV(etCryptoHashInit(&ctx, alg));
      Status = pOpenSSLProtocol->EVP_SHA1_Init (
                  pOpenSSLProtocol,
                  Sha1Ctx
                  );
      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return Status;
      }
      if (!Iteration) {
        //CHECK_RV(etCryptoHashUpdate(&ctx, D, v));
        Status = pOpenSSLProtocol->EVP_SHA1_Update (
                    pOpenSSLProtocol,
                    Sha1Ctx, 
                    D, 
                    V
                    );
        if (EFI_ERROR (Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          return Status;
        }
        //CHECK_RV(etCryptoHashUpdate(&ctx, I, sLen+pLen));
        Status = pOpenSSLProtocol->EVP_SHA1_Update (
                    pOpenSSLProtocol,
                    Sha1Ctx, 
                    I, 
                    SLen + PLen
                    );
      } else {
        //CHECK_RV(etCryptoHashUpdate(&ctx, iterBuf, hashLen));
        Status = pOpenSSLProtocol->EVP_SHA1_Update (
                    pOpenSSLProtocol,
                    Sha1Ctx, 
                    IterBuf, 
                    HashLen
                    );
      }
      //CHECK_RV(etCryptoHashResult(&ctx, iterBuf, &hashLen));
      //SHA1_Final(unsigned char *md, SHA_CTX *c);
      Status = pOpenSSLProtocol->EVP_SHA1_Final (
                  pOpenSSLProtocol,
                  IterBuf, 
                  Sha1Ctx
                  );
      //etCryptoFree(&ctx);
    }
// Fix by Vladimir o-ptr was not moved. The rest of fixes may be over-killing
// but since it is not my code, I prefer to be careful
// probably it wasenough just to add o+=hashLength
// We move from the range, but probably it is not important
//blockLen = min(hashLen, outLen);
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    
    BlockLen = MIN(HashLen, OutLen);
    //memmove(o, iterBuf, blockLen);
    
    CopyMem(O, IterBuf, BlockLen);
    DEBUG ((EFI_D_ERROR, "%a.%d BlockLen=%d\n", __FUNCTION__, __LINE__, BlockLen));
    DumpBytes(O, BlockLen);
    O += BlockLen;
    OutLen -= BlockLen;
    if (OutLen == 0) {
      break;
    }

    for (Idx = 0; Idx < V; Idx++) {
      B[Idx] = IterBuf[Idx % HashLen];
    }

    P = I;
    for (Idx = 0; Idx < SLen + PLen; Idx += V, P += V) {
      UINTN X = 1;
      UINTN Carry = 0;
      INTN Jdx;
      for (Jdx = (INTN)V - 1; Jdx >= 0; Jdx--) {
        X += B[Jdx]; 
        X += P[Jdx]; 
        X += Carry;
        P[Jdx] = (UINT8)(X & 0xFF);
        Carry = X > 255; 
        X = 0;
      }
    }
  }
#else
  (VOID)P, (VOID)BlockLen, (VOID)B, (VOID)O;
  (VOID)IterBuf, (VOID)Iteration;
#endif  

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  FreePool (I);

//end:;
//etCryptoFree(&ctx);
//etFreeMemory(I);
//return rv;
  return EFI_SUCCESS;
}



EFI_STATUS
EtCryptoPbePkcs12 (
  IN VOID *Pass, 
  IN UINTN PassLen, 
  IN VOID *Salt, 
  IN UINTN SaltLen, 
  IN UINTN Iter,
  IN UINT8 Purpose, 
  IN OUT VOID *Out, 
  IN UINTN OutLen
  )
{
  UINTN Utf16Len = PassLen + 1;
  UINTN Idx;
  UINT16 *Utf16;
  CHAR8 *Ptr8;
  EFI_STATUS Status = EFI_SUCCESS;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Utf16 = AllocateZeroPool (Utf16Len * sizeof(UINT16));
  if (NULL == Utf16) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Ptr8 = Pass;
  for (Idx = 0; Idx < PassLen; Idx++) {
    Utf16[Idx] = (UINT16)Ptr8[Idx] << 8;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = EtCryptoPbePkcs12Raw(
              0, 
              Utf16, 
              Utf16Len * sizeof(UINT16), 
              Salt,
              SaltLen,
              Iter,
              Purpose,
              Out,
              OutLen);

  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", 
    __FUNCTION__, __LINE__, Status));
  
  return Status;
}


#define CRYPTO_PBE_PURPOSE_ENCRYPT   1 
#define CRYPTO_PBE_PURPOSE_IV        2
#define CRYPTO_PBE_PURPOSE_MAC       3


EFI_STATUS
eTokenJavaEncryptPin (
  IN UINT8 *Pin,
  IN UINTN PinSize,
  IN UINT8 *Salt,
  IN UINTN SaltSize,
  IN UINT8 *Challendge,
  IN OUT UINT8 *Response
  )
{
  //#define RESPONSE_SIZE 8
  UINT8 Key[24];

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  ZeroMem (Key, 24);

  EtCryptoPbePkcs12 (
      //0, 
      Pin, 
      PinSize, 
      Salt, 
      SaltSize, 
      999, 
      CRYPTO_PBE_PURPOSE_MAC, 
      Key, 
      24);

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (Key, 24);

#if 0  
  int outLen = RESPONSE_SIZE;
  CryptoContext ctx;
  etCryptoMacInit  (&ctx, etCryptoAlgDES3, key, KEY_SIZE);
  etCryptoMacUpdate(&ctx, challenge, RESPONSE_SIZE);
  etCryptoMacResult(&ctx, CRYPTO_PAD_ANSI, response, &outLen);
  etCryptoFree     (&ctx);
#endif
#if 1
  {
    VOID *Cipher = NULL;
    STATIC VOID *CipherCtx = NULL;
    UINTN OutLen, ResLen;
    EFI_STATUS Status;

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

#if 0    
    Cipher = pOpenSSLProtocol->EVP_des_ede_cbc (
                pOpenSSLProtocol
                );
#else
    Cipher = pOpenSSLProtocol->EVP_des_ede3 (
                pOpenSSLProtocol
                );
#endif
        
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
    DumpBytes (Response, 8);
  }
#endif 
  return EFI_SUCCESS;
}


UINTN
eTokenJavaCountCertsInDirData (
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

  if (*Ptr != 0x0A || DirDataLen < 2) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return 0; 
  }

  Len = *(Ptr + 1);
  // skip tag and len
  DirDataLen -= 2;
  Ptr += 2;
  while (Len) {
    if (DirDataLen < 2 || Len < 2) {
      return eTokenObjCnt;
    }
    if (*Ptr == 0x10) {
      eTokenObjCnt++;
    }
    Ptr += 2;
    Len -= 2;
    DirDataLen -= 2;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d eTokenObjCnt=%d\n", 
    __FUNCTION__, __LINE__, eTokenObjCnt));
  return eTokenObjCnt;
}

EFI_STATUS
eTokenJavaFindCertsInDirData (
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
  if (DirData == NULL || ObjData == NULL || ObjDataLen == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (DirData, DirDataLen);

  Ptr = DirData;
  eTokenObjCnt = eTokenJavaCountCertsInDirData (DirData, DirDataLen);
  if (eTokenObjCnt == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  eTokenObj = AllocateZeroPool (sizeof(ETOKEN_OBJ_DATA) * eTokenObjCnt);
  if (eTokenObj == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Idx = 0;
  Len = *(Ptr + 1);
  // Skip tag and len
  Ptr += 2;
  for (Idx = 0; Idx < eTokenObjCnt; Idx++) {
    while (*Ptr != 0x10) {
      Ptr += 2; 
      if (DirDataLen < 2 || Len < 2) {
        break;
      }
      DirDataLen -= 2;
      Len -= 2;
    }
    if (DirDataLen < 2 || Len == 0) {
      break;
    }
    eTokenObj[Idx].ObjId = *(Ptr + 1); //*(Ptr) << 8 | *(Ptr + 1);
    eTokenObj[Idx].ObjType = CERT_ID_TYPE; // certificate    
    Ptr += 2;
    DirDataLen -= 2;
    Len -= 2;
  }
  
  *ObjData = (UINT8*)eTokenObj;
  *ObjDataLen = eTokenObjCnt * sizeof(ETOKEN_OBJ_DATA);
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenJavaDirectory (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Cmd[] = {0x00, 0x00, 0x00, 0x80, 
                 0x01, 0x00, 0x00, 0x04, 
                 0x09, 0x02, 0x00, 0x00, 
                 0x00, 0x00};
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
  Cmd[2] = 0x0A; // length
  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, sizeof(Cmd) - 1, &Cmd[sizeof(Cmd) - 1]);
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (Cmd, sizeof (Cmd));
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
eTokenJavaGetPKeyId (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT16 *Id
  )
{
  EFI_STATUS Status;  
  UINT8 Path[] = {0x66, 0x66, 0x50, 0x00, 0x02, 0x20, 0x30, 0x01};
  UINT8 Data[255];
  UINTN DataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Id == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenJavaSelectFileByPath(
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              Data,
              &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    // try to 3002 EF
    Path[sizeof (Path) - 1] = 0x02;
    Status = eTokenJavaSelectFileByPath(
              This, 
              Path, 
              sizeof(Path), 
              FALSE,
              Data,
              &DataLen);
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
  }

  DEBUG((EFI_D_ERROR, "%a.%d DataLen=%d\n", 
    __FUNCTION__, __LINE__, DataLen));
  DumpBytes (Data, DataLen);
  if (DataLen < 2) {
    return EFI_NOT_FOUND;
  }
  *Id = Data[DataLen - 1] << 8 | Data[DataLen - 2];
  return Status;
}



EFI_STATUS
eTokenJavaGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;  
  UINT8 Path[] = {0x66, 0x66, 0x50, 0x00, 0x02, 0x20};
  UINT8 Data[255], *DirData = NULL;
  UINTN DataLen, DirDataLen;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || ObjData == NULL || ObjDataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = eTokenJavaSelectFileByPath(
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

  DEBUG((EFI_D_ERROR, "%a.%d DataLen=%d\n", 
    __FUNCTION__, __LINE__, DataLen));
  DumpBytes (Data, DataLen);

  Status = eTokenJavaDirectory(This, &DirData, &DirDataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  Status = eTokenJavaFindCertsInDirData (
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
eTokenJavaGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  )
{
  EFI_STATUS Status;
  UINT8 Path[] = {0x66, 0x66, 0x50, 0x00, 0x02, 0x20, 0x10, 0x00, 0x00, 0x02};
  UINT8 Data[255], *RdData = NULL, *RdPtr;
  UINTN DataLen, TotalLen, Offs, ChunkSize;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL || Id == NULL || IdLen == 0 || IdLen > 2 || 
      ObjData == NULL || ObjDataLen == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Path[7] = Id[0];
#if 0  
  if (IdLen > 1) {
    Path[6] = Id[1];
  }
#endif  

  Offs = 0;
  Status = eTokenJavaSelectFileByPath (
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
  //                                      | Len 
  // 01 01 02 02 02 00 02 03 02 05 70
  TotalLen = (UINTN)Data[9] << 8 | (UINTN)Data[10];
  DEBUG((EFI_D_ERROR, "%a.%d TotalLen = %d\n", 
    __FUNCTION__, __LINE__, TotalLen));
  Status = eTokenJavaReadBinary (
              This,
              Data,
              Offs,
              128);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }  

  RdData = RdPtr = AllocateZeroPool(TotalLen);
  if (RdData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
#if 1
  DataLen = TotalLen;
  ChunkSize = DataLen > 128 ? 128 : DataLen;
  CopyMem (RdPtr, &Data, ChunkSize);
  Offs += 128;
  RdPtr += ChunkSize;
  DataLen -= ChunkSize;

  while (DataLen) {
    ChunkSize = DataLen >= 128 ? 128 : DataLen;
    Status = eTokenJavaReadBinary (
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
eTokenJavaChallendge (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8 *Challendge
  )
{
  
  UINT8 Cmd[] = {0x00, 0x00, 0x05, 0x80, 0x17, 0x00, 0x00, 0x08, 0x00};
  UINTN CmdLen;
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize, RespLen;  
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Challendge == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
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
eTokenJavaVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  )
{
  // 0x80,0x11,0x00,0x11,0x0A,0x10,0x08
  // 00 00 10 80 11 00 11 0A 10 08 DF 85 8F C0 F9 4E 18 CD 00 F5
  UINT8 Cmd[] = {
    0x00, 0x00, 0x10, 0x80, 0x11, 0x00, 0x11, 0x0A, 
    0x10, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  };
  UINTN CmdLen;
  EFI_STATUS                 Status;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  UINT8 Challendge[8];
  UINT8 Salt[40];
  UINTN SaltSize;
  UINT8 Path[] = {0x66,0x66,0x50,0x00,0x00,0x0F};
  UINT8 Data[10];
  UINTN DataLen = 0;
  UINT8 Resp[32];
  UINT8 CmdReadSalt[] = {
    0x00, 0x00, 0x0A, 0x80,0x18,0x00,0x00,0x04,0x0E,0x02,0x00,0x00,0x14, 0x00
  };

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  Reader = &Device->SmartCardReaderIo;
  ASSERT (Device != NULL);

  bFci = TRUE;
  Status = eTokenJavaSelectFileByPath (
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

  (VOID)CmdReadSalt;
  SaltSize = 0x14;
  Status = eTokenJavaReadBinary (
              This,
              Salt,
              0,
              SaltSize
              );
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d SaltSize=%d\n", __FUNCTION__, __LINE__, SaltSize));
  
  Status = eTokenJavaChallendge(This, Challendge);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  SaltSize = 20;
  Status = eTokenJavaEncryptPin(PinCode, PinCodeLen, Salt, SaltSize, Challendge, 
    Resp);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CmdLen = sizeof(Cmd);

  if (UserId == ScCredentialAdministrator) {
    Cmd[6] |= 0x4;
  }
  CopyMem(&Cmd[10], Resp, 8);

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
eTokenJavaLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  )
{
  UINTN TriesLeft = 1;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return eTokenJavaVerify (
           This,
           Admin ? ScCredentialAdministrator : ScCredentialUser,
           LocalRightsNone,
           Pin,
           PinLen,
           &TriesLeft
           );
}

EFI_STATUS
eTokenJaveSelectMain (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  UINT8 Cmd[] = {0x00, 0x00, 0x0D, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 
           0x00, 0x03, 0x12, 0x02, 0x02, 0x00, 0x00};
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize;
  EFI_STATUS Status;

  CmdLen = sizeof(Cmd);

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
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenJavaSelectFileByPath (
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

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (This == NULL || Path == NULL || PathLen == 0 || PathLen > PATH_MAX_LEN ||
      Data == NULL || Len == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (Path[0] != 0x66 || Path[1] != 0x66) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d *Len=%d, AbsPath=%d\n", 
    __FUNCTION__, __LINE__, *Len, AbsPath));
  DumpBytes(Path, PathLen);

  CmdLen = 9 + PathLen + 1;
  Cmd = AllocateZeroPool(CmdLen);
  if (NULL == Cmd) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Cmd[2] = (UINT8)((6 + PathLen) & 0xFF);
  Cmd[3] = 0x00; // CLA
  Cmd[4] = 0xA4; // INS
  Cmd[5] = AbsPath ? 0x09 : 0x08; //P1
  Cmd[6] = bFci ? 0x0C : 0x04; //0x0C;  P2 (FCI)
  bFci = FALSE;
  Cmd[7] = (UINT8)(PathLen & 0xFF);
  CopyMem(&Cmd[8], Path, PathLen);

  UpdatePcbNsBit(Cmd);
  CsumLrcCompute(Cmd, CmdLen, &Cmd[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
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

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
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
      __FUNCTION__, __LINE__, RecvBuffer[3 + *Len], RecvBuffer[4 + *Len]));
    return EFI_ABORTED;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
eTokenJavaReadBinary (
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
  CmdLen = 14;
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
          //0x80,0x18,0x00,0x00,0x04,0x0E,0x02,0x00,0x00,0x14
  //00 40 05 0x80 0x18 0x00 0x00 0x04 0x0E 0x02 0x00 0x00 0x14 C1
  while (Len) {
    Cmd[2]  = 0x0A;
    Cmd[3]  = 0x80; // CLA
    Cmd[4]  = 0x18; // INS
    Cmd[5]  = 0x00; // P1 (UINT8)(Off / 256);
    Cmd[6]  = 0x00; // P2 (UINT8)(Off % 256);
    Cmd[7]  = 0x04; // len cmd data
    Cmd[8]  = 0x0E; // TAG binary offs
    Cmd[9]  = 0x02; // len tag data
    Cmd[10] = (UINT8)(Off / 256);
    Cmd[11] = (UINT8)(Off % 256);
    Cmd[12] = (UINT8)Len;

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
eTokenJavaGetSN (
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

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (This == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  Status = eTokenJaveSelectMain (This);
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
  Cmd[6] = 0x07;

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
  if (RxLen == 0 || RxLen < 11) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  } else {    
    AsciiSPrint(This->SerialNumberStr8, 
      sizeof (This->SerialNumberStr8),
      "%02X%02X%02X%02X", 
                RecvBuffer[7], 
                RecvBuffer[8],
                RecvBuffer[9],
                RecvBuffer[10]
                );
    DEBUG((EFI_D_ERROR, "%a.%d Data=%a\n", 
      __FUNCTION__, __LINE__, This->SerialNumberStr8));
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
eTokenJavaDigestInit (
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
eTokenJavaDigest (
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
eTokenJavaEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  
  Status = eTokenJavaGetPKeyId (This, &PKeyId);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%r PKeyId=%X\n", 
    __FUNCTION__, __LINE__, Status, PKeyId));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Status;
}

EFI_STATUS
eTokenJavaEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  )
{
  EFI_STATUS Status;
  UINT8 Digest[255];
  UINT8 Cmd1[] = {
    0x00, 0x00, 0xFC,
    0x80, 0x0C, 0x03, 0x31, 0x00, 0x01, 0x04, 0x10, 
    0xFF, 0x01, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 
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
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0xF3, 
    0xE9, 0x57, 0xDB, 0x8E, 00
  };
  UINT8 Cmd2[] = {
    0x00, 0x00, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00
  };
  UINTN CmdLen;
  USB_CCID_DEV               *Device;
  SMART_CARD_READER_PROTOCOL *Reader;
  UINT8 RecvBuffer[BULK_BUFFER_SIZE];
  UINTN RecvSize, RxDataSize, Rest;
  UINT8 *RxData, *RxDataPtr;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = eTokenJavaDigestInit (This, 0);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = eTokenJavaDigest(This, Data, DataLen, Digest);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((EFI_D_ERROR, "%a.%d Digest:\n", __FUNCTION__, __LINE__));
  DumpBytes (Digest, sizeof (Digest));

  CmdLen = sizeof (Cmd1);
  CopyMem (&Cmd1[CmdLen - 10], &PKeyId, 2);
  CopyMem (&Cmd1[CmdLen - 6], Digest, 5);

  Cmd1[1] |= PCB_M_BIT;
  UpdatePcbNsBit(Cmd1);
  CsumLrcCompute(Cmd1, CmdLen, &Cmd1[CmdLen - 1]);
  DEBUG((EFI_D_ERROR, "%a.%d TX:\n", __FUNCTION__, __LINE__));
  DumpBytes(Cmd1, CmdLen);

  Device = CR (This, USB_CCID_DEV, SmartCard, CCID_DEV_SIGNATURE);
  ASSERT (Device != NULL);

  Reader = &Device->SmartCardReaderIo;
  RecvSize = sizeof(CCID_RESPONSE_MESSAGE) - 
                   sizeof( CCID_RESPONSE_MSG_HEADER ) -
                   sizeof(CCID_RDR_TO_PC_DATA_BLOCK);
  
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

  CmdLen = sizeof (Cmd2);
  CopyMem (&Cmd2[3], &Digest[5], 15);

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
    if (RxDataSize > 4) {
      RxDataSize -= 4;
      CopyMem (RxData, RxData + 4, RxDataSize);      
    }
    *Ecp = RxData;
    *EcpLen = RxDataSize;
    DEBUG((EFI_D_ERROR, "%a.%d Signature (%d):\n", 
        __FUNCTION__, __LINE__, *EcpLen));
    DumpBytes (RxData, RxDataSize);
  }

  return Status;
}


