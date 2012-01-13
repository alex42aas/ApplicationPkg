/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "RemoteCfgPktDxe.h"


#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif


STATIC REMOTE_CFG_PKT_PRIVATE_DATA RemotePktPrivateData;

STATIC
EFI_STATUS
ByteBufToString(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  IN OUT CHAR8 *Str,
  IN UINTN StrLen
  )
{
  UINTN i;
  CHAR8 *TmpPtr;

  if (ByteBuf == NULL || Str == NULL || StrLen == 0 || BufLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (StrLen < (BufLen << 1)) {
    return EFI_INVALID_PARAMETER;
  }

  for (i = 0, TmpPtr = Str; i < BufLen; i++) {
    AsciiSPrint (TmpPtr, (BufLen - i) * 2 + 1, "%02X", ByteBuf[i]);
    TmpPtr += 2;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ByteBufToStringRev (
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  IN OUT CHAR8 *Str,
  IN UINTN StrLen
  )
{
  UINTN i;
  CHAR8 *TmpPtr;

  if (ByteBuf == NULL || Str == NULL || StrLen == 0 || BufLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (StrLen < (BufLen << 1)) {
    return EFI_INVALID_PARAMETER;
  }

  for (i = BufLen, TmpPtr = Str; i > 0; i--) {
    AsciiSPrint (TmpPtr, i * 2 + 1, "%02X", ByteBuf[i - 1]);
    TmpPtr += 2;
  }
  return EFI_SUCCESS;
}


STATIC
VOID
EFIAPI
ReverseByteBuf(
  IN UINT8 *ByteBuf,
  IN UINTN BufSize
  )
{
  UINTN i;
  UINT8 Tmp;
  
  for (i = 0; i < BufSize / 2; i++) {
    Tmp = ByteBuf[i];
    ByteBuf[i] = ByteBuf[BufSize - 1 - i];
    ByteBuf[BufSize - 1 - i] = Tmp;
  }
}


STATIC
VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  )
{
  UINTN i;

  for (i = 0; i < Len; i++) {
    if (i && !(i & 0xF)) {
      LOG(( EFI_D_ERROR, "\n"));
    }
    LOG(( EFI_D_ERROR, "%02x ", Bytes[i]));
  }
  LOG(( EFI_D_ERROR, "\n"));
}


VOID
Crc8Calc(
  IN OUT UINT8 *Crc, 
  IN UINT8 Data
  )
{
  UINT8 Mask;
  INTN Idx;

  for (Idx = 0; Idx < 8; Idx++) {
    Mask = (*Crc & 0x1) ^ (Data & 0x1);
    Data >>=  1;
    *Crc >>=  1;

    if (Mask == 1) {
      *Crc ^= POLINOM;
    }
  }
}


EFI_STATUS
ValidateChecksumCrc8 (
  IN CIRC_BUF_DESC8 *BufDesc,
  IN UINTN PktLen
  )
{
  UINT8 *BegTmp;
  UINT8 Crc, TmpCrc;
  UINTN Idx;
  CHAR8 CrcAsciiStr[3];

  BegTmp = BufDesc->Begin;
  /* skip start of packet ':' */
  BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  for (Idx = 1, TmpCrc = 0; Idx < PktLen - 5; Idx++) {
    if (BegTmp == BufDesc->End) {
      return EFI_ABORTED;
    }
    Crc8Calc(&TmpCrc, *BegTmp);
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  }

  // skip 2-bytes of CRC-type
  BegTmp = CircPtr8(BegTmp, 2, BufDesc->Base, BufDesc->Size);

  CrcAsciiStr[0] = *BegTmp;
  BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  CrcAsciiStr[1] = *BegTmp;
  CrcAsciiStr[2] = '\0';
  
  Crc = (UINT8)(AsciiStrHexToUintn (CrcAsciiStr) & 0xFF);

  if (Crc != TmpCrc) {
    LOG ((EFI_D_ERROR, "%a.%d CRC error! Crc=%02X TmpCrc=%02X\n", 
      __FUNCTION__, __LINE__, Crc, TmpCrc));
    return EFI_CRC_ERROR;
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
ValidateChecksumMD5 (
  IN CIRC_BUF_DESC8 *BufDesc,
  IN UINTN PktLen,
  IN UINTN DataLen
  )
{
  UINT8 *BegTmp;
  UINTN Idx;
  CHAR8 Md5AsciiStr[(MD5_HASHSIZE + 1) * 2];
  CHAR8 Md5AsciiStrCmp[(MD5_HASHSIZE + 1) * 2];
  MD5_CTX Md5Ctx;
  UINT8 HashVal[MD5_HASHSIZE];

  ZeroMem (&Md5Ctx, sizeof (Md5Ctx));
  MD5Init (&Md5Ctx);

  BegTmp = BufDesc->Begin;
  /* skip start of packet ':' */
  BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  for (Idx = 1; Idx < (RCFG_PKT_DATA_OFFS + DataLen) * 2 + 1; Idx++) {
    if (BegTmp == BufDesc->End) {
      return EFI_ABORTED;
    }
    MD5Update(&Md5Ctx, BegTmp, 1);
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  }

  MD5Final(&Md5Ctx, HashVal);

  ZeroMem (Md5AsciiStrCmp, sizeof (Md5AsciiStrCmp));
  ByteBufToString(
    HashVal, 
    sizeof (HashVal), 
    Md5AsciiStrCmp, 
    sizeof (Md5AsciiStrCmp)
    );

  // skip 2-bytes of CRC-type
  BegTmp = CircPtr8(BegTmp, 2, BufDesc->Base, BufDesc->Size);

  // obtain HASH string
  ZeroMem (Md5AsciiStr, sizeof (Md5AsciiStr));
  for (Idx = 0; Idx < MD5_HASHSIZE * 2; Idx++) {
    Md5AsciiStr[Idx] = *BegTmp;
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);    
  }
  
  if (AsciiStrCmp(Md5AsciiStr, Md5AsciiStrCmp)) {
    LOG ((EFI_D_ERROR, "%a.%d CRC error! Crc=%a CrcCmp=%a\n", 
      __FUNCTION__, __LINE__, Md5AsciiStr, Md5AsciiStrCmp));
    return EFI_CRC_ERROR;
  }
  
  return EFI_SUCCESS;
}

EFI_STATUS
CheckRxPktSymbols (
  IN CIRC_BUF_DESC8 *BufDesc,
  IN UINTN PktLen
  )
{
  UINT8 *BegTmp;
  UINTN Idx;

  if (BufDesc == NULL || PktLen <= 2) {
    return EFI_INVALID_PARAMETER;
  }

  BegTmp = BufDesc->Begin;
  for (Idx = 1; Idx < PktLen - 1; Idx++) {    
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
    if (*BegTmp >= '0' && *BegTmp <= '9') {
      continue;
    }
    if (*BegTmp >= 'a' && *BegTmp <= 'f') {
      continue;
    }
    if (*BegTmp >= 'A' && *BegTmp <= 'F') {
      continue;
    }
    return EFI_ABORTED;
  }
  return EFI_SUCCESS;
}


EFI_STATUS
PktAsciiToPlainBuffer (
  IN CIRC_BUF_DESC8 *BufDesc,
  IN UINTN PktLen,
  OUT UINT8 **PlainBuffer,
  IN OUT UINTN *PlainBufferLen,
  IN OUT UINT8 *StatusCode
  )
{
  UINT8 *BegTmp, *BufPtr;
  UINTN Idx;
  CHAR8 AsciiStr[3];
  EFI_STATUS Status = EFI_SUCCESS;

  if (BufDesc == NULL || PktLen == 0 || PlainBuffer == NULL ||
      PlainBufferLen == NULL || StatusCode == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = CheckRxPktSymbols(BufDesc, PktLen);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  LOG ((EFI_D_ERROR, "%a.%d PktLen=%d BufDesc->Begin=%p\n", 
    __FUNCTION__, __LINE__, PktLen, BufDesc->Begin));
  BegTmp = BufDesc->Begin;

  LOG ((EFI_D_ERROR, "\t *BegTmp=%02X\n", *BegTmp));

  /* skip  start of packet symbol ':' */
  BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
  LOG ((EFI_D_ERROR, "\t *BegTmp=%02X\n", *BegTmp));
  PktLen--;
  /* skip CR */
  PktLen--;

  if (PktLen % 2) {
    *StatusCode = SC_WRONG_PKT_LEN;
    LOG ((EFI_D_ERROR, "%a.%d Error! PktLen=%d\n", 
      __FUNCTION__, __LINE__, PktLen));
    Status = EFI_INVALID_PARAMETER;
  }

  BufPtr = *PlainBuffer = AllocateZeroPool(PktLen / 2);
  if (NULL == PlainBuffer) {
    *StatusCode = SC_RX_INTERNAL_ERR;
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }  
  
  for (Idx = 0; Idx < PktLen / 2; Idx++) {
    if (GetCircBuf8UsedSpace (BufDesc) < 2) {
      *StatusCode = SC_RX_INTERNAL_ERR;
      FreePool (*PlainBuffer);
      *PlainBuffer = NULL;
      *PlainBufferLen = 0;
      LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    AsciiStr[0] = *BegTmp;
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);  
    LOG ((EFI_D_ERROR, "\t *BegTmp=%02X\n", *BegTmp));
    AsciiStr[1] = *BegTmp;
    BegTmp = CircPtr8(BegTmp, 1, BufDesc->Base, BufDesc->Size);
    LOG ((EFI_D_ERROR, "\t *BegTmp=%02X\n", *BegTmp));
    
    AsciiStr[2] = '\0';
    LOG ((EFI_D_ERROR, "\t AsciiStr=%a", AsciiStr));
    *BufPtr++ = (UINT8)(AsciiStrHexToUintn (AsciiStr) & 0xFF);
  }

  *PlainBufferLen = PktLen / 2;
  return Status;
}


STATIC
EFI_STATUS
SendAns (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 Addr,
  IN UINT8 Func,
  IN UINT8 Sc,
  IN UINTN DataLen,
  IN UINT8 *Data,
  IN UINT8 CrcType
  )
{
  CHAR8 *Pkt = NULL, *PtrPkt;
  UINT8 PktNum = 0, Crc;
  UINTN Offs, PktSize, Idx, CrcSize, PktDataLen;
  EFI_STATUS Status = EFI_SUCCESS;
  REMOTE_CFG_PKT_DATA *pData;

  if (This == NULL || Handle == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  CrcType = pData->LastPktCrcType;

  if (CrcType == CRC_TYPE_CRC8) {
    CrcSize = 2;
  } else {
    CrcSize = MD5_HASHSIZE * 2;
  }

  PktSize = RCFG_MIN_PKT_LEN * 2 + DataLen * 2 + CrcSize;
  PtrPkt = Pkt = AllocateZeroPool (PktSize);
  if (PtrPkt == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  Offs = 0;
  PktNum = pData->LastPktNum;
  Offs = AsciiSPrint(PtrPkt, PktSize, ":%02X%02X%02X%02X%08X", 
    Addr, PktNum, Func, Sc, DataLen * 2);
  PtrPkt += Offs;
  PktSize -= Offs;

  for (Idx = 0; Idx < DataLen; Idx++) {
    Offs = AsciiSPrint(PtrPkt, PktSize, "%02X", Data[Idx]);
    PtrPkt += Offs;
    if (PktSize < Offs) {
      Status = EFI_ABORTED;
      goto Done;
    }
    PktSize -= Offs;
  }

  PktDataLen = AsciiStrLen(Pkt);
  
  Crc = 0;
  Offs = AsciiSPrint(PtrPkt, PktSize, "%02X", CrcType);
  PtrPkt += Offs;
  PktSize -= Offs;

  
  if (CrcType == CRC_TYPE_CRC8) {
    UINTN Idx;
    /* Idx = 1 ---- skip start of packet ':' */
    for (Idx = 1; Idx < PktDataLen; Idx++) {
      Crc8Calc(&Crc, Pkt[Idx]);
    }
    Offs = AsciiSPrint(PtrPkt, PktSize, "%02X", Crc);
    PtrPkt += Offs;
    PktSize -= Offs;
  } else if (CrcType == CRC_TYPE_MD5) {
    UINTN Idx;
    MD5_CTX Md5Ctx;
    UINT8 HashVal[MD5_HASHSIZE];
    CHAR8 Md5AsciiStr[(MD5_HASHSIZE + 1) * 2];

    ZeroMem (&Md5Ctx, sizeof (MD5_CTX));

    MD5Init(&Md5Ctx);

    /* Idx = 1 ---- skip start of packet ':' */
    for (Idx = 1; Idx < PktDataLen; Idx++) {
      MD5Update(&Md5Ctx, &Pkt[Idx], 1);
    }
    MD5Final(&Md5Ctx, HashVal);

    ZeroMem (Md5AsciiStr, sizeof (Md5AsciiStr));
    ByteBufToString(
      HashVal, 
      sizeof (HashVal), 
      Md5AsciiStr, 
      sizeof (Md5AsciiStr)
      );
    
    Offs = AsciiSPrint(PtrPkt, PktSize, "%a", Md5AsciiStr);
    PtrPkt += Offs;
    PktSize -= Offs;
  }

  AsciiSPrint(PtrPkt, PktSize, "\n");

  PktSize = AsciiStrLen(Pkt);

  if (GetCircBuf8FreeSpace(&pData->TxPktBuf) <= PktSize) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  LOG ((EFI_D_ERROR, "%a.%d PktSize=%d\n", __FUNCTION__, __LINE__, PktSize));
  for (Idx = 0; Idx < PktSize; Idx++) {
    *pData->TxPktBuf.End = Pkt[Idx];
    pData->TxPktBuf.End = CircPtr8(pData->TxPktBuf.End, 1, pData->TxPktBuf.Base, 
      pData->TxPktBuf.Size);
  }

Done:
  if (Pkt) {
    FreePool (Pkt);
  }
  return Status;
}


EFI_STATUS
CheckStartProtocolPkt (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *Buf,
  IN UINTN BufLen
  )
{
  UINT8 CheckBuf[] = {
    0x00, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x55, 0xAA,
    0xAA, 0x55
    };
  UINT8 Sc = SC_SUCCESS;
  REMOTE_CFG_PKT_DATA *pData;

  if (Handle == NULL || Buf == NULL || BufLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;
  
  if (CompareMem(Buf, CheckBuf, sizeof(CheckBuf))) {
    DumpBytes(Buf, sizeof(CheckBuf));
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (pData->bProtocolStarted) {
    Sc = SC_ALLREADY_STARTED; // set status to allready started
  }

  SendAns (
    This,
    Handle,
    Buf[RCFG_PKT_ADDR_OFFS],
    0x80,
    Sc,
    0,
    NULL,
    pData->LastPktCrcType);

  pData->bProtocolStarted = TRUE;
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}



STATIC
EFI_STATUS
SendSimpleErr (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *PlainBuffer,
  IN UINT8 StatusCode
  )
{
  EFI_STATUS Status;
  REMOTE_CFG_PKT_DATA *pData;

  if (Handle == NULL || PlainBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  PlainBuffer[RCFG_PKT_OPCODE_OFFS] |= RCFG_OPCODE_ANS_FLAG;
  PlainBuffer[RCFG_PKT_STATUS_OFFS] &= ~RCFG_FRAG_PKT_FLAG;
  PlainBuffer[RCFG_PKT_STATUS_OFFS] |= StatusCode;
  WriteUnaligned32((UINT32*)&PlainBuffer[RCFG_PKT_LEN_OFFS], 0);

  Status = SendAns (
              This,
              Handle,
              PlainBuffer[RCFG_PKT_ADDR_OFFS],
              PlainBuffer[RCFG_PKT_OPCODE_OFFS],
              PlainBuffer[RCFG_PKT_STATUS_OFFS],
              0,
              NULL,
              pData->LastPktCrcType
              );
  
  return Status;
}


EFI_STATUS
AddToRxFragmBuffer (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *PlainBuffer,
  IN UINTN PlainBufferLen,
  IN UINTN DataLen
  )
{
  UINTN Idx, Offs;
  REMOTE_CFG_PKT_DATA *pData;

  if (Handle == NULL || PlainBuffer == NULL || DataLen == 0 || 
      PlainBufferLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  if (GetCircBuf8FreeSpace(&pData->RxFragmPktBuf) < PlainBufferLen) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  if (pData->RxFragmPktNum == 0) {
    Offs = 0;
  } else {
    Offs = RCFG_PKT_DATA_OFFS;
  }
  
  
  for (Idx = Offs; Idx < RCFG_PKT_DATA_OFFS + DataLen; Idx++) {
    *pData->RxFragmPktBuf.End = PlainBuffer[Idx];
    pData->RxFragmPktBuf.End = CircPtr8(
                          pData->RxFragmPktBuf.End, 
                          1,
                          pData->RxFragmPktBuf.Base,
                          pData->RxFragmPktBuf.Size);
  }
  return EFI_SUCCESS;
}


EFI_STATUS
AssemblyFragmentedRxPkt (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *PlainBuffer,
  IN UINTN PlainBufferLen,
  IN UINTN DataLen,
  IN OUT UINT8 **AssembledPkt,
  IN OUT UINTN *AssembledPktLen
  )
{
  EFI_STATUS Status;
  UINT8 *TmpPkt;
  UINTN Idx, TmpPktLen;
  REMOTE_CFG_PKT_DATA *pData;

  if (Handle == NULL || PlainBuffer == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  Status = AddToRxFragmBuffer (
                This, 
                Handle, 
                PlainBuffer, 
                PlainBufferLen, 
                DataLen);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  TmpPktLen = GetCircBuf8UsedSpace(&pData->RxFragmPktBuf);
  if (TmpPktLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  TmpPkt = AllocateZeroPool(TmpPktLen);
  if (TmpPkt == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }  

  for (Idx = 0; Idx < TmpPktLen; Idx++) {
    TmpPkt[Idx] = *pData->RxFragmPktBuf.Begin;
    pData->RxFragmPktBuf.Begin = CircPtr8(
                            pData->RxFragmPktBuf.Begin,
                            1,
                            pData->RxFragmPktBuf.Base,
                            pData->RxFragmPktBuf.Size);
  }

  WriteUnaligned32((UINT32*)&TmpPkt[RCFG_PKT_LEN_OFFS], pData->RxFragmTotalLen);
  pData->RxFragmTotalLen = 0;

  *AssembledPkt = TmpPkt;
  *AssembledPktLen = TmpPktLen;

  return EFI_SUCCESS;
}


EFI_STATUS
PktValidation (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  OUT UINT8 **Buf,
  IN OUT UINTN *BufLen
  )
{
  UINTN PktLen, PlainBufferLen;
  UINT8 *PlainBuffer, StatusCode, CrcType;
  EFI_STATUS Status = EFI_SUCCESS;
  UINT32 DataLen;
  REMOTE_CFG_PKT_DATA *pData;

  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  pData->LastPktNum = 0;
  PlainBuffer = NULL;
  PlainBufferLen = 0;
#if 0
  gST->ConOut->ClearScreen (gST->ConOut);
#endif
  PktLen = GetCircBuf8UsedSpace (&pData->RxPktBuf);
  LOG ((EFI_D_ERROR, "%a.%d PktLen=0x%X\n", __FUNCTION__, __LINE__, PktLen));
  
  if (PktLen < RCFG_MIN_PKT_LEN) {
    /* too short packet */
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  Status = PktAsciiToPlainBuffer(
                &pData->RxPktBuf, 
                PktLen, 
                &PlainBuffer, 
                &PlainBufferLen, 
                &StatusCode);
  if (EFI_ERROR(Status)) {
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  LOG ((EFI_D_ERROR, "%a.%d PlainBufferLen=%d\n", 
    __FUNCTION__, __LINE__, PlainBufferLen));
  //DumpBytes (PlainBuffer, PlainBufferLen); 

  ReverseByteBuf (&PlainBuffer[RCFG_PKT_LEN_OFFS], sizeof (UINT32));
  DataLen = ReadUnaligned32((UINT32*)&PlainBuffer[RCFG_PKT_LEN_OFFS]);

  if (DataLen % 2) {
    LOG ((EFI_D_ERROR, "%a.%d DataLen=%X\n", 
      __FUNCTION__, __LINE__, DataLen));
    Status = EFI_INVALID_PARAMETER;
    StatusCode = SC_WRONG_PKT_LEN;
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  DataLen /= 2;

  WriteUnaligned32((UINT32*)&PlainBuffer[RCFG_PKT_LEN_OFFS], DataLen);
  
  pData->LastPktNum = PlainBuffer[RCFG_PKT_NUM_OFFS];

  if (DataLen > (PlainBufferLen - RCFG_PKT_DATA_OFFS)) {
    LOG ((EFI_D_ERROR, "%a.%d DataLen=%X PlainBufferLen=%d\n", 
      __FUNCTION__, __LINE__, DataLen, PlainBufferLen));
    Status = EFI_INVALID_PARAMETER;
    StatusCode = SC_WRONG_PKT_LEN;
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  CrcType = PlainBuffer[RCFG_PKT_DATA_OFFS + DataLen];
  LOG ((EFI_D_ERROR, "%a.%d CrcType = %02X\n", 
    __FUNCTION__, __LINE__, CrcType));
  pData->LastPktCrcType = CrcType;
  if (CrcType == CRC_TYPE_CRC8) {
    if (PktLen < RCFG_MIN_PKT_CRC8_LEN) {
      Status = EFI_INVALID_PARAMETER;
      StatusCode = SC_WRONG_PKT_LEN;
      if (PlainBuffer) {
        SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
      }
      LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto Done;
    }
    Status = ValidateChecksumCrc8(&pData->RxPktBuf, PktLen);    
  } else if (CrcType == CRC_TYPE_MD5) {
    if (PktLen < RCFG_MIN_PKT_MD5_LEN) {
      Status = EFI_INVALID_PARAMETER;
      StatusCode = SC_WRONG_PKT_LEN;
      if (PlainBuffer) {
        SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
      }
      LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto Done;
    }
    Status = ValidateChecksumMD5(&pData->RxPktBuf, PktLen, DataLen);
  } else {
    Status = EFI_CRC_ERROR;
  }

  if (EFI_ERROR(Status)) {
    /* TODO: send error */
    StatusCode = SC_CRC_ERR;
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  /* init protocol pkt check */
  Status = CheckStartProtocolPkt (
              This, 
              Handle, 
              PlainBuffer, 
              PlainBufferLen
              );
  if (!EFI_ERROR(Status)) {
    /* TODO: send error */
    LOG ((EFI_D_ERROR, "%a.%d START PROTOCOL!\n", __FUNCTION__, __LINE__));
    FreePool (PlainBuffer);
    PlainBuffer = NULL;
    PlainBufferLen = 0;
    pData->bRxFragmPkt = FALSE;
    pData->RxFragmPktNum = 0;
    pData->RxFragmPktFunc = PlainBuffer[RCFG_PKT_OPCODE_OFFS];
    pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
      pData->RxFragmPktBuf.Base;
    pData->RxFragmTotalLen = 0;
    goto Done;
  } else {
    Status = EFI_SUCCESS;    
  }
  
  if (!pData->bProtocolStarted) {
    /* TODO: send error */
    StatusCode = SC_PROTOCOL_NOT_INIT;
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  if (PlainBuffer[RCFG_PKT_OPCODE_OFFS] >= FUNC_UNKNOWN) {
    Status = EFI_ABORTED;
    StatusCode = SC_UNKNOWN_FUNC;
    if (PlainBuffer) {
      SendSimpleErr(This, Handle, PlainBuffer, StatusCode);
    }
    /* TODO: send error */
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  if (PlainBuffer[RCFG_PKT_STATUS_OFFS] & RCFG_FRAG_PKT_FLAG) {
    if (pData->bRxFragmPkt) {
      if (pData->RxFragmPktFunc != PlainBuffer[RCFG_PKT_OPCODE_OFFS]) {
        pData->RxFragmPktNum = 0;
        pData->RxFragmPktFunc = PlainBuffer[RCFG_PKT_OPCODE_OFFS];
        pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
          pData->RxFragmPktBuf.Base;
        pData->RxFragmTotalLen = 0;
      }
      if (pData->RxFragmPktNum != PlainBuffer[RCFG_PKT_NUM_OFFS]) {
        pData->RxFragmPktNum = 0;
        pData->RxFragmPktFunc = FUNC_UNKNOWN;
        SendSimpleErr(This, Handle, PlainBuffer, SC_WRONG_PKT_NUM);
        Status = EFI_INVALID_PARAMETER;
      }
    } else {
      if (PlainBuffer[RCFG_PKT_NUM_OFFS] != 0) {
        SendSimpleErr(This, Handle, PlainBuffer, SC_WRONG_PKT_NUM);
        Status = EFI_INVALID_PARAMETER;
      } else {
        pData->RxFragmPktNum = 0;
        pData->RxFragmTotalLen = 0;
        pData->RxFragmPktFunc = PlainBuffer[RCFG_PKT_OPCODE_OFFS];        
      }
    }    

    pData->bRxFragmPkt = FALSE;
    if (EFI_ERROR(Status)) {
      pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
        pData->RxFragmPktBuf.Base;
      pData->RxFragmTotalLen = 0;
    } else {
      pData->RxFragmTotalLen += DataLen;
      Status = AddToRxFragmBuffer (
                    This, 
                    Handle, 
                    PlainBuffer, 
                    PlainBufferLen, 
                    DataLen
                    );
      if (EFI_ERROR(Status)) {
        SendSimpleErr(This, Handle, PlainBuffer, SC_RX_INTERNAL_ERR);
        pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
          pData->RxFragmPktBuf.Base;
        pData->RxFragmTotalLen = 0;
      } else {
        pData->bRxFragmPkt = TRUE;
        pData->RxFragmPktNum++;
        Status = EFI_NOT_READY;
        SendSimpleErr(This, Handle, PlainBuffer, SC_SUCCESS);
      }
    }
  } else {
    if (pData->bRxFragmPkt) {
      if (pData->RxFragmPktFunc != PlainBuffer[RCFG_PKT_OPCODE_OFFS]) {
        
      } else if (pData->RxFragmPktNum != PlainBuffer[RCFG_PKT_NUM_OFFS]) {
        SendSimpleErr(This, Handle, PlainBuffer, SC_WRONG_PKT_NUM);
        Status = EFI_INVALID_PARAMETER;
      } else {
        UINT8 *AssembledPkt;
        UINTN AssembledPktLen;
        pData->RxFragmTotalLen += DataLen;
        Status = AssemblyFragmentedRxPkt(
                    This,
                    Handle,
                    PlainBuffer,
                    PlainBufferLen, 
                    DataLen,
                    &AssembledPkt, 
                    &AssembledPktLen);
        if (EFI_ERROR(Status)) {
          SendSimpleErr(This, Handle, PlainBuffer, SC_RX_INTERNAL_ERR);  
        } else {
          FreePool (PlainBuffer);
          PlainBufferLen = AssembledPktLen;
          PlainBuffer = AssembledPkt;
        }
        
      }      
    }
    pData->RxFragmPktNum = 0;
    pData->RxFragmPktFunc = FUNC_UNKNOWN;
    pData->bRxFragmPkt = FALSE;
    pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
      pData->RxFragmPktBuf.Base;
  } 
  

Done:
  if (EFI_ERROR(Status)) {
    if (PlainBuffer != NULL) {
      FreePool (PlainBuffer);
    }
    *Buf = NULL;
    *BufLen = 0;
  } else {
    *Buf = PlainBuffer;
    *BufLen = PlainBufferLen;
  }
  LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
MainRxPktFsm (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *InBuf,
  IN UINTN InBufLen,
  OUT UINT8 **Buf,
  IN OUT UINTN *BufLen
  )
{
  EFI_STATUS RxStatus = EFI_SUCCESS;
  REMOTE_CFG_PKT_DATA *pData;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Handle == NULL || InBuf == NULL || InBufLen == 0 || 
      Buf == NULL || BufLen == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  if (pData->RxPktBuf.Base == NULL || pData->RxPktBuf.Size == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_READY;
  }

  while (InBufLen--) {
    switch (pData->State) {
    case ST_START:
      if (*InBuf == RCFG_PKT_START_BYTE) {
        pData->RxPktBuf.Begin = pData->RxPktBuf.End = pData->RxPktBuf.Base;
        *pData->RxPktBuf.End = *InBuf;
        LOG ((EFI_D_ERROR, "\t *RxPktBuf.End=%X\n", *pData->RxPktBuf.End));  
        LOG ((EFI_D_ERROR, "\t RxPktBuf.End=%p\n", pData->RxPktBuf.End));
        pData->RxPktBuf.End = CircPtr8 (pData->RxPktBuf.End, 1, 
          pData->RxPktBuf.Base, pData->RxPktBuf.Size);
        LOG ((EFI_D_ERROR, "\t RxPktBuf.End=%p\n", pData->RxPktBuf.End));
        pData->State = ST_PKT;
      }
      break;

    case ST_PKT:
      if (GetCircBuf8FreeSpace (&pData->RxPktBuf) >= 1) {
        *pData->RxPktBuf.End = *InBuf;
        LOG ((EFI_D_ERROR, "\t *RxPktBuf.End=%X\n", *pData->RxPktBuf.End));  
        LOG ((EFI_D_ERROR, "\t RxPktBuf.End=%p\n", pData->RxPktBuf.End));
        pData->RxPktBuf.End = CircPtr8 (pData->RxPktBuf.End, 1, pData->RxPktBuf.Base, 
          pData->RxPktBuf.Size);
        LOG ((EFI_D_ERROR, "\t RxPktBuf.End=%p\n", pData->RxPktBuf.End));
      } else {
        // overflow flag
      }
      if (*InBuf == RCFG_PKT_END_CR) {    
        LOG ((EFI_D_ERROR, "%a.%d New Pkt RX!\n", __FUNCTION__, __LINE__));
        RxStatus = PktValidation (This, Handle, Buf, BufLen);
        pData->State = ST_START;
      } else if (*InBuf == RCFG_PKT_START_BYTE) {
        // reset buffer 
        pData->RxPktBuf.Begin = pData->RxPktBuf.End = pData->RxPktBuf.Base;
      }
      break;

    default:
      pData->State = ST_START;
    }
    InBuf++;
  }

  return RxStatus;
}

EFI_STATUS
RemoteCfgPktClose (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN OUT EFI_HANDLE Handle
  )
{
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA *)Handle;
  if (pData->RxFragmPktBuf.Base) {
    FreePool (pData->RxFragmPktBuf.Base);
  }
  if (pData->RxPktBuf.Base) {
    FreePool (pData->RxPktBuf.Base);
  }
  if (pData->TxPktBuf.Base) {
    FreePool (pData->TxPktBuf.Base);
  }

  FreePool (Handle);

  return EFI_SUCCESS;
}


#define MAX_RX_PKT_SIZE       (8192 * 1024)
#define MAX_TX_PKT_SIZE       (1024 * 1024)


EFI_STATUS
RemoteCfgPktOpen (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN OUT EFI_HANDLE *Handle
  )
{
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  pData = AllocateZeroPool (sizeof(*pData));
  if (pData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  pData->RxPktBuf.Base = AllocateZeroPool (MAX_RX_PKT_SIZE);
  if (pData->RxPktBuf.Base == NULL) {
    RemoteCfgPktClose (This, (EFI_HANDLE)pData);
    return EFI_OUT_OF_RESOURCES;
  }
  pData->RxPktBuf.Begin = pData->RxPktBuf.End = pData->RxPktBuf.Base;
  pData->RxPktBuf.Size = MAX_RX_PKT_SIZE;

  pData->TxPktBuf.Base = AllocateZeroPool (MAX_TX_PKT_SIZE);
  if (pData->TxPktBuf.Base == NULL) {
    RemoteCfgPktClose (This, (EFI_HANDLE)pData);
    return EFI_OUT_OF_RESOURCES;
  }
  pData->TxPktBuf.Begin = pData->TxPktBuf.End = 
      pData->TxPktBuf.Base;
  pData->TxPktBuf.Size = MAX_TX_PKT_SIZE;

  pData->RxFragmPktBuf.Base = AllocateZeroPool (MAX_RX_PKT_SIZE);
  if (pData->RxFragmPktBuf.Base == NULL) {
    RemoteCfgPktClose (This, (EFI_HANDLE)pData);
    return EFI_OUT_OF_RESOURCES;
  }
  pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
    pData->RxFragmPktBuf.Base;
  pData->RxFragmPktBuf.Size = MAX_RX_PKT_SIZE;

  *Handle = (EFI_HANDLE)pData;
  return EFI_SUCCESS;
}

STATIC
UINT8
GetState (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  )
{
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL) {
    return ST_ERR;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;
  return pData->State;
}

STATIC
BOOLEAN
ProtocolStarted (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  )
{
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL) {
    return FALSE;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;
  return pData->bProtocolStarted;
}

STATIC 
EFI_STATUS
ProcessingRxPackets (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *InData,
  IN UINTN InDataLen,
  IN OUT BOOLEAN *bNewPktRx,
  IN OUT UINT8 **NewPkt,
  IN OUT UINTN *NewPktLen
  )
{
  EFI_STATUS Status;
  
  if (This == NULL || Handle == NULL || InData == NULL || bNewPktRx == NULL ||
      NewPkt == NULL || NewPktLen == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  *bNewPktRx = FALSE;
  *NewPkt = NULL;
  *NewPktLen = 0;
  

  Status = MainRxPktFsm (
              This,
              Handle,
              InData, 
              InDataLen,
              NewPkt,
              NewPktLen);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  LOG ((EFI_D_ERROR, "%a.%d *NewPktLen=%d {%p}\n", 
    __FUNCTION__, __LINE__, *NewPktLen, *NewPkt));
  if (*NewPkt != NULL && *NewPktLen != 0) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    *bNewPktRx = TRUE;
  }
  return EFI_SUCCESS;
}

STATIC 
VOID
ResetState (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  )
{
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL) {
    return;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;
  pData->State = ST_START;
  pData->bProtocolStarted = FALSE;
  pData->RxFragmPktBuf.Begin = pData->RxFragmPktBuf.End = 
    pData->RxFragmPktBuf.Base;
  pData->RxFragmTotalLen = 0;
  
  pData->RxPktBuf.Begin = pData->RxPktBuf.End = pData->RxPktBuf.Base;

  pData->TxPktBuf.Begin = pData->TxPktBuf.End = pData->TxPktBuf.Base;
}


STATIC 
EFI_STATUS
Tx (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *TxBuf,
  IN OUT UINTN *TxLen
  )
{
  UINTN Idx, Len;
  REMOTE_CFG_PKT_DATA *pData;
  
  if (This == NULL || Handle == NULL || TxBuf == NULL || TxLen == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (*TxLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  pData = (REMOTE_CFG_PKT_DATA*)Handle;

  Len = GetCircBuf8UsedSpace(&pData->TxPktBuf);
  if (Len == 0) {
    *TxLen = 0;    
    return EFI_SUCCESS;
  }

  LOG ((EFI_D_ERROR, "%a.%d Len=%d *TxLen=%d\n", 
    __FUNCTION__, __LINE__, Len, *TxLen));

  if (Len > *TxLen) {
    Len = *TxLen;
  }

  for (Idx = 0; Idx < Len; Idx++) {
    *TxBuf++ = *pData->TxPktBuf.Begin;
    pData->TxPktBuf.Begin = CircPtr8(
                pData->TxPktBuf.Begin, 
                1, 
                pData->TxPktBuf.Base, 
                pData->TxPktBuf.Size
                );
  }

  LOG ((EFI_D_ERROR, "%a.%d Len=%d\n", __FUNCTION__, __LINE__, Len));
  *TxLen = Len;
  
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
RemoteCfgPktDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  RemotePktPrivateData.DriverHandle = ImageHandle;
  RemotePktPrivateData.HandlerProtocol.GetState = GetState;
  RemotePktPrivateData.HandlerProtocol.ProcessingRxPackets = ProcessingRxPackets;
  RemotePktPrivateData.HandlerProtocol.ProtocolClose = RemoteCfgPktClose;
  RemotePktPrivateData.HandlerProtocol.ProtocolOpen = RemoteCfgPktOpen;
  RemotePktPrivateData.HandlerProtocol.ProtocolStarted = ProtocolStarted;
  RemotePktPrivateData.HandlerProtocol.ResetState = ResetState;
  RemotePktPrivateData.HandlerProtocol.SendAns = SendAns;
  RemotePktPrivateData.HandlerProtocol.Tx = Tx;
  
  Status = gBS->InstallProtocolInterface( 
    &RemotePktPrivateData.DriverHandle, 
    &gRemoteCfgPktProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &RemotePktPrivateData.HandlerProtocol
    );

  LOG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  
  return Status;
}

