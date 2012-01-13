/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/Ccid.h>



EFI_STATUS
CcidCheckRespone(
  IN CCID_RESPONSE_MSG_HEADER *ResultMessage,
  IN UINTN Length
  )
{
  if( ResultMessage->bStatus.bmCommandStatus == CCID_RESPONSE_NO_ERROR ) {
    return EFI_SUCCESS;
  }

  if( ResultMessage->bStatus.bmCommandStatus == CCID_RESPONSE_MORE_TIME ) {
    return EFI_NOT_READY;
  }

  switch( ResultMessage->bError ) {
  case CCID_ERR_ICC_MUTE:
    return EFI_NO_MEDIA;
    
  case CCID_ERR_XFR_PARITY:
  case CCID_ERR_OVERRUN:
    return EFI_PROTOCOL_ERROR;
    
  case CCID_ERR_BAD_ATR_TS:
  case CCID_ERR_BAD_ATR_TCK:
    return EFI_PROTOCOL_ERROR;
    
  case CCID_ERR_PROT_NOSUP:
  case CCID_ERR_CLASS_NOSUP:
    return EFI_UNSUPPORTED;
    
  case CCID_ERR_BAD_PROC_BYTE:
    return EFI_INVALID_PARAMETER;
    
  case CCID_ERR_BUSY_AUTO_SEQ:
  case CCID_ERR_SLOT_BUSY:
    return EFI_TIMEOUT;
    
  case CCID_ERR_PIN_TIMEOUT:
    return EFI_TIMEOUT;
    
  case CCID_ERR_PIN_CANCELED:
    return EFI_ABORTED;
    
  case CCID_OFFSET_MSGTYPE:
    return EFI_UNSUPPORTED;
    
  case CCID_OFFSET_SLOT:
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_PROTOCOL_ERROR;
}


EFI_STATUS
CcidParseAtr(
  OUT    CCID_ATR_INFO *AtrInfo,
  IN     UINT8 *Atr,
  IN     UINTN AtrLength
  )
{
  EFI_STATUS Status;
  ATR_BYTE *AtrStr;
  UINTN Index;
          // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
  UINT8 BitsLen[] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };


  if(AtrInfo == NULL || Atr == NULL || AtrLength == 0) {
    Status = EFI_INVALID_PARAMETER;
    goto _exit;
  }

  ZeroMem( AtrInfo, sizeof(CCID_ATR_INFO) );

  for( Index = 0; Index < 4; Index++ ) {
    AtrInfo->TA[Index] = ATR_NONE;
    AtrInfo->TB[Index] = ATR_NONE;
    AtrInfo->TC[Index] = ATR_NONE;
  }

  AtrStr = (ATR_BYTE *) Atr;

  if( (UINTN)(AtrStr->T0.K + 2) > AtrLength) {
    Status = EFI_INVALID_PARAMETER;
    goto _exit;
  }

  // Skip historical bytes
  AtrLength -= AtrStr->T0.K;

  Index = 0;
  while(TRUE) {
    ATR_BYTE_TDI TDi;
    UINTN Length;

    if(Index > 3) {
      Status = EFI_INVALID_PARAMETER;
      goto _exit;
    }


    TDi = AtrStr->TDi;
    Length = AtrStr->TDByte - Atr;

    if( (TDi.Y == 0) || ((BitsLen[TDi.Y] + Length) > AtrLength)) {
      Status = EFI_INVALID_PARAMETER;
      goto _exit;
    }

    if( Index ) {
      if( AtrInfo->DefaultProtocol == CCID_PROTOCOL_NONE ) {
        AtrInfo->DefaultProtocol = TDi.T;
      }
      AtrInfo->SupportedProtocols |= (1 << TDi.T);
    }

    if( TDi.Y & ATR_TA ) {
      AtrInfo->TA[Index] = AtrStr->Data;
      ATR_NEXT(AtrStr);
    }

    if( TDi.Y & ATR_TB ) {
      AtrInfo->TB[Index] = AtrStr->Data;
      ATR_NEXT(AtrStr);
    }

    if( TDi.Y & ATR_TC ) {
      AtrInfo->TC[Index] = AtrStr->Data;
      ATR_NEXT(AtrStr);
    }

    if( TDi.Y & ATR_TCK ) {
      break;
    }

    ATR_NEXT(AtrStr);
    Index++;
  }

  if(AtrInfo->SupportedProtocols == 0) {
    AtrInfo->SupportedProtocols = CCID_PROTOCOL_T0;
    AtrInfo->DefaultProtocol = CCID_PROTOCOL_T0;
  }

  DEBUG((EFI_D_ERROR, "supported protocols:0x%x default:0x%x\n",
  AtrInfo->SupportedProtocols, AtrInfo->DefaultProtocol ));

  Status = EFI_SUCCESS;

_exit:
  return Status;
}




EFI_STATUS
CcidBuildCommand(
  IN OUT CCID_CMD *CcidCmd,
  IN UINTN CommandLen,
  IN UINT8 Slot,
  IN UINT8 Cmd,
  IN CCID_CTL *Ctl,
  IN UINT8 *SendData,
  IN UINTN SendDataLen,
  IN OUT UINT8 *Sequence
  )
{
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if(CcidCmd == NULL || CommandLen == 0) {
    Status = EFI_INVALID_PARAMETER;
    goto _exit;
  }

  if( SendDataLen + sizeof(CCID_CMD_HEADER) > CommandLen) {
    Status = EFI_BAD_BUFFER_SIZE;
    goto _exit;
  }

  CcidCmd->Header.Command = Cmd;
  CcidCmd->Header.Length = (UINT32) SendDataLen;
  CcidCmd->Header.Slot = Slot;
  CcidCmd->Header.Sequence = (*Sequence)++;

  if( Ctl != NULL ) {
    CopyMem( &CcidCmd->Ctl.Raw, Ctl, sizeof(CCID_CTL) );
  } else {
    ZeroMem( &CcidCmd->Ctl.Raw, sizeof(CCID_CTL) );
  }

  if( SendDataLen ) {
    CopyMem( &CcidCmd->abCommandRawData[0], SendData, SendDataLen );
  }

  Status = EFI_SUCCESS;

_exit:
  DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


