/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <Library/Base64.h>

CONST CHAR8 Base64TblDefault[] = 
    "ABCD""EFGH""IJKL""MNOP" //0x00 - 0x0F
    "QRST""UVWX""YZab""cdef" //0x10 - 0x1F
    "ghij""klmn""opqr""stuv" //0x20 - 0x2F
    "wxyz""0123""4567""89+/" //0x30 - 0x3F
    "="; //end filling symbol
CONST CHAR8 Base64TblCustom[] = 
    "ABCD""EFGH""IJKL""MNOP" //0x00 - 0x0F
    "QRST""UVWX""YZab""cdef" //0x10 - 0x1F
    "ghij""klmn""opqr""stuv" //0x20 - 0x2F
    "wxyz""0123""4567""89#=" //0x30 - 0x3F
    "-"; //end filling symbol

BOOLEAN
Base64TestChar(
  IN CONST CHAR8 *Base64Tbl,
  IN CHAR8 Letter
  )
{
  UINT8 i;
  for (i = 0; i < BASE64_TBL_SIZE; i++) {
    if (Base64Tbl[i] == Letter) {
      return TRUE;
    }
  }
  if (Letter == Base64Tbl[BASE64_FILL_SYMBOL]) {
    return TRUE;
  }
  return FALSE;
}

INTN
Base64EncodeCustom(
  IN CONST CHAR8 *Base64Tbl,
  IN CONST UINT8 *Buf,
  IN UINTN BufLen,
  OUT CHAR8 *StrEnc,
  IN UINTN StrEncMaxLen,
  OUT UINTN *StrEncLen
  )
{
  UINTN StrNeededSize;
  UINTN iBuf, CurBlockLen;
  UINTN iStr;
  
  //call to Base64Encode(NULL, BufLen, NULL, 0, NULL) returns string size needed for encoding
  StrNeededSize = (BufLen + ((BufLen % 3 == 0) ? 0 : (3 - (BufLen % 3))) ) * 4 / 3 + 1;
  if (StrNeededSize > StrEncMaxLen) {
    if (StrEncLen != NULL) {
      *StrEncLen = StrNeededSize;
      return 0;
    } else {
      return -1;
    }
  }

  if (Buf == NULL || StrEnc == NULL) {
    return -1;
  }

  for (iBuf = 0, iStr = 0; iBuf < BufLen; iBuf+=3, iStr+=4) {
    CurBlockLen = ((BufLen - iBuf) >= 3 ? 3: (BufLen - iBuf));

    StrEnc[iStr + 0] = Base64Tbl[ Buf[iBuf + 0] >> 2 ];
    StrEnc[iStr + 1] = Base64Tbl[ ((Buf[iBuf + 0] & 0x03) << 4) | (CurBlockLen > 1 ? ((Buf[iBuf + 1] & 0xF0) >> 4) : 0) ];

    StrEnc[iStr + 2] = (CurBlockLen > 1 ? Base64Tbl[ ((Buf[iBuf + 1] & 0x0F) << 2) | ((Buf[iBuf + 2] & 0xC0) >> 6) ] : Base64Tbl[BASE64_FILL_SYMBOL]);
    StrEnc[iStr + 3] = (CurBlockLen > 2 ? Base64Tbl[ Buf[iBuf + 2] & 0x3F ] : Base64Tbl[BASE64_FILL_SYMBOL]);
  }
  StrEnc[iStr] = '\0';

  if (StrEncLen != NULL) {
    *StrEncLen = iStr;
  }

  return 0;
}

INTN
Base64Encode(
  IN CONST UINT8 *Buf,
  IN UINTN BufLen,
  OUT CHAR8 *StrEnc,
  IN UINTN StrEncMaxLen,
  OUT UINTN *StrEncLen
  )
{
  return Base64EncodeCustom(Base64TblDefault, Buf, BufLen, StrEnc, StrEncMaxLen, StrEncLen);
}

UINT8
Base64ReverseChar(
  IN CONST CHAR8 *Base64Tbl,
  IN CHAR8 Letter
  )
{
  UINT8 i;
  for (i = 0; i < BASE64_TBL_SIZE; i++) {
    if (Base64Tbl[i] == Letter) {
      return i;
    }
  }
  if (Letter == Base64Tbl[BASE64_FILL_SYMBOL]) {
    return BASE64_FILL_SYMBOL;
  }
  return BASE64_BAD_SYMBOL;
}

INTN
Base64DecodeCustom(
  IN CONST CHAR8 *Base64Tbl,
  IN CONST CHAR8 *Str,
  OUT UINT8 *BufDec,
  IN UINTN BufDecMaxLen,
  OUT UINTN *BufDecLen
  )
{
  UINTN StrLength;
  UINTN BufNeededSize;
  UINTN iStr, CurBlockLen;
  UINTN iBuf;
  UINT8 TmpStr[4];
  UINTN iTmp;
  
  if (Str == NULL) {
    return -1;
  }
  StrLength = AsciiStrLen(Str);

  //call to Base64Decode(Str, NULL, 0, NULL) returns buf size needed for decoding
  BufNeededSize = StrLength * 3 / 4;
  if (BufNeededSize > BufDecMaxLen) {
    if (BufDecLen != NULL) {
      *BufDecLen = BufNeededSize;
      return 0;
    } else {
      return -1;
    }
  }

  if (BufDec == NULL) {
    return -1;
  }

  for (iStr = 0, iBuf = 0; iStr < StrLength; iStr+=4) {
    CurBlockLen = ((StrLength - iStr) >= 4 ? 4: (StrLength - iStr));
    
    for (iTmp = 0; iTmp < CurBlockLen; iTmp++) {
      TmpStr[iTmp] = Base64ReverseChar(Base64Tbl, Str[iStr + iTmp]);
      if (TmpStr[iTmp] == BASE64_FILL_SYMBOL) {
        CurBlockLen = iTmp;
        break;
      } if (TmpStr[iTmp] == BASE64_BAD_SYMBOL) {
        return -1;
      }
    }

    if (CurBlockLen >= 2) {
      BufDec[iBuf] = (TmpStr[0] << 2 | TmpStr[1] >> 4);
      iBuf++;
    }
    if (CurBlockLen >= 3) {
      BufDec[iBuf] = (TmpStr[1] << 4 | TmpStr[2] >> 2);
      iBuf++;
    }
    if (CurBlockLen == 4) {
      BufDec[iBuf] = (((TmpStr[2] << 6) & 0xc0) | TmpStr[3]);
      iBuf++;
    }
    if (CurBlockLen < 4) {
      break;
    }
  }

  if (BufDecLen != NULL) {
    *BufDecLen = iBuf;
  }

  return 0;
}

INTN
Base64Decode(
  IN CONST CHAR8 *Str,
  OUT UINT8 *BufDec,
  IN UINTN BufDecMaxLen,
  OUT UINTN *BufDecLen
  )
{
  return Base64DecodeCustom(Base64TblDefault, Str, BufDec, BufDecMaxLen, BufDecLen);
}
