/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <Library/Base32.h>

CONST CHAR8 Base32Tbl[] = 
    "AB1C""DE2F""GH3I""JK4L" //0x00 - 0x0F
    "MN5P""QR6S""TU7V""8W9X" //0x10 - 0x1F
    "Y"//end filling symbol
    "OZ0";//unused

BOOLEAN
Base32TestChar(
  IN CHAR8 Letter
  )
{
  UINT8 i;
  //case insensitive
  if (Letter >= 'a' && Letter <= 'z') {
    Letter = Letter - ('a' - 'A');
  }
  for (i = 0; i < BASE32_TBL_SIZE; i++) {
    if (Base32Tbl[i] == Letter) {
      return TRUE;
    }
  }
  if (Letter == Base32Tbl[BASE32_FILL_SYMBOL]) {
    return TRUE;
  }
  return FALSE;
}

INTN
Base32Encode(
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
  
  //call to Base32Encode(NULL, BufLen, NULL, 0, NULL) returns string size needed for encoding
  StrNeededSize = (BufLen + ((BufLen % 5 == 0) ? 0 : (5 - (BufLen % 5))) ) * 8 / 5 + 1;
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

  for (iBuf = 0, iStr = 0; iBuf < BufLen; iBuf+=5, iStr+=8) {
    CurBlockLen = ((BufLen - iBuf) >= 5 ? 5: (BufLen - iBuf));
    
    //0 - 5
    StrEnc[iStr + 0] = Base32Tbl[ Buf[iBuf + 0] >> 3 ];
    //0 - 3, 1 - 2
    StrEnc[iStr + 1] = Base32Tbl[ ((Buf[iBuf + 0] & 0x07) << 2) | (CurBlockLen > 1 ? ((Buf[iBuf + 1] & 0xC0) >> 6) : 0) ];
    //1 - 5
    StrEnc[iStr + 2] = Base32Tbl[ (CurBlockLen > 1 ? ((Buf[iBuf + 1] & 0x3E) >> 1) : BASE32_FILL_SYMBOL) ];
    //1 - 1, 2 - 4
    StrEnc[iStr + 3] = (CurBlockLen > 1 ? 
      Base32Tbl[ ((Buf[iBuf + 1] & 0x01) << 4) | (CurBlockLen > 2 ? ((Buf[iBuf + 2] & 0xF0) >> 4) : 0) ] : 
      Base32Tbl[BASE32_FILL_SYMBOL]);
    //2 - 4, 3 - 1
    StrEnc[iStr + 4] = (CurBlockLen > 2 ? 
      Base32Tbl[ ((Buf[iBuf + 2] & 0x0F) << 1) | (CurBlockLen > 3 ? ((Buf[iBuf + 3] & 0x80) >> 7) : 0) ] : 
      Base32Tbl[BASE32_FILL_SYMBOL]);
    //3 - 5
    StrEnc[iStr + 5] = Base32Tbl[ (CurBlockLen > 3 ? ((Buf[iBuf + 3] & 0x7C) >> 2) : BASE32_FILL_SYMBOL) ];
    //3 - 2, 4 - 3
    StrEnc[iStr + 6] = (CurBlockLen > 3 ? 
      Base32Tbl[ ((Buf[iBuf + 3] & 0x03) << 3) | (CurBlockLen > 4 ? ((Buf[iBuf + 4] & 0xE0) >> 5) : 0) ] : 
      Base32Tbl[BASE32_FILL_SYMBOL]);
    //4 - 5
    StrEnc[iStr + 7] = Base32Tbl[ (CurBlockLen > 4 ? (Buf[iBuf + 4] & 0x1F) : BASE32_FILL_SYMBOL) ];
  }
  StrEnc[iStr] = '\0';

  if (StrEncLen != NULL) {
    *StrEncLen = iStr;
  }

  return 0;
}

UINT8
Base32ReverseChar(
  IN CHAR8 Letter
  )
{
  UINT8 i;
  //case insensitive
  if (Letter >= 'a' && Letter <= 'z') {
    Letter = Letter - ('a' - 'A');
  }
  for (i = 0; i < BASE32_TBL_SIZE; i++) {
    if (Base32Tbl[i] == Letter) {
      return i;
    }
  }
  if (Letter == Base32Tbl[BASE32_FILL_SYMBOL]) {
    return BASE32_FILL_SYMBOL;
  }
  return BASE32_BAD_SYMBOL;
}

INTN
Base32Decode(
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
  UINT8 TmpStr[8];
  UINTN iTmp;
  
  if (Str == NULL) {
    return -1;
  }
  StrLength = AsciiStrLen(Str);

  //call to Base32Decode(Str, NULL, 0, NULL) returns buf size needed for decoding
  BufNeededSize = StrLength * 5 / 8;
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

  for (iStr = 0, iBuf = 0; iStr < StrLength; iStr+=8) {
    CurBlockLen = ((StrLength - iStr) >= 8 ? 8: (StrLength - iStr));
    
    for (iTmp = 0; iTmp < CurBlockLen; iTmp++) {
      TmpStr[iTmp] = Base32ReverseChar(Str[iStr + iTmp]);
      if (TmpStr[iTmp] == BASE32_FILL_SYMBOL) {
        CurBlockLen = iTmp;
        break;
      } if (TmpStr[iTmp] == BASE32_BAD_SYMBOL) {
        return -1;
      }
    }

    if (CurBlockLen >= 2) {//0 - 5, 1 - 3
      BufDec[iBuf] = (TmpStr[0] << 3 | TmpStr[1] >> 2);
      iBuf++;
    }
    if (CurBlockLen >= 4) {//1 - 2, 2 - 5, 3 - 1
      BufDec[iBuf] = (TmpStr[1] << 6 | TmpStr[2] << 1 | TmpStr[3] >> 4);
      iBuf++;
    }
    if (CurBlockLen >= 5) {//3 - 4, 4 - 4
      BufDec[iBuf] = (TmpStr[3] << 4 | TmpStr[4] >> 1);
      iBuf++;
    }
    if (CurBlockLen >= 7) {//4 - 1, 5 - 5, 6 - 2
      BufDec[iBuf] = (TmpStr[4] << 7 | TmpStr[5] << 2 | TmpStr[6] >> 3);
      iBuf++;
    }
    if (CurBlockLen == 8) {//6 - 3, 7 - 5
      BufDec[iBuf] = (TmpStr[6] << 5 | TmpStr[7]);
      iBuf++;
    }
    if (CurBlockLen < 8) {
      break;
    }
  }

  if (BufDecLen != NULL) {
    *BufDecLen = iBuf;
  }

  return 0;
}
