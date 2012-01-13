/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Apdu.h"
#include "SmartCard.h"

struct _APDU_STRUCT {
  APDU_COMMAND Command;
  APDU_CLASS   Class;

};

VOID
ApduBuild (
  IN     APDU         *Apdu,
  IN     APDU_TYPE    Type,
  IN     APDU_CLASS   Class,
  IN     APDU_COMMAND Command,
  IN     UINT8        P1,
  IN     UINT8        P2
  )
{
  ASSERT (Apdu != NULL);
  ZeroMem (Apdu, sizeof(APDU));
  Apdu->Type = Type;
  Apdu->Cla = Class;
  Apdu->Ins = Command;
  Apdu->P1 = P1;
  Apdu->P2 = P2;
}

EFI_STATUS
ApduSetData (
  IN     APDU   *Apdu,
  IN     VOID   *Data,
  IN     UINT16 DataLen
  )
{
  if (Apdu == NULL || Data == NULL || DataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Apdu->DataLen = DataLen;
  Apdu->Lc = DataLen;
  Apdu->Data = Data;
  return EFI_SUCCESS;
}

EFI_STATUS
ApduSetResData (
  IN     APDU   *Apdu,
  IN     VOID   *Result,
  IN     UINT16 ResultLength
  )
{
  if (Apdu == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Result == NULL && ResultLength != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Result != NULL && ResultLength == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Apdu->ResponseLen = ResultLength;
  Apdu->Le = ResultLength;
  Apdu->ResponseData = Result;
  return EFI_SUCCESS;
}

UINTN
ApduLength (
  IN     APDU CONST *Apdu,
  IN     CARD_PROTO Proto
  )
{
  UINTN Result = 4; // Cla+Ins+P1+P2

  if (Apdu == NULL) {
    return Result;
  }

  switch (Apdu->Type) {
  case APDU_TYPE_1:
    if (Proto == ProtoT0) {
      Result++;
    }

    break;
  case APDU_TYPE_2_SHORT:
    Result++;
    break;
  case APDU_TYPE_2_EXT:
    Result += (Proto == ProtoT0 ? 1 : 3 );
    break;
  case APDU_TYPE_3_SHORT:
    Result += Apdu->Lc + 1;
    break;
  case APDU_TYPE_3_EXT:
    Result += Apdu->Lc + (Proto == ProtoT0 ? 1 : 3 );
   break;
  case  APDU_TYPE_4_SHORT:
    Result += Apdu->Lc + (Proto == ProtoT0 ? 1 : 2);
   break;
  case  APDU_TYPE_4_EXT:
    Result += Apdu->Lc + (Proto == ProtoT0 ? 1 : 5);
    break;
  default:
    Result = 0;
  }

  return Result;
}

static inline void emit (CHAR16 const *s) { DEBUG ((EFI_D_ERROR, "%s\n", s)); }
static inline void Dump (void const *d, UINTN l, void (*emit)(CHAR16 const *))
{
        if (d != NULL && emit != NULL)
        {
                UINT8 const *p = d;
                UINT8 const *const start = p;
                UINT8 const *const end = p + l;

                while (p < end)
                {
                        CHAR16 const xlat[] = {
                                L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7',
                                L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F' };

                        CHAR16 buf[80];
                        CHAR16 *phex = buf + 7;
                        CHAR16 *psym = phex + 49;
                        UINT8 const *const lend = p + 16 < end ? p + 16 : end;
                        UINTN v = p - start;

                        buf[0] = xlat[(v >> 12) & 0xf];
                        buf[1] = xlat[(v >> 8) & 0xf];
                        buf[2] = xlat[(v >> 4) & 0xf];
                        buf[3] = xlat[v & 0xf];
                        buf[4] = L':';
                        buf[5] = buf[6] = L' ';

                        while (p < lend)
                        {
                                unsigned int sym = *p++;

                                *phex++ = xlat[(sym >> 4) & 0xf];
                                *phex++ = xlat[sym & 0xf];
                                *phex++ = L' ';
                                *psym++ = sym < ' ' || sym > '~' ? L'.' : (CHAR16)sym;
                        }

                        while (phex < buf + 7 + 49)
                          *phex++ = L' ';

                        *psym = L'\0';
                        (*emit)(buf);
                }
        }
}

EFI_STATUS
Apdu2Buffer (
  IN     APDU CONST *Apdu,
  IN     CARD_PROTO Proto,
  IN     UINT8      *Buffer,
  IN OUT UINTN      *BufferLength
  )
{
  UINTN      Length;
  UINT8      *Ptr;

#define PutByte(X) *Ptr++ = (UINT8)(X)

  Ptr = Buffer;

  if (Apdu == NULL || Buffer == NULL || BufferLength == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Length = ApduLength (Apdu, Proto);

  if ((Length == 0) || (Length > *BufferLength)) {
    return EFI_INVALID_PARAMETER;
  }

  PutByte (Apdu->Cla);
  PutByte (Apdu->Ins);
  PutByte (Apdu->P1);
  PutByte (Apdu->P2);

  switch (Apdu->Type) {
  case APDU_TYPE_1:
    if (Proto == ProtoT0) {
      PutByte (0);
    }
    break;

  case APDU_TYPE_2_SHORT:
    PutByte (Apdu->Le);
    break;

  case APDU_TYPE_2_EXT:
    if (Proto == ProtoT0) {
      PutByte (Apdu->Le);
    } else {
      PutByte (0);
      PutByte (Apdu->Le >> 8);
      PutByte (Apdu->Le);
    }
    break;

  case APDU_TYPE_3_SHORT:
    PutByte (Apdu->Lc);
    CopyMem (Ptr, Apdu->Data, Apdu->Lc);
    Ptr += Apdu->Lc;
    break;

  case APDU_TYPE_3_EXT:
    if (Proto == ProtoT0) {
      if (Apdu->Lc > 255) {
        return EFI_INVALID_PARAMETER;
      }
      // XXX Is need  Lc copy?
    } else {
      PutByte (0);
      PutByte (Apdu->Lc >> 8);
      PutByte (Apdu->Lc);
    }

    CopyMem (Ptr, Apdu->Data, Apdu->Lc);
    Ptr += Apdu->Lc;
    break;

  case APDU_TYPE_4_SHORT:
    PutByte (Apdu->Lc);
    CopyMem (Ptr, Apdu->Data, Apdu->Lc);
    Ptr += Apdu->Lc;

    if (Proto != ProtoT0) {
      PutByte (Apdu->Le);
    }

    break;
  case APDU_TYPE_4_EXT:
    if (Proto == ProtoT0) {
      PutByte (Apdu->Lc);
      CopyMem (Ptr, Apdu->Data, Apdu->Lc);
      Ptr += Apdu->Lc & 0xFF;
    } else {
      PutByte (0);
      PutByte (Apdu->Lc >> 8);
      PutByte (Apdu->Lc);

      CopyMem (Ptr, Apdu->Data, Apdu->Lc);
      Ptr += Apdu->Lc;

      PutByte (Apdu->Le >> 8);
      PutByte (Apdu->Le);
    }

    break;
  default:
    ASSERT(0);
    return EFI_INVALID_PARAMETER;
    break;
  }

  DEBUG ((EFI_D_ERROR, "%s(): Command length = %d:\n", L"Apdu2Buffer", Length));
  Dump (Buffer, Length, &emit);

  *BufferLength = Length;

#undef PutByte

  return EFI_SUCCESS;
}
