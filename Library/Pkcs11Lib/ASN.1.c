/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "ASN.1.h"

#include <Uefi.h>

#include <Protocol/SmartCard.h>
#include <Library/BaseMemoryLib.h>

/* This is needed to be included to get the code Microsoft-compatible */
#include <FixForMicrosoft.h>

/* The next inclusion should be removed when ASN.1 has finally debugged */
#include <Library/DebugLib.h>

#if 0
#define LOG(P_) DEBUG (P_)
#define DUMP(P_, L_) Dump16 (P_, L_, &emit)
#else
#define LOG(P_)
#define DUMP(P_, L_)
#endif

#define INTERNAL_ERROR \
  DEBUG ((EFI_D_ERROR, "Internal Error: " __FILE__ ", %d\n", __LINE__))

#define ENTER   DEBUG ((EFI_D_ERROR, "%s(): Enter\n", ToChar16 (__FUNCTION__)))
#define LEAVE   DEBUG ((EFI_D_ERROR, "%s(): Leave\n", ToChar16 (__FUNCTION__)))
#define LEAVING DEBUG ((EFI_D_ERROR, "%s(): Leaving\n", ToChar16 (__FUNCTION__)))

typedef struct {
  CK_ULONG      Tag;
  CK_ULONG      TagLen;
  CK_BYTE CONST *Body;
  CK_ULONG      BodyLen;
} ASN1_PRE_PARSED_INFO;

static CK_BBOOL gExplicitTagging = CK_TRUE;

VOID SetDefaultTagging (CK_BBOOL Explicit)
{
  gExplicitTagging = Explicit;
}

extern CK_RV GetTagInfo (ASN1_TAG_INFO *TI, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_ULONG      Tag;
  CK_ULONG      Len;

  /* For at least the 1-byte tag and the 1-byte length field */
  if (L-- < 2) {
    return CKR_FUNCTION_FAILED;
  }

  /* If the tag is at least 2-byte */
  if (((Tag = *P++) & ASN1_MASK_TAG) == ASN1_MASK_TAG) {
    if (L-- < 2) { /* For at least the tag 2nd byte and the 1-byte length */
      return CKR_FUNCTION_FAILED;
    }

    /* If the tag is 3-byte */
    if ((Tag = *P++) > 0x80) {
      CK_BYTE ThirdByte = *P++;

      if (L-- < 2) { /* For at least the tag 3nd byte and the 1-byte length */
        return CKR_FUNCTION_FAILED;
      }

      if (ThirdByte > 0x7F) {
        return CKR_FUNCTION_FAILED;
      }

      Tag = ((Tag & 0x7F) << 7) | (ThirdByte & 0x7F);
    } else {
      if (Tag < 0x1F || Tag == 0x80) {
        return CKR_FUNCTION_FAILED;
      }
    }
  }

  L--; /* Take into consideration the 1st byte of the body length field */

  /* If the body length has more than 1 byte */
  if ((Len = *P++) > 0x7F) {
    if (Len >= 0x81 && Len <= 0x84) { /* From 1 to 4 bytes */
      CK_ULONG I;
      CK_ULONG Limit = Len - 0x80;

      /* For all the additional bytes of the body length */
      if (L < Limit) {
        return CKR_FUNCTION_FAILED;
      }

      /* Accumulate the body length value from the big endian representation */
      for (I = Len = 0; I < Limit; I++) {
        Len = Len * 256 + *P++;
      }

      L -= Limit;
    } else {
      return CKR_FUNCTION_FAILED;
    }
  }

  TI->Tag = Tag;
  TI->Pld = P;
  TI->Len = Len;
  return CKR_OK;
}

static CK_RV ParseTag (
  ASN1_TAG_INFO       *TI,
  ASN1_TYPE_DEF CONST *Def,
  CK_BYTE CONST       *P,
  CK_ULONG            L
  );

static CK_RV ParseTagExec (
  ASN1_TAG_INFO       *TI,
  ASN1_TYPE_DEF CONST *Def,
  CK_BBOOL            IgnoreTagging,
  CK_BYTE CONST       *P,
  CK_ULONG            L
  )
{
  CK_ULONG Tag = Def->Tag;
  CK_BBOOL Exp = CK_FALSE;
  CK_RV    rv;
  CK_ULONG I;

#if 0
LOG ((
  EFI_D_ERROR,
  "Def->Tag = %02X, TI->Tag = %02X, Def->Type = %s, Def->Name = %s\n",
  Def->Tag,
  TI->Tag,
  Def->Type == ASN1_PRIM_CLASS_TYPE ? L"ASN1_PRIM_CLASS_TYPE" :
    Def->Type == ASN1_SEQUENCE_CLASS_TYPE ? L"ASN1_SEQUENCE_CLASS_TYPE" :
    Def->Type == ASN1_SEQUENCE_OF_CLASS_TYPE ? L"ASN1_SEQUENCE_OF_CLASS_TYPE" :
    Def->Type == ASN1_SET_CLASS_TYPE ? L"ASN1_SET_CLASS_TYPE" :
    Def->Type == ASN1_SET_OF_CLASS_TYPE ? L"ASN1_SET_OF_CLASS_TYPE" :
    Def->Type == ASN1_CHOICE_CLASS_TYPE ? L"ASN1_CHOICE_CLASS_TYPE" : L"Unknown",
  Def->Name != NULL_PTR ? Def->Name : L""));
DUMP (P, L < 64 ? L : 64);
#endif
  if (Tag != ASN1_NO_TAG && !IgnoreTagging) { /* Tagging exists */
    if(Def->Tagging == ASN1_TAGGING_EXPLICIT                         ||
       (Def->Tagging == ASN1_TAGGING_BY_DEFAULT && gExplicitTagging) ||
       Def->Type == ASN1_CHOICE_CLASS_TYPE) {

      /* Tagging is EXPLICIT, so EXPLICIT tag feeding is needed */
      Exp = CK_TRUE;
    }
  } else { /* NO tagging, assign native tags      */
    switch (Def->Type) {
    case ASN1_PRIM_CLASS_TYPE:
      Tag = Def->TypeRef.Prim->Tag;
      break;
    case ASN1_SEQUENCE_CLASS_TYPE:
      Tag = ASN1_SEQUENCE_TAG;
      break;
    case ASN1_SEQUENCE_OF_CLASS_TYPE:
      Tag = ASN1_SEQUENCE_OF_TAG;
      break;
    case ASN1_SET_CLASS_TYPE:
      Tag = ASN1_SET_TAG;
      break;
    case ASN1_SET_OF_CLASS_TYPE:
      Tag = ASN1_SET_OF_TAG;
      break;
    case ASN1_CHOICE_CLASS_TYPE:
      break; /* Choice itself has no tag, no assignment */
    }
  }

  if (Def->Type != ASN1_CHOICE_CLASS_TYPE) {
    switch (Def->Type) {
    case ASN1_PRIM_CLASS_TYPE:
      if (!Exp) { /* Non-constructed match is for implicit enconding only */
        /* Check whether a tag matches or not */
        TI->SucNum.Suc =
#ifdef _MSC_VER
          (CK_BBOOL)
#endif /* _MSC_VER */
          (TI->Tag == (~ASN1_ENCODING_CONSTRUCTED & Tag));
        break;
      }
      /* Intentionally pass through (for explicit encoding) */
    case ASN1_SEQUENCE_CLASS_TYPE:
    case ASN1_SEQUENCE_OF_CLASS_TYPE:
    case ASN1_SET_CLASS_TYPE:
    case ASN1_SET_OF_CLASS_TYPE:
      /* Check whether a tag matches or not */
      TI->SucNum.Suc =
#ifdef _MSC_VER
        (CK_BBOOL)
#endif /* _MSC_VER */
        (TI->Tag == (ASN1_ENCODING_CONSTRUCTED | Tag));
      break;
    default:
      INTERNAL_ERROR;
      return CKR_FUNCTION_FAILED;
    }

    if (TI->SucNum.Suc && Exp) {
      if ((rv = GetTagInfo (TI, TI->Pld, TI->Len))                 != CKR_OK ||
          (rv = ParseTagExec (TI, Def, CK_TRUE, TI->Pld, TI->Len)) != CKR_OK) {
        return rv;
      }
    }
  } else {
    for (I = 0; I < Def->TypeRef.Choice->Cnt; I++) {
      if (Exp) {
        if (TI->Tag != (ASN1_ENCODING_CONSTRUCTED | Tag)) {
          continue;
        }

        /* EXPLICIT tag feeding */
        P = TI->Pld;
        L = TI->Len;
      }

      if ((rv = GetTagInfo (TI, P, L))                      != CKR_OK ||
          (rv = ParseTag (TI, &Def->TypeRef.Choice->Item[I], P, L)) != CKR_OK) {
        return rv;
      }

      if (Def->TypeRef.Choice->Item[I].Type == ASN1_CHOICE_CLASS_TYPE) {
        if (TI->SucNum.Num < Def->TypeRef.Choice->Item[I].TypeRef.Choice->Cnt) {
          break;
        }
      } else {
        if (TI->SucNum.Suc) {
          break;
        }
      }
    }

    /* If a choice is found then I is less than Def->Choice->Cnt */
    TI->SucNum.Num = I;

    /* Assign the TI->Pld/TI->Len fields their previous values */
    TI->Pld = P;
    TI->Len = L;
  }

  return CKR_OK;
}

static CK_RV ParseTag (
  ASN1_TAG_INFO       *TI,
  ASN1_TYPE_DEF CONST *Def,
  CK_BYTE CONST       *P,
  CK_ULONG            L
  )
{
  return ParseTagExec (TI, Def, CK_FALSE, P, L);
}

/* ASN.1 type freeers */

static CK_RV FreePrim (ASN1_PRIM_TYPE_VAL *V, ASN1_PRIM_TYPE T)
{
  CK_RV rv = CKR_OK;

  switch (T) {
  case ASN1_BOOLEAN_PRIM_TYPE:
    V->Boolean = CK_FALSE;
    break;
  case ASN1_INTEGER_PRIM_TYPE:
    if (V->Integer.Long) {
      if (FreeMem (V->Integer.Val.Long.Val) != CKR_OK) {
        return rv;
      }

      V->Integer.Val.Long.Val = NULL_PTR;
      V->Integer.Val.Long.Len = 0;
    } else {
      V->Integer.Val.Val = 0;
    }
    break;
  case ASN1_ENUMERATED_PRIM_TYPE:
    V->Enumerated = 0;
    break;
  case ASN1_BIT_STRING_PRIM_TYPE:
    if (FreeMem (V->BitString.Hex) != CKR_OK) {
      return rv;
    }

    if (FreeMem (V->BitString.Val) != CKR_OK) {
      return rv;
    }

    V->BitString.Val = NULL_PTR;
    V->BitString.Len = 0;
    break;
  case ASN1_NULL_PRIM_TYPE:
    break;
  case ASN1_OCTET_STRING_PRIM_TYPE:
    if (FreeMem (V->OctetString.Val) != CKR_OK) {
      return rv;
    }

    V->OctetString.Val = NULL_PTR;
    V->OctetString.Len = 0;
    break;
  case ASN1_TELETEXT_STRING_PRIM_TYPE:
  case ASN1_UTF8_STRING_PRIM_TYPE:
    if (FreeMem (V->Utf8String.Val) != CKR_OK) {
      return rv;
    }

    V->Utf8String.Val = NULL_PTR;
    V->Utf8String.Len = 0;
    break;
  case ASN1_NUMERIC_STRING_PRIM_TYPE:
    if (FreeMem (V->NumericString.Val) != CKR_OK) {
      return rv;
    }

    V->NumericString.Val = NULL_PTR;
    V->NumericString.Len = 0;
    break;
  case ASN1_PRINTABLE_STRING_PRIM_TYPE:
    if (FreeMem (V->PrintableString.Val) != CKR_OK) {
      return rv;
    }

    V->PrintableString.Val = NULL_PTR;
    V->PrintableString.Len = 0;
    break;
  case ASN1_IA5_STRING_PRIM_TYPE:
    if (FreeMem (V->IA5String.Val) != CKR_OK) {
      return rv;
    }

    V->IA5String.Val = NULL_PTR;
    V->IA5String.Len = 0;
    break;
  case ASN1_BMP_STRING_PRIM_TYPE:
    if (FreeMem (V->BmpString.Val) != CKR_OK) {
      return rv;
    }

    V->BmpString.Val = NULL_PTR;
    V->BmpString.Len = 0;
    break;
  case ASN1_UTC_TIME_PRIM_TYPE:
    if (FreeMem (V->UTCTime.Val) != CKR_OK) {
      return rv;
    }

    V->UTCTime.Val = NULL_PTR;
    V->UTCTime.Len = 0;
    break;
  case ASN1_GENERALIZED_TIME_PRIM_TYPE:
    if (FreeMem (V->GeneralizedTime.Val) != CKR_OK) {
      return rv;
    }

    V->GeneralizedTime.Val = NULL_PTR;
    V->GeneralizedTime.Len = 0;
    break;
  case ASN1_OBJECT_IDENTIFIER_PRIM_TYPE:
    if (FreeMem (V->ObjectIdentifier.Val) != CKR_OK) {
      return rv;
    }

    V->ObjectIdentifier.Val = NULL_PTR;
    V->ObjectIdentifier.Len = 0;
    break;
  default:
    INTERNAL_ERROR;
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

static CK_RV FreeConstructed (ASN1_CONS_TYPE_ITEM_VAL **V, CK_ULONG *Cnt)
{
  CK_ULONG I;
  CK_RV    rv;

  for (I = 0; I < *Cnt; I++) {
    if ((rv = FreeASN1 (&(*V)[I].Val)) != CKR_OK) {
      return rv;
    }
  }

  if ((rv = FreeMem (*V)) != CKR_OK) {
    return rv;
  }

  *V   = NULL_PTR;
  *Cnt = 0;
  return CKR_OK;
}

static CK_RV FreeConstructedOf (ASN1_TYPE_VAL **V, CK_ULONG *Cnt)
{
  CK_ULONG I;
  CK_RV    rv;

  for (I = 0; I < *Cnt; I++) {
    if ((rv = FreeASN1 (&(*V)[I])) != CKR_OK) {
      return rv;
    }
  }

  if ((rv = FreeMem (*V)) != CKR_OK) {
    return rv;
  }

  *V   = NULL_PTR;
  *Cnt = 0;
  return CKR_OK;
}

static CK_RV FreeSequence (ASN1_SEQUENCE_TYPE_VAL *V)
{
  return FreeConstructed (&V->Item, &V->Cnt);
}

static CK_RV FreeSequenceOf (ASN1_SEQUENCE_OF_TYPE_VAL *V)
{
  return FreeConstructedOf (&V->Item, &V->Cnt);
}

static CK_RV FreeSet (ASN1_SET_TYPE_VAL *V)
{
  return FreeConstructed (&V->Item, &V->Cnt);
}

static CK_RV FreeSetOf (ASN1_SET_OF_TYPE_VAL *V)
{
  return FreeConstructedOf (&V->Item, &V->Cnt);
}

static CK_RV FreeChoice (ASN1_CHOICE_TYPE_VAL *V)
{
  CK_ULONG Cnt = 1;

  return FreeConstructed (&V->Item, &Cnt);
}

CK_RV FreeASN1 (ASN1_TYPE_VAL *V)
{
  CK_RV rv = CKR_OK;

  if (V == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (V->Decoded) {
    switch (V->Def->Type) {
    case ASN1_PRIM_CLASS_TYPE:
      rv = FreePrim (&V->TypeVal.Prim, V->Def->TypeRef.Prim->Type);
      break;
    case ASN1_SEQUENCE_CLASS_TYPE:
      rv = FreeSequence (&V->TypeVal.Sequence);
      break;
    case ASN1_SEQUENCE_OF_CLASS_TYPE:
      rv = FreeSequenceOf (&V->TypeVal.SequenceOf);
      break;
    case ASN1_SET_CLASS_TYPE:
      rv = FreeSet (&V->TypeVal.Set);
      break;
    case ASN1_SET_OF_CLASS_TYPE:
      rv = FreeSetOf (&V->TypeVal.SetOf);
      break;
    case ASN1_CHOICE_CLASS_TYPE:
      rv = FreeChoice (&V->TypeVal.Choice);
      break;
    default:
      INTERNAL_ERROR;
      return CKR_FUNCTION_FAILED;
    }

    if (rv == CKR_OK) {
      if (V->ASN1.Val != NULL_PTR && V->ASN1.Len != 0) {
#if 0
LOG ((EFI_D_ERROR, "FreeASN1: %s, Len = %d\n", V->Def->Name != NULL_PTR ? V->Def->Name : L"", V->ASN1.Len));
DUMP (V->ASN1.Val, V->ASN1.Len);
#endif
        if (FreeMem (V->ASN1.Val) != CKR_OK) {
          return rv;
        }

        V->ASN1.Val = NULL_PTR;
        V->ASN1.Len = 0;
      }

      V->Decoded = CK_FALSE;
    }
  }

  return rv;
}

/* ASN.1 primitive type decoders */

static CK_RV DecodeBoolean (ASN1_BOOLEAN_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  if (L != 1) {
    LOG ((EFI_D_ERROR, "ASN.1 BOOLEAN length MUST be 1 instead of %d\n",L));
    return CKR_FUNCTION_FAILED;
  }

  *V = *P != 0;
  LOG ((EFI_D_ERROR, ": BOOLEAN: %s\n", ToChar16(*V ? "TRUE" : "FALSE")));
  return CKR_OK;
}

static CK_RV DecodeInteger (
  ASN1_INTEGER_VAL *V,
  CK_LONG          Min,
  CK_LONG          Max,
  CK_BYTE CONST    *P,
  CK_ULONG         L
  )
{
  if (L < 1) {
    LOG ((EFI_D_ERROR, "ASN.1 INTEGER length CANNOT be less than 1\n"));
    return CKR_FUNCTION_FAILED;
  } else {
    if ((V->Long =
#ifdef _MSC_VER
           (CK_BBOOL)
#endif /* _MSC_VER */
           (L > sizeof V->Val.Val)) != CK_FALSE) {
      CK_RV rv = AllocMem ((CK_VOID_PTR *)&V->Val.Long.Val, L);

      if (rv != CKR_OK) {
        return rv;
      }

      CopyMem (V->Val.Long.Val, P, V->Val.Long.Len = L);
    } else {
      V->Val.Val = *P < 0x80 ? 0 : -1;

      while (L--) {
        V->Val.Val = V->Val.Val << 8 | *P++;
      }

      /* Check constraints */
      if ((Min != 0 && V->Val.Val < Min) || (Max != 0 && V->Val.Val > Max)) {
        LOG ((EFI_D_ERROR, "ASN.1 constraints for INTEGER failed\n"));
        return CKR_FUNCTION_FAILED;
      }
    }
  }

  if (V->Long) {
    LOG ((EFI_D_ERROR, ": INTEGER (long):\n"));
    DUMP (V->Val.Long.Val, V->Val.Long.Len);
  } else {
    LOG ((EFI_D_ERROR, ": INTEGER (native): %d\n", V->Val.Val));
  }

  return CKR_OK;
}

static CK_RV DecodeEnumerated (
  ASN1_ENUMERATED_VAL *V,
  CK_ULONG            Min,
  CK_ULONG            Max,
  CK_BYTE CONST       *P,
  CK_ULONG            L
  )
{
  ASN1_ENUMERATED_VAL A   = 0;

  if (L > sizeof *V) {
    LOG ((EFI_D_ERROR, "ASN.1 ENUMERATED is too large\n"));
    return CKR_FUNCTION_FAILED;
  }

  while (L--) {
    A = A << 8 | *P++;
  }

  /* Check constraints */
  if ((Min != 0 && A < Min) || (Max != 0 && A > Max)) {
    return CKR_FUNCTION_FAILED;
  }

  *V = *P != 0;
  LOG ((EFI_D_ERROR, ": ENUMERATED: %d\n", *V));
  return CKR_OK;
}

static CK_RV DecodeBitString (
  ASN1_BIT_STRING_VAL *V,
  CK_ULONG            Min,
  CK_ULONG            Max,
  CK_BYTE CONST       *P,
  CK_ULONG            L
  )
{
  enum { BYTE_BITS = 8 };

  CK_VOID_PTR Val = NULL_PTR;
  CK_ULONG    Len = 0;

  /* For the 'excess bits' byte */
  if (L-- > 1) {
    CK_ULONG    ExcessBits = *P++;
    CK_RV       rv;
    CK_ULONG    I;

    if (ExcessBits >= BYTE_BITS) {
      LOG ((EFI_D_ERROR, "Invalid encoding of ASN.1 BIT STRING excess bits\n"));
      return CKR_FUNCTION_FAILED;
    }

    Len = L * BYTE_BITS - ExcessBits;

    /* Check constraints */
    if ((Min != 0 && Len < Min) || (Max != 0 && Len > Max)) {
      LOG ((EFI_D_ERROR, "ASN.1 constraints for BIT STRING failed\n"));
      return CKR_FUNCTION_FAILED;
    }

    if ((rv = AllocMem (&Val, L)) != CKR_OK) {
      return rv;
    }

    CopyMem (V->Hex = Val, P, L);
    V->Hex[L] &= ~((1 << ExcessBits) - 1); /* Zeroize last byte excess bits */

    if ((rv = AllocMem (&Val, Len)) != CKR_OK) {
      FreeMem (V->Hex);
      return rv;
    }

    V->Val = Val;
    V->Len = Len;

    for (I = 0; I < Len; I++) {
      V->Val[I] =
#ifdef _MSC_VER
        (CK_BBOOL)
#endif /* _MSC_VER */
        ((P[I / BYTE_BITS] & (1 << (BYTE_BITS - I % BYTE_BITS - 1))) != 0);
    }

  }

  LOG ((EFI_D_ERROR, ": BIT STRING (%d): ", Len));

  for (L = 0; L < Len; L++) {
    LOG ((EFI_D_ERROR, "%c", V->Val[L] ? '1' : '0'));
  }

  LOG ((EFI_D_ERROR, "\n"));

  L = (V->Len + BYTE_BITS - 1) / BYTE_BITS; /* Hex length */

  LOG ((EFI_D_ERROR, "  IN HEX (%d):\n", L));
  DUMP (V->Hex, L);
  return CKR_OK;
}

static CK_RV DecodeString (
  CK_VOID_PTR_PTR Val,
  CK_ULONG        *Len,
  CK_ULONG        Min,
  CK_ULONG        Max,
  CK_BYTE CONST   *P,
  CK_ULONG        L
  )
{
  /* Check constraints */
  if ((Min != 0 && L < Min) || (Max != 0 && L > Max)) {
    LOG ((EFI_D_ERROR, "ASN.1 constraints for XXX STRING failed\n"));
    return CKR_FUNCTION_FAILED;
  }

  if (L > 0) {
    CK_RV rv = AllocMem (Val, L);

    if (rv != CKR_OK) {
      return rv;
    }

    CopyMem (*Val, P, L);
  }

  *Len = L;
  DUMP (*Val, *Len);
  return CKR_OK;
}

static CK_RV DecodeOctetString (
  ASN1_OCTET_STRING_VAL *V,
  CK_ULONG              Min,
  CK_ULONG              Max,
  CK_BYTE CONST         *P,
  CK_ULONG              L
  )
{
  LOG ((EFI_D_ERROR, ": OCTET STRING:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeNull (CK_ULONG L)
{
  LOG ((EFI_D_ERROR, ": NULL:\n"));
  return L == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV DecodeUtf8String (
  ASN1_UTF8_STRING_VAL *V,
  CK_ULONG             Min,
  CK_ULONG             Max,
  CK_BYTE CONST        *P,
  CK_ULONG             L
  )
{
  LOG ((EFI_D_ERROR, ": UTF8 STRING:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeNumericString (
  ASN1_NUMERIC_STRING_VAL   *V,
  CK_ULONG                  Min,
  CK_ULONG                  Max,
  CK_BYTE CONST             *P,
  CK_ULONG                  L
  )
{
  LOG ((EFI_D_ERROR, ": NUMERIC STRING:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodePrintableString (
  ASN1_PRINTABLE_STRING_VAL *V,
  CK_ULONG                  Min,
  CK_ULONG                  Max,
  CK_BYTE CONST             *P,
  CK_ULONG                  L
  )
{
  LOG ((EFI_D_ERROR, ": PRINTABLE STRING:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeIA5String (
  ASN1_IA5_STRING_VAL *V,
  CK_ULONG             Min,
  CK_ULONG             Max,
  CK_BYTE CONST        *P,
  CK_ULONG             L
  )
{
  LOG ((EFI_D_ERROR, ": IA5 STRING:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeBmpString (
  ASN1_BMP_STRING_VAL  *V,
  CK_ULONG             Min,
  CK_ULONG             Max,
  CK_BYTE CONST        *P,
  CK_ULONG             L
  )
{
  CK_RV rv;

  LOG ((EFI_D_ERROR, ": BMP STRING:\n"));

  if ((rv = DecodeString (
              (CK_VOID_PTR_PTR) &V->Val,
              &V->Len,
              Min,
              Max,
              P,
              L
              )) != CKR_OK) {
    return rv;
  }

  /* BMP string items are 16-bit */
  if (V->Len % 2) {
    return CKR_FUNCTION_FAILED;
  }

  /* Let Len to keep number of items iinstead of bytes */
  V->Len /= 2;

  return CKR_OK;
}

static CK_RV DecodeUTCTime (
  ASN1_UTC_TIME_VAL *V,
  CK_ULONG          Min,
  CK_ULONG          Max,
  CK_BYTE CONST     *P,
  CK_ULONG          L
  )
{
  LOG ((EFI_D_ERROR, ": UTCTime:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeGeneralizedTime (
  ASN1_GENERALIZED_TIME_VAL *V,
  CK_ULONG                  Min,
  CK_ULONG                  Max,
  CK_BYTE CONST             *P,
  CK_ULONG                  L
  )
{
  LOG ((EFI_D_ERROR, ": GeneralizedTime:\n"));
  return DecodeString (
           (CK_VOID_PTR_PTR) &V->Val,
           &V->Len,
           Min,
           Max,
           P,
           L
           );
}

static CK_RV DecodeObjectIdentifier (
  ASN1_OBJECT_IDENTIFIER_VAL *V,
  CK_BYTE CONST              *P,
  CK_ULONG                   L
  )
{
  CK_ULONG    I;
  CK_ULONG    N; /* Number of subidentifiers */
  CK_VOID_PTR Val = NULL_PTR;
  CK_RV       rv;

  if (L == 0) {
    LOG ((EFI_D_ERROR, "ASN.1 OBJECT IDENTIFIER CANNOT have length of 0\n"));
    return CKR_FUNCTION_FAILED;
  }

  /* Count the number of subidentifiers (number of bytes with MSBit unset ) */
  for (I = 0, N = 1; I < L; I++) {
    if (!(P[I] & 0x80)) {
      N++;
    }
  }

  /* The last byte must have the highest bit unset */
  if ((P[I - 1] & 0x80)) {
    LOG ((
      EFI_D_ERROR,
      "ASN.1 OBJECT IDENTIFIER last byte MUST have the highest bit unset\n"
      ));

    return CKR_FUNCTION_FAILED;
  }

  /* Allocate memory for subidentifiers */
  if ((rv = AllocMem (&Val, N * sizeof *V->Val)) != CKR_OK) {
    return rv;
  }

  V->Val = Val;

  /* Decode an Object Identifier */
  for (I = 1; I < N; I++) {
    V->Val[I] = 0;

    /* Concatenate each 7 low bits of the bytes comprising a subidentifier */
    do {
      V->Val[I] = V->Val[I] * 128 + (*P & 0x7F);
    } while ((*P++ & 0x80)); /* Catch the end of a subidentifier */
  }

  /* Split the first value into two ones (meaning 40 * X + Y formula) */
  V->Val[0] = V->Val[1] / 40;
  V->Val[1] %= 40;

  V->Len = N;

  LOG ((EFI_D_ERROR, ": OBJECT IDENTIFIER: "));

  for (I = 0; I < N; I++) {
    LOG ((EFI_D_ERROR, "%s%d", ToChar16 (I != 0 ? "." : ""), V->Val[I]));
  }

  LOG ((EFI_D_ERROR, "\n"));
  return CKR_OK;
}

/* The decoder of ASN.1 primitive types */
static CK_RV DecodePrimExec (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  switch (V->Def->TypeRef.Prim->Type) {
  case ASN1_BOOLEAN_PRIM_TYPE:
    return DecodeBoolean (&V->TypeVal.Prim.Boolean, P, L);
  case ASN1_INTEGER_PRIM_TYPE:
    return DecodeInteger (
             &V->TypeVal.Prim.Integer,
             V->Def->TypeRef.Prim->Constraints.Int.Min,
             V->Def->TypeRef.Prim->Constraints.Int.Max,
             P,
             L
             );
  case ASN1_ENUMERATED_PRIM_TYPE:
    return DecodeEnumerated (
             &V->TypeVal.Prim.Enumerated,
             V->Def->TypeRef.Prim->Constraints.Enu.Min,
             V->Def->TypeRef.Prim->Constraints.Enu.Max,
             P,
             L
             );
  case ASN1_BIT_STRING_PRIM_TYPE:
    return DecodeBitString (
             &V->TypeVal.Prim.BitString,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_OCTET_STRING_PRIM_TYPE:
    return DecodeOctetString (
             &V->TypeVal.Prim.OctetString,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_NULL_PRIM_TYPE:
    return DecodeNull (L);
  case ASN1_TELETEXT_STRING_PRIM_TYPE:
  case ASN1_UTF8_STRING_PRIM_TYPE:
    return DecodeUtf8String (
             &V->TypeVal.Prim.Utf8String,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_NUMERIC_STRING_PRIM_TYPE:
    return DecodeNumericString (
             &V->TypeVal.Prim.NumericString,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_PRINTABLE_STRING_PRIM_TYPE:
    return DecodePrintableString (
             &V->TypeVal.Prim.PrintableString,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_IA5_STRING_PRIM_TYPE:
    return DecodeIA5String (
             &V->TypeVal.Prim.IA5String,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_BMP_STRING_PRIM_TYPE:
    return DecodeBmpString (
             &V->TypeVal.Prim.BmpString,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_UTC_TIME_PRIM_TYPE:
    return DecodeUTCTime (
             &V->TypeVal.Prim.UTCTime,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_GENERALIZED_TIME_PRIM_TYPE:
    return DecodeGeneralizedTime (
             &V->TypeVal.Prim.GeneralizedTime,
             V->Def->TypeRef.Prim->Constraints.Len.Min,
             V->Def->TypeRef.Prim->Constraints.Len.Max,
             P,
             L
             );
  case ASN1_OBJECT_IDENTIFIER_PRIM_TYPE:
    return DecodeObjectIdentifier (&V->TypeVal.Prim.ObjectIdentifier, P, L);
  }

  INTERNAL_ERROR;
  return CKR_FUNCTION_FAILED;
}

static inline CK_RV DecodePrim (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_RV rv = DecodePrimExec (V, P, L);

  if (rv == CKR_OK) {
    V->Decoded = CK_TRUE;
  }

  return rv;
}

extern CK_RV AddConsTypeItem (
  ASN1_CONS_TYPE_ITEM_VAL **Item,
  ASN1_TYPE_VAL           **V,
  ASN1_TYPE_DEF CONST     *Def,
  CK_ULONG                Cnt,
  CK_ULONG                Ord
  )
{
  CK_VOID_PTR Tmp = NULL_PTR;
  CK_RV       rv  = AllocMem (&Tmp, (Cnt + 1) * sizeof **Item);

  if (rv != CKR_OK) {
    return rv;
  }

  if (Cnt != 0) {
    CopyMem (Tmp, *Item, Cnt * sizeof **Item);

    if ((rv = FreeMem (*Item)) != CKR_OK) {
      return rv;
    }
  }

  *V               = &(*Item = Tmp)[Cnt].Val;
  (*V)->Def        = Def;
  (*V)->Decoded    = CK_FALSE;
  (*V)->ASN1.Val   = NULL_PTR;
  (*V)->ASN1.Len   = 0;
  (*Item)[Cnt].Ord = Ord;
  return CKR_OK;
}

extern CK_RV AddTypeItem (
  ASN1_TYPE_VAL       **Item,
  ASN1_TYPE_VAL       **V,
  ASN1_TYPE_DEF CONST *Def,
  CK_ULONG            Cnt
  )
{
  CK_VOID_PTR Tmp = NULL_PTR;
  CK_RV       rv  = AllocMem (&Tmp, (Cnt + 1) * sizeof **Item);

  if (rv != CKR_OK) {
    return rv;
  }

  if (Cnt != 0) {
    CopyMem (Tmp, *Item, Cnt * sizeof **Item);

    if ((rv = FreeMem (*Item)) != CKR_OK) {
      return rv;
    }
  }

  *V             = &(*Item = Tmp)[Cnt];
  (*V)->Def      = Def;
  (*V)->Decoded  = CK_FALSE;
  (*V)->ASN1.Val = NULL_PTR;
  (*V)->ASN1.Len = 0;
  return CKR_OK;
}

static CK_RV DoesFit (CK_BBOOL *Fits, ASN1_TYPE_DEF CONST *T, ASN1_TAG_INFO *TI)
{
  CK_BYTE CONST *P = TI->Pld;
  CK_ULONG      L  = TI->Len;
  CK_RV         rv = GetTagInfo (TI, TI->Pld, TI->Len);

  if (rv != CKR_OK) {
    LOG ((EFI_D_ERROR, "ASN.1 decoder error while getting tag info\n"));
    return rv;
  }

  if ((rv = ParseTag (TI, T, P, L)) != CKR_OK) {
    LOG ((EFI_D_ERROR, "ASN.1 decoder error while parsing tag\n"));
    return rv;
  }

  if ((*Fits =
#ifdef _MSC_VER
         (CK_BBOOL)
#endif /* _MSC_VER */
           (T->Type != ASN1_CHOICE_CLASS_TYPE ?
             TI->SucNum.Suc :
             TI->SucNum.Num < T->TypeRef.Choice->Cnt)) &&
              T->Type != ASN1_CHOICE_CLASS_TYPE        &&
              T->ASN1) { /* ASN.1 representation must be kept in the value */
    TI->ASN1 = P;
  }

  return CKR_OK;
}

static CK_RV SetDefaultValue (
  ASN1_TYPE_VAL       *Item,
  ASN1_TYPE_VAL CONST *Default
  )
{
  if (Item == NULL || Default == NULL) {
    return CKR_OK;
  }
  /* FIXME: Allocate memory dynamically and perform copying instead of this: */
#ifdef _MSC_VER
  CopyMem (Item, Default, sizeof *Default);
#else /* _MSC_VER */
  *Item = *Default;
#endif /* _MSC_VER */

  return CKR_OK;
}

/* The decoder of ASN.1 sequence */
static CK_RV DecodeSequence (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_ULONG I;

  LOG ((
    EFI_D_ERROR,
    ":> SEQUENCE: %s\n",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  V->TypeVal.Sequence.Item = NULL_PTR;
  V->TypeVal.Sequence.Cnt  = 0;

  /* Walk through the sequence items as specified in its ASN.1 definition */
  for (I = 0; I < V->Def->TypeRef.Sequence->Cnt; I++) {
    /* After a tag is preparsed from the buffer, start an internal loop */
    for (; I < V->Def->TypeRef.Sequence->Cnt; I++) {
      CK_RV         rv;
      ASN1_TYPE_VAL *W    = NULL_PTR;
      CK_BBOOL      Fits  = CK_FALSE;

      FFM_INITIALIZE_AUTO (
        ASN1_TAG_INFO,
        TI,
        5,
        (
          .SucNum.Suc = CK_FALSE,
          .Tag        = ASN1_NO_TAG,
          .Pld        = P,
          .Len        = L,
          .ASN1       = NULL_PTR
        )
      );

      if (L > 0 && *P != ASN1_NO_TAG && *P != ASN1_FF_TAG &&
          (rv = DoesFit (
                  &Fits,
                  &V->Def->TypeRef.Sequence->Item[I].Val,
                  &TI
                  )) != CKR_OK) {
        return rv;
      }

      if (!Fits) {
        switch (V->Def->TypeRef.Sequence->Item[I].Type) {
        case ASN1_ITEM_OPTIONAL:
          /* The optional item does NOT match the tag, so, go to the next one */
          LOG ((
            EFI_D_ERROR,
            "   Skipping OPTIONAL field: %s\n",
            V->Def->TypeRef.Sequence->Item[I].Val.Name != NULL_PTR ?
              V->Def->TypeRef.Sequence->Item[I].Val.Name :
              L""
            ));

          continue;
        case ASN1_ITEM_DEFAULT:
          /* The default item is processed later */
          break;
        case ASN1_ITEM_NORMAL:
          LOG ((
            EFI_D_ERROR,
            "ASN.1 SEQUENCE field: tag mismatch or tag not found\n"));
          return CKR_FUNCTION_FAILED;
        default:
          INTERNAL_ERROR;
          return CKR_FUNCTION_FAILED;
        }
      }

      /* Increase the space occuped by items for one more item to fit */
      if ((rv = AddConsTypeItem (
                  &V->TypeVal.Sequence.Item,
                  &W,
                  &V->Def->TypeRef.Sequence->Item[I].Val,
                  V->TypeVal.Sequence.Cnt,
                  I
                  )) != CKR_OK) {
        return rv;
      }

      /* Starting from this point V is due to be really freed by FreeASN1() */
      V->Decoded = CK_TRUE;

      switch (V->Def->TypeRef.Sequence->Item[I].Type) {
      case ASN1_ITEM_DEFAULT:
        if (!Fits) { /* In this case the item should be restored */
          LOG ((
            EFI_D_ERROR,
            "   Setting default value for DEFAULT field: %s\n",
            V->Def->TypeRef.Sequence->Item[I].Val.Name != NULL_PTR ?
              V->Def->TypeRef.Sequence->Item[I].Val.Name :
              L""
            ));

          /* The default item is restored from the value prestored in its type */
          if ((rv = SetDefaultValue (
                      W,
                      V->Def->TypeRef.Sequence->Item[I].Default
                      )) != CKR_OK) {
            return rv;
          }

          V->TypeVal.Sequence.Cnt++;
          continue;
        }

      /* Otherwise, the tag is matched and a default item is to be decoded */
      /* The 'break' statement is intentionaly absent: passthrough */

      /* Both the normal and optional items are decoded from the buffer */
      case ASN1_ITEM_OPTIONAL:
      case ASN1_ITEM_NORMAL:
        LOG ((
          EFI_D_ERROR,
          "   Decoding %s field: %s\n",
          V->Def->TypeRef.Sequence->Item[I].Type == ASN1_ITEM_NORMAL ?
            L"NORMAL" :
            V->Def->TypeRef.Sequence->Item[I].Type == ASN1_ITEM_OPTIONAL ?
              L"OPTIONAL" :
              L"DEFAULT",
          V->Def->TypeRef.Sequence->Item[I].Val.Name != NULL_PTR ?
            V->Def->TypeRef.Sequence->Item[I].Val.Name :
            L""
          ));

        if ((rv = DecodeSubtype (W, &TI)) != CKR_OK) {
          return rv;
        }
      default: /* In order to avoid a possible compiler warning(s) */
        break;
      }

      /* It is needed because of choice type */
      if ((rv = GetTagInfo (&TI, P, L)) != CKR_OK) {
        LOG ((EFI_D_ERROR, "ASN.1 decoder error while getting tag info\n"));
        return rv;
      }

      /* Step within the buffer by the item to be decoded */
      L -=
#ifdef _MSC_VER
        (CK_ULONG)
#endif /* _MSC_VER */
        (TI.Pld - P + TI.Len);
      P += TI.Pld - P + TI.Len;

      /* The last item is initialized, set the counter of items appropriately */
      V->TypeVal.Sequence.Cnt++;

      /* Leave the internal loop */
      break;
    }
  }

  LOG ((
    EFI_D_ERROR,
    ":< SEQUENCE: %s\n",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  return CKR_OK;
}

/* The decoder of ASN.1 set */
static CK_RV DecodeSet (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  ASN1_TYPE_VAL *W = NULL_PTR;
  CK_ULONG      I;
  CK_RV         rv;

  LOG ((
    EFI_D_ERROR,
    ":> SET: %s\n",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  V->TypeVal.Set.Item = NULL_PTR;
  V->TypeVal.Set.Cnt  = 0;

  while (L > 0 && *P != ASN1_NO_TAG && *P != ASN1_FF_TAG) {
    /* Prevent from neverending cycling in case of an empty SET */
    if (V->Def->TypeRef.Set->Cnt == 0) {
      P += L;
      break;
    }

    /* Walk through the set items as specified in its ASN.1 definition */
    for (I = 0; I < V->Def->TypeRef.Set->Cnt; I++) {
      CK_ULONG J;
      CK_BBOOL Fits  = CK_FALSE;

      FFM_INITIALIZE_AUTO (
        ASN1_TAG_INFO,
        TI,
        5,
        (
          .SucNum.Suc = CK_FALSE,
          .Tag        = ASN1_NO_TAG,
          .Pld        = P,
          .Len        = L,
          .ASN1       = NULL_PTR
        )
      );

      if (L > 0 && (rv = DoesFit (
                           &Fits,
                           &V->Def->TypeRef.Sequence->Item[I].Val,
                           &TI
                           )) != CKR_OK) {
        return rv;
      }

      if (!Fits) {
        continue;
      }

      /* Find out whether the item is already decoded */
      for (J = 0; J < V->TypeVal.Set.Cnt; J++) {
        /* If a field is encountered twice (the field is already decoded) */
        if (V->TypeVal.Set.Item[J].Ord == I) {
          LOG ((EFI_D_ERROR, "ASN.1 SEQUENCE has the same field twice\n"));
          return CKR_FUNCTION_FAILED;
        }
      }

      /* Increase the space occuped by items for one more item to fit */
      if ((rv = AddConsTypeItem (
                  &V->TypeVal.Set.Item,
                  &W,
                  &V->Def->TypeRef.Set->Item[I].Val,
                  V->TypeVal.Set.Cnt,
                  I
                  )) != CKR_OK) {
        return rv;
      }

      /* Starting from this point V is due to be really freed by FreeASN1() */
      V->Decoded = CK_TRUE;

      LOG ((
        EFI_D_ERROR,
        "   Decoding field: %s\n",
        V->Def->TypeRef.Set->Item[I].Val.Name != NULL_PTR ?
          V->Def->TypeRef.Set->Item[I].Val.Name :
          L""
        ));

      if ((rv = DecodeSubtype (W, &TI)) != CKR_OK) {
        return rv;
      }

      /* It is needed because of choice type */
      if ((rv = GetTagInfo (&TI, P, L)) != CKR_OK) {
        LOG ((EFI_D_ERROR, "ASN.1 decoder error while getting tag info\n"));
        return rv;
      }

      /* Step within the buffer by the item to be decoded */
      L -=
#ifdef _MSC_VER
        (CK_ULONG)
#endif /* _MSC_VER */
        (TI.Pld - P + TI.Len);
      P += TI.Pld - P + TI.Len;

      /* The last item is initialized, set the counter of items appropriately */
      V->TypeVal.Set.Cnt++;
    }

    if (!(I < V->Def->TypeRef.Set->Cnt)) {
      /* As in sequence, unknown members are allowed and are skipped silently */
    }
  }

  /* Find uninitialized default set items and initialize them */
  for (I = 0; I < V->Def->TypeRef.Set->Cnt; I++) {
    if (V->Def->TypeRef.Set->Item[I].Type == ASN1_ITEM_DEFAULT) {
      CK_ULONG J;

      for (J = 0; J < V->TypeVal.Set.Cnt; J++) {
        if (V->TypeVal.Set.Item[J].Ord == I) {
          break;
        }
      }

      /*If uninitialized default set item is found then initialize it */
      if (!(J < V->TypeVal.Set.Cnt)) {
        /* Increase the space occuped by items for one more item to fit */
        if ((rv = AddConsTypeItem (
                    &V->TypeVal.Set.Item,
                    &W,
                    &V->Def->TypeRef.Set->Item[I].Val,
                    V->TypeVal.Set.Cnt,
                    I
                    )) != CKR_OK) {
          return rv;
        }

        /* Starting from this point V is due to be really freed by FreeASN1() */
        V->Decoded = CK_TRUE;

        /* The default item is restored from the value prestored in its type */
        if ((rv = SetDefaultValue (
                    W,
                    V->Def->TypeRef.Set->Item[I].Default
                    )) != CKR_OK) {
          return rv;
        }

        /* The last item is initialized, set the counter of items appropriately */
        V->TypeVal.Set.Cnt++;
      }
    }
  }

  LOG ((
    EFI_D_ERROR,
    ":< SET: %s\n",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  return CKR_OK;
}

/* The generalized decoder of ASN.1 sequence-of/set-of */
static CK_RV DecodeSequenceSetOf (
  ASN1_TYPE_VAL *V,
  CK_BBOOL      Seq,
  CK_BYTE CONST *P,
  CK_ULONG      L
  )
{
  LOG ((
    EFI_D_ERROR,
    ":> %s: %s\n",
    Seq ? L"SEQUENCE OF" : L"SET OF",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  *(Seq ? &V->TypeVal.SequenceOf.Item : &V->TypeVal.SetOf.Item) = NULL_PTR;
  *(Seq ? &V->TypeVal.SequenceOf.Cnt :  &V->TypeVal.SetOf.Cnt)  = 0;

  /* Starting from this point V is due to be really freed by FreeASN1() */
  V->Decoded = CK_TRUE;

  while (L > 0 && *P != ASN1_NO_TAG && *P != ASN1_FF_TAG) {
    CK_BBOOL      Fits;
    ASN1_TYPE_VAL *W = NULL_PTR;

    FFM_INITIALIZE_AUTO (
      ASN1_TAG_INFO,
      TI,
      5,
      (
        .SucNum.Suc = CK_FALSE,
        .Tag        = ASN1_NO_TAG,
        .Pld        = P,
        .Len        = L,
        .ASN1       = NULL_PTR
      )
    );

    CK_RV rv = DoesFit (
                 &Fits,
                 Seq ? V->Def->TypeRef.SequenceOf : V->Def->TypeRef.SetOf,
                 &TI
                 );

    if (rv != CKR_OK) {
      return rv;
    }

    if (!Fits) {
      LOG ((EFI_D_ERROR, "ASN.1 SEQUENCE OF/SET OF underlying type mismatch\n"));
      return CKR_FUNCTION_FAILED;
    }

    /* Increase the space occuped by items for one more item to fit */
    if ((rv = AddTypeItem (
                Seq ? &V->TypeVal.SequenceOf.Item : &V->TypeVal.SetOf.Item,
                &W,
                Seq ? V->Def->TypeRef.SequenceOf  : V->Def->TypeRef.SetOf,
                Seq ? V->TypeVal.SequenceOf.Cnt   : V->TypeVal.SetOf.Cnt
                )) != CKR_OK) {
      return rv;
    }

    LOG ((
      EFI_D_ERROR,
      "   Decoding field: %s\n",
      (Seq ?
         V->Def->TypeRef.SequenceOf :
         V->Def->TypeRef.SetOf)->Name != NULL_PTR ?
           (Seq ? V->Def->TypeRef.SequenceOf : V->Def->TypeRef.SetOf)->Name :
           L""
      ));

    if ((rv = DecodeSubtype (W, &TI)) != CKR_OK) {
      return rv;
    }

    /* It is needed because of choice type */
    if ((rv = GetTagInfo (&TI, P, L)) != CKR_OK) {
      LOG ((EFI_D_ERROR, "ASN.1 decoder error while getting tag info\n"));
      return rv;
    }

    /* Step within the buffer by the item to be decoded */
    L -=
#ifdef _MSC_VER
      (CK_ULONG)
#endif /* _MSC_VER */
      (TI.Pld - P + TI.Len);
    P += TI.Pld - P + TI.Len;

    /* The last item is initialized, set the counter of items appropriately */
    V->TypeVal.SequenceOf.Cnt++;
  }

  LOG ((
    EFI_D_ERROR,
    ":< %s: %s\n",
    Seq ? L"SEQUENCE OF" : L"SET OF",
    V->Def->Name != NULL_PTR ? V->Def->Name : L""
    ));

  return CKR_OK;
}

/* The decoder of ASN.1 sequence-of */
static inline CK_RV DecodeSequenceOf (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  return DecodeSequenceSetOf (V, CK_TRUE, P, L);
}

/* The decoder of ASN.1 set-of */
static inline CK_RV DecodeSetOf (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  return DecodeSequenceSetOf (V, CK_FALSE, P, L);
}

/* The decoder of ASN.1 choice */
static CK_RV DecodeChoice (ASN1_TYPE_VAL *V, CK_ULONG Ord, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_BBOOL      Fits;
  ASN1_TYPE_VAL *W = NULL_PTR;

  FFM_INITIALIZE_AUTO (
    ASN1_TAG_INFO,
    TI,
    5,
    (
      .SucNum.Num = Ord,
      .Tag        = ASN1_NO_TAG,
      .Pld        = P,
      .Len        = L,
      .ASN1       = NULL_PTR
    )
  );

  CK_RV rv = AddConsTypeItem (
               &V->TypeVal.Choice.Item,
               &W,
               &V->Def->TypeRef.Choice->Item[Ord],
               0,
               Ord
               );

  if (rv != CKR_OK) {
    return rv;
  }

  V->Decoded = CK_TRUE;

  LOG ((
    EFI_D_ERROR,
    ":> CHOICE: %d(%d): %s\n",
    Ord,
    V->Def->TypeRef.Choice->Cnt - 1,
    V->Def->TypeRef.Choice->Item[Ord].Name != NULL_PTR ?
      V->Def->TypeRef.Choice->Item[Ord].Name :
      L""
    ));

  if ((rv = DoesFit (&Fits, W->Def, &TI)) != CKR_OK) {
    return rv;
  }

  if (!Fits) {
    LOG ((EFI_D_ERROR, "No one of ASN.1 CHOICE choices fits\n"));
    return CKR_FUNCTION_FAILED;
  }

  rv = DecodeSubtype (W, &TI);

  LOG ((
    EFI_D_ERROR,
    ":< CHOICE: %d(%d): %s\n",
    Ord,
    V->Def->TypeRef.Choice->Cnt - 1,
    V->Def->TypeRef.Choice->Item[Ord].Name != NULL_PTR ?
      V->Def->TypeRef.Choice->Item[Ord].Name :
      L""
    ));

  return rv;
}

static CK_RV DecodeSubtypeExec (ASN1_TYPE_VAL *V, ASN1_TAG_INFO *TI)
{
  switch (V->Def->Type) {
  case ASN1_PRIM_CLASS_TYPE:
    return DecodePrim (V, TI->Pld, TI->Len);
  case ASN1_SEQUENCE_CLASS_TYPE:
    return DecodeSequence (V, TI->Pld, TI->Len);
  case ASN1_SEQUENCE_OF_CLASS_TYPE:
    return DecodeSequenceOf (V, TI->Pld, TI->Len);
  case ASN1_SET_CLASS_TYPE:
    return DecodeSet (V, TI->Pld, TI->Len);
  case ASN1_SET_OF_CLASS_TYPE:
    return DecodeSetOf (V, TI->Pld, TI->Len);
  case ASN1_CHOICE_CLASS_TYPE:
    return DecodeChoice (V, TI->SucNum.Num, TI->Pld, TI->Len);
  default:
    break;
  }

  INTERNAL_ERROR;
  return CKR_FUNCTION_FAILED;
}

CK_RV DecodeSubtype (ASN1_TYPE_VAL *V, ASN1_TAG_INFO *TI)
{
  CK_RV    rv = DecodeSubtypeExec (V, TI);

  V->ASN1.Val = NULL_PTR;
  V->ASN1.Len = 0;

  if (rv == CKR_OK && V->Def->ASN1 && V->Def->Type != ASN1_CHOICE_CLASS_TYPE) {
    if (TI->ASN1 == NULL_PTR) { /* TI->ASN1 MUST already be initialized here! */
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 type '%s' definition specifies to save ASN.1 representation, "
          "but ASN.1 type instance has NULL pointer to ASN.1 data\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    if (TI->ASN1 != NULL_PTR || TI->ASN1 <= TI->Pld) {
      CK_ULONG L = TI->Pld - TI->ASN1 + TI->Len;

      if ((rv = AllocMem ((CK_VOID_PTR_PTR)&V->ASN1.Val, L)) == CKR_OK) {
        CopyMem (V->ASN1.Val, TI->ASN1, V->ASN1.Len = L);
      }
    } else {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }
  }

  return rv;
}

/* ASN.1 API: Decode */
CK_RV Decode (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_BBOOL      Fits;
  CK_RV         rv = FreeASN1 (V); /* V != NULL_PTR is checked here */
  FFM_INITIALIZE_AUTO (
    ASN1_TAG_INFO,
    TI,
    5,
    (
      .SucNum.Suc = CK_FALSE,
      .Tag        = ASN1_NO_TAG,
      .Pld        = P,
      .Len        = L,
      .ASN1       = NULL_PTR
    )
  );

  /* FreeASN1() might fail including 'V == NULL_PTR' case */
  if (rv != CKR_OK) {
    return rv;
  }

  if (P == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (L > 0 && *P != ASN1_NO_TAG && *P != ASN1_FF_TAG) {
    if ((rv = DoesFit (&Fits, V->Def, &TI)) != CKR_OK) {
      return rv;
    }

    if (!Fits) {
      return CKR_FUNCTION_FAILED;
    }

    if ((rv = DecodeSubtype (V, &TI)) != CKR_OK) {
      return rv;
    }
  }

  return CKR_OK;
}

/* ASN.1 API: DecodePayload */
CK_RV DecodePayload (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L)
{
  CK_RV         rv = FreeASN1 (V); /* V != NULL_PTR is checked here */
  FFM_INITIALIZE_AUTO (
    ASN1_TAG_INFO,
    TI,
    5,
    (
      .SucNum.Suc = CK_FALSE,
      .Tag        = ASN1_NO_TAG,
      .Pld        = P,
      .Len        = L,
      .ASN1       = NULL_PTR
    )
  );

  /* FreeASN1() might fail including 'V == NULL_PTR' case */
  if (rv != CKR_OK) {
    return rv;
  }

  if (P == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((L > 0 && *P != ASN1_NO_TAG && *P != ASN1_FF_TAG) ||
       /* 'SEQUENCE OF' and 'SET OF' types may have zero items */
       V->Def->Type == ASN1_SEQUENCE_OF_CLASS_TYPE      ||
       V->Def->Type == ASN1_SET_OF_CLASS_TYPE) {

    /* CHOICE cannot be decoded without the tag */
    if (V->Def->Type == ASN1_CHOICE_CLASS_TYPE) {
      DEBUG ((EFI_D_ERROR, "Cannot decode payload for choice\n"));
      return CKR_FUNCTION_FAILED;
    }

    if ((rv = DecodeSubtype (V, &TI)) != CKR_OK) {
      return rv;
    }
  }

  return CKR_OK;
}

/* ASN.1 API: GetValByOrd */
CK_RV GetValByOrd (ASN1_TYPE_VAL **V, CK_ULONG Ord)
{
  CK_ULONG                I;
  CK_ULONG                Limit;
  CK_ULONG                Ords;
  ASN1_CONS_TYPE_ITEM_VAL *Item;
  ASN1_ITEM_TYPE          ItemType;

  if (!(*V)->Decoded) {
    return CKR_FUNCTION_FAILED;
  }

  if (V == NULL_PTR || *V == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  switch ((*V)->Def->Type) {
  case ASN1_SEQUENCE_CLASS_TYPE:
    Item  = (*V)->TypeVal.Sequence.Item;
    Limit = (*V)->TypeVal.Sequence.Cnt;
    Ords  = (*V)->Def->TypeRef.Sequence->Cnt;
    break;
  case ASN1_SET_CLASS_TYPE:
    Item  = (*V)->TypeVal.Set.Item;
    Limit = (*V)->TypeVal.Set.Cnt;
    Ords  = (*V)->Def->TypeRef.Set->Cnt;
    break;
  default:
    return CKR_FUNCTION_FAILED;
  }

  if (!(Ord < Ords)) {
    return CKR_FUNCTION_FAILED;
  }

  for (I = 0; I < Limit; I++) {
    if (Item[I].Ord == Ord) {
      *V = &Item[I].Val;
      return CKR_OK;
    }
  }

  switch ((*V)->Def->Type) {
  case ASN1_SEQUENCE_CLASS_TYPE:
    ItemType  = (*V)->Def->TypeRef.Sequence->Item[Ord].Type;
    break;
  case ASN1_SET_CLASS_TYPE:
    ItemType  = (*V)->Def->TypeRef.Set->Item[Ord].Type;
    break;
  default:
    return CKR_FUNCTION_FAILED;
  }

  if (ItemType != ASN1_ITEM_OPTIONAL) {
    return CKR_FUNCTION_FAILED;
  }

  *V = NULL_PTR;
  return CKR_OK;
}
