/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ASN_1__
#define __ASN_1__

#include <Library/Pkcs11Lib.h>

#include <SomeCompilerFixes.h>

/* Number of array elements is often needed to know */
#define ARRAY_ITEMS(Array_) \
  (sizeof (Array_) / sizeof (*Array_))

/* ASN.1 type enumerations */
typedef enum {
  ASN1_PRIM_CLASS_TYPE,
  ASN1_SEQUENCE_CLASS_TYPE,
  ASN1_SEQUENCE_OF_CLASS_TYPE,
  ASN1_SET_CLASS_TYPE,
  ASN1_SET_OF_CLASS_TYPE,
  ASN1_CHOICE_CLASS_TYPE
} ASN1_CLASS_TYPE;

typedef enum {
  ASN1_BOOLEAN_PRIM_TYPE,
  ASN1_INTEGER_PRIM_TYPE,
  ASN1_BIT_STRING_PRIM_TYPE,
  ASN1_OCTET_STRING_PRIM_TYPE,
  ASN1_NULL_PRIM_TYPE,
  ASN1_OBJECT_IDENTIFIER_PRIM_TYPE,
  ASN1_ENUMERATED_PRIM_TYPE,
  ASN1_UTF8_STRING_PRIM_TYPE,
  ASN1_NUMERIC_STRING_PRIM_TYPE,
  ASN1_PRINTABLE_STRING_PRIM_TYPE,
  ASN1_TELETEXT_STRING_PRIM_TYPE,
  ASN1_IA5_STRING_PRIM_TYPE,
  ASN1_UTC_TIME_PRIM_TYPE,
  ASN1_GENERALIZED_TIME_PRIM_TYPE,
  ASN1_BMP_STRING_PRIM_TYPE,
} ASN1_PRIM_TYPE;

/* ASN.1 tags */
typedef enum _ASN1_TAG {
  ASN1_NO_TAG                = 0x00,
  ASN1_BOOLEAN_TAG           = 0x01,
  ASN1_INTEGER_TAG           = 0x02,
  ASN1_BIT_STRING_TAG        = 0x03,
  ASN1_OCTET_STRING_TAG      = 0x04,
  ASN1_NULL_TAG              = 0x05,
  ASN1_OBJECT_IDENTIFIER_TAG = 0x06,
  ASN1_ENUMERATED_TAG        = 0x0A,
  ASN1_UTF8_STRING_TAG       = 0x0C,
  ASN1_SEQUENCE_TAG          = 0x10,
  ASN1_SEQUENCE_OF_TAG       = 0x10,
  ASN1_SET_TAG               = 0x11,
  ASN1_SET_OF_TAG            = 0x11,
  ASN1_NUMERIC_STRING_TAG    = 0x12,
  ASN1_PRINTABLE_STRING_TAG  = 0x13,
  ASN1_TELETEXT_STRING_TAG   = 0x14,
  ASN1_IA5_STRING_TAG        = 0x16,
  ASN1_UTC_TIME_TAG          = 0x17,
  ASN1_GENERALIZED_TIME_TAG  = 0x18,
  ASN1_BMP_STRING_TAG        = 0x1E,
  ASN1_FF_TAG                = 0xFF
} ASN1_TAG;

/* Masks for ASN.1 tag fields */
typedef enum _ASN1_MASK {
  ASN1_MASK_CLASS             = 0xC0,
  ASN1_MASK_ENCODING          = 0x20,
  ASN1_MASK_TAG               = 0x1F
} ASN1_MASK;

/* Tag encoding field values */
typedef enum _ASN1_ENCODING {
  ASN1_ENCODING_PRIMITIVE     = 0x00,
  ASN1_ENCODING_CONSTRUCTED   = 0x20
} ASN1_ENCODING;

/* Tag class field values */
typedef enum _ASN1_CLASS {
  ASN1_CLASS_UNIVERSAL        = 0x00,
  ASN1_CLASS_APPLICATION      = 0x40,
  ASN1_CLASS_CONTEXT_SPECIFIC = 0x80,
  ASN1_CLASS_PRIVATE          = 0xC0
} ASN1_CLASS;

/* ASN.1 taggings */
typedef enum {
  ASN1_TAGGING_BY_DEFAULT,
  ASN1_TAGGING_IMPLICIT,
  ASN1_TAGGING_EXPLICIT
} ASN1_TAGGING;

/* ASN.1 sequence item specificators */
typedef enum {
  ASN1_ITEM_NORMAL,
  ASN1_ITEM_OPTIONAL,
  ASN1_ITEM_DEFAULT
} ASN1_ITEM_TYPE;

/* ASN.1 type definitions */

/* There is no CONST protection for the Microsoft compiler below */
#if defined _MSC_VER
#undef CONST
#define CONST
#endif

/* ASN.1 definitions of primitive types */
typedef struct {
  ASN1_PRIM_TYPE CONST Type; /* The particular ASN.1 primitive type          */
  ASN1_TAG       CONST Tag;  /* The native ASN.1 type tag                    */

  union {
    struct {
      CK_LONG CONST Min;
      CK_LONG CONST Max;
    } Int;                    /* Integer Min/Max constraints for the type    */

    struct {
      CK_ULONG CONST Min;
      CK_ULONG CONST Max;
    } Enu;                    /* Enumerated Min/Max constraints for the type */

    struct {
      CK_ULONG CONST Min;
      CK_ULONG CONST Max;
    } Len;                    /* Bit/Octet/Utf8 string length constraints    */
  } Constraints;
} ASN1_PRIM_TYPE_DEF;

/* ASN.1 definitions of constructed types */

typedef struct _ASN1_TYPE_DEF          ASN1_TYPE_DEF;
typedef struct _ASN1_SEQUENCE_ITEM_DEF ASN1_SEQUENCE_ITEM_DEF;
typedef struct _ASN1_SET_ITEM_DEF      ASN1_SET_ITEM_DEF;

typedef struct {
  ASN1_SEQUENCE_ITEM_DEF CONST *CONST Item;
  CK_ULONG CONST                      Cnt;
} ASN1_SEQUENCE_TYPE_DEF;

typedef struct {
  ASN1_SET_ITEM_DEF CONST *CONST Item;
  CK_ULONG CONST                 Cnt;
} ASN1_SET_TYPE_DEF;

typedef struct {
  ASN1_TYPE_DEF CONST *CONST Item;
  CK_ULONG CONST             Cnt;
} ASN1_CHOICE_TYPE_DEF;

/* ASN.1 general type definition */
struct _ASN1_TYPE_DEF {
  CHAR16 CONST   *CONST Name;

  ASN1_CLASS_TYPE CONST Type;
  CK_ULONG CONST        Tag;
  ASN1_TAGGING CONST    Tagging;

  union {
    ASN1_PRIM_TYPE_DEF     CONST *CONST Prim;
    ASN1_SEQUENCE_TYPE_DEF CONST *CONST Sequence;
    ASN1_TYPE_DEF          CONST *CONST SequenceOf;
    ASN1_SET_TYPE_DEF      CONST *CONST Set;
    ASN1_TYPE_DEF          CONST *CONST SetOf;
    ASN1_CHOICE_TYPE_DEF   CONST *CONST Choice;
  }                     TypeRef;

  CK_BBOOL     CONST    ASN1; /* Store ASN1 representation while decoding */
};

/* Restore CONST protection */
#if defined _MSC_VER
#undef CONST
#define CONST const
#endif

/* ASN.1 value definitions */

/* ASN.1 values of primitive types */
typedef CK_BBOOL ASN1_BOOLEAN_VAL;
typedef CK_ULONG ASN1_ENUMERATED_VAL;

typedef struct {
  CK_BBOOL  Long; /* Whether Integer is stored in the long format */

  union {
    CK_LONG Val;  /* The storage for the short (native) format */

    struct {
      CK_BYTE *Val;
      CK_ULONG Len;
    }       Long; /* The storage for the long (kind an octet string) format */
  } Val;
} ASN1_INTEGER_VAL;

typedef struct {
  CK_BYTE  *Hex;
  CK_BYTE  *Val;
  CK_ULONG Len;
} ASN1_BIT_STRING_VAL;

typedef struct {
  CK_BYTE  *Val;
  CK_ULONG Len;
} ASN1_OCTET_STRING_VAL;

typedef struct {
  CK_UTF8CHAR *Val;
  CK_ULONG    Len;
} ASN1_UTF8_STRING_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_NUMERIC_STRING_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_PRINTABLE_STRING_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_TELETEXT_STRING_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_IA5_STRING_VAL;

typedef struct {
  CK_UTF16CHAR *Val;
  CK_ULONG     Len;
} ASN1_BMP_STRING_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_UTC_TIME_VAL;

typedef struct {
  CK_CHAR  *Val;
  CK_ULONG Len;
} ASN1_GENERALIZED_TIME_VAL;

typedef struct {
  CK_ULONG *Val;
  CK_ULONG Len;
} ASN1_OBJECT_IDENTIFIER_VAL;

typedef union {
  ASN1_BOOLEAN_VAL           Boolean;
  ASN1_INTEGER_VAL           Integer;
  ASN1_ENUMERATED_VAL        Enumerated;
  ASN1_BIT_STRING_VAL        BitString;
  ASN1_OCTET_STRING_VAL      OctetString;
  ASN1_UTF8_STRING_VAL       Utf8String;
  ASN1_NUMERIC_STRING_VAL    NumericString;
  ASN1_PRINTABLE_STRING_VAL  PrintableString;
  ASN1_TELETEXT_STRING_VAL   TeletextString;
  ASN1_IA5_STRING_VAL        IA5String;
  ASN1_BMP_STRING_VAL        BmpString;
  ASN1_UTC_TIME_VAL          UTCTime;
  ASN1_GENERALIZED_TIME_VAL  GeneralizedTime;
  ASN1_OBJECT_IDENTIFIER_VAL ObjectIdentifier;
} ASN1_PRIM_TYPE_VAL;

/* ASN.1 values of constructed types */

/* Forward declaration */
typedef struct _ASN1_CONS_TYPE_ITEM_VAL ASN1_CONS_TYPE_ITEM_VAL;
typedef struct _ASN1_TYPE_VAL           ASN1_TYPE_VAL;

typedef struct {
  ASN1_CONS_TYPE_ITEM_VAL *Item;
  CK_ULONG                Cnt;
} ASN1_SEQUENCE_TYPE_VAL;

typedef struct {
  ASN1_TYPE_VAL *Item;
  CK_ULONG      Cnt;
} ASN1_SEQUENCE_OF_TYPE_VAL;

typedef struct {
  ASN1_CONS_TYPE_ITEM_VAL *Item;
  CK_ULONG                Cnt;
} ASN1_SET_TYPE_VAL;

typedef struct {
  ASN1_TYPE_VAL *Item;
  CK_ULONG      Cnt;
} ASN1_SET_OF_TYPE_VAL;

typedef struct {
  ASN1_CONS_TYPE_ITEM_VAL *Item;
} ASN1_CHOICE_TYPE_VAL;

/* ASN.1 value general type */
struct  _ASN1_TYPE_VAL {
  ASN1_TYPE_DEF CONST   *Def;
  CK_BBOOL              Decoded;

  union {
    ASN1_PRIM_TYPE_VAL        Prim;
    ASN1_SEQUENCE_TYPE_VAL    Sequence;
    ASN1_SEQUENCE_OF_TYPE_VAL SequenceOf;
    ASN1_SET_TYPE_VAL         Set;
    ASN1_SET_OF_TYPE_VAL      SetOf;
    ASN1_CHOICE_TYPE_VAL      Choice;
  }                     TypeVal;

  ASN1_OCTET_STRING_VAL ASN1; /* ASN1 representation storage */
};

struct _ASN1_CONS_TYPE_ITEM_VAL {
  ASN1_TYPE_VAL Val;
  CK_ULONG      Ord;
};

/* There is no CONST protection for the Microsoft compiler below */
#if defined _MSC_VER
#undef CONST
#define CONST
#endif

/* This ones are from ASN.1 type definitions part */
struct _ASN1_SEQUENCE_ITEM_DEF {
  ASN1_ITEM_TYPE CONST       Type;
  ASN1_TYPE_DEF CONST        Val;
  ASN1_TYPE_VAL CONST *CONST Default;
};

struct _ASN1_SET_ITEM_DEF {
  ASN1_ITEM_TYPE CONST       Type;
  ASN1_TYPE_DEF CONST        Val;
  ASN1_TYPE_VAL CONST *CONST Default;
};

/* Restore CONST protection */
#if defined _MSC_VER
#undef CONST
#define CONST const
#endif


/* ASN.1 API */

/* Set wich tagging to use by default */
extern VOID SetDefaultTagging (CK_BBOOL Explicit);

/* Decode a buffer into V as the type specified in V->Def */
extern CK_RV Decode (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L);

/* Decode a buffer into V as the type specified in V->Def considering
   the buffer as an ASN.1 value body with the tag/len stripped */
extern CK_RV DecodePayload (ASN1_TYPE_VAL *V, CK_BYTE CONST *P, CK_ULONG L);

/* Get the Val of a sequence/set item */
extern CK_RV GetValByOrd (ASN1_TYPE_VAL **V, CK_ULONG Ord);

/* Free memory resources from the previously decoded ASN.1 value */
extern CK_RV FreeASN1 (ASN1_TYPE_VAL *V);

/* This struct is filled by GeTagInfo() */
typedef struct {
  union {
    CK_BBOOL Suc;
    CK_ULONG Num;
  } SucNum;

  CK_ULONG      Tag;
  CK_BYTE CONST *Pld;
  CK_ULONG      Len;
  CK_BYTE CONST *ASN1;
} ASN1_TAG_INFO;

/* These are all needed in Pkcs11Lib.c */
extern CK_RV GetTagInfo (ASN1_TAG_INFO *TI, CK_BYTE CONST *P, CK_ULONG L);

extern CK_RV DecodeSubtype (ASN1_TYPE_VAL *V, ASN1_TAG_INFO *TI);

extern CK_RV AddConsTypeItem (
  ASN1_CONS_TYPE_ITEM_VAL **Item,
  ASN1_TYPE_VAL           **V,
  ASN1_TYPE_DEF CONST     *Def,
  CK_ULONG                Cnt,
  CK_ULONG                Ord
  );

extern CK_RV AddTypeItem (
  ASN1_TYPE_VAL       **Item,
  ASN1_TYPE_VAL       **V,
  ASN1_TYPE_DEF CONST *Def,
  CK_ULONG            Cnt
  );

/* Inline functions */

/**
  Returns (in the static buffer) a string converted from CHAR8 to CHAR16

  The function converts not more than the first 255 symbols from a CHAR8 string
  to the CHAR16 one that is placed in the internal static buffer.

  @param  s    Input CHAR8 string

  @return Converted CHAR16 string placed in the internal static buffer.

**/
static inline CHAR16 const *ToChar16(CHAR8 const *s)
{
        static CHAR16  Buf[256];
        auto   CHAR16 *p = &Buf[0];

        while (p < &Buf[sizeof Buf / sizeof *Buf - 1] && (*p++ = *s++) != '\0')
          ;

        Buf[sizeof Buf / sizeof *Buf - 1] = L'\0';
        return Buf;
}

static inline void Dump16(void const *d, UINTN l, void (*emit)(CHAR16 const *))
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

#endif /* __ASN_1__ */
