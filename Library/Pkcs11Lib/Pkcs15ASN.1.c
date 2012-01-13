/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#define FIX_FOR_MACROS "Pkcs15ASN.1.h"

/* Performing the first inclusion and providing control macros undefined */
#define FFM_CMD_UNDEF
#include FIX_FOR_MACROS

/* Define the macro for the getting the code Microsoft-compatible header */
#define FIX_FOR_MICROSOFT "FixForMicrosoft.h"

/* The header is needed to be included to get the code Microsoft-compatible */
#include FIX_FOR_MICROSOFT

/* There is no CONST protection for the Microsoft compiler below */
#if defined _MSC_VER
#undef CONST
#define CONST
#endif

/* Set the function name generation mode for the FIX_FOR_MICROSOFT header */
#define FFM_CMD_NEXT_FUN_NAME

/* PKCS15 Constants (PKCS#15 v1.1, Annex A, page 54) */
typedef enum _ASN1_PKCS15_CONSTANT {
  PKCS15_UB_IDENTIFIER          = 255,
  PKCS15_UB_REFERENCE           = 255,
  PKCS15_UB_INDEX               = 65535,
  PKCS15_UB_LABEL               = PKCS15_UB_IDENTIFIER,
  PKCS15_LB_MIN_PIN_LENGTH      = 4,
  PKCS15_UB_MIN_PIN_LENGTH      = 8,
  PKCS15_UB_STORED_PIN_LENGTH   = 64,
  PKCS15_UB_RECORD_LENGTH       = 16383,
  PKCS15_UB_USER_CONSENT        = 15,
  PKCS15_UB_SECURITY_CONDITIONS = 255,
  PKCS15_UB_SE_INFO             = 255
} ASN1_PKCS15_CONSTANT;

/* ISO 7816-4 constants */
typedef enum _ASN1_ISO7816_4_CONSTANT {
  ISO7816_4_MAX_OFF_LEN         = 16383 + 255
} ASN1_ISO7816_4_CONSTANT;

/* Pure ASN.1 types */

/* ASN.1 BOOLEAN */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_BooleanPrim,
  4,
  (
    .Type                = ASN1_BOOLEAN_PRIM_TYPE,
    .Tag                 = ASN1_BOOLEAN_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  ASN1_Boolean,
  6,
  (
    .Name         = L"ASN1 Boolean",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &ASN1_BooleanPrim,
    .ASN1         = CK_FALSE
  )
)

/* ASN.1 INTEGER */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_IntegerPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Int.Min = 0,
    .Constraints.Int.Max = 0
  )
)

/* ASN.1 BIT STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_BitStringPrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Int.Min = 0,
    .Constraints.Int.Max = 0
  )
)

/* ASN.1 OCTET STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_OctetStringPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 NULL */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_NullPrim,
  4,
  (
    .Type                = ASN1_NULL_PRIM_TYPE,
    .Tag                 = ASN1_NULL_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 OBJECT IDENTIFIER */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_ObjectIdentifierPrim,
  4,
  (
    .Type                = ASN1_OBJECT_IDENTIFIER_PRIM_TYPE,
    .Tag                 = ASN1_OBJECT_IDENTIFIER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  ASN1_ObjectIdentifier,
  6,
  (
    .Name         = L"ASN1 ObjectIdentifier",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &ASN1_ObjectIdentifierPrim,
    .ASN1         = CK_FALSE
  )
)

/* ASN.1 UTF8 STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_Utf8StringPrim,
  4,
  (
    .Type                = ASN1_UTF8_STRING_PRIM_TYPE,
    .Tag                 = ASN1_UTF8_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 NUMERIC STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_NumericStringPrim,
  4,
  (
    .Type                = ASN1_NUMERIC_STRING_PRIM_TYPE,
    .Tag                 = ASN1_NUMERIC_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 PRINTABLE STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_PrintableStringPrim,
  4,
  (
    .Type                = ASN1_PRINTABLE_STRING_PRIM_TYPE,
    .Tag                 = ASN1_PRINTABLE_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN1 TELETEXT STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
  FFM_INITIALIZE (
    static ASN1_PRIM_TYPE_DEF,
    ASN1_TeletextStringPrim,
    4,
    (
      .Type                = ASN1_TELETEXT_STRING_PRIM_TYPE,
      .Tag                 = ASN1_TELETEXT_STRING_TAG,
      .Constraints.Len.Min = 0,
      .Constraints.Len.Max = 0
    )
  )

/* ASN.1 IA5 STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_IA5StringPrim,
  4,
  (
    .Type                = ASN1_IA5_STRING_PRIM_TYPE,
    .Tag                 = ASN1_IA5_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 BMP STRING */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_BMPStringPrim,
  4,
  (
    .Type                = ASN1_BMP_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BMP_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 UTCTime */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_UTCTimePrim,
  4,
  (
    .Type                = ASN1_UTC_TIME_PRIM_TYPE,
    .Tag                 = ASN1_UTC_TIME_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ASN.1 GeneralizedTime */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ASN1_GeneralizedTimePrim,
  4,
  (
    .Type                = ASN1_GENERALIZED_TIME_PRIM_TYPE,
    .Tag                 = ASN1_GENERALIZED_TIME_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0
  )
)

/* ISO 7816-4 specific types */

/* Constraint types */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ISO7816_4_DataLenPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = ISO7816_4_MAX_OFF_LEN
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ISO7816_4_LCSPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 1,
    .Constraints.Len.Max = 1
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ISO7816_4_FileIdDescPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 2,
    .Constraints.Len.Max = 2
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ISO7816_4_ProprietaryInfoPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 6,
    .Constraints.Len.Max = 6
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  ISO7816_4_SecAttrPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 15,
    .Constraints.Len.Max = 15
  )
)

/* File Control Information (partially), see ISO 7816-4, page 20, table 12 */

/* Self-made ASN.1 definition:

FCI ::= [APPLICATION 15] SEQUENCE {
  dataLen         [0]  INTEGER (0..ISO7816_4_MAX_OFF_LEN),
  fullLen         [1]  INTEGER,
  fileDescriptor  [2]  OCTET STRING (2..2),
  fileId          [3]  OCTET STRING (2..2),
  proprietaryInfo [5]  OCTET STRING (6..6),
  secAttr         [6]  OCTET STRING (15..15),
  LCS             [10] OCTET STRING (1..1)
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SET_ITEM_DEF,
  ISO7816_4_FCISetItems,
  7,
  8,
  (
    ( /* dataLen */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"dataLen",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_DataLenPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* fullLen */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name         = L"fullLen",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* fileDescriptor */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name         = L"fileDescriptor",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_FileIdDescPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* fileId */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name         = L"fileId",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_FileIdDescPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* proprietaryInfo */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"proprietaryInfo",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 5,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_ProprietaryInfoPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* secAttr */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"secAttr",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 6,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_SecAttrPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* LCS */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"LCS",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 10,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ISO7816_4_LCSPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SET_TYPE_DEF,
  ISO7816_4_FCISet,
  2,
  (
    .Item = &ISO7816_4_FCISetItems[0],
    .Cnt  = ARRAY_ITEMS (ISO7816_4_FCISetItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  ISO7816_4_FCI,
  6,
  (
    .Name        = L"ISO-7816-4 FCI",
    .Type        = ASN1_SET_CLASS_TYPE,
    .Tag         = ASN1_CLASS_APPLICATION | 15,
    .Tagging     = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Set = &ISO7816_4_FCISet,
    .ASN1        = CK_FALSE
  )
)

/* PKCS15 specific types */

/* PKCS15 v1.1, ANNEX A, page 55
Identifier ::= OCTET STRING (SIZE (0..pkcs15-ub-identifier)) */

/* PKCS15 Identifier primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_IdentifierPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_IDENTIFIER
  )
)

/* PKCS15 Identifier */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Identifier,
  6,
  (
    .Name         = L"PKCS15_Identifier",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &PKCS15_IdentifierPrim,
    .ASN1         = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 55
Reference ::= INTEGER (0..pkcs15-ub-reference) */

/* PKCS15 Identifier primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_ReferencePrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_LABEL
  )
)

/* PKCS15 Identifier */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Reference,
  6,
  (
    .Name         = L"PKCS15_Reference",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &PKCS15_ReferencePrim,
    .ASN1         = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 55
Label ::= UTF8String (SIZE(0..pkcs15-ub-label)) */

/* PKCS15 Label primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_LabelPrim,
  4,
  (
    .Type                = ASN1_UTF8_STRING_PRIM_TYPE,
    .Tag                 = ASN1_UTF8_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_LABEL
  )
)

/* PKCS15 Label */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Label,
  6,
  (
    .Name         = L"PKCS15_Label",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &PKCS15_LabelPrim,
    .ASN1         = CK_FALSE
  )
)

/* PKCS15 Certificate version primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_CertificateVersionPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 2
  )
)

/* PKCS15 Label */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CertificateVersion,
  6,
  (
    .Name         = L"PKCS15_CertificateVersion",
    .Type         = ASN1_PRIM_CLASS_TYPE,
    .Tag          = ASN1_NO_TAG,
    .Tagging      = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Prim = &PKCS15_CertificateVersionPrim,
    .ASN1         = CK_FALSE
  )
)

/* PKCS#15 v1.1 ANNEX A, page 56:
Path ::= SEQUENCE {
         path   OCTET STRING,
         index  INTEGER (0..pkcs15-ub-index) OPTIONAL,
         length [0] INTEGER (0..pkcs15-ub-index) OPTIONAL
         }( WITH COMPONENTS {..., index PRESENT, length PRESENT}|
         WITH COMPONENTS {..., index ABSENT, length ABSENT}
) */

/* PKCS15 Integer (0..pkcs15-ub-index) primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_Integer0PKCS15_UB_INDEXPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_INDEX
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_PathSequenceItems,
  3,
  8,
  (
    ( /* path */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"path",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_OctetStringPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* index */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"index",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_INDEXPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* length */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"length",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_INDEXPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_PathSequence,
  2,
  (
    .Item = &PKCS15_PathSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PathSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Path,
  6,
  (
    .Name             = L"PKCS15_Path",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_PathSequence,
    .ASN1             = CK_FALSE
  )
)

/* FIXME: incomplete */
/* PKCS#5 v2.1, page 26:
AlgorithmIdentifier { ALGORITHM-IDENTIFIER:InfoObjectSet }
::=
SEQUENCE {
  algorithm ALGORITHM-IDENTIFIER.&id({InfoObjectSet}),
  parameters ALGORITHM-IDENTIFIER.&Type({InfoObjectSet}
    {@algorithm}) OPTIONAL }

ALGORITHM-IDENTIFIER ::= TYPE-IDENTIFIER
*/

/* FIXME: needs to be populated */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS5_AlgorithmIdentifierSequenceItems,
  1,
  0,
  (
    (
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS5_AlgorithmIdentifierSequence,
  2,
  (
    .Item = &PKCS5_AlgorithmIdentifierSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS5_AlgorithmIdentifierSequenceItems)
  )
)

/* PKCS#15 v1.1, ANNEX A, page 56:
DigestInfoWithDefault ::= SEQUENCE {
        digestAlg      AlgorithmIdentifier {{DigestAlgorithms}} DEFAULT alg-id-sha1,
        digest         OCTET STRING (SIZE(8..128))
} */

/* PKCS15 OCTET STRING (SIZE(8..128) */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_OctetString_8_128Prim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 8,
    .Constraints.Len.Max = 128
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_DigestInfoWithDefaultSequenceItems,
  2,
  8,
  (
    ( /* digestAlg */
      .Type                 = ASN1_ITEM_DEFAULT,
      .Val.Name             = L"digestAlg",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS5_AlgorithmIdentifierSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* digest */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"digest",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &PKCS15_OctetString_8_128Prim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_DigestInfoWithDefaultSequence,
  2,
  (
    .Item = &PKCS15_DigestInfoWithDefaultSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_DigestInfoWithDefaultSequenceItems)
  )
)

/* PKCS#15 v1.1, ANNEX A, page 56:
URL ::= CHOICE {
        url       PrintableString,
        urlWithDigest [3] SEQUENCE {
            url         IA5String,
            digest      DigestInfoWithDefault
            }
} */

/* PKCS15 urlWithDigest anonymous sequence */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_urlWithDigestSequenceItems,
  2,
  8,
  (
    ( /* url */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name             = L"url",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_IA5StringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* digest */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name             = L"digest",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_DigestInfoWithDefaultSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_urlWithDigestSequence,
  2,
  (
    .Item = &PKCS15_urlWithDigestSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_urlWithDigestSequenceItems)
  )
)

/* URL itself */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_URLChoiceItems,
  2,
  6,
  (
    ( /* url */
      .Name             = L"url",
      .Type             = ASN1_PRIM_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim     = &ASN1_PrintableStringPrim,
      .ASN1             = CK_FALSE
    ),
    ( /* urlWithDigest */
      .Name             = L"urlWithDigest",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PKCS15_urlWithDigestSequence,
      .ASN1             = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_URLChoice,
  2,
  (
    .Item = &PKCS15_URLChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_URLChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_URL,
  6,
  (
    .Name           = L"PKCS15_URL",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_URLChoice,
    .ASN1           = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 56:
ReferencedValue {Type} ::= CHOICE {
       path     Path,
       url      URL
       } (CONSTRAINED BY {-- 'path' or 'url' shall point to an object of type -- Type})
*/

/* ReferencedValue is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 66:
EnvelopedData {Type} ::= SEQUENCE {
       version                 INTEGER{v0(0),v1(1),v2(2),v3(3),v4(4)}(v0|v1|v2,...),
       originatorInfo          [0] OriginatorInfo OPTIONAL,
       recipientInfos          RecipientInfos,
       encryptedContentInfo    EncryptedContentInfo{Type},
       unprotectedAttrs        [1] SET SIZE (1..MAX) OF Attribute OPTIONAL
} */

/* EnvelopedData is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 56:
ObjectValue { Type } ::= CHOICE {
       indirect                  ReferencedValue {Type},
       direct                    [0] Type,
       indirect-protected        [1] ReferencedValue {EnvelopedData {Type}},
       direct-protected          [2] EnvelopedData {Type}
       }(CONSTRAINED BY {-- if indirection is being used, then it is expected that the reference
       -- points either to a (possibly enveloped) object of type -- Type -- or (key case) to a card-
       -- specific key file --})
*/

/* ObjectValue is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 56:
PathOrObjects {ObjectType} ::= CHOICE {
       path      Path,
       objects [0] SEQUENCE OF ObjectType,
       ...,
       indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
       direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType}
} */

/* PathOrObjects is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS15 v1.1, ANNEX A, page 57:
CommonObjectFlags ::= BIT STRING {
     private        (0),
     modifiable     (1)
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_CommonObjectFlagsPrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 2
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
AccessMode ::= BIT STRING {
       read     (0),
       update (1),
       execute (2)
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_AccessModePrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 3
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
SecurityCondition ::= CHOICE {
        authId Identifier,
        not[0] SecurityCondition,
        and         [1] SEQUENCE SIZE (2..pkcs15-ub-securityConditions) OF SecurityCondition,
        or          [2] SEQUENCE SIZE (2..pkcs15-ub-securityConditions) OF SecurityCondition,
        ... -- For future extensions
} */

static ASN1_CHOICE_TYPE_DEF CONST PKCS15_SecurityConditionChoice;
static ASN1_TYPE_DEF CONST PKCS15_SecurityCondition;

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_SecurityConditionChoiceItems,
  4,
  6,
  (
    ( /* authId */
      .Name         = L"authId",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &PKCS15_IdentifierPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* not */
      .Name         = L"not",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PKCS15_SecurityConditionChoice,
      .ASN1         = CK_FALSE
    ),
    ( /* and */
      .Name         = L"and",
      .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.SequenceOf = &PKCS15_SecurityCondition,
      .ASN1         = CK_FALSE
    ),
    ( /* or */
      .Name         = L"or",
      .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.SequenceOf = &PKCS15_SecurityCondition,
      .ASN1         = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_SecurityConditionChoice,
  2,
  (
    .Item = &PKCS15_SecurityConditionChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_SecurityConditionChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_SecurityCondition,
  6,
  (
    .Name           = L"PKCS15_SecuruityCondition",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_SecurityConditionChoice,
    .ASN1           = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
AccessControlRule ::= SEQUENCE {
       accessMode              AccessMode,
       securityCondition       SecurityCondition,
       ... -- For future extensions
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_AccessControlRuleSequenceItems,
  2,
  8,
  (
    ( /* accessMode */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"accessMode",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &PKCS15_AccessModePrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* securityCondition */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"securityCondition",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &PKCS15_SecurityConditionChoice,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_AccessControlRuleSequence,
  2,
  (
    .Item = &PKCS15_AccessControlRuleSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_AccessControlRuleSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_AccessControlRule,
  6,
  (
    .Name             = L"PKCS15_AccessControlRule",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_AccessControlRuleSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 56:
CommonObjectAttributes ::= SEQUENCE {
        label         Label OPTIONAL,
        flags         CommonObjectFlags OPTIONAL,
        authId        Identifier OPTIONAL,
        ...,
        userConsent INTEGER (1..pkcs15-ub-userConsent) OPTIONAL,
        accessControlRules SEQUENCE SIZE (1..MAX) OF AccessControlRule OPTIONAL
     } (CONSTRAINED BY {-- authId should be present in the IC card case if flags.private is set.
     -- It must equal an authID in one AuthRecord in the AODF -- })
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_Integer1PKCS15_UB_USER_CONSENTPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_USER_CONSENT
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CommonObjectAttributesSequenceItems,
  5,
  8,
  (
    ( /* label */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"label",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* flags */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"flags",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_CommonObjectFlagsPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* authId */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"authId",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_IdentifierPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* userConsent */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"userConsent",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_Integer1PKCS15_UB_USER_CONSENTPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* accessControlRules */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"accessControlRules",
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.SequenceOf = &PKCS15_AccessControlRule,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CommonObjectAttributesSequence,
  2,
  (
    .Item = &PKCS15_CommonObjectAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CommonObjectAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CommonObjectAttributes,
  6,
  (
    .Name             = L"PKCS15_CommonObjectAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CommonObjectAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
KeyUsageFlags ::= BIT STRING {
       encrypt             (0),
       decrypt             (1),
       sign                (2),
       signRecover         (3),
       wrap                (4),
       unwrap              (5),
       verify              (6),
       verifyRecover (7),
       derive              (8),
       nonRepudiation      (9)
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_KeyUsageFlagsPrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 10
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
KeyAccessFlags ::= BIT STRING {
       sensitive           (0),
       extractable         (1),
       alwaysSensitive     (2),
       neverExtractable    (3),
       local               (4)
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_KeyAccessFlagsPrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 5
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
CommonKeyAttributes ::= SEQUENCE {
     iD                 Identifier,
     usage              KeyUsageFlags,
     native             BOOLEAN DEFAULT TRUE,
     accessFlags        KeyAccessFlags OPTIONAL,
     keyReference       Reference OPTIONAL,
     startDate          GeneralizedTime OPTIONAL,
     endDate            [0] GeneralizedTime OPTIONAL,
     ... -- For future extensions
} */

/* The default value for the 'native' item */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_VAL,
  PKCS15_CommonKeyAttributesSequenceItems_native,
  3,
  (
    .Def                  = &ASN1_Boolean,
    .Decoded              = CK_TRUE,
    .TypeVal.Prim.Boolean = CK_TRUE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CommonKeyAttributesSequenceItems,
  5,
  8,
  (
    ( /* iD */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name         = L"iD",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_IdentifierPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* usage */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name         = L"usage",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_KeyUsageFlagsPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* native */
      .Type = ASN1_ITEM_DEFAULT,
      .Val.Name         = L"native",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_BooleanPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = &PKCS15_CommonKeyAttributesSequenceItems_native
    ),
    ( /* accessFlags */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"accessFlags",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_KeyAccessFlagsPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* keyReference */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"keyReference",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_ReferencePrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

    /* FIXME: implementation should be completed */
#if 0
    ( /* startDate */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer1PKCS15_UB_USER_CONSENTPrim,
      .Default          = NULL_PTR
    ),
    ( /* endDate */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer1PKCS15_UB_USER_CONSENTPrim,
      .Default          = NULL_PTR
    )
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CommonKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_CommonKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CommonKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CommonKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_CommonKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CommonKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 57:
CommonPrivateKeyAttributes ::= SEQUENCE {
     subjectName Name OPTIONAL,
     keyIdentifiers [0] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
     ... -- For future extensions
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CommonPrivateKeyAttributesSequenceItems,
  1,
  8,
  (
    ( /* subjectName */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"subjectName",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    )
  )
)

    /* FIXME: implementation should be completed */
#if 0
    ( /* keyIdentifiers */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.SequenceOf = &PKCS15_CredentialIdentifier,
      .Default                = NULL_PTR
    )
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CommonPrivateKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_CommonPrivateKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CommonPrivateKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CommonPrivateKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_CommonPrivateKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CommonPrivateKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 58:
Usage ::= SEQUENCE {
        keyUsage     KeyUsage OPTIONAL,
        extKeyUsage SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER OPTIONAL
        }(WITH COMPONENTS {..., keyUsage PRESENT} |
          WITH COMPONENTS {..., extKeyUsage PRESENT})
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_UsageSequenceItems,
  1,
  8,
  (
    ( /* extKeyUsage */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"extKeyUsage",
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.SequenceOf = &ASN1_ObjectIdentifier,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    )
  )
)

    /* FIXME: implementation is needed */
#if 0
    ( /* keyUsage */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_KeyUsagePrim,
      .Default                = NULL_PTR
    ),
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_UsageSequence,
  2,
  (
    .Item = &PKCS15_UsageSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_UsageSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Usage,
  6,
  (
    .Name             = L"PKCS15_Usage",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_UsageSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS15 v1.1, ANNEX A, page 58:
CommonPublicKeyAttributes ::= SEQUENCE {
     subjectName Name OPTIONAL,
     ...,
     trustedUsage [0] Usage OPTIONAL
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CommonPublicKeyAttributesSequenceItems,
  2,
  8,
  (
    ( /* subjectName */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"subjectName",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &PKCS15_LabelPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* trustedUsage */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"subjectName",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_UsageSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CommonPublicKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_CommonPublicKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CommonPublicKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CommonPublicKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_CommonPublicKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CommonPublicKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 58:
PKCS15Object {ClassAttributes, SubClassAttributes, TypeAttributes} ::= SEQUENCE {
      commonObjectAttributes CommonObjectAttributes,
      classAttributes        ClassAttributes,
      subClassAttributes     [0] SubClassAttributes OPTIONAL,
      typeAttributes         [1] TypeAttributes
} */

/* PKCS15Object is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 59:
PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
        CommonKeyAttributes, CommonPrivateKeyAttributes, KeyAttributes}
*/

/* PrivateKeyObject is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 60:
PublicKeyObject {KeyAttributes} ::= PKCS15Object {
       CommonKeyAttributes, CommonPublicKeyAttributes, KeyAttributes}
*/

/* PublicKeyObject is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS#15 v1.1, ANNEX A, page 58:
KeyInfo {ParameterType, OperationsType} ::= CHOICE {
        reference    Reference,
        paramsAndOps SEQUENCE {
           parameters          ParameterType,
           supportedOperations OperationsType OPTIONAL
}
} */

/* KeyInfo is a macro and defined in the 'Pkcs15ASN.1.h' */


/* PKCS15 v1.1, ANNEX A, page 59:
RSAPrivateKeyObject ::= SEQUENCE {
       modulus         [0] INTEGER OPTIONAL, -- n
       publicExponent  [1] INTEGER OPTIONAL, -- e
       privateExponent [2] INTEGER OPTIONAL, -- d
       prime1          [3] INTEGER OPTIONAL, -- p
       prime2          [4] INTEGER OPTIONAL, -- q
       exponent1       [5] INTEGER OPTIONAL, -- d mod (p-1)
       exponent2       [6] INTEGER OPTIONAL, -- d mod (q-1)
       coefficient     [7] INTEGER OPTIONAL -- inv(q) mod p
} (CONSTRAINED BY {-- must be possible to reconstruct modulus and privateExponent from
-- selected fields --})
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_RSAPrivateKeyObjectSequenceItems,
  8,
  8,
  (
    ( /* modulus */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"modulus",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* publicExponent */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"publicExponent",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* privateExponent */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"privateExponent",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* prime1 */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"prime1",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* prime2 */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"prime2",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* exponent1 */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"exponent1",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* exponent2 */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"exponent2",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* coefficient */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"coefficient",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_RSAPrivateKeyObjectSequence,
  2,
  (
    .Item = &PKCS15_RSAPrivateKeyObjectSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_RSAPrivateKeyObjectSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_RSAPrivateKeyObject,
  6,
  (
    .Name             = L"PKCS15_RSAPrivateKeyObject",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_RSAPrivateKeyObjectSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 59:
PrivateRSAKeyAttributes ::= SEQUENCE {
        value ObjectValue {RSAPrivateKeyObject},
        modulusLength  INTEGER, -- modulus length in bits, e.g. 1024
        keyInfo   KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
        ... -- For future extensions
} */

/* Preparing 'ObjectValue' pseudo-macro parameters */
#define FFM_CMD_OBJECT_VALUE_Type_ \
  PKCS15_RSAPrivateKeyObjectSequence

#define FFM_CMD_OBJECT_VALUE_ClassType_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_OBJECT_VALUE_UnionType_ \
  Sequence

#define FFM_CMD_OBJECT_VALUE_ASN1_ \
  CK_FALSE

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_OBJECT_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_PrivateRSAKeyAttributesSequenceItems,
  2,
  8,
  (
    ( /* value */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (
                               PKCS15_RSAPrivateKeyObjectSequence
                               ),
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* modulusLength */
      .Type = ASN1_ITEM_NORMAL,
      .Val.Name           = L"modulusLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

    /* FIXME: implementation should be completed */
#if 0
    ( /* keyInfo */
      .Type = ASN1_ITEM_OPTIONAL,
        = {
      .Val.Type           = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (
                              RSAPrivateKeyObject,
                              ASN1_SEQUENCE_CLASS_TYPE,
                              Sequence
                              ),
      .Default            = NULL_PTR
    ),
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_PrivateRSAKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_PrivateRSAKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PrivateRSAKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PrivateRSAKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_PrivateRSAKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_PrivateRSAKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 60:
PrivateKEAKeyAttributes ::= SEQUENCE {
        value   ObjectValue {KEAPrivateKey},
        keyInfo KeyInfo {DomainParameters, PublicKeyOperations} OPTIONAL,
        ... -- For future extensions
} */

/* PKCS#15 v1.1, ANNEX A, page 60:
KEAPrivateKey ::= INTEGER
*/

/* Preparing 'ObjectValue' pseudo-macro parameters */
#define FFM_CMD_OBJECT_VALUE_Type_ \
  ASN1_IntegerPrim /* KEAPrivateKey */

#define FFM_CMD_OBJECT_VALUE_ClassType_ \
  ASN1_PRIM_CLASS_TYPE

#define FFM_CMD_OBJECT_VALUE_UnionType_ \
  Prim

#define FFM_CMD_OBJECT_VALUE_ASN1_ \
  CK_FALSE

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_OBJECT_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_PrivateKEAKeyAttributesSequenceItems,
  1,
  8,
  (
    ( /* value */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
                                                   /* KEAPrivateKey */
      .Val.TypeRef.Choice = &ObjectValueNameChoice (ASN1_IntegerPrim),
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

    /* FIXME: implementation should be completed */
#if 0
    ( /* keyInfo */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Type           = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (
                              RSAPrivateKeyObject,
                              ASN1_SEQUENCE_CLASS_TYPE,
                              Sequence
                              ),
      .Default          = NULL_PTR
    ),
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_PrivateKEAKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_PrivateKEAKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PrivateKEAKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PrivateKEAKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_PrivateKEAKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_PrivateKEAKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, page 59:
PrivateKeyType ::= CHOICE {
        privateRSAKey PrivateKeyObject {PrivateRSAKeyAttributes},
        privateECKey            [0] PrivateKeyObject {PrivateECKeyAttributes},
        privateDHKey            [1] PrivateKeyObject {PrivateDHKeyAttributes},
        privateDSAKey [2] PrivateKeyObject {PrivateDSAKeyAttributes},
        privateKEAKey [3] PrivateKeyObject {PrivateKEAKeyAttributes},
        ... -- For future extensions
} */

/* Preparing 'PrivateKeyObject' pseudo-macro parameters */
#define FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_ \
  PKCS15_PrivateRSAKeyAttributesSequence

#define FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_ \
  Sequence

/* Preparing to 'call' 'PrivateKeyObject' pseudo-macros */
#define FFM_CMD_PRIVATE_KEY_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Preparing 'PrivateKeyObject' pseudo-macro parameters */
#define FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_ \
  PKCS15_PrivateKEAKeyAttributesSequence

#define FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_ \
  Sequence

/* Preparing to 'call' 'PrivateKeyObject' pseudo-macros */
#define FFM_CMD_PRIVATE_KEY_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_PrivateKeyTypeChoiceItems,
  5,
  6,
  (
    ( /* privateRSAKey */
      .Name             = L"privateRSAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PrivateKeyObjectNameSequence (
                             PKCS15_PrivateRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* privateECKey */
      .Name             = L"privateECKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PrivateKeyObjectNameSequence (
                             PKCS15_PrivateRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* privateDHKey */
      .Name             = L"privateDHKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PrivateKeyObjectNameSequence (
                             PKCS15_PrivateRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* privateDSAKey */
      .Name             = L"privateDSAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PrivateKeyObjectNameSequence (
                             PKCS15_PrivateRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    ( /* privateKEAKey */
      .Name             = L"privateKEAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PrivateKeyObjectNameSequence (
                             PKCS15_PrivateKEAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_PrivateKeyTypeChoice,
  2,
  (
    .Item = &PKCS15_PrivateKeyTypeChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PrivateKeyTypeChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_PrivateKeyType,
  6,
  (
    .Name           = L"PKCS15_PrivateKeyType",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_PrivateKeyTypeChoice,
    .ASN1           = CK_FALSE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (\
  ASN1_TYPE_DEF,
  PKCS15_PrivateKeyTypeSequenceOf,
  6,
  (
    .Name               = L"PKCS15_PrivateKeyTypeSequenceOf",
    .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
    .Tag                = ASN1_NO_TAG,
    .Tagging            = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.SequenceOf = &PKCS15_PrivateKeyType,
    .ASN1               = CK_FALSE
  )
)

/* FIXME: should be defined real RSAPublicKey instead of this stub */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_RSAPublicKeySequenceItems,
  2,
  8,
  (
    ( /* value */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"value",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* modulusLength */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"modulusLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_IntegerPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)
  /* FIXME: implementation should be completed */
#if 0
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Type           = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (
                               RSAPrivateKeyObject,
                               ASN1_SEQUENCE_CLASS_TYPE,
                               Sequence
                               )
      .Default            = NULL_PTR
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_RSAPublicKeySequence,
  2,
  (
    .Item = &PKCS15_RSAPublicKeySequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_RSAPublicKeySequenceItems)
  )
)

/* PKCS#15 v1.1, ANNEX A, page 60:
RSAPublicKeyChoice ::= CHOICE {
      raw      RSAPublicKey,
      spki    [1] SubjectPublicKeyInfo, -- See X.509. Must contain a public RSA key
      ...
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_RSAPublicKeyChoiceChoiceItems,
  1,
  6,
  (
    ( /* raw */
      .Name             = L"raw",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PKCS15_RSAPublicKeySequence,
      .ASN1             = CK_TRUE
    )
  )
)
  /* FIXME: implementation should be completed */
#if 0
  {
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_RSAPublicKeySequence
  } /* spki */
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_RSAPublicKeyChoiceChoice,
  2,
  (
    .Item = &PKCS15_RSAPublicKeyChoiceChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_RSAPublicKeyChoiceChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_RSAPublicKeyChoice,
  6,
  (
    .Name           = L"PKCS15_RSAPublicKeyChoice",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_RSAPublicKeyChoiceChoice,
    .ASN1           = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 60:
PublicRSAKeyAttributes ::= SEQUENCE {
       value                   ObjectValue {RSAPublicKeyChoice},
       modulusLength           INTEGER, -- modulus length in bits, e.g. 1024
       keyInfo                 KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
       ... -- For future extensions
} */

/* Preparing 'ObjectValue' pseudo-macro parameters */
#define FFM_CMD_OBJECT_VALUE_Type_ \
  PKCS15_RSAPublicKeyChoiceChoice

#define FFM_CMD_OBJECT_VALUE_ClassType_ \
  ASN1_CHOICE_CLASS_TYPE

#define FFM_CMD_OBJECT_VALUE_UnionType_ \
  Choice

#define FFM_CMD_OBJECT_VALUE_ASN1_ \
  CK_FALSE

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_OBJECT_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_PublicRSAKeyAttributesSequenceItems,
  2,
  8,
  (
    ( /* value */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (PKCS15_RSAPublicKeyChoiceChoice),
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* modulusLength */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"modulusLength",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_IntegerPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#if 0
  {
    .Type = ASN1_ITEM_OPTIONAL,
    .Val  = {
      .Type           = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag            = ASN1_NO_TAG,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &ObjectValueNameChoice (
                          RSAPrivateKeyObject,
                          ASN1_SEQUENCE_CLASS_TYPE,
                          Sequence
                          )
    },
    NULL_PTR
  }, /* keyInfo */
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_PublicRSAKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_PublicRSAKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PublicRSAKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PublicRSAKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_PublicRSAKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_PublicRSAKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* GOST Public Key primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_KEAPublicKeyPrim,
  4,
  (
    .Type                = ASN1_OCTET_STRING_PRIM_TYPE,
    .Tag                 = ASN1_OCTET_STRING_TAG,
    .Constraints.Len.Min = 64,
    .Constraints.Len.Max = 64
  )
)

/* PKCS#15 v1.1, ANNEX A, page 61:
KEAPublicKeyChoice ::= CHOICE {
      raw     INTEGER,
      spki    SubjectPublicKeyInfo, -- See X.509. Must contain a public KEA key
      ...
} */

/* GOST is used instead of KEA */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY(
  static ASN1_TYPE_DEF,
  PKCS15_KEAPublicKeyChoiceChoiceItems,
  1,
  6,
  (
    ( /* gost */
      .Name         = L"raw",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &PKCS15_KEAPublicKeyPrim,
      .ASN1         = CK_TRUE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_KEAPublicKeyChoiceChoice,
  2,
  (
    .Item = &PKCS15_KEAPublicKeyChoiceChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_KEAPublicKeyChoiceChoiceItems)
  )
)

/* PKCS#15 v1.1, ANNEX A, page61:
PublicKEAKeyAttributes ::= SEQUENCE {
       value   ObjectValue {KEAPublicKeyChoice},
       keyInfo KeyInfo {DomainParameters, PublicKeyOperations} OPTIONAL,
       ... -- For future extensions
} */

/* Preparing 'ObjectValue' pseudo-macro parameters */
#define FFM_CMD_OBJECT_VALUE_Type_ \
  PKCS15_KEAPublicKeyChoiceChoice

#define FFM_CMD_OBJECT_VALUE_ClassType_ \
  ASN1_CHOICE_CLASS_TYPE

#define FFM_CMD_OBJECT_VALUE_UnionType_ \
  Choice

#define FFM_CMD_OBJECT_VALUE_ASN1_ \
  CK_FALSE

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_OBJECT_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_PublicKEAKeyAttributesSequenceItems,
  1,
  8,
  (
    ( /* value */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (PKCS15_KEAPublicKeyChoiceChoice),
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#if 0
  {
    .Type = ASN1_ITEM_OPTIONAL,
    .Val  = {
      .Type           = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag            = ASN1_NO_TAG,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &ObjectValueNameChoice (
                          RSAPrivateKeyObject,
                          ASN1_SEQUENCE_CLASS_TYPE,
                          Sequence
                          )
    },
    NULL_PTR
  }, /* keyInfo */
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_PublicKEAKeyAttributesSequence,
  2,
  (
    .Item = &PKCS15_PublicKEAKeyAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PublicKEAKeyAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PublicKEAKeyAttributes,
  6,
  (
    .Name             = L"PKCS15_PublicKEAKeyAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_PublicKEAKeyAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 60:
PublicKeyType ::= CHOICE {
       publicRSAKey PublicKeyObject {PublicRSAKeyAttributes},
       publicECKey             [0] PublicKeyObject {PublicECKeyAttributes},
       publicDHKey             [1] PublicKeyObject {PublicDHKeyAttributes},
       publicDSAKey [2] PublicKeyObject {PublicDSAKeyAttributes},
       publicKEAKey [3] PublicKeyObject {PublicKEAKeyAttributes},
       ... -- For future extensions
} */


/* Preparing 'PublicKeyObject' pseudo-macro parameters */
#define FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_ \
  PKCS15_PublicRSAKeyAttributesSequence

#define FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PUBLIC_KEY_OBJECT_UnionKeyAttributes_ \
  Sequence

/* Preparing to 'call' 'PublicKeyObject' pseudo-macros */
#define FFM_CMD_PUBLIC_KEY_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Preparing 'PublicKeyObject' pseudo-macro parameters */
#define FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_ \
  PKCS15_PublicKEAKeyAttributesSequence

#define FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PUBLIC_KEY_OBJECT_UnionKeyAttributes_ \
  Sequence

/* Preparing to 'call' 'PublicKeyObject' pseudo-macros */
#define FFM_CMD_PUBLIC_KEY_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_PublicKeyTypeChoiceItems,
  5,
  6,
  (
    ( /* publicRSAKey */
      .Name             = L"publicRSAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PublicKeyObjectNameSequence (
                             PKCS15_PublicRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* publicECKey */
      .Name             = L"publicECKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PublicKeyObjectNameSequence (
                             PKCS15_PublicRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* publicDHKey */
      .Name             = L"publicDHKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PublicKeyObjectNameSequence (
                             PKCS15_PublicRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    /* FIXME: implementation should be completed */
    ( /* publicDSAKey */
      .Name             = L"publicDSAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PublicKeyObjectNameSequence (
                             PKCS15_PublicRSAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    ),
    ( /* publicKEAKey */
      .Name             = L"publicKEAKey",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PublicKeyObjectNameSequence (
                             PKCS15_PublicKEAKeyAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_PublicKeyTypeChoice,
  2,
  (
    .Item = &PKCS15_PublicKeyTypeChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PublicKeyTypeChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_PublicKeyType,
  6,
  (
    .Name           = L"PKCS15_PublicKeyType",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_PublicKeyTypeChoice,
    .ASN1           = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 61:
GenericSecretKeyAttributes ::= SEQUENCE {
     value       ObjectValue { OCTET STRING },
     ... -- For future extensions
     }
*/

/* PKCS#15 v1.1, ANNEX A, page 58:
CommonSecretKeyAttributes ::= SEQUENCE {
     keyLen INTEGER OPTIONAL, -- keylength (in bits)
     ... -- For future extensions
     }
*/

/* PKCS#15 v1.1, ANNEX A, page 61:
SecretKeyObject {KeyAttributes} ::= PKCS15Object {
        CommonKeyAttributes, CommonSecretKeyAttributes, KeyAttributes}
*/

/* PKCS#15 v1.1, ANNEX A, page 61:
SecretKeyType ::= CHOICE {
       genericSecretKey SecretKeyObject {GenericSecretKeyAttributes},
       rc2key             [0] SecretKeyObject {GenericSecretKeyAttributes},
       rc4key             [1] SecretKeyObject {GenericSecretKeyAttributes},
       desKey             [2] SecretKeyObject {GenericSecretKeyAttributes},
       des2Key            [3] SecretKeyObject {GenericSecretKeyAttributes},
       des3Key            [4] SecretKeyObject {GenericSecretKeyAttributes},
       castKey            [5] SecretKeyObject {GenericSecretKeyAttributes},
       cast3Key           [6] SecretKeyObject {GenericSecretKeyAttributes},
       cast128Key         [7] SecretKeyObject {GenericSecretKeyAttributes},
       rc5Key             [8] SecretKeyObject {GenericSecretKeyAttributes},
       ideaKey            [9] SecretKeyObject {GenericSecretKeyAttributes},
       skipjackKey        [10] SecretKeyObject {GenericSecretKeyAttributes},
       batonKey           [11] SecretKeyObject {GenericSecretKeyAttributes},
       juniperKey         [12] SecretKeyObject {GenericSecretKeyAttributes},
       rc6Key             [13] SecretKeyObject {GenericSecretKeyAttributes},
       otherKey [14] OtherKey,
       ... -- For future extensions
       }
*/

/* FIXME: These is the FAKE object, and MUST be replaced with real one */
ASN1_TYPE_DEF CONST PKCS15_SecretKeyType;

/* Found somewhere in the Internet...
OOBCertHash ::= SEQUENCE {
                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
                      certId      [1] CertId                  OPTIONAL,
                      hashVal         BIT STRING
                      -- hashVal is calculated over the DER encoding of the
                      -- self-signed certificate with the identifier certID.
       }
*/

/* PKCS#15 v1.1, ANNEX A, page 58:
CommonCertificateAttributes ::= SEQUENCE {
     iD                    Identifier,
     authority             BOOLEAN DEFAULT FALSE,
     identifier            CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
     certHash              [0] OOBCertHash OPTIONAL,
     ...,
     trustedUsage          [1] Usage OPTIONAL,
     identifiers           [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} OPTIONAL,
     implicitTrust         [3] BOOLEAN DEFAULT FALSE
     }
*/

/* The default value for the 'iD' and 'implicitTrust' items */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_VAL,
  PKCS15_CommonCertificateAttributesSequenceItems_authority_implicitTrust,
  3,
  (
    .Def                  = &ASN1_Boolean,
    .Decoded              = CK_TRUE,
    .TypeVal.Prim.Boolean = CK_FALSE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CommonCertificateAttributesSequenceItems,
  3,
  8,
  (
    ( /* iD */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"iD",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_IdentifierPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = &PKCS15_CommonCertificateAttributesSequenceItems_authority_implicitTrust
    ),
    ( /* authority */
      .Type             = ASN1_ITEM_OPTIONAL, /* By fact */
      .Val.Name         = L"authority",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_BooleanPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),

    /* FIXME: Optional fields must be implemented */

    ( /* implicitTrust */
      .Type             = ASN1_ITEM_OPTIONAL, /* By fact */
      .Val.Name         = L"implicitTrust",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_BooleanPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = &PKCS15_CommonCertificateAttributesSequenceItems_authority_implicitTrust
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CommonCertificateAttributesSequence,
  2,
  (
    .Item = &PKCS15_CommonCertificateAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CommonCertificateAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_CommonCertificateAttributes,
  6,
  (
    .Name             = L"PKCS15_CommonCertificateAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CommonCertificateAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* X.509 Certificates (RFC 5280, the URL is: http://tools.ietf.org/html/rfc5280)
   defifnitions came from: AuthenticationFramework
  {joint-iso-itu-t ds(5) module(1) authenticationFramework(7) 6}, the URL is:
  http://www.itu.int/
  ITU-T/formal-language/itu-t/x/x509/2008/AuthenticationFramework.html */

/*
AlgorithmParameterSet ::= SEQUENCE {
  cipherParameterSet OBJECT IDENTIFIER,
  hashParameterSet   OBJECT IDENTIFIER
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_ParameterSetSequenceItems,
  2,
  8,
  (
    ( /* cipherParameterSet */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"cipherParameterSet",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1           = CK_TRUE,
      .Default            = NULL_PTR
    ),
    ( /* hashParameterSet */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"hashParameterSet",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1           = CK_TRUE,
      .Default            = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_ParameterSetSequence,
  2,
  (
    .Item = &PKCS15_ParameterSetSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_ParameterSetSequenceItems)
  )
)

/*
AlgorithmParameters ::= CHOICE {
  null     NULL,
  sequence AlgorithmParameterSet
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_AlgorithmParametersChoiceItems,
  2,
  6,
  (
    ( /* null */
      .Name             = L"null",
      .Type             = ASN1_PRIM_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim     = &ASN1_NullPrim,
      .ASN1             = CK_FALSE
    ),
    ( /* sequence */
      .Name             = L"sequence",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &PKCS15_ParameterSetSequence,
      .ASN1             = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_AlgorithmParametersChoice,
  2,
  (
    .Item = &PKCS15_AlgorithmParametersChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_AlgorithmParametersChoiceItems)
  )
)

/*
AlgorithmIdentifier{ALGORITHM:SupportedAlgorithms} ::= SEQUENCE {
  algorithm   ALGORITHM.&id({SupportedAlgorithms}),
  parameters  ALGORITHM.&Type({SupportedAlgorithms}{@algorithm}) OPTIONAL
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_AlgorithmIdentifierSequenceItems,
  2,
  8,
  (
    ( /* algorithm */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"algorithm",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* parameters */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"parameters",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &PKCS15_AlgorithmParametersChoice,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_AlgorithmIdentifierSequence,
  2,
  (
    .Item = &PKCS15_AlgorithmIdentifierSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_AlgorithmIdentifierSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_AlgorithmIdentifier,
  6,
  (
    .Name             = L"PKCS15_AlgorithmIdentifier",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_AlgorithmIdentifierSequence,
    .ASN1             = CK_FALSE
  )
)

/*
AttributeTypeAndDistinguishedValue ::= SEQUENCE {
  type                  ATTRIBUTE.&id({SupportedAttributes}),
  value                 ATTRIBUTE.&Type({SupportedAttributes}{@type}),
  primaryDistinguished  BOOLEAN DEFAULT TRUE,
  valuesWithContext
    SET SIZE (1..MAX) OF
      SEQUENCE {distingAttrValue
                  [0]  ATTRIBUTE.&Type({SupportedAttributes}{@type})
                    OPTIONAL,
                contextList       SET SIZE (1..MAX) OF Context} OPTIONAL
}
*/

/* The default value for the 'primaryDistinguished' item */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_VAL,
  PKCS15_AttributeTypeAndDistinguishedValueSequenceItems_primaryDistinguished,
  3,
  (
    .Def                  = &ASN1_Boolean,
    .Decoded              = CK_TRUE,
    .TypeVal.Prim.Boolean = CK_TRUE
  )
)

/* CHOICE for the 'value' field */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_AttributeTypeAndDistinguishedValueChoiceItems,
  6,
  6,
  (
    ( /* printableString */
      .Name         = L"printableString",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_PrintableStringPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* IA5String */
      .Name         = L"IA5String",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_IA5StringPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* UTF8String !!! Added by direction of Pavel !!! */
      .Name         = L"UTF8String",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_Utf8StringPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* BMPString !!! Added by direction of Pavel !!! */
      .Name         = L"BMPString",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_BMPStringPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* Teletext String  */
      .Name         = L"TeletextString",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_TeletextStringPrim,
      .ASN1         = CK_FALSE
    ),
    ( /* numericString */
      .Name         = L"numericString",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_NumericStringPrim,
      .ASN1         = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_AttributeTypeAndDistinguishedValueChoice,
  2,
  (
    .Item = &PKCS15_AttributeTypeAndDistinguishedValueChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_AttributeTypeAndDistinguishedValueChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_AttributeTypeAndDistinguishedValueSequenceItems,
  3,
  8,
  (
    ( /* type */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"type",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* value */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &PKCS15_AttributeTypeAndDistinguishedValueChoice,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* primaryDistinguished */
      .Type               = ASN1_ITEM_DEFAULT,
      .Val.Name           = L"primaryDistinguished",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_BooleanPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            =
  &PKCS15_AttributeTypeAndDistinguishedValueSequenceItems_primaryDistinguished
    )
  )
)

/* FIXME: To be implemented */
#if 0
    ( /* valuesWithContext */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"valuesWithContext",
      .Val.Type           = ASN1_SET_OF_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.SetOf  = &Empty,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
#endif

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_AttributeTypeAndDistinguishedValueSequence,
  2,
  (
    .Item = &PKCS15_AttributeTypeAndDistinguishedValueSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_AttributeTypeAndDistinguishedValueSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_AttributeTypeAndDistinguishedValue,
  6,
  (
    .Name             = L"PKCS15_AttributeTypeAndDistinguishedValue",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_AttributeTypeAndDistinguishedValueSequence,
    .ASN1             = CK_FALSE
  )
)

/*
RelativeDistinguishedName ::=
  SET SIZE (1..MAX) OF AttributeTypeAndDistinguishedValue
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_RelativeDistinguishedName,
  6,
  (
    .Name          = L"PKCS15_RelativeDistinguishedName",
    .Type          = ASN1_SET_OF_CLASS_TYPE,
    .Tag           = ASN1_NO_TAG,
    .Tagging       = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.SetOf = &PKCS15_AttributeTypeAndDistinguishedValue,
    .ASN1          = CK_FALSE
  )
)

/*
Name ::= CHOICE { -- only one possibility for now --rdnSequence  RDNSequence
RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_NameChoiceItems,
  1,
  6,
  (
    ( /* rdnSequence */
      .Name               = L"rdnSequence",
      .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Tag                = ASN1_NO_TAG,
      .Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.SequenceOf = &PKCS15_RelativeDistinguishedName,
      .ASN1               = CK_TRUE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_NameChoice,
  2,
  (
    .Item = &PKCS15_NameChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_NameChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_Name,
  6,
  (
    .Name           = L"PKCS15_Name",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_NameChoice,
    .ASN1           = CK_FALSE
  )
)

/*
Time ::= CHOICE {utcTime          UTCTime,
                 generalizedTime  GeneralizedTime
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_TimeChoiceItems,
  2,
  6,
  (
    ( /* utcTime */
      .Name         = L"utcTime",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_UTCTimePrim,
      .ASN1         = CK_FALSE
    ),
    ( /* generalizedTime */
      .Name         = L"generalizedTime",
      .Type         = ASN1_PRIM_CLASS_TYPE,
      .Tag          = ASN1_NO_TAG,
      .Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim = &ASN1_GeneralizedTimePrim,
      .ASN1         = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_TimeChoice,
  2,
  (
    .Item = &PKCS15_TimeChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_TimeChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_Time,
  6,
  (
    .Name           = L"PKCS15_Time",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_TimeChoice,
    .ASN1           = CK_FALSE
  )
)

/*
Validity ::= SEQUENCE {notBefore  Time,
                       notAfter   Time
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_ValiditySequenceItems,
  2,
  8,
  (
    ( /* notBefore */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"notBefore",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &PKCS15_TimeChoice,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* notAfter */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"notAfter",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &PKCS15_TimeChoice,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_ValiditySequence,
  2,
  (
    .Item = &PKCS15_ValiditySequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_ValiditySequenceItems)
  )
)

/*
SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm         AlgorithmIdentifier{{SupportedAlgorithms}},
  subjectPublicKey  BIT STRING
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_SubjectPublicKeyInfoSequenceItems,
  2,
  8,
  (
    ( /* algorithm */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"algorithm",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_AlgorithmIdentifierSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* subjectPublicKey */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"subjectPublicKey",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_BitStringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_SubjectPublicKeyInfoSequence,
  2,
  (
    .Item = &PKCS15_SubjectPublicKeyInfoSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_SubjectPublicKeyInfoSequenceItems)
  )
)

/*
-- For those extensions where ordering of individual extensions within the SEQUENCE is significant, the
-- specification of those individual extensions shall include the rules for the significance of the order therein
Extension ::= SEQUENCE {
  extnId     EXTENSION.&id({ExtensionSet}),
  critical   BOOLEAN DEFAULT FALSE,
  extnValue
    OCTET STRING
      (CONTAINING EXTENSION.&ExtnType({ExtensionSet}{@extnId})
       ENCODED BY
       der)
}
*/

/* The default value for the 'critical' item */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_VAL,
  PKCS15_ExtensionSequenceItems_critical,
  3,
  (
    .Def                  = &ASN1_Boolean,
    .Decoded              = CK_TRUE,
    .TypeVal.Prim.Boolean = CK_FALSE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_ExtensionSequenceItems,
  3,
  8,
  (
    ( /* extnId */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"extnId",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* critical */
      .Type             = ASN1_ITEM_DEFAULT,
      .Val.Name         = L"critical",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_BooleanPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR /*&PKCS15_ExtensionSequenceItems_critical*/
    ),
    ( /* extnValue */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"extnValue",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_OctetStringPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_ExtensionSequence,
  2,
  (
    .Item = &PKCS15_ExtensionSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_ExtensionSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  Extension,
  6,
  (
    .Name             = L"Extension",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_ExtensionSequence,
    .ASN1             = CK_FALSE
  )
)

/*
CertificateContent ::= SEQUENCE {
  version                  [0]  Version DEFAULT v1,
  serialNumber             CertificateSerialNumber,
  signature                AlgorithmIdentifier{{SupportedAlgorithms}},
  issuer                   Name,
  validity                 Validity,
  subject                  Name,
  subjectPublicKeyInfo     SubjectPublicKeyInfo,
  issuerUniqueIdentifier   [1] IMPLICIT UniqueIdentifier OPTIONAL,
  -- if present, version shall be v2 or v3
  subjectUniqueIdentifier  [2] IMPLICIT UniqueIdentifier OPTIONAL,
  -- if present, version shall be v2 or v3
  extensions               [3]  Extensions OPTIONAL
  -- If present, version shall be v3 
}

UniqueIdentifier ::= BIT STRING
Extensions ::= SEQUENCE OF Extension
*/

/* The default value for the 'version' item */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_VAL,
  PKCS15_CertificateContentSequenceItems_version,
  4,
  (
    .Def                          = &PKCS15_CertificateVersion,
    .Decoded                      = CK_TRUE,
    .TypeVal.Prim.Integer.Long    = CK_FALSE,
    .TypeVal.Prim.Integer.Val.Val = 0
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CertificateContentSequenceItems,
  10,
  8,
  (
    (  /* version */
      .Type                   = ASN1_ITEM_DEFAULT,
      .Val.Name               = L"version",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging            = ASN1_TAGGING_EXPLICIT, /* EXPLICIT !!! */
      .Val.TypeRef.Prim       = &PKCS15_CertificateVersionPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = &PKCS15_CertificateContentSequenceItems_version
    ),
    (  /* serialNumber */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"serialNumber",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_IntegerPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* signature */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"signature",
      .Val.Type               = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence   = &PKCS15_AlgorithmIdentifierSequence,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* issuer */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"issuer",
      .Val.Type               = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice     = &PKCS15_NameChoice,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* validity */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"validity",
      .Val.Type               = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence   = &PKCS15_ValiditySequence,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* subject */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"subject",
      .Val.Type               = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice     = &PKCS15_NameChoice,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* subjectPublicKeyInfo */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"subjectPublicKeyInfo",
      .Val.Type               = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence   = &PKCS15_SubjectPublicKeyInfoSequence,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* issuerUniqueIdentifier */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"issuerUniqueIdentifier",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_BitStringPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* subjectUniqueIdentifier */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"subjectUniqueIdentifier",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_BitStringPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    (  /* extensions */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"extensions",
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Val.Tagging            = ASN1_TAGGING_EXPLICIT, /* EXPLICIT !!! */
      .Val.TypeRef.SequenceOf = &Extension,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CertificateContentSequence,
  2,
  (
    .Item = &PKCS15_CertificateContentSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CertificateContentSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_CertificateContent,
  6,
  (
    .Name             = L"PKCS15_CertificateContent",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CertificateContentSequence,
    .ASN1             = CK_FALSE
  )
)

/* Certificate */

/*
Certificate ::= SIGNED{CertificateContent}

or, after substituting:

Certificate ::= SEQUENCE {
  certificateContent   CertificateContent,
  signatureAlgorithm   AlgorithmIdentifier{{SupportedAlgorithms}},
  signatureValue       BIT STRING
}
*/

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_CertificateSequenceItems,
  3,
  8,
  (
    ( /* certificateContent */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"certificateContent",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_CertificateContentSequence,
      .Val.ASN1             = CK_TRUE,
      .Default              = NULL_PTR
    ),
    ( /* algorithmIdentifier */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"signatureAlgorithm",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_AlgorithmIdentifierSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* encrypted */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"signatureValue",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_BitStringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_CertificateSequence,
  2,
  (
    .Item = &PKCS15_CertificateSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CertificateSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_Certificate,
  6,
  (
    .Name             = L"PKCS15_Certificate",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_CertificateSequence,
    .ASN1             = CK_TRUE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 62:
X509CertificateAttributes ::= SEQUENCE {
       value              ObjectValue { Certificate },
       subject            Name OPTIONAL,
       issuer             [0] Name OPTIONAL,
       serialNumber       CertificateSerialNumber OPTIONAL,
       ... -- For future extensions
       }
*/

/* Preparing 'ObjectValue' pseudo-macro parameters */
#define FFM_CMD_OBJECT_VALUE_Type_ \
  PKCS15_CertificateSequence

#define FFM_CMD_OBJECT_VALUE_ClassType_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_OBJECT_VALUE_UnionType_ \
  Sequence

#define FFM_CMD_OBJECT_VALUE_ASN1_ \
  CK_TRUE

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_OBJECT_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_X509CertificateAttributesSequenceItems,
  4,
  8,
  (
    ( /* value */
      .Type               = ASN1_ITEM_NORMAL,
      .Val.Name           = L"value",
      .Val.Type           = ASN1_CHOICE_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Choice = &ObjectValueNameChoice (PKCS15_CertificateSequence),
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* subject */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"subject",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &PKCS15_LabelPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* issuer */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"issuer",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &PKCS15_LabelPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    ),
    ( /* serialNumber */
      .Type               = ASN1_ITEM_OPTIONAL,
      .Val.Name           = L"serialNumber",
      .Val.Type           = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag            = ASN1_NO_TAG,
      .Val.Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim   = &ASN1_IntegerPrim,
      .Val.ASN1           = CK_FALSE,
      .Default            = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_X509CertificateAttributesSequence,
  2,
  (
    .Item = &PKCS15_X509CertificateAttributesSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_X509CertificateAttributesSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_X509CertificateAttributes,
  6,
  (
    .Name             = L"PKCS15_X509CertificateAttributes",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_X509CertificateAttributesSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 62:
CertificateType ::= CHOICE {
         x509Certificate          CertificateObject { X509CertificateAttributes},
         x509AttributeCertificate [0] CertificateObject {X509AttributeCertificateAttributes},
         spkiCertificate          [1] CertificateObject {SPKICertificateAttributes},
         pgpCertificate           [2] CertificateObject {PGPCertificateAttributes},
         wtlsCertificate          [3] CertificateObject {WTLSCertificateAttributes},
         x9-68Certificate         [4] CertificateObject {X9-68CertificateAttributes},
         ...,
         cvCertificate            [5] CertificateObject {CVCertificateAttributes}
         }
*/


/* Preparing 'CertificateObject' pseudo-macro parameters */
#define FFM_CMD_CERTIFICATE_OBJECT_CertAttributes_ \
  PKCS15_X509CertificateAttributesSequence

#define FFM_CMD_CERTIFICATE_OBJECT_ClassCertAttributes_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_CERTIFICATE_OBJECT_UnionCertAttributes_ \
  Sequence

/* Preparing to 'call' 'CertificateObject' pseudo-macros */
#define FFM_CMD_CERTIFICATE_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_CertificateTypeChoiceItems,
  1,
  6,
  (
    (
      .Name             = L"PKCS15_CertificateTypeChoiceItems",
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Tag              = ASN1_NO_TAG,
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Sequence = &CertificateObjectNameSequence (
                             PKCS15_X509CertificateAttributesSequence
                             ),
      .ASN1             = CK_FALSE
    )  /* x509Certificate */

  /* FIXME: Other fields must be implemented */

  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_CertificateTypeChoice,
  2,
  (
    .Item = &PKCS15_CertificateTypeChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_CertificateTypeChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CertificateType,
  6,
  (
    .Name           = L"PKCS15_CertificateType",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_CertificateTypeChoice,
    .ASN1           = CK_FALSE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_CertificateTypeSequenceOf,
  6,
  (
    .Name               = L"PKCS15_CertificateTypeSequenceOf",
    .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
    .Tag                = ASN1_NO_TAG,
    .Tagging            = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.SequenceOf = &PKCS15_CertificateType,
    .ASN1               = CK_FALSE
  )
)

/* FIXME: These are FAKE objects, and MUST be replaced with real ones */
ASN1_TYPE_DEF CONST PKCS15_DataType;
ASN1_TYPE_DEF CONST PKCS15_AuthenticationType;

/* PKCS#15 v1.1, ANNEX A, page 59:
PrivateKeys ::= PathOrObjects {PrivateKeyType}
*/

/* PathOrObject 'template' instantiation for the PrivateKeyType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_PrivateKeyType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 59:
PublicKeys ::= PathOrObjects {PublicKeyType}
*/

/* PathOrObject 'template' instantiation for the PublicKeyType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_PublicKeyType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 59:
SecretKeys ::= PathOrObjects {SecretKeyType}
*/

/* PathOrObject 'template' instantiation for the SecretKeyType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_SecretKeyType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 59:
Certificates ::= PathOrObjects {CertificateType}
*/

/* PathOrObject 'template' instantiation for the CertificateType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_CertificateType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 59:
DataObjects ::= PathOrObjects {DataType}
*/

/* PathOrObject 'template' instantiation for the DataType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_DataType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 59:
AuthObjects ::= PathOrObjects {AuthenticationType}
*/

/* PathOrObject 'template' instantiation for the AuthenticationType */
#define FFM_CMD_PATH_OR_OBJECTS
#define FFM_CMD_PATH_OR_OBJECTS_Type_ PKCS15_AuthenticationType
#include FIX_FOR_MACROS


/* PKCS#15 v1.1, ANNEX A, page 58:
PKCS15Objects ::= CHOICE {
     privateKeys         [0] PrivateKeys,
     publicKeys          [1] PublicKeys,
     trustedPublicKeys   [2] PublicKeys,
     secretKeys          [3] SecretKeys,
     certificates        [4] Certificates,
     trustedCertificates [5] Certificates,
     usefulCertificates  [6] Certificates,
     dataObjects         [7] DataObjects,
     authObjects         [8] AuthObjects,
     ... -- For future extensions
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_PKCS15ObjectsChoiceItems,
  9,
  6,
  (
    ( /* privateKeys */
      .Name           = L"privateKeys",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_PrivateKeyType),
      .ASN1           = CK_FALSE
    ),
    ( /* publicKeys */
      .Name           = L"publicKeys",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_PublicKeyType),
      .ASN1           = CK_FALSE
    ),
    ( /* trustedPublicKeys */
      .Name           = L"trustedPublicKeys",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_PublicKeyType),
      .ASN1           = CK_FALSE
    ),
    ( /* secretKeys */
      .Name           = L"secretKeys",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_SecretKeyType),
      .ASN1           = CK_FALSE
    ),
    ( /* certificates */
      .Name           = L"certificates",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 4,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_CertificateType),
      .ASN1           = CK_FALSE
    ),
    ( /* trustedCertificates */
      .Name           = L"trustedCertificates",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 5,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_CertificateType),
      .ASN1           = CK_FALSE
    ),
    ( /* usefulCertificates */
      .Name           = L"usefulCertificates",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 6,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_CertificateType),
      .ASN1           = CK_FALSE
    ),
    ( /* dataObjects */
      .Name           = L"dataObjects",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 7,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_DataType),
      .ASN1           = CK_FALSE
    ),
    ( /* authObjects */
      .Name           = L"authObjects",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_CLASS_CONTEXT_SPECIFIC | 8,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &PathOrObjectsNameChoice (PKCS15_AuthenticationType),
      .ASN1           = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_PKCS15ObjectsChoice,
  2,
  (
    .Item = &PKCS15_PKCS15ObjectsChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_PKCS15ObjectsChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PKCS15Objects,
  6,
  (
    .Name           = L"PKCS15_PKCS15Objects",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_PKCS15ObjectsChoice,
    .ASN1           = CK_FALSE
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_PKCS15ObjectsSequenceOf,
  6,
  (
    .Name               = L"PKCS15_PKCS15ObjectsSequenceOf",
    .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
    .Tag                = ASN1_NO_TAG,
    .Tagging            = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.SequenceOf = &PKCS15_PKCS15Objects,
    .ASN1               = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 65:
TokenFlags ::= BIT STRING {
       readonly       (0),
       loginRequired  (1),
       prnGeneration  (2),
       eidCompliant   (3)
} */

/* PKCS15 TokenFlags primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_TokenFlagsPrim,
  4,
  (
    .Type                = ASN1_BIT_STRING_PRIM_TYPE,
    .Tag                 = ASN1_BIT_STRING_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 4
  )
)

/* PKCS15 v1.1, ANNEX A, page 65:
SecurityEnvironmentInfo ::= SEQUENCE {
        se          INTEGER (0..pkcs15-ub-seInfo),
        owner       OBJECT IDENTIFIER,
        ... -- For future extensions
} */

/* PKCS15 Integer (0..pkcs15-ub-seInfo) primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_Integer0PKCS15_UB_SE_INFOPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_SE_INFO
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_SecurityEnvironmentInfoSequenceItems,
  2,
  8,
  (
    ( /* se */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"se",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_SE_INFOPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* owner */
      .Type             = ASN1_ITEM_NORMAL,
      .Val.Name         = L"owner",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_NO_TAG,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_SecurityEnvironmentInfoSequence,
  2,
  (
    .Item = &PKCS15_SecurityEnvironmentInfoSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_SecurityEnvironmentInfoSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_SecurityEnvironmentInfo,
  6,
  (
    .Name             = L"PKCS15_SecurityEnvironmentInfo",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_SecurityEnvironmentInfoSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 65:
RecordInfo ::= SEQUENCE {
       oDFRecordLength   [0] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       prKDFRecordLength [1] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       puKDFRecordLength [2] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       sKDFRecordLength  [3] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       cDFRecordLength   [4] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       dODFRecordLength  [5] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL,
       aODFRecordLength  [6] INTEGER (0..pkcs15-ub-recordLength) OPTIONAL
} */

/* PKCS15 Integer (0..pkcs15-ub-recordLength) primitive */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF,
  PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
  4,
  (
    .Type                = ASN1_INTEGER_PRIM_TYPE,
    .Tag                 = ASN1_INTEGER_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = PKCS15_UB_RECORD_LENGTH
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_RecordInfoSequenceItems,
  7,
  8,
  (
    ( /* oDFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"oDFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* prKDFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"prKDFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* puKDFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"puKDFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* sKDFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"sKDFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* cDFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"cDFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 4,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* dODFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"dODFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 5,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    ),
    ( /* aODFRecordLength */
      .Type             = ASN1_ITEM_OPTIONAL,
      .Val.Name         = L"aODFRecordLength",
      .Val.Type         = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag          = ASN1_CLASS_CONTEXT_SPECIFIC | 6,
      .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim = &PKCS15_Integer0PKCS15_UB_RECORD_LENGTHPrim,
      .Val.ASN1         = CK_FALSE,
      .Default          = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_RecordInfoSequence,
  2,
  (
    .Item = &PKCS15_RecordInfoSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_RecordInfoSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_RecordInfo,
  6,
  (
    .Name             = L"PKCS15_RecordInfo",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_RecordInfoSequence,
    .ASN1             = CK_FALSE
  )
)

/*
LastUpdate ::= CHOICE {
       generalizedTime GeneralizedTime,
       referencedTime ReferencedValue {GeneralizedTime},
       ...
}
*/

#define FFM_CMD_REFERENCED_VALUE_Type_ \
  ASN1_GeneralizedTimePrim

/* Preparing to 'call' 'ObjectValue' pseudo-macros */
#define FFM_CMD_REFERENCED_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_TYPE_DEF,
  PKCS15_LastUpdateChoiceItems,
  2,
  6,
  (
    ( /* generalizedTime */
      .Name           = L"generalizedTime",
      .Type           = ASN1_PRIM_CLASS_TYPE,
      .Tag            = ASN1_NO_TAG,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Prim   = &ASN1_GeneralizedTimePrim,
      .ASN1           = CK_FALSE
    ),
    ( /* referencedTime */
      .Name           = L"referencedTime",
      .Type           = ASN1_CHOICE_CLASS_TYPE,
      .Tag            = ASN1_NO_TAG,
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,
      .TypeRef.Choice = &ReferencedValueNameChoice (ASN1_GeneralizedTimePrim),
      .ASN1           = CK_FALSE
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_CHOICE_TYPE_DEF,
  PKCS15_LastUpdateChoice,
  2,
  (
    .Item = &PKCS15_LastUpdateChoiceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_LastUpdateChoiceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_TYPE_DEF,
  PKCS15_LastUpdate,
  6,
  (
    .Name           = L"PKCS15_LastUPdate",
    .Type           = ASN1_CHOICE_CLASS_TYPE,
    .Tag            = ASN1_NO_TAG,
    .Tagging        = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Choice = &PKCS15_LastUpdateChoice,
    .ASN1           = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, pages 64-65:
TokenInfo ::= SEQUENCE {
     version             INTEGER {v1(0)} (v1,...),
     serialNumber        OCTET STRING,
     manufacturerID      Label OPTIONAL,
     label               [0] Label OPTIONAL,
     tokenflags          TokenFlags,
     seInfo              SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,
     recordInfo          [1] RecordInfo OPTIONAL,
     supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL,
     ...,
     issuerId            [3] Label OPTIONAL,
     holderId            [4] Label OPTIONAL,
     lastUpdate          [5] LastUpdate OPTIONAL,
     preferredLanguage   PrintableString OPTIONAL -- In accordance with IETF RFC 1766
     } (CONSTRAINED BY { -- Each AlgorithmInfo.reference value must be unique --}
) */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_TokenInfoSequenceItems,
  12,
  8,
  (
    ( /* version */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"version",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_IntegerPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* serialNumber */
      .Type                   = ASN1_ITEM_NORMAL,
      .Val.Name               = L"serialNumber",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_OctetStringPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* manufacturerID */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"manufacturerID",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* label */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"label",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* tokenflags */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"tokenflags",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_TokenFlagsPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* seInfo */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"seInfo",
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.SequenceOf = &PKCS15_SecurityEnvironmentInfo,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* recordInfo */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"recordInfo",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence   = &PKCS15_RecordInfoSequence,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* supportedAlgorithms */
      .Type = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"supportedAlgorithms",
      .Val.Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 2,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,

      /* FIXME: supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL */
      .Val.TypeRef.SequenceOf = &PKCS15_SecurityEnvironmentInfo,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* issuerId */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"issuerId",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 3,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* holderId */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"holderId",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 4,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &PKCS15_LabelPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* lastUpdate */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"lastUpdate",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,      /* By fact */
      .Val.Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 5,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_GeneralizedTimePrim, /* By fact */
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    ),
    ( /* preferredLanguage */
      .Type                   = ASN1_ITEM_OPTIONAL,
      .Val.Name               = L"preferredLanguage",
      .Val.Type               = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag                = ASN1_NO_TAG,
      .Val.Tagging            = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim       = &ASN1_PrintableStringPrim,
      .Val.ASN1               = CK_FALSE,
      .Default                = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_TokenInfoSequence,
  2,
  (
    .Item = &PKCS15_TokenInfoSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_TokenInfoSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_TokenInfo,
  6,
  (
    .Name             = L"PKCS15_TokenInfo",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_TokenInfoSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 67:
DDO ::= SEQUENCE {
        oid           OBJECT IDENTIFIER,
        odfPath       Path OPTIONAL,
        tokenInfoPath [0] Path OPTIONAL,
        unusedPath    [1] Path OPTIONAL,
        ... -- For future extensions
} */

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_DDOSequenceItems,
  4,
  8,
  (
    ( /* oid */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"oid",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_ObjectIdentifierPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* odfPath */
      .Type                 = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"odfPath",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_NO_TAG,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_PathSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* tokenInfoPath */
      .Type                 = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"tokenInfoPath",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 0,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_PathSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* unusedPath */
      .Type                 = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"unusedPath",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_CONTEXT_SPECIFIC | 1,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_PathSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_DDOSequence,
  2,
  (
    .Item = &PKCS15_DDOSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_DDOSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_DDO,
  6,
  (
    .Name             = L"PKCS15_DDO",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_NO_TAG,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_DDOSequence,
    .ASN1             = CK_FALSE
  )
)

/* PKCS#15 v1.1, ANNEX A, page 67:
DIRRecord ::= [APPLICATION 1] SEQUENCE {
       aid      [APPLICATION 15] OCTET STRING,
       label    [APPLICATION 16] UTF8String OPTIONAL,
       path     [APPLICATION 17] OCTET STRING,
       ddo      [APPLICATION 19] DDO OPTIONAL
} */

/* PKCS15 DIR Record */
#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE_ARRAY (
  static ASN1_SEQUENCE_ITEM_DEF,
  PKCS15_DIRRecordSequenceItems,
  4,
  8,
  (
    ( /* aid */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"aid",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_APPLICATION | 15,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_OctetStringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* label */
      .Type                 = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"label",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_APPLICATION | 16,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_Utf8StringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* path */
      .Type                 = ASN1_ITEM_NORMAL,
      .Val.Name             = L"path",
      .Val.Type             = ASN1_PRIM_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_APPLICATION | 17,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Prim     = &ASN1_OctetStringPrim,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    ),
    ( /* ddo */
      .Type                 = ASN1_ITEM_OPTIONAL,
      .Val.Name             = L"ddo",
      .Val.Type             = ASN1_SEQUENCE_CLASS_TYPE,
      .Val.Tag              = ASN1_CLASS_APPLICATION | 19,
      .Val.Tagging          = ASN1_TAGGING_BY_DEFAULT,
      .Val.TypeRef.Sequence = &PKCS15_DDOSequence,
      .Val.ASN1             = CK_FALSE,
      .Default              = NULL_PTR
    )
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  static ASN1_SEQUENCE_TYPE_DEF,
  PKCS15_DIRRecordSequence,
  2,
  (
    .Item = &PKCS15_DIRRecordSequenceItems[0],
    .Cnt  = ARRAY_ITEMS (PKCS15_DIRRecordSequenceItems)
  )
)

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */
FFM_INITIALIZE (
  ASN1_TYPE_DEF,
  PKCS15_DIRRecord,
  6,
  (
    .Name             = L"PKCS15_DIRRecord",
    .Type             = ASN1_SEQUENCE_CLASS_TYPE,
    .Tag              = ASN1_CLASS_APPLICATION | 1,
    .Tagging          = ASN1_TAGGING_BY_DEFAULT,
    .TypeRef.Sequence = &PKCS15_DIRRecordSequence,
    .ASN1             = CK_FALSE
  )
)

VOID PKCS15_InitializeStatics (VOID)
{
#if defined _MSC_VER
  static int Initialized = 0; /* Repeated call protection */

  if (!Initialized) {
/* Unset the function name generation mode for the FIX_FOR_MICROSOFT header */
#undef FFM_CMD_NEXT_FUN_NAME

/* Set the invocation of functions mode for the FIX_FOR_MICROSOFT header */
#define FFM_CMD_INVOKE_FUNS

#include FIX_FOR_MICROSOFT /* Invoke all the functions the names are generated for */

    Initialized = 1;
  }
#endif /* _MSC_VER */
}
