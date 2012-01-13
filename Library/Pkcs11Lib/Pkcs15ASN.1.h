/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PKCS15_ASN_1__
#define __PKCS15_ASN_1__

#include "ASN.1.h"

/* There is no CONST protection for the Microsoft compiler below */
#if defined _MSC_VER
#undef CONST
#define CONST
#endif

/* Number of array elements is often needed to know */
#define ARRAY_ITEMS(Array_) \
  (sizeof (Array_) / sizeof (*Array_))

/* One more distinct concatenating macro is needed */
#define FFM_INV(Macro_, Parameters_) \
  Macro_ Parameters_

/* And one more distinct concatenating macro is needed */
#define FFM_INV_AUX(Macro_, Parameters_) \
  Macro_ Parameters_

#ifdef _MSC_VER
#define FFM_LSTR3(Par_, Str1_, Str2_) \
L#Str1_ L"(" L#Par_ L"): " L#Str2_
#else /* _MSC_VER */
#define FFM_LSTR3(Par_, Str1_, Str2_) \
L"" #Str1_ L"(" #Par_ L"): " #Str2_
#endif /* _MSC_VER */

#define FFM_LSTR2(Par_, Str_) FFM_LSTR3 (Par_, Str_,)

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 56:
PathOrObjects {ObjectType} ::= CHOICE {
       path      Path,
       objects [0] SEQUENCE OF ObjectType,
       ...,
       indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
       direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType}
} */

#define PathOrObjectsName(Type_) \
  PKCS15_PathOrObjects##Type_

#define PathOrObjectsNameChoice(Type_) \
  PKCS15_PathOrObjects##Type_##Choice

#define PathOrObjectsNameChoiceItems(Type_) \
  PKCS15_PathOrObjects##Type_##ChoiceItems

/* PathOrObjects pseudo-macro 3 subobjects */
#define PathOrObjects_0(Type_) \
  FFM_INITIALIZE_ARRAY (                                                 \
    static ASN1_TYPE_DEF,                                                \
    PathOrObjectsNameChoiceItems (Type_),                                \
    2,                                                                   \
    6,                                                                   \
    (                                                                    \
      ( /* path */                                                       \
        .Name               = FFM_LSTR3 (Type_, PathOrObjects, path),    \
        .Type               = ASN1_SEQUENCE_CLASS_TYPE,                  \
        .Tag                = ASN1_NO_TAG,                               \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                   \
        .TypeRef.Sequence   = &PKCS15_PathSequence,                      \
        .ASN1               = CK_FALSE                                   \
      ),                                                                 \
      ( /* objects */                                                    \
        .Name               = FFM_LSTR3 (Type_, PathOrObjects, objects), \
        .Type               = ASN1_SEQUENCE_OF_CLASS_TYPE,               \
        .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,           \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                   \
        .TypeRef.SequenceOf = &Type_,                                    \
        .ASN1               = CK_FALSE                                   \
      )                                                                  \
      /* FIXME: to be imlemented:                                        \
      indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}}, \
      direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType}        \
      */                                                                 \
    )                                                                    \
  )

#define PathOrObjects_1(Type_) \
  FFM_INITIALIZE (                                               \
    ASN1_CHOICE_TYPE_DEF,                                        \
    PathOrObjectsNameChoice (Type_),                             \
    2,                                                           \
    (                                                            \
      .Item = &PathOrObjectsNameChoiceItems (Type_)[0],          \
      .Cnt  = ARRAY_ITEMS (PathOrObjectsNameChoiceItems (Type_)) \
    )                                                            \
  )

#define PathOrObjects_2(Type_) \
  FFM_INITIALIZE (                                               \
    ASN1_TYPE_DEF,                                               \
    PathOrObjectsName (Type_),                                   \
    6,                                                           \
    (                                                            \
      .Name           = FFM_LSTR2 (Type_, PathOrObjects),        \
      .Type           = ASN1_CHOICE_CLASS_TYPE,                  \
      .Tag            = ASN1_NO_TAG,                             \
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,                 \
      .TypeRef.Choice = &PathOrObjectsNameChoice (Type_),        \
      .ASN1           = CK_FALSE                                 \
    )                                                            \
  )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 56:
ReferencedValue {Type} ::= CHOICE {
       path     Path,
       url      URL
       } (CONSTRAINED BY {-- 'path' or 'url' shall point to an object of type -- Type})
*/

#define ReferencedValueName(Type_) \
  PKCS15_ReferencedValue##Type_

#define ReferencedValueNameChoice(Type_) \
  PKCS15_ReferencedValue##Type_##Choice

#define ReferencedValueNameChoiceItems(Type_) \
  PKCS15_ReferencedValue##Type_##ChoiceItems

#define ReferencedValue_0(Type_) \
  FFM_INITIALIZE_ARRAY (                                                      \
    static ASN1_TYPE_DEF,                                                     \
    ReferencedValueNameChoiceItems (Type_),                                   \
    2,                                                                        \
    6,                                                                        \
    (                                                                         \
      ( /* path */                                                            \
        .Name             = FFM_LSTR3 (Type_, ReferencedValue, path),         \
        .Type             = ASN1_SEQUENCE_CLASS_TYPE,                         \
        .Tag              = ASN1_NO_TAG,                                      \
        .Tagging          = ASN1_TAGGING_BY_DEFAULT,                          \
        .TypeRef.Sequence = &PKCS15_PathSequence,                             \
        .ASN1             = CK_FALSE                                          \
      ),                                                                      \
      ( /* url */                                                             \
        .Name             = FFM_LSTR3 (Type_, ReferencedValue, url),          \
        .Type             = ASN1_CHOICE_CLASS_TYPE,                           \
        .Tag              = ASN1_NO_TAG,                                      \
        .Tagging          = ASN1_TAGGING_BY_DEFAULT,                          \
        .TypeRef.Choice   = &PKCS15_URLChoice,                                \
        .ASN1             = CK_FALSE                                          \
      )                                                                       \
    )                                                                         \
  )                                                                           \

#define ReferencedValue_1(Type_) \
  FFM_INITIALIZE (                                                            \
    static ASN1_CHOICE_TYPE_DEF,                                              \
    ReferencedValueNameChoice (Type_),                                        \
    2,                                                                        \
    (                                                                         \
      .Item = &ReferencedValueNameChoiceItems (Type_)[0],                     \
      .Cnt  = ARRAY_ITEMS (ReferencedValueNameChoiceItems (Type_))            \
    )                                                                         \
  )

#define ReferencedValue_2(Type_) \
  FFM_INITIALIZE (                                                            \
    ASN1_TYPE_DEF,                                                            \
    ReferencedValueName (Type_),                                              \
    6,                                                                        \
    (                                                                         \
      .Name           = FFM_LSTR2 (Type_, ReferencedValue),                   \
      .Type           = ASN1_CHOICE_CLASS_TYPE,                               \
      .Tag            = ASN1_NO_TAG,                                          \
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,                              \
      .TypeRef.Choice = &ReferencedValueNameChoice (Type_),                   \
      .ASN1           = CK_FALSE                                              \
    )                                                                         \
  )

/*****************************************************************************/
/* FIXME: implementation should be completed */
/* PKCS#15 v1.1, ANNEX A, page 66:
EnvelopedData {Type} ::= SEQUENCE {
       version                 INTEGER{v0(0),v1(1),v2(2),v3(3),v4(4)}(v0|v1|v2,...),
       originatorInfo          [0] OriginatorInfo OPTIONAL,
       recipientInfos          RecipientInfos,
       encryptedContentInfo    EncryptedContentInfo{Type},
       unprotectedAttrs        [1] SET SIZE (1..MAX) OF Attribute OPTIONAL
} */

#define EnvelopedDataName(Type_) \
  PKCS15_EnvelopedData##Type_

#define EnvelopedDataNameSequence(Type_) \
  PKCS15_EnvelopedData##Type_##Sequence

#define EnvelopedDataNameSequenceItems(Type_) \
  PKCS15_EnvelopedData##Type_##SequenceItems

/* FIXME: to be completed */
#define EnvelopedData_0(Type_) \
  FFM_INITIALIZE_ARRAY (                                                       \
    static ASN1_SEQUENCE_ITEM_DEF,                                             \
    EnvelopedDataNameSequenceItems (Type_),                                    \
    1,                                                                         \
    8,                                                                         \
    (                                                                          \
      ( /* version */                                                          \
        .Type = ASN1_ITEM_NORMAL,                                              \
        .Val.Name         = FFM_LSTR3 (Type_, EnvelopedData, version),         \
        .Val.Type         = ASN1_PRIM_CLASS_TYPE,                              \
        .Val.Tag          = ASN1_NO_TAG,                                       \
        .Val.Tagging      = ASN1_TAGGING_BY_DEFAULT,                           \
        .Val.TypeRef.Prim = &ASN1_IntegerPrim,                                 \
        .Val.ASN1         = CK_FALSE,                                          \
        .Default          = NULL_PTR                                           \
      )                                                                        \
    )                                                                          \
  )

#define EnvelopedData_1(Type_) \
  FFM_INITIALIZE (                                                             \
    static ASN1_SEQUENCE_TYPE_DEF,                                             \
    EnvelopedDataNameSequence (Type_),                                         \
    2,                                                                         \
    (                                                                          \
      .Item = &EnvelopedDataNameSequenceItems (Type_)[0],                      \
      .Cnt  = ARRAY_ITEMS (EnvelopedDataNameSequenceItems (Type_))             \
    )                                                                          \
  )

#define EnvelopedData_2(Type_) \
  FFM_INITIALIZE (                                                             \
    ASN1_TYPE_DEF,                                                             \
    EnvelopedDataName (Type_),                                                 \
    6,                                                                         \
    (                                                                          \
      .Name             = FFM_LSTR2 (Type_, EnvelopedData),                    \
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,                            \
      .Tag              = ASN1_NO_TAG,                                         \
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,                             \
      .TypeRef.Sequence = &EnvelopedDataNameSequence (Type_),                  \
      .ASN1             = CK_FALSE                                             \
    )                                                                          \
  )

/*****************************************************************************/
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

#define ObjectValueName(Type_) \
  PKCS15_ObjectValue##Type_

#define ObjectValueNameChoice(Type_) \
  PKCS15_ObjectValue##Type_##Choice

#define ObjectValueNameChoiceItems(Type_) \
  PKCS15_ObjectValue##Type_##ChoiceItems

#define ObjectValue_0(Type_, ClassType_, UnionType_, ASN1_) \
  FFM_INITIALIZE_ARRAY (                                                \
    static ASN1_TYPE_DEF,                                               \
    ObjectValueNameChoiceItems (Type_),                                 \
    4,                                                                  \
    6,                                                                  \
    (                                                                   \
      ( /* indirect */                                                  \
        .Name               = FFM_LSTR3 (Type_, ObjectValue, indirect), \
        .Type               = ASN1_CHOICE_CLASS_TYPE,                   \
        .Tag                = ASN1_NO_TAG,                              \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                  \
        .TypeRef.Choice     = &ReferencedValueNameChoice (Type_),       \
        .ASN1               = CK_FALSE                                  \
      ),                                                                \
      ( /* direct */                                                    \
        .Name               = FFM_LSTR3 (Type_, ObjectValue, direct),   \
        .Type               = ClassType_,                               \
        .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 0,          \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                  \
        .TypeRef.UnionType_ = &Type_,                                   \
        .ASN1               = ASN1_                                     \
      ),                                                                \
      ( /* indirect-protected */                                        \
        .Name               = FFM_LSTR3 (                               \
                                Type_,                                  \
                                ObjectValue,                            \
                                indirect-protected),                    \
        .Type               = ASN1_CHOICE_CLASS_TYPE,                   \
        .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 1,          \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                  \
        .TypeRef.Choice     = &FFM_INV_AUX (                            \
                             ReferencedValueNameChoice,                 \
                             (EnvelopedDataNameSequence (Type_))),      \
        .ASN1               = CK_FALSE                                  \
      ),                                                                \
      ( /* direct-protected */                                          \
        .Name               = FFM_LSTR3 (                               \
                                Type_,                                  \
                                ObjectValue,                            \
                                direct-protected),                      \
        .Type               = ASN1_SEQUENCE_CLASS_TYPE,                 \
        .Tag                = ASN1_CLASS_CONTEXT_SPECIFIC | 2,          \
        .Tagging            = ASN1_TAGGING_BY_DEFAULT,                  \
        .TypeRef.Sequence   = &EnvelopedDataNameSequence(Type_),        \
        .ASN1               = CK_FALSE                                  \
      )                                                                 \
    )                                                                   \
  )

#define ObjectValue_1(Type_, ClassType_, UnionType_) \
  FFM_INITIALIZE (                                                      \
    static ASN1_CHOICE_TYPE_DEF,                                        \
    ObjectValueNameChoice (Type_),                                      \
    2,                                                                  \
    (                                                                   \
      .Item = &ObjectValueNameChoiceItems (Type_)[0],                   \
      .Cnt  = ARRAY_ITEMS (ObjectValueNameChoiceItems (Type_))          \
    )                                                                   \
  )

#define ObjectValue_2(Type_, ClassType_, UnionType_) \
  FFM_INITIALIZE (                                                      \
    ASN1_TYPE_DEF,                                                      \
    ObjectValueName (Type_),                                            \
    6,                                                                  \
    (                                                                   \
      .Name           = FFM_LSTR2 (Type_, ObjectValue),                 \
      .Type           = ASN1_CHOICE_CLASS_TYPE,                         \
      .Tag            = ASN1_NO_TAG,                                    \
      .Tagging        = ASN1_TAGGING_BY_DEFAULT,                        \
      .TypeRef.Choice = &ObjectValueNameChoice (Type_),                 \
      .ASN1           = CK_FALSE                                        \
    )                                                                   \
  )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 58:
PKCS15Object {ClassAttributes, SubClassAttributes, TypeAttributes} ::= SEQUENCE {
      commonObjectAttributes CommonObjectAttributes,
      classAttributes        ClassAttributes,
      subClassAttributes     [0] SubClassAttributes OPTIONAL,
      typeAttributes         [1] TypeAttributes
} */

#define PKCS15ObjectName(Class_, SubClass_, Type_) \
  PKCS15_PKCS15Object##Class_##SubClass_##Type_

#define PKCS15ObjectNameSequence(Class_, SubClass_, Type_) \
  PKCS15_PKCS15Object##Class_##SubClass_##Type_##Sequence

#define PKCS15ObjectNameSequenceItems(Class_, SubClass_, Type_) \
  PKCS15_PKCS15Object##Class_##SubClass_##Type_##SequenceItems

#define PKCS15Object_0( \
          Class_,         \
          ClassClass_,    \
          UnionClass_,    \
          SubClass_,      \
          ClassSubClass_, \
          UnionSubClass_, \
          Type_,          \
          ClassType_,     \
          UnionType_      \
          )               \
  FFM_INITIALIZE_ARRAY (                                                       \
    static ASN1_SEQUENCE_ITEM_DEF,                                             \
    PKCS15ObjectNameSequenceItems (Class_, SubClass_, Type_),                  \
    4,                                                                         \
    8,                                                                         \
    (                                                                          \
      ( /* commonObjectAttributes */                                           \
        .Type                       = ASN1_ITEM_NORMAL,                        \
        .Val.Name                   = FFM_LSTR3 (                              \
                                        Type_,                                 \
                                        PKCS15Object,                          \
                                        commonObjectAttributes),               \
        .Val.Type                   = ASN1_SEQUENCE_CLASS_TYPE,                \
        .Val.Tag                    = ASN1_NO_TAG,                             \
        .Val.Tagging                = ASN1_TAGGING_BY_DEFAULT,                 \
        .Val.TypeRef.Sequence       = &PKCS15_CommonObjectAttributesSequence,  \
        .Val.ASN1                   = CK_FALSE,                                \
        .Default                    = NULL_PTR                                 \
      ),                                                                       \
      ( /* classAttributes */                                                  \
        .Type                       = ASN1_ITEM_NORMAL,                        \
        .Val.Name                   = FFM_LSTR3 (                              \
                                        Type_,                                 \
                                        PKCS15Object,                          \
                                        classAttributes),                      \
        .Val.Type                   = ClassClass_,                             \
        .Val.Tag                    = ASN1_NO_TAG,                             \
        .Val.Tagging                = ASN1_TAGGING_BY_DEFAULT,                 \
        .Val.TypeRef.UnionClass_    = &Class_,                                 \
        .Val.ASN1                   = CK_FALSE,                                \
        .Default                    = NULL_PTR                                 \
      ),                                                                       \
      ( /* subClassAttributes */                                               \
        .Type                       = ASN1_ITEM_OPTIONAL,                      \
        .Val.Name                   = FFM_LSTR3 (                              \
                                        Type_,                                 \
                                        PKCS15Object,                          \
                                        subClassAttributes),                   \
        .Val.Type                   = ClassSubClass_,                          \
        .Val.Tag                    = ASN1_CLASS_CONTEXT_SPECIFIC | 0,         \
        .Val.Tagging                = ASN1_TAGGING_BY_DEFAULT,                 \
        .Val.TypeRef.UnionSubClass_ = &SubClass_,                              \
        .Val.ASN1                   = CK_FALSE,                                \
        .Default                    = NULL_PTR                                 \
      ),                                                                       \
      ( /* typeAttributes */                                                   \
        .Type                       = ASN1_ITEM_NORMAL,                        \
        .Val.Name                   = FFM_LSTR3 (                              \
                                        Type_,                                 \
                                        PKCS15Object,                          \
                                        typeAttributes),                       \
        .Val.Type                   = ClassType_,                              \
        .Val.Tag                    = ASN1_CLASS_CONTEXT_SPECIFIC | 1,         \
        .Val.Tagging                = ASN1_TAGGING_EXPLICIT, /* By fact */     \
        .Val.TypeRef.UnionType_     = &Type_,                                  \
        .Val.ASN1                   = CK_FALSE,                                \
        .Default                    = NULL_PTR                                 \
      )                                                                        \
    )                                                                          \
  )

#define PKCS15Object_1( \
          Class_,         \
          ClassClass_,    \
          UnionClass_,    \
          SubClass_,      \
          ClassSubClass_, \
          UnionSubClass_, \
          Type_,          \
          ClassType_,     \
          UnionType_      \
          )               \
  FFM_INITIALIZE (                                                             \
    static ASN1_SEQUENCE_TYPE_DEF,                                             \
    PKCS15ObjectNameSequence (Class_, SubClass_, Type_),                       \
    2,                                                                         \
    (                                                                          \
      .Item = &PKCS15ObjectNameSequenceItems (Class_, SubClass_, Type_)[0],    \
      .Cnt  = ARRAY_ITEMS (PKCS15ObjectNameSequenceItems (                     \
                             Class_,                                           \
                             SubClass_,                                        \
                             Type_                                             \
                             ))                                                \
    )                                                                          \
  )

#define PKCS15Object_2( \
          Class_,         \
          ClassClass_,    \
          UnionClass_,    \
          SubClass_,      \
          ClassSubClass_, \
          UnionSubClass_, \
          Type_,          \
          ClassType_,     \
          UnionType_      \
          )               \
  FFM_INITIALIZE (                                                             \
    ASN1_TYPE_DEF,                                                             \
    PKCS15ObjectName (Class_, SubClass_, Type_),                               \
    6,                                                                         \
    (                                                                          \
      .Name             = FFM_LSTR2 (Type_, PKCS15Object),                     \
      .Type             = ASN1_SEQUENCE_CLASS_TYPE,                            \
      .Tag              = ASN1_NO_TAG,                                         \
      .Tagging          = ASN1_TAGGING_BY_DEFAULT,                             \
      .TypeRef.Sequence = &PKCS15ObjectNameSequence (Class_, SubClass_, Type_),\
      .ASN1             = CK_FALSE                                             \
    )                                                                          \
  )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 59:
PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
        CommonKeyAttributes, CommonPrivateKeyAttributes, KeyAttributes}
*/

#define PrivateKeyObjectNameSequence(KeyAttributes_) \
  PKCS15ObjectNameSequence (                   \
    PKCS15_CommonKeyAttributesSequence,        \
    PKCS15_CommonPrivateKeyAttributesSequence, \
    KeyAttributes_                             \
    )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 60:
PublicKeyObject {KeyAttributes} ::= PKCS15Object {
       CommonKeyAttributes, CommonPublicKeyAttributes, KeyAttributes}
*/

#define PublicKeyObjectNameSequence(KeyAttributes_) \
  PKCS15ObjectNameSequence (                   \
    PKCS15_CommonKeyAttributesSequence,        \
    PKCS15_CommonPublicKeyAttributesSequence,  \
    KeyAttributes_                             \
    )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 62:
CertificateObject {CertAttributes} ::= PKCS15Object {
         CommonCertificateAttributes, NULL, CertAttributes}
*/

#define CertificateObjectNameSequence(CertAttributes_) \
  PKCS15ObjectNameSequence (                    \
    PKCS15_CommonCertificateAttributesSequence, \
    ASN1_NullPrim,                              \
    CertAttributes_                             \
    )

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 58:
KeyInfo {ParameterType, OperationsType} ::= CHOICE {
        reference    Reference,
        paramsAndOps SEQUENCE {
           parameters          ParameterType,
           supportedOperations OperationsType OPTIONAL
}
} */

#if 0
#define KeyInfo(ParameterType_, OperationsType_) \
static ASN1_TYPE_DEF CONST PKCS15_KeyInfoChoiceItems[] = {
  .Type           = ASN1_PRIM_CLASS_TYPE,
  .Tag            = ASN1_NO_TAG,
  .Tagging        = ASN1_TAGGING_BY_DEFAULT,
  .TypeRef.Choice = &PKCS15_ReferencePrim
};
#endif

/*****************************************************************************/

extern ASN1_TYPE_DEF CONST PKCS15_Identifier;
extern ASN1_TYPE_DEF CONST PKCS15_Reference;
extern ASN1_TYPE_DEF CONST PKCS15_Label;
extern ASN1_TYPE_DEF CONST PKCS15_Path;
extern ASN1_TYPE_DEF CONST PKCS15_RecordInfo;
extern ASN1_TYPE_DEF CONST PKCS15_DDO;
extern ASN1_TYPE_DEF CONST PKCS15_PKCS15Objects;
extern ASN1_TYPE_DEF CONST PKCS15_PrivateKeyTypeSequenceOf;
extern ASN1_TYPE_DEF CONST PKCS15_PublicKeyTypeSequenceOf;
extern ASN1_TYPE_DEF CONST PKCS15_CertificateTypeSequenceOf;

extern ASN1_TYPE_DEF CONST PKCS15_RSAPublicKey;
extern ASN1_TYPE_DEF CONST PKCS15_KEAPublicKey;
extern ASN1_TYPE_DEF CONST PKCS15_Certificate;
extern ASN1_TYPE_DEF CONST PKCS15_CertificateType;

/* Self-made ASN.1 definition:

FCI ::= [APPLICATION 15] SEQUENCE {
  dataLen         [0]  INTEGER (0..ISO7816_4_MAX_OFF_LEN),
  fullLen         [1]  INTEGER,
  fileDescriptor  [2]  OCTET STRING (2..2),
  fileId          [3]  OCTET STRING (2..2),
  proprietaryInfo [5]  OCTET STRING (6..6) OPTIONAL,
  secAttr         [6]  OCTET STRING (15..15) OPTIONAL,
  LCS             [10] OCTET STRING (1..1)
} */

typedef enum {
  FCI_DATA_LEN_ORD,
  FCI_FULL_LEN_ORD,
  FCI_FILE_DESCRIPTOR_ORD,
  FCI_FILE_ID_ORD,
  FCI_PROPRIETARY_INFO_ORD,
  FCI_SEC_ATTR_ORD,
  FCI_LCS_ORD
} FCI_SEQUENCE_ITEM_ORD;

extern ASN1_TYPE_DEF CONST ISO7816_4_FCI;

/* PKCS#15 v1.1, ANNEX A, page 67:
DIRRecord ::= [APPLICATION 1] SEQUENCE {
       aid      [APPLICATION 15] OCTET STRING,
       label    [APPLICATION 16] UTF8String OPTIONAL,
       path     [APPLICATION 17] OCTET STRING,
       ddo      [APPLICATION 19] DDO OPTIONAL
} */

typedef enum {
  DIRRECORD_AID_ORD,
  DIRRECORD_LABEL_ORD,
  DIRRECORD_PATH_ORD,
  DIRRECORD_DDO_ORD
} DIRRECORD_SEQUENCE_ITEM_ORD;

extern ASN1_TYPE_DEF CONST PKCS15_DIRRecord;

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

typedef enum {
  TOKEN_INFO_VERSION_ORD,
  TOKEN_INFO_SERIAL_NUMBER_ORD,
  TOKEN_INFO_MANUFACTURER_ID_ORD,
  TOKEN_INFO_LABEL_ORD,
  TOKEN_INFO_TOKEN_FLAGS_ORD,
  TOKEN_INFO_SE_INFO_ORD,
  TOKEN_INFO_RECORD_INFO_ORD,
  TOKEN_INFO_SUPPORTED_ALGORITHMS_ORD,
  TOKEN_INFO_ISSUER_ID_ORD,
  TOKEN_INFO_HOLDER_ID_ORD,
  TOKEN_INFO_LAST_UPDATE_ORD,
  TOKEN_INFO_PREFERRED_LANGUAGE_ORD
} TOKEN_INFO_SEQUENCE_ITEM_ORD;

extern ASN1_TYPE_DEF CONST PKCS15_TokenInfo;

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

typedef enum {
  PKCS15_OBJECTS_PRIVATE_KEYS_ORD,
  PKCS15_OBJECTS_PUBLIC_KEYS_ORD,
  PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD,
  PKCS15_OBJECTS_SECRET_KEYS_ORD,
  PKCS15_OBJECTS_CERTIFICATES_ORD,
  PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD,
  PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD,
  PKCS15_OBJECTS_DATA_OBJECTS_ORD,
  PKCS15_OBJECTS_AUTH_OBJECTS_ORD,
  PKCS15_OBJECTS_CHOICE_ITEM_ORD_ITEMS
} PKCS15_OBJECTS_CHOICE_ITEM_ORD;

extern ASN1_TYPE_DEF CONST PKCS15_PKCS15ObjectsSequenceOf;

/* PKCS#15 v1.1, ANNEX A, page 56:
Path ::= SEQUENCE {
         path   OCTET STRING,
         index  INTEGER (0..pkcs15-ub-index) OPTIONAL,
         length [0] INTEGER (0..pkcs15-ub-index) OPTIONAL
         }( WITH COMPONENTS {..., index PRESENT, length PRESENT}|
         WITH COMPONENTS {..., index ABSENT, length ABSENT}
) */

typedef enum {
  PATH_PATH_ORD,
  PATH_INDEX_ORD,
  PATH_LENGTH_ORD
} PATH_SEQUENCE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 56:
PathOrObjects {ObjectType} ::= CHOICE {
       path      Path,
       objects [0] SEQUENCE OF ObjectType,
       ...,
       indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
       direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType}
} */

typedef enum {
  PATH_OR_OBJECTS_PATH_ORD,
  PATH_OR_OBJECTS_OBJECTS_ORD,

#if 0
  PATH_OR_OBJECTS_INDIRECT_PROTECTED_ORD,
  PATH_OR_OBJECTS_DIRECT_PROTECTED_ORD,
#endif
  PATH_OR_OBJECTS_CHOICE_ITEM_ORD_ITEMS
} PATH_OR_OBJECTS_CHOICE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 56:
ReferencedValue {Type} ::= CHOICE {
       path     Path,
       url      URL
       } (CONSTRAINED BY {-- 'path' or 'url' shall point to an object of type -- Type})
*/

typedef enum {
  REFERENCED_VALUE_PATH_ORD,
  REFERENCED_VALUE_URL_ORD,
  REFERENCED_VALUE_CHOICE_ITEM_ORD_ITEMS
} REFERENCED_VALUE_CHOICE_ITEM_ORD;

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

typedef enum {
  OBJECT_VALUE_INDIRECT_ORD,
  OBJECT_VALUE_DIRECT_ORD,
  OBJECT_VALUE_INDIRECT_PROTECTED_ORD,
  OBJECT_VALUE_DIRECT_PROTECTED_ORD,
  OBJECT_VALUE_CHOICE_ITEM_ORD_ITEMS
} OBJECT_VALUE_CHOICE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 58:
PKCS15Object {ClassAttributes, SubClassAttributes, TypeAttributes} ::= SEQUENCE {
      commonObjectAttributes CommonObjectAttributes,
      classAttributes        ClassAttributes,
      subClassAttributes     [0] SubClassAttributes OPTIONAL,
      typeAttributes         [1] TypeAttributes
} */

typedef enum {
  PKCS15_OBJECT_COMMON_OBJECT_ATTRIBUTES_ORD,
  PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD,
  PKCS15_OBJECT_SUB_CLASS_ATTRIBUTES_ORD,
  PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD,
  PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS
} PKCS15_OBJECT_SEQUENCE_ITEM_ORD;

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

typedef enum {
  COMMON_OBJECT_ATTRIBUTES_LABEL_ORD,
  COMMON_OBJECT_ATTRIBUTES_FLAGS_ORD,
  COMMON_OBJECT_ATTRIBUTES_AUTHID_ORD,
  COMMON_OBJECT_ATTRIBUTES_USER_CONSENT_ORD,
  COMMON_OBJECT_ATTRIBUTES_ACCESS_CONTROL_RULES_ORD
} COMMON_OBJECT_ATTRIBUTES_SEQUENCE_ITEM_ORD;

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

typedef enum {
  COMMON_KEY_ATTRIBUTES_ID,
  COMMON_KEY_ATTRIBUTES_USAGE,
  COMMON_KEY_ATTRIBUTES_NATIVE,
  COMMON_KEY_ATTRIBUTES_ACCESS_FLAGS,
  COMMON_KEY_ATTRIBUTES_KEY_REFERENCE,
  COMMON_KEY_ATTRIBUTES_START_DATE,
  COMMON_KEY_ATTRIBUTES_END_DATE,
} COMMON_KEY_ATTRIBUTES_SEQUENCE_ITEM_ORD;

/*
PrivateKeys  ::= PathOrObjects {PrivateKeyType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_PrivateKeyType);

/* PKCS#15 v1.1, page 59:
PrivateKeyType ::= CHOICE {
        privateRSAKey PrivateKeyObject {PrivateRSAKeyAttributes},
        privateECKey            [0] PrivateKeyObject {PrivateECKeyAttributes},
        privateDHKey            [1] PrivateKeyObject {PrivateDHKeyAttributes},
        privateDSAKey [2] PrivateKeyObject {PrivateDSAKeyAttributes},
        privateKEAKey [3] PrivateKeyObject {PrivateKEAKeyAttributes},
        ... -- For future extensions
} */

typedef enum {
  PRIVATE_KEY_TYPE_PRIVATE_RSA_KEY,
  PRIVATE_KEY_TYPE_PRIVATE_EC_KEY,
  PRIVATE_KEY_TYPE_PRIVATE_DH_KEY,
  PRIVATE_KEY_TYPE_PRIVATE_DSA_KEY,
  PRIVATE_KEY_TYPE_PRIVATE_KEA_KEY
} PRIVATE_KEY_TYPE_CHOICE_ITEM_ORD;

/*
PublicKeys   ::= PathOrObjects {PublicKeyType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_PublicKeyType);

/* PKCS#15 v1.1, ANNEX A, page 60:
PublicKeyType ::= CHOICE {
       publicRSAKey PublicKeyObject {PublicRSAKeyAttributes},
       publicECKey             [0] PublicKeyObject {PublicECKeyAttributes},
       publicDHKey             [1] PublicKeyObject {PublicDHKeyAttributes},
       publicDSAKey [2] PublicKeyObject {PublicDSAKeyAttributes},
       publicKEAKey [3] PublicKeyObject {PublicKEAKeyAttributes},
       ... -- For future extensions
} */

typedef enum {
  PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY,
  PUBLIC_KEY_TYPE_PUBLIC_EC_KEY,
  PUBLIC_KEY_TYPE_PUBLIC_DH_KEY,
  PUBLIC_KEY_TYPE_PUBLIC_DSA_KEY,
  PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY,
  PUBLIC_KEY_TYPE_CHOICE_ITEM_ORD_ITEMS
} PUBLIC_KEY_TYPE_CHOICE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 60:
PublicRSAKeyAttributes ::= SEQUENCE {
       value                   ObjectValue {RSAPublicKeyChoice},
       modulusLength           INTEGER, -- modulus length in bits, e.g. 1024
       keyInfo                 KeyInfo {NULL, PublicKeyOperations} OPTIONAL,
       ... -- For future extensions
} */

typedef enum {
  PUBLIC_RSA_KEY_ATTRIBUTES_VALUE,
  PUBLIC_RSA_KEY_ATTRIBUTES_MODULUS_LENGTH,
  PUBLIC_RSA_KEY_ATTRIBUTES_KEY_INFO,
  PUBLIC_RSA_KEY_ATTRIBUTES_ITEM_ORD_ITEMS
} PUBLIC_RSA_KEY_ATTRIBUTES_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page61:
PublicKEAKeyAttributes ::= SEQUENCE {
       value   ObjectValue {KEAPublicKeyChoice},
       keyInfo KeyInfo {DomainParameters, PublicKeyOperations} OPTIONAL,
       ... -- For future extensions
} */

typedef enum {
  PUBLIC_KEA_KEY_ATTRIBUTES_VALUE,
#if 0
  PUBLIC_KEA_KEY_ATTRIBUTES_KEY_INFO,
#endif
  PUBLIC_KEA_KEY_ATTRIBUTES_ITEM_ORD_ITEMS
} PUBLIC_KEA_KEY_ATTRIBUTES_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 60:
RSAPublicKeyChoice ::= CHOICE {
      raw      RSAPublicKey,
      spki    [1] SubjectPublicKeyInfo, -- See X.509. Must contain a public RSA key
      ...
} */

typedef enum {
  RSA_PUBLIC_KEY_CHOICE_RAW,
#if 0
  RSA_PUBLIC_KEY_CHOICE_SPKI,
#endif
  RSA_PUBLIC_KEY_CHOICE_ITEM_ORD_ITEMS
} RSA_PUBLIC_KEY_CHOICE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 61:
KEAPublicKeyChoice ::= CHOICE {
      raw     INTEGER,
      spki    SubjectPublicKeyInfo, -- See X.509. Must contain a public KEA key
      ...
} */

typedef enum {
  KEA_PUBLIC_KEY_CHOICE_RAW,
#if 0
  KEA_PUBLIC_KEY_CHOICE_SPKI,
#endif
  KEA_PUBLIC_KEY_CHOICE_ITEM_ORD_ITEMS
} KEA_PUBLIC_KEY_CHOICE_ITEM_ORD;
/*
SecretKeys   ::= PathOrObjects {SecretKeyType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_SecretKeyType);

/* PKCS#15 v1.1, ANNEX A, page 58:
CommonCertificateAttributes ::= SEQUENCE {
     iD                    Identifier,
     authority             BOOLEAN DEFAULT FALSE,
     identifier       CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
     certHash              [0] OOBCertHash OPTIONAL,
     ...,
     trustedUsage          [1] Usage OPTIONAL,
     identifiers           [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} OPTIONAL,
     implicitTrust         [3] BOOLEAN DEFAULT FALSE
} */

typedef enum {
  COMMON_CERTIFICATE_ATTRIBUTES_ID,
  COMMON_CERTIFICATE_ATTRIBUTES_AUTHORITY,

/* These ones commented by '#if 0/#endif' below are NOT implemented yet */
#if 0
  COMMON_CERTIFICATE_ATTRIBUTES_IDENTIFIER,
  COMMON_CERTIFICATE_ATTRIBUTES_CERT_HASH,
  COMMON_CERTIFICATE_ATTRIBUTES_TRUSTED_USAGE,
  COMMON_CERTIFICATE_ATTRIBUTES_IDENTIFIERS,
#endif

  COMMON_CERTIFICATE_ATTRIBUTES_IMPLICIT_TRUST
} COMMON_CERTIFICATE_ATTRIBUTES_SEQUENCE_ITEM_ORD;

/*
Certificates ::= PathOrObjects {CertificateType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_CertificateType);

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

typedef enum {
  CERTIFICATE_TYPE_X509_CERTIFICATE,
/* FIXME: NOT implemented yet */
#if 0
  CERTIFICATE_TYPE_X509_ATTRIBUTE_CERTIFICATE,
  CERTIFICATE_TYPE_SPKI_CERTIFICATE,
  CERTIFICATE_TYPE_PGP_CERTIFICATE,
  CERTIFICATE_TYPE_WTLS_CERTIFICATE,
  CERTIFICATE_TYPE_X9_68_CERTIFICATE,
  CERTIFICATE_TYPE_CV_CERTIFICATE,
#endif
  CERTIFICATE_TYPE_CHOICE_ITEM_ORD_ITEMS
} CERTIFICATE_TYPE_CHOICE_ITEM_ORD;

/* PKCS#15 v1.1, ANNEX A, page 62:
X509CertificateAttributes ::= SEQUENCE {
       value              ObjectValue { Certificate },
       subject            Name OPTIONAL,
       issuer             [0] Name OPTIONAL,
       serialNumber       CertificateSerialNumber OPTIONAL,
       ... -- For future extensions
       }
*/

typedef enum {
  X509_CERTIFICATE_ATTRIBUTES_VALUE,
  X509_CERTIFICATE_ATTRIBUTES_SUBJECT,
  X509_CERTIFICATE_ATTRIBUTES_ISSUER,
  X509_CERTIFICATE_ATTRIBUTES_SERIAL_NUMBER,
  X509_CERTIFICATE_ATTRIBUTES_ITEM_ORD_ITEMS
} X509_CERTIFICATE_ATTRIBUTES_ITEM_ORD;

/*
Certificate ::= SIGNED{CertificateContent}

or, after substituting:

Certificate ::= SEQUENCE {
  certificateContent   CertificateContent,
  signatureAlgorithm   AlgorithmIdentifier{{SupportedAlgorithms}},
  signatureValue       BIT STRING
}
*/

typedef enum {
  CERTIFICATE_CERTIFICATE_CONTENT,
  CERTIFICATE_SIGNATURE_ALGORITHM,
  CERTIFICATE_SIGNATURE_VALUE,
  CERTIFICATE_ITEM_ORD_ITEMS
} CERTIFICATE_ITEM_ORD;

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

typedef enum {
  CERTIFICATE_CONTENT_VERSION,
  CERTIFICATE_CONTENT_SERIAL_NUMBER,
  CERTIFICATE_CONTENT_SIGNATURE,
  CERTIFICATE_CONTENT_ISSUER,
  CERTIFICATE_CONTENT_VALIDITY,
  CERTIFICATE_CONTENT_SUBJECT,
  CERTIFICATE_CONTENT_SUBJECT_PUBLIC_KEY_INFO,
  CERTIFICATE_CONTENT_ISSUER_UNIQUE_IDENTIFIER,
  CERTIFICATE_CONTENT_SUBJECT_UNIQUE_IDENTIFIER,
  CERTIFICATE_CONTENT_EXTENSIONS,
  CERTIFICATE_CONTENT_ITEM_ORD_ITEMS
} CERTIFICATE_CONTENT_ITEM_ORD;

/*
Name ::= CHOICE { -- only one possibility for now --rdnSequence  RDNSequence
RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
}
*/

typedef enum {
  NAME_RDN_SEQUENCE,
  NAME_ITEM_ORD_ITEMS
} NAME_ITEM_ORD;

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

typedef enum {
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_TYPE,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_VALUE,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_PRIMARY_DISTINGUISHED,
#if 0
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_VALUES_WITH_CONTEXT,
#endif
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_ITEM_ORD_ITEMS
} ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_ITEM_ORD;

/*
AttributeTypeAndDistinguishedValueChoice ::= CHOICE {
  printableString RPINTABLE STRING;
  ia5String       IA5STRING
}
*/

typedef enum {
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_PRINTABLE_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_IA5_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_UTF8_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_BMP_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_TELETEXT_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_NUMERIC_STRING,
  ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_ITEM_ORD_ITEMS
} ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_ITEM_ORD;

/*
Time ::= CHOICE {utcTime          UTCTime,
                 generalizedTime  GeneralizedTime
}
*/

typedef enum {
  TIME_UTC_TIME,
  TIME_GENERALIZED_TIME,
  TIME_ITEM_ORD_ITEMS
} TIME_ITEM_ORD;

/*
SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm         AlgorithmIdentifier{{SupportedAlgorithms}},
  subjectPublicKey  BIT STRING
}
*/

typedef enum {
  SUBJECT_PUBLIC_KEY_INFO_ALGORITHM,
  SUBJECT_PUBLIC_KEY_INFO_SUBJECT_PUBLIC_KEY,
  SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD_ITEMS
} SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD;

/*
AlgorithmIdentifier{ALGORITHM:SupportedAlgorithms} ::= SEQUENCE {
  algorithm   ALGORITHM.&id({SupportedAlgorithms}),
  parameters  ALGORITHM.&Type({SupportedAlgorithms}{@algorithm}) OPTIONAL
}
*/

typedef enum {
  ALGORITHM_IDENTIFIER_ALGORITHM,
  ALGORITHM_IDENTIFIER_PARAMETERS,
  ALGORITHM_IDENTIFIER_ITEM_ORD_ITEMS
} ALGORITHM_IDENTIFIER_ITEM_ORD;

/*
AlgorithmParameters ::= CHOICE {
  null     NULL,
  sequence AlgorithmParameterSet
}
*/

typedef enum {
  ALGORITHM_PARAMETERS_NULL,
  ALGORITHM_PARAMETERS_SEQUENCE,
  ALGORITHM_PARAMETERS_ITEM_ORD_ITEMS
} ALGORITHM_PARAMETERS_ITEM_ORD;

/*
AlgorithmParameterSet ::= SEQUENCE {
  cipherParameterSet OBJECT IDENTIFIER,
  hashParameterSet   OBJECT IDENTIFIER
}
*/

typedef enum {
  ALGORITHM_PARAMETER_SET_CIPHER_PARAMETER_SET,
  ALGORITHM_PARAMETER_SET_HASH_PARAMETER_SET,
  ALGORITHM_PARAMETER_SET_ITEM_ORD_ITEMS
} ALGORITHM_PARAMETER_SET_ITEM_ORD;

/*
DataObjects  ::= PathOrObjects {DataType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_DataType);

/*
AuthObjects  ::= PathOrObjects {AuthenticationType}
*/

extern ASN1_CHOICE_TYPE_DEF CONST PathOrObjectsNameChoice (PKCS15_AuthenticationType);

extern VOID PKCS15_InitializeStatics (VOID);

/* Restore CONST protection */
#if defined _MSC_VER
#undef CONST
#define CONST const
#endif

#endif /* __PKCS15_ASN_1__ */

/* Multiple inclusion section starts here */

/* There are two commands to process: 'next fun name' and 'invoke funs' */
#if defined FFM_CMD_UNDEF

#undef FFM_CMD_OBJECT_VALUE
#undef FFM_CMD_REFERENCED_VALUE
#undef FFM_CMD_ENVELOPED_DATA
#undef FFM_CMD_PATH_OR_OBJECTS
#undef FFM_CMD_PKCS15_OBJECT
#undef FFM_CMD_PRIVATE_KEY_OBJECT
#undef FFM_CMD_PUBLIC_KEY_OBJECT
#undef FFM_CMD_UNDEF

#else /* FFM_CMD_UNDEF */

#if defined FFM_CMD_PATH_OR_OBJECTS   || defined FFM_CMD_REFERENCED_VALUE   || \
    defined FFM_CMD_ENVELOPED_DATA    || defined FFM_CMD_OBJECT_VALUE       || \
    defined FFM_CMD_PKCS15_OBJECT     || defined FFM_CMD_PRIVATE_KEY_OBJECT || \
    defined FFM_CMD_PUBLIC_KEY_OBJECT || defined FFM_CMD_CERTIFICATE_OBJECT

#ifndef FIX_FOR_MACROS

#error The FIX_FOR_MACROS macro MUST be defined before
#error including "Pkcs15ASN.1.h" as follows:
#error #define FIX_FOR_MACROS "Pkcs15ASN.1.h"
#error and later "Pkcs15ASN.1.h" should be included as follows:
#error #include FIX_FOR_MACROS

#else /* FIX_FOR_MACROS */

/*****************************************************************************/
/* 'PathOrObjects' pseudo-macro */
#if defined FFM_CMD_PATH_OR_OBJECTS

#ifndef FFM_CMD_PATH_OR_OBJECTS_Type_
#error The Type_ parameter for the 'PathOrObjects' pseudo-macro is undefined
#error (FFM_CMD_PATH_OR_OBJECTS_Type_ for FFM_CMD_PATH_OR_OBJECTS)
#endif

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 56:
PathOrObjects {ObjectType} ::= CHOICE {
       path      Path,
       objects [0] SEQUENCE OF ObjectType,
       ...,
       indirect-protected [1] ReferencedValue {EnvelopedData {SEQUENCE OF ObjectType}},
       direct-protected [2] EnvelopedData {SEQUENCE OF ObjectType}
} */

/* 'PathOrObjects (Type_)' */

/* Initialize 3 parts of PathOrObjects in Microsoft-compatible way */
#include FIX_FOR_MICROSOFT
FFM_INV (PathOrObjects_0, (FFM_CMD_PATH_OR_OBJECTS_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (PathOrObjects_1, (FFM_CMD_PATH_OR_OBJECTS_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (PathOrObjects_2, (FFM_CMD_PATH_OR_OBJECTS_Type_));


/* Undefine parameters for this macro */
#undef FFM_CMD_PATH_OR_OBJECTS_Type_

/*****************************************************************************/
/* 'ReferencedValue' pseudo-macro */
#elif defined FFM_CMD_REFERENCED_VALUE

#ifndef FFM_CMD_REFERENCED_VALUE_Type_
#error The Type_ parameter for the 'ReferencedValue' pseudo-macro is undefined
#error (FFM_CMD_REFERENCED_VALUE_Type_ for FFM_CMD_REFERENCED_VALUE)
#endif

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 56:
ReferencedValue {Type} ::= CHOICE {
       path     Path,
       url      URL
       } (CONSTRAINED BY {-- 'path' or 'url' shall point to an object of type -- Type})
*/

/* 'ReferencedValue (Type_)' */

/* Initialize 3 parts of ReferencedValue in Microsoft-compatible way */
#include FIX_FOR_MICROSOFT
FFM_INV (ReferencedValue_0, (FFM_CMD_REFERENCED_VALUE_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (ReferencedValue_1, (FFM_CMD_REFERENCED_VALUE_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (ReferencedValue_2, (FFM_CMD_REFERENCED_VALUE_Type_));

/* Undefine parameters for this macro */
#undef FFM_CMD_REFERENCED_VALUE_Type_


/* 'EnvelopedData' pseudo-macro */
#elif defined FFM_CMD_ENVELOPED_DATA

#ifndef FFM_CMD_ENVELOPED_DATA_Type_
#error The Type_ parameter for the 'EnvelopedData' pseudo-macro is undefined
#error (FFM_CMD_ENVELOPED_DATA_Type_ for FFM_CMD_ENVELOPED_DATA)
#endif

/* FIXME: implementation should be completed */
/* PKCS#15 v1.1, ANNEX A, page 66:
EnvelopedData {Type} ::= SEQUENCE {
       version                 INTEGER{v0(0),v1(1),v2(2),v3(3),v4(4)}(v0|v1|v2,...),
       originatorInfo          [0] OriginatorInfo OPTIONAL,
       recipientInfos          RecipientInfos,
       encryptedContentInfo    EncryptedContentInfo{Type},
       unprotectedAttrs        [1] SET SIZE (1..MAX) OF Attribute OPTIONAL
} */

/* 'EnvelopedData (Type_)' */

/* Initialize 3 parts of EnvelopedData in Microsoft-compatible way */
#include FIX_FOR_MICROSOFT
FFM_INV (EnvelopedData_0, (FFM_CMD_ENVELOPED_DATA_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (EnvelopedData_1, (FFM_CMD_ENVELOPED_DATA_Type_));
#include FIX_FOR_MICROSOFT
FFM_INV (EnvelopedData_2, (FFM_CMD_ENVELOPED_DATA_Type_));


/* Undefine parameters for this macro */
#undef FFM_CMD_ENVELOPED_DATA_Type_

/*****************************************************************************/
/* 'ObjectValue' pseudo-macro */
#elif defined FFM_CMD_OBJECT_VALUE

#ifndef FFM_CMD_OBJECT_VALUE_Type_
#error The Type_ parameter for the 'ObjectValue' pseudo-macro is undefined
#error (FFM_CMD_OBJECT_VALUE_Type_ for FFM_CMD_OBJECT_VALUE)
#endif
#ifndef FFM_CMD_OBJECT_VALUE_ClassType_
#error The ClassType_ parameter for the 'ObjectValue' pseudo-macro is undefined
#error (FFM_CMD_OBJECT_VALUE_ClassType_ for FFM_CMD_OBJECT_VALUE)
#endif
#ifndef FFM_CMD_OBJECT_VALUE_UnionType_
#error The UnionType_ parameter for the 'ObjectValue' pseudo-macro is undefined
#error (FFM_CMD_OBJECT_VALUE_UnionType_ for FFM_CMD_OBJECT_VALUE)
#endif
#ifndef FFM_CMD_OBJECT_VALUE_ASN1_
#error The ASN1_ parameter for the 'ObjectValue' pseudo-macro is undefined
#error (FFM_CMD_OBJECT_VALUE_ASN1_ for FFM_CMD_OBJECT_VALUE)
#endif

/* Preparing to 'call' another pseudo-macros */
#undef FFM_CMD_OBJECT_VALUE


/*****************************************************************************/
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

/* Here the instance of 'ReferencedValue (Type_)' is needed */

/* Preparing 'ReferencedValue' pseudo-macro parameters */
#define FFM_CMD_REFERENCED_VALUE_Type_ \
  FFM_CMD_OBJECT_VALUE_Type_

/* Preparing to 'call' 'ReferencedValue' pseudo-macros */
#define FFM_CMD_REFERENCED_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Here the instance of 'EnvelopedData (Type_)' is needed */

/* Preparing 'EnvelopedData' pseudo-macro parameters */
#define FFM_CMD_ENVELOPED_DATA_Type_ \
  FFM_CMD_OBJECT_VALUE_Type_

/* Preparing to 'call' 'EnvelopedData' pseudo-macros */
#define FFM_CMD_ENVELOPED_DATA

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* 'ReferencedValue (EnvelopedDataNameSequence (Type_))' is needed */

/* Preparing 'ReferencedVaule' pseudo-macro parameters */
#define FFM_CMD_REFERENCED_VALUE_Type_ \
  FFM_INV (EnvelopedDataNameSequence, (FFM_CMD_OBJECT_VALUE_Type_))

/* Preparing to 'call' 'ReferencedVaule' pseudo-macros */
#define FFM_CMD_REFERENCED_VALUE

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* 'ObjectValue (Type_, ClassType_, UnionType_)' */

/* Initialize 3 parts of ObjectValue in Microsoft-compatible way */
#include FIX_FOR_MICROSOFT
FFM_INV (ObjectValue_0, (
           FFM_CMD_OBJECT_VALUE_Type_,
           FFM_CMD_OBJECT_VALUE_ClassType_,
           FFM_CMD_OBJECT_VALUE_UnionType_,
           FFM_CMD_OBJECT_VALUE_ASN1_));
#include FIX_FOR_MICROSOFT
FFM_INV (ObjectValue_1, (
           FFM_CMD_OBJECT_VALUE_Type_,
           FFM_CMD_OBJECT_VALUE_ClassType_,
           FFM_CMD_OBJECT_VALUE_UnionType_));
#include FIX_FOR_MICROSOFT
FFM_INV (ObjectValue_2, (
           FFM_CMD_OBJECT_VALUE_Type_,
           FFM_CMD_OBJECT_VALUE_ClassType_,
           FFM_CMD_OBJECT_VALUE_UnionType_));


/* Undefine parameters for this macro */
#undef FFM_CMD_OBJECT_VALUE_Type_
#undef FFM_CMD_OBJECT_VALUE_ClassType_
#undef FFM_CMD_OBJECT_VALUE_UnionType_
#undef FFM_CMD_OBJECT_VALUE_ASN1_

/*****************************************************************************/
/* 'PKCS15Object' pseudo-macro */
#elif defined FFM_CMD_PKCS15_OBJECT

#ifndef FFM_CMD_PKCS15_OBJECT_Class_
#error The Type_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_Class_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_ClassClass_
#error The ClassClass_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_ClassClass_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_UnionClass_
#error The UnionClass_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_UnionClass_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_SubClass_
#error The SubClass_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_SubClass_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_ClassSubClass_
#error The ClassSubClass_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_ClassSubClass_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_UnionSubClass_
#error The UnionSubClass_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_UnionSubClass_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_Type_
#error The Type_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_Type_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_ClassType_
#error The ClassType_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_ClassType_ for FFM_CMD_PKCS15_OBJECT)
#endif
#ifndef FFM_CMD_PKCS15_OBJECT_UnionType_
#error The UnionType_ parameter for the 'PKCS15Object' pseudo-macro is undefined
#error (FFM_CMD_PKCS15_OBJECT_UnionType_ for FFM_CMD_PKCS15_OBJECT)
#endif

/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 58:
PKCS15Object {ClassAttributes, SubClassAttributes, TypeAttributes} ::= SEQUENCE {
      commonObjectAttributes CommonObjectAttributes,
      classAttributes        ClassAttributes,
      subClassAttributes     [0] SubClassAttributes OPTIONAL,
      typeAttributes         [1] TypeAttributes
} */

/* 'PKCS15Object (Class_, ClassClass_, UnionClass_, ... UnionType_)' */

/* Initialize 3 parts of PKCS15Object in Microsoft-compatible way */
#include FIX_FOR_MICROSOFT
FFM_INV (PKCS15Object_0, (
           FFM_CMD_PKCS15_OBJECT_Class_,
           FFM_CMD_PKCS15_OBJECT_ClassClass_,
           FFM_CMD_PKCS15_OBJECT_UnionClass_,
           FFM_CMD_PKCS15_OBJECT_SubClass_,
           FFM_CMD_PKCS15_OBJECT_ClassSubClass_,
           FFM_CMD_PKCS15_OBJECT_UnionSubClass_,
           FFM_CMD_PKCS15_OBJECT_Type_,
           FFM_CMD_PKCS15_OBJECT_ClassType_,
           FFM_CMD_PKCS15_OBJECT_UnionType_
           ))
#include FIX_FOR_MICROSOFT
FFM_INV (PKCS15Object_1, (
           FFM_CMD_PKCS15_OBJECT_Class_,
           FFM_CMD_PKCS15_OBJECT_ClassClass_,
           FFM_CMD_PKCS15_OBJECT_UnionClass_,
           FFM_CMD_PKCS15_OBJECT_SubClass_,
           FFM_CMD_PKCS15_OBJECT_ClassSubClass_,
           FFM_CMD_PKCS15_OBJECT_UnionSubClass_,
           FFM_CMD_PKCS15_OBJECT_Type_,
           FFM_CMD_PKCS15_OBJECT_ClassType_,
           FFM_CMD_PKCS15_OBJECT_UnionType_
           ))
#include FIX_FOR_MICROSOFT
FFM_INV (PKCS15Object_2, (
           FFM_CMD_PKCS15_OBJECT_Class_,
           FFM_CMD_PKCS15_OBJECT_ClassClass_,
           FFM_CMD_PKCS15_OBJECT_UnionClass_,
           FFM_CMD_PKCS15_OBJECT_SubClass_,
           FFM_CMD_PKCS15_OBJECT_ClassSubClass_,
           FFM_CMD_PKCS15_OBJECT_UnionSubClass_,
           FFM_CMD_PKCS15_OBJECT_Type_,
           FFM_CMD_PKCS15_OBJECT_ClassType_,
           FFM_CMD_PKCS15_OBJECT_UnionType_
           ))


/* Undefine parameters for this macro */
#undef FFM_CMD_PKCS15_OBJECT_Class_
#undef FFM_CMD_PKCS15_OBJECT_ClassClass_
#undef FFM_CMD_PKCS15_OBJECT_UnionClass_
#undef FFM_CMD_PKCS15_OBJECT_SubClass_
#undef FFM_CMD_PKCS15_OBJECT_ClassSubClass_
#undef FFM_CMD_PKCS15_OBJECT_UnionSubClass_
#undef FFM_CMD_PKCS15_OBJECT_Type_
#undef FFM_CMD_PKCS15_OBJECT_ClassType_
#undef FFM_CMD_PKCS15_OBJECT_UnionType_

/*****************************************************************************/
/* 'PrivateKeyObject' pseudo-macro */
#elif defined FFM_CMD_PRIVATE_KEY_OBJECT

#ifndef FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_
#error The KeyAttributes_ parameter for the 'PrivateKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_ for FFM_CMD_PRIVATE_KEY_OBJECT)
#endif
#ifndef FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_
#error The ClassKeyAttributes_ parameter for the 'PrivateKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_ for FFM_CMD_PRIVATE_KEY_OBJECT)
#endif
#ifndef FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_
#error The UnionKeyAttributes_ parameter for the 'PrivateKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_ for FFM_CMD_PRIVATE_KEY_OBJECT)
#endif

/* Preparing to 'call' another pseudo-macros */
#undef FFM_CMD_PRIVATE_KEY_OBJECT


/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 59:
PrivateKeyObject {KeyAttributes} ::= PKCS15Object {
        CommonKeyAttributes, CommonPrivateKeyAttributes, KeyAttributes}
*/

/* Preparing 'PKCS15Object' pseudo-macro parameters */
#define FFM_CMD_PKCS15_OBJECT_Class_         \
  PKCS15_CommonKeyAttributesSequence

#define FFM_CMD_PKCS15_OBJECT_ClassClass_    \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionClass_    \
  Sequence

#define FFM_CMD_PKCS15_OBJECT_SubClass_      \
  PKCS15_CommonPrivateKeyAttributesSequence

#define FFM_CMD_PKCS15_OBJECT_ClassSubClass_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionSubClass_ \
  Sequence

#define FFM_CMD_PKCS15_OBJECT_Type_          \
  FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_

#define FFM_CMD_PKCS15_OBJECT_ClassType_     \
  FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_

#define FFM_CMD_PKCS15_OBJECT_UnionType_     \
  FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_

/* Preparing to 'call' 'PKCS15Object' pseudo-macros */
#define FFM_CMD_PKCS15_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Undefine parameters for this macro */
#undef FFM_CMD_PRIVATE_KEY_OBJECT_KeyAttributes_
#undef FFM_CMD_PRIVATE_KEY_OBJECT_ClassKeyAttributes_
#undef FFM_CMD_PRIVATE_KEY_OBJECT_UnionKeyAttributes_

/*****************************************************************************/
/* 'PublicKeyObject' pseudo-macro */
#elif defined FFM_CMD_PUBLIC_KEY_OBJECT

#ifndef FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_
#error The KeyAttributes_ parameter for the 'PublicKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_ for FFM_CMD_PUBLIC_KEY_OBJECT)
#endif
#ifndef FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_
#error The ClassKeyAttributes_ parameter for the 'PublicKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_ for FFM_CMD_PUBLIC_KEY_OBJECT)
#endif
#ifndef FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_
#error The UnionKeyAttributes_ parameter for the 'PublicKeyObject' pseudo-macro is undefined
#error (FFM_CMD_PUBLIC_KEY_OBJECT_UnionKeyAttributes_ for FFM_CMD_PUBLIC_KEY_OBJECT)
#endif

/* Preparing to 'call' another pseudo-macros */
#undef FFM_CMD_PUBLIC_KEY_OBJECT


/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 60:
PublicKeyObject {KeyAttributes} ::= PKCS15Object {
       CommonKeyAttributes, CommonPublicKeyAttributes, KeyAttributes}
*/

/* Preparing 'PKCS15Object' pseudo-macro parameters */
#define FFM_CMD_PKCS15_OBJECT_Class_         \
  PKCS15_CommonKeyAttributesSequence

#define FFM_CMD_PKCS15_OBJECT_ClassClass_    \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionClass_    \
  Sequence

#define FFM_CMD_PKCS15_OBJECT_SubClass_      \
  PKCS15_CommonPublicKeyAttributesSequence

#define FFM_CMD_PKCS15_OBJECT_ClassSubClass_ \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionSubClass_ \
  Sequence

#define FFM_CMD_PKCS15_OBJECT_Type_          \
  FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_

#define FFM_CMD_PKCS15_OBJECT_ClassType_     \
  FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_

#define FFM_CMD_PKCS15_OBJECT_UnionType_     \
  FFM_CMD_PUBLIC_KEY_OBJECT_UnionKeyAttributes_

/* Preparing to 'call' 'PKCS15Object' pseudo-macros */
#define FFM_CMD_PKCS15_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Undefine parameters for this macro */
#undef FFM_CMD_PUBLIC_KEY_OBJECT_KeyAttributes_
#undef FFM_CMD_PUBLIC_KEY_OBJECT_ClassKeyAttributes_
#undef FFM_CMD_PUBLIC_KEY_OBJECT_UnionKeyAttributes_

/*****************************************************************************/
/* 'CertificateObject' pseudo-macro */
#elif defined FFM_CMD_CERTIFICATE_OBJECT

#ifndef FFM_CMD_CERTIFICATE_OBJECT_CertAttributes_
#error The CertAttributes_ parameter for the 'CertificateObject' pseudo-macro is undefined
#error (FFM_CMD_CERTIFICATE_OBJECT_CertAttributes_ for FFM_CMD_CERTIFICATE_OBJECT)
#endif
#ifndef FFM_CMD_CERTIFICATE_OBJECT_ClassCertAttributes_
#error The ClassCertAttributes_ parameter for the 'CertificateObject' pseudo-macro is undefined
#error (FFM_CMD_CERTIFICATE_OBJECT_ClassCertAttributes_ for FFM_CMD_CERTIFICATE_OBJECT)
#endif
#ifndef FFM_CMD_CERTIFICATE_OBJECT_UnionCertAttributes_
#error The UnionCertAttributes_ parameter for the 'CertificateObject' pseudo-macro is undefined
#error (FFM_CMD_CERTIFICATE_OBJECT_UnionCertAttributes_ for FFM_CMD_CERTIFICATE_OBJECT)
#endif

/* Preparing to 'call' another pseudo-macros */
#undef FFM_CMD_CERTIFICATE_OBJECT


/*****************************************************************************/
/* PKCS#15 v1.1, ANNEX A, page 62:
CertificateObject {CertAttributes} ::= PKCS15Object {
         CommonCertificateAttributes, NULL, CertAttributes}
*/

/* Preparing 'PKCS15Object' pseudo-macro parameters */
#define FFM_CMD_PKCS15_OBJECT_Class_         \
  PKCS15_CommonCertificateAttributesSequence

#define FFM_CMD_PKCS15_OBJECT_ClassClass_    \
  ASN1_SEQUENCE_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionClass_    \
  Sequence

#define FFM_CMD_PKCS15_OBJECT_SubClass_      \
  ASN1_NullPrim

#define FFM_CMD_PKCS15_OBJECT_ClassSubClass_ \
  ASN1_PRIM_CLASS_TYPE

#define FFM_CMD_PKCS15_OBJECT_UnionSubClass_ \
  Prim

#define FFM_CMD_PKCS15_OBJECT_Type_          \
  FFM_CMD_CERTIFICATE_OBJECT_CertAttributes_

#define FFM_CMD_PKCS15_OBJECT_ClassType_     \
  FFM_CMD_CERTIFICATE_OBJECT_ClassCertAttributes_

#define FFM_CMD_PKCS15_OBJECT_UnionType_     \
  FFM_CMD_CERTIFICATE_OBJECT_UnionCertAttributes_

/* Preparing to 'call' 'PKCS15Object' pseudo-macros */
#define FFM_CMD_PKCS15_OBJECT

/* 'Call' the pseudo-macros */
#include FIX_FOR_MACROS


/* Undefine parameters for this macro */
#undef FFM_CMD_CERTIFICATE_OBJECT_KeyAttributes_
#undef FFM_CMD_CERTIFICATE_OBJECT_ClassKeyAttributes_
#undef FFM_CMD_CERTIFICATE_OBJECT_UnionKeyAttributes_

#endif /* FFM_CMD_OBJECT_VALUE */

#endif /* FIX_FOR_MACROS */

/* Undefine all macros */
#define FFM_CMD_UNDEF
#include FIX_FOR_MACROS

#endif /* FFM_CMD_PATH_OR_OBJECTS   || FFM_CMD_REFERENCED_VALUE   ||
          FFM_CMD_ENVELOPED_DATA    || FFM_CMD_OBJECT_VALUE       ||
          FFM_CMD_PKCS15_OBJECT     || FFM_CMD_PRIVATE_KEY_OBJECT ||
          FFM_CMD_PUBLIC_KEY_OBJECT || FFM_CMD_CERTIFICATE_OBJECT */

#endif /* FFM_CMD_UNDEF */
