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

#define FIX_FOR_MACROS "Pkcs15ASN.1.h"

/* Performing the first inclusion and providing control macros are undefined */
#define FFM_CMD_UNDEF
#include FIX_FOR_MACROS

#include <Library/Pkcs11Lib.h>

#include <Uefi.h>

#include <Protocol/SmartCard.h>
#include <Library/BaseMemoryLib.h>

/* Define the macro for the getting the code Microsoft-compatible header */
#define FIX_FOR_MICROSOFT "FixForMicrosoft.h"

/* The header is needed to be included to get the code Microsoft-compatible */
#include FIX_FOR_MICROSOFT

/* This inclusion should be removed when Pkcs11Lib has finally debugged */
#include <Library/DebugLib.h>

#if 1
#define LOG(P_) DEBUG (P_)
#define DUMP(P_, L_) Dump16 (P_, L_, &emit)
#else
#define LOG(P_)
#define DUMP(P_, L_)
#endif

#define INTERNAL_ERROR \
  DEBUG ((EFI_D_ERROR, "Internal Error: " __FILE__ ", %d\n", __LINE__))

/* Note about R/W sessions: R/W sessions are enabled by default.
   When disabled, an attempt to open an R/W session leads to return of the
   CKR_TOKEN_WRITE_PROTECTED error code. In order to get R/W sessions allowed,
   the CRYPTOKI_RW_SESSIONS_ALLOWED preprocessor symbol must somehow be defined
   when compiling this file (either specified on the command line or
   hard-coded within a source/header file):

*/

#define CRYPTOKI_RW_SESSIONS_ALLOWED

#ifndef UINT8_MAX
#define UINT8_MAX 0xff
#endif /* UINT8_MAX */

typedef enum {
  Rutoken_older_2_0 = 1,
  Rutoken_2_0  
} TokenModels;

/* Operations, which are in progress (treated as binary ORed flags) */
typedef enum {
  OPERATION_NONE    = 0,      /* 0x00000000 */
  OPERATION_DIGEST  = 1 << 0, /* 0x00000001 */
  OPERATION_DECRYPT = 1 << 1, /* 0x00000002 */
  OPERATION_VERIFY  = 1 << 2, /* 0x00000004 */
  OPERATION_SIGN    = 1 << 3  /* 0x00000008 */
} OPERATIONS;

/* Digest/decryption/verify processing states */
typedef enum {
  PROCESSING_STATE_NONE,  /* Initial and after Op() and OpFinal() calls state */
  PROCESSING_STATE_INIT,  /* The state after OpInit() call */
  PROCESSING_STATE_UPDATE /* The state after OpUpdate() call */
} PROCESSING_STATE;

/* Particular types of objects and the whole number of types available */
typedef enum {
  SESSION_OBJECT,               /* Search among session objects only        */
  TOKEN_OBJECT,                 /* Search among token objects only          */
  ANY_OBJECT,                   /* Search among all the objects             */
  OBJECT_TYPES_NUM = ANY_OBJECT /* Number of distinct object types possible */
} OBJECT_TYPE;

/* PKCS#11 Template object */
typedef struct {
  CK_BBOOL         Initialized;
  OBJECT_TYPE      SearchType;  /* A particular type or ANY_OBJECT        */
  CK_ULONG         ObjOrd;      /* Ordinal in the array of PKCS15 objects */
  OBJECT_TYPE      ObjType;     /* Ordinal in the PKCS11 type sub-array   */
  CK_ULONG         ItemOrd;     /* Ordinal within the object SEQUENCE OF  */
  CK_ATTRIBUTE_PTR pTemplate;   /* Array of attributes   */
  CK_ULONG         ulCount;     /* Number of array items */
} PKCS11_TEMPLATE;

/* PKCS#11 session */
typedef struct {
  CK_SESSION_HANDLE Handle;
  CK_STATE          State;
  CK_FLAGS          Flags;
  PKCS11_TEMPLATE   Search; /* Search state for FindObjects()   */
  CK_BYTE           KeyRef; /* References a key when decrypting */
} PKCS11_SESSION;

/* PKCS#15 Data */
typedef struct {
  ASN1_OCTET_STRING_VAL AppPath;
  ASN1_OCTET_STRING_VAL TokenInfoPath;
  ASN1_OCTET_STRING_VAL ODFPath;

  ASN1_TYPE_VAL         Objects[PKCS15_OBJECTS_CHOICE_ITEM_ORD_ITEMS]
                               [OBJECT_TYPES_NUM];
} PKCS15_DATA;

/* CCID slot */
typedef struct {
  EFI_HANDLE          Handle;
  SMART_CARD_PROTOCOL *Interface;

  PKCS11_SESSION      Session;
  PKCS15_DATA         Data;

  OPERATIONS          Operations;          /* Operations being processed      */
  PROCESSING_STATE    ProcessingState;     /* The state of processing         */
  CK_MECHANISM_TYPE   DigestMechanism;     /* Digest mechanism being used     */
  CK_MECHANISM_TYPE   DecryptionMechanism; /* Decryption mechanism being used */
  GOSTR3410_PARAM_SET DecryptionParamSet;  /* Decryption set of parameters    */
  CK_BYTE             Digest[32];          /* Digest storage                  */
  CK_ULONG            DigestCount;         /* Accumulated number of bytes     */
  ASN1_TYPE_VAL       *VerifyKey;

  CK_TOKEN_INFO       TokenInfo;
} CCID_SLOT;

/* Cryptoki object */
typedef struct {
  CCID_SLOT         *Slots;
  CK_ULONG          SlotNum;
  CK_SESSION_HANDLE NextSessionHandle; /* Incremented unique value */
  BOOLEAN           Initialized;
  BOOLEAN           bWithoutToken;
  BOOLEAN           bScInfoReaded;
} CRYPTOKI;

/* EFI Boot Services table */
extern EFI_BOOT_SERVICES *gBS;

/* Set the function name generation mode for the FIX header */
#define FFM_CMD_NEXT_FUN_NAME

#include FIX_FOR_MICROSOFT /* Generate the next initialization function name */

/* There is no CONST protection needed here */
#undef CONST
#define CONST

static
BOOLEAN
IsFieldIsCN (
  CK_ULONG_PTR value,
  CK_ULONG     lenOfvalue
)
{
  static CK_ULONG cn[] = { 2, 5, 4, 3 };
  CK_ULONG cnLen = 0, count = 0;

  cnLen = ARRAY_ITEMS (cn);
  if (cnLen != lenOfvalue)
    return FALSE;

  for(count = 0; count < cnLen; count++) {
    if (cn[count] != value[count])
      return FALSE;
  }

  return TRUE;
}


/* The Cryptoki singleton */
FFM_INITIALIZE (
  static CRYPTOKI,                          /* Storage class and type   */
  Cryptoki,                                 /* Variable name            */
  5,                                        /* The number of fields     */
  (
    .Slots             = NULL,              /* Field N_1 C99 init style */
    .SlotNum           = 0,                 /* Field N_2 C99 init style */
    .NextSessionHandle = CK_INVALID_HANDLE, /* Field N_3 C99 init style */
    .Initialized       = FALSE,             /* Field N_4 C99 init style */
    .bWithoutToken     = FALSE
  )
)

/* Restore CONST protection */
#undef CONST
#define CONST const

static VOID PKCS11_InitializeStatics (VOID)
{
#if defined _MSC_VER
  static int Initialized = 0; /* Repeated call protection */

  if (!Initialized) {
/* Unset the function name generation mode for the FIX header */
#undef FFM_CMD_NEXT_FUN_NAME

/* Set the invocation of functions mode for the FIX header */
#define FFM_CMD_INVOKE_FUNS

#include FIX_FOR_MICROSOFT /* Invoke all the functions the names are generated for */

    Initialized = 1;
  }
#endif /* _MSC_VER */
}

/* Implementation of Cryptoki helper functions */

static inline CK_RV MapErr (EFI_STATUS Status)
{
    switch (Status) {
    case EFI_SUCCESS:
      return CKR_OK;
    case EFI_INVALID_PARAMETER:
      return CKR_ARGUMENTS_BAD;
    case EFI_OUT_OF_RESOURCES:
      return CKR_HOST_MEMORY;
    case EFI_DEVICE_ERROR:
      return CKR_DEVICE_ERROR;
    }

    return CKR_FUNCTION_FAILED;
}

CK_RV AllocMem (CK_VOID_PTR *P, CK_ULONG L)
{
  EFI_STATUS Status = gBS->AllocatePool (EfiBootServicesData, L, P);

//DEBUG ((EFI_D_ERROR, "AllocMem(): L = %d, P = %p\n", L, *P));
  return MapErr (Status);
//  return MapErr (gBS->AllocatePool (EfiBootServicesData, L, P));
}

CK_RV FreeMem (CK_VOID_PTR P)
{
//DEBUG ((EFI_D_ERROR, "FreeMem(): P = %p\n", P));
  return MapErr (gBS->FreePool (P));
}

static VOID InitializePath (ASN1_OCTET_STRING_VAL *V)
{
  V->Val = NULL_PTR;
  V->Len = 0;
}

static VOID InitializePKCS15Data (PKCS15_DATA *Data)
{
  CK_ULONG I;

  /* FIXME: find a way to get rid of gcc 'initializer element is not constant'
            error and make it static */
#ifdef _MSC_VER
  ASN1_TYPE_DEF *Defs[PKCS15_OBJECTS_CHOICE_ITEM_ORD_ITEMS];
  
Defs[PKCS15_OBJECTS_PRIVATE_KEYS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_PrivateKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_PUBLIC_KEYS_ORD]          =
      &PathOrObjectsNameChoice (PKCS15_PublicKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD]  =
      &PathOrObjectsNameChoice (PKCS15_PublicKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_SECRET_KEYS_ORD]          =
      &PathOrObjectsNameChoice (PKCS15_SecretKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_CERTIFICATES_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD] =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD]  =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_DATA_OBJECTS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_DataType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
Defs[PKCS15_OBJECTS_AUTH_OBJECTS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_AuthenticationType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD];
#else /* _MSC_VER */
  ASN1_TYPE_DEF CONST *Defs[] = {
    [PKCS15_OBJECTS_PRIVATE_KEYS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_PrivateKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_PUBLIC_KEYS_ORD]          =
      &PathOrObjectsNameChoice (PKCS15_PublicKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD]  =
      &PathOrObjectsNameChoice (PKCS15_PublicKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_SECRET_KEYS_ORD]          =
      &PathOrObjectsNameChoice (PKCS15_SecretKeyType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_CERTIFICATES_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD] =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD]  =
      &PathOrObjectsNameChoice (PKCS15_CertificateType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_DATA_OBJECTS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_DataType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD],
    [PKCS15_OBJECTS_AUTH_OBJECTS_ORD]         =
      &PathOrObjectsNameChoice (PKCS15_AuthenticationType).
        Item[PATH_OR_OBJECTS_OBJECTS_ORD]
  };
#endif /* _MSC_VER */

  InitializePath (&Data->AppPath);
  InitializePath (&Data->TokenInfoPath);
  InitializePath (&Data->ODFPath);

  for (I = 0; I < ARRAY_ITEMS (Data->Objects); I++) {
    CK_ULONG J;

    for (J = 0; J < ARRAY_ITEMS (Data->Objects[I]); J++) {
      Data->Objects[I][J].Def      = Defs[I];
      Data->Objects[I][J].Decoded  = CK_FALSE;
      Data->Objects[I][J].ASN1.Val = NULL_PTR;
      Data->Objects[I][J].ASN1.Len = 0;
    }
  }
}

static VOID FreePath (ASN1_OCTET_STRING_VAL *V)
{
  if (V->Val != NULL_PTR) {
    FreeMem (V->Val);

    InitializePath (V);
  }
}

static void FreePKCS15Data (PKCS15_DATA *Data)
{
  CK_ULONG I;

  for (I = ARRAY_ITEMS (Data->Objects); I > 0; I--) {
    CK_ULONG J;

    for (J = ARRAY_ITEMS (Data->Objects[I - 1]); J > 0; J--) {
      FreeASN1 (&Data->Objects[I - 1][J - 1]);
    }
  }

  FreePath (&Data->ODFPath);
  FreePath (&Data->TokenInfoPath);
  FreePath (&Data->AppPath);
}

static CK_RV OpenProtocol (SMART_CARD_PROTOCOL **Iface, EFI_HANDLE Handle)
{
  return MapErr (gBS->OpenProtocol (
                        Handle,
                        &gSmartCardProtocolGuid,
                        (VOID **)Iface,
                        Handle,
                        NULL,
                        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
                        ));
}

static VOID CloseProtocol (EFI_HANDLE Handle)
{
  // 0xAA55AA55 - special case: fake handle
  if (Handle && Handle != (EFI_HANDLE)(UINTN)0xAA55AA55) { 
    gBS->CloseProtocol (Handle, &gSmartCardProtocolGuid, Handle, NULL);
  }
}

static CK_RV FindHandles (CK_VOID_PTR **H, CK_ULONG *N)
{
  UINTN      Num     = 0;
  EFI_HANDLE *Handle = NULL;

  /* Find all the handles, which SMART_CARD_PROTOCOL is attached to */
  CK_RV rv = MapErr (gBS->LocateHandleBuffer (
                            ByProtocol,
                            &gSmartCardProtocolGuid,
                            NULL,
                            &Num,
                            &Handle
                            ));

  if (rv == CKR_OK) {
    *N = Num;
    *H = Handle;
  }

  return rv;
}

static VOID InitializeInfo (CK_TOKEN_INFO_PTR Info)
{
  /* Blank pad */
  SetMem (Info->label, sizeof Info->label, ' ');
  SetMem (Info->manufacturerID, sizeof Info->manufacturerID, ' ');
  SetMem (Info->model, sizeof Info->model, ' ');
  SetMem (Info->serialNumber, sizeof Info->serialNumber, ' ');

  /* Set the flags uninitialized here; should be initialized later */
  Info->flags = 0;

  /* It is designed to have at most one session */
  Info->ulMaxSessionCount   = 1;
  Info->ulMaxRwSessionCount = 1;

  /* Values that actual just after initialization */
  Info->ulSessionCount     = 0;
  Info->ulRwSessionCount   = 0;

  /* Set uninitialized; should be initialized later from AODF */
  Info->ulMinPinLen = 0;
  Info->ulMaxPinLen = 0;

  /* This info is left unsupported as PKCS#11 allows it to be */
  Info->ulTotalPublicMemory  = (CK_ULONG)-1;
  Info->ulFreePublicMemory   = (CK_ULONG)-1;
  Info->ulTotalPrivateMemory = (CK_ULONG)-1;
  Info->ulFreePrivateMemory  = (CK_ULONG)-1;

  /* Hardware/firmware versions should be initialized from TokenInfo */
  Info->hardwareVersion.major  = 0;
  Info->hardwareVersion.minor  = 0;
  Info->firmwareVersion.major  = 0;
  Info->firmwareVersion.minor  = 0;

  /* Zero padded */
  SetMem (Info->utcTime, sizeof Info->utcTime, 0);
}

static CK_RV FreeTemplate (PKCS11_TEMPLATE *pTmpl)
{
  /* Free template memory */
  if (pTmpl->pTemplate != NULL_PTR) {
    CK_RV rv = FreeMem (pTmpl->pTemplate);

    if (rv != CKR_OK) {
      return rv;
    }

    pTmpl->pTemplate = NULL_PTR;
    pTmpl->ulCount   = 0;
  }

  pTmpl->Initialized = CK_FALSE;
  pTmpl->SearchType  = ANY_OBJECT;
  pTmpl->ObjOrd      = 0;
  pTmpl->ObjType     = SESSION_OBJECT;
  pTmpl->ItemOrd     = 0;
  return CKR_OK;
}

static CK_RV SetAppPath (PKCS15_DATA *Data)
{
  CK_RV                 rv       = CKR_OK;
  ASN1_OCTET_STRING_VAL *AppPath = &Data->AppPath;

  if (Data->AppPath.Val == NULL_PTR) {
    CK_BYTE AP[] = ASN1_PKCS15_APP_PATH_DEFAULT_VALUE;

    if ((rv = AllocMem ((CK_VOID_PTR_PTR)&AppPath->Val, sizeof AP)) == CKR_OK) {
      CopyMem (AppPath->Val, AP, AppPath->Len = sizeof AP);
    }
  }

  return rv;
}

static CK_RV SetTokenInfoPath (PKCS15_DATA *Data)
{
  CK_RV                 rv             = CKR_OK;
  ASN1_OCTET_STRING_VAL *TokenInfoPath = &Data->TokenInfoPath;
  ASN1_OCTET_STRING_VAL *AppPath       = &Data->AppPath;

  if (TokenInfoPath->Val == NULL_PTR) {
    CK_BYTE TI[] = ASN1_PKCS15_TI_NAME_DEFAULT_VALUE;

    if (AppPath->Val != NULL_PTR) {
      if ((rv = AllocMem (
                  (CK_VOID_PTR_PTR)&TokenInfoPath->Val,
                  AppPath->Len + sizeof TI
                  )) == CKR_OK) {
        CopyMem (TokenInfoPath->Val, AppPath->Val, AppPath->Len);
        CopyMem (TokenInfoPath->Val + AppPath->Len, TI, sizeof TI);
        TokenInfoPath->Len = AppPath->Len + sizeof TI;
      }
    } else {
      rv = CKR_FUNCTION_FAILED;
    }
  }

  return rv;
}

static CK_RV SetODFPath (PKCS15_DATA *Data)
{
  CK_RV                 rv        = CKR_OK;
  ASN1_OCTET_STRING_VAL *ODFPath  = &Data->ODFPath;
  ASN1_OCTET_STRING_VAL *AppPath  = &Data->AppPath;

  if (ODFPath->Val == NULL_PTR) {
    CK_BYTE ODF[] = PKCS15_ODF_NAME_DEFAULT_VALUE;

    if (AppPath->Val != NULL_PTR) {
      if ((rv = AllocMem (
                  (CK_VOID_PTR_PTR)&ODFPath->Val,
                  AppPath->Len + sizeof ODF
                  )) == CKR_OK) {
        CopyMem (ODFPath->Val, AppPath->Val, AppPath->Len);
        CopyMem (ODFPath->Val + AppPath->Len, ODF, sizeof ODF);

        ODFPath->Len = AppPath->Len + sizeof ODF;
      }
    } else {
      rv = CKR_FUNCTION_FAILED;
    }
  }

  return rv;
}

static CK_RV FindSlotBySession (CK_ULONG *CONST I, CK_SESSION_HANDLE hSession)
{
  /* If a session handle value is out of range */
  if (hSession == CK_INVALID_HANDLE || hSession >= Cryptoki.NextSessionHandle) {
    return CKR_SESSION_HANDLE_INVALID;
  }

  /* Find a slot that has the specified session */
  for (*I = 0; *I < Cryptoki.SlotNum; ++*I) {
    if (Cryptoki.Slots[*I].Session.Handle == hSession) {
      return CKR_OK;
    }
  }

  /* The slot is NOT found, the session was used previously and now is closed */
  return CKR_SESSION_CLOSED;
}

static CK_RV ReadTokenFile (
  SMART_CARD_PROTOCOL *Iface,
  CK_BYTE_PTR         Path,
  CK_ULONG            PathLen,

  /* On success MUST be freed via FreeMem() by a caller (after use)!!! */
  CK_BYTE_PTR  *Data,
  CK_ULONG_PTR Len
  )
{
  UINT8         Info[TRANS_MAX_LEN];
  UINTN         InfoLen  = sizeof Info;

  FFM_INITIALIZE_AUTO (
    ASN1_TYPE_VAL,
    Fci,
    2,
    (
      .Def     = &ISO7816_4_FCI,
      .Decoded = CK_FALSE
    )
  );

  ASN1_TYPE_VAL *V       = &Fci;
  CK_RV         rv       = CKR_OK;
  CK_BBOOL      AbsPath  = CK_FALSE;
  CK_BYTE       MFPath[] = PKCS15_MF_PATH_DEFAULT_VALUE;
  VOID          *P;

  *Len = 0;

  if (Path == NULL_PTR || PathLen < sizeof MFPath ||
      Data == NULL_PTR || Len == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Find out whether the path is absolute or not and perform adjustments */
  if (CompareMem (Path, MFPath, sizeof MFPath) == 0) {
    Path    += sizeof MFPath;
    PathLen -= sizeof MFPath;
    AbsPath  = CK_TRUE;
  }

  if ((rv = MapErr ((*Iface->SelectFileByPath) (
                               Iface,
                               Path,
                               PathLen,
                               AbsPath,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
    return rv;
  }

  if (InfoLen == 0) {
    return rv;
  }

  if ((rv = Decode (&Fci, Info, InfoLen)) != CKR_OK) {
    return rv;
  }

  do { /* "try/finally emulation" try block starts here (for FreeASN1()) */
    /* Get the data length field of the FCI structure */
    if ((rv = GetValByOrd (&V, FCI_DATA_LEN_ORD)) != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "Failed to get data length\n"));
      break; /* "try/finally emulation" throw (raise) statement */
    }

    /* Data length field ASN1 object should have appropriate attributes */
    if (V                           == NULL_PTR               ||
        V->Def->Type                != ASN1_PRIM_CLASS_TYPE   ||
        V->Def->TypeRef.Prim->Type != ASN1_INTEGER_PRIM_TYPE) {
      rv = CKR_FUNCTION_FAILED;
      break; /* "try/finally emulation" throw (raise) statement */
    }

    /* Whether the file length is valid in the FCI structure? */
    if (V->TypeVal.Prim.Integer.Long ||
        V->TypeVal.Prim.Integer.Val.Val > MAX_OFFSET + TRANS_MAX_LEN) {
      DEBUG ((
        EFI_D_ERROR,
        "File length value is invalid in the file FCI structure\n"
        ));

      rv = CKR_DEVICE_ERROR;
      break; /* "try/finally emulation" throw (raise) statement */
    }

    /* Allocate memory for binary data */
    if ((rv = MapErr (gBS->AllocatePool (
                             EfiBootServicesData,
                             V->TypeVal.Prim.Integer.Val.Val,
                             &P
                             ))) != CKR_OK) {
      break; /* "try/finally emulation" throw (raise) statement */
    }

    if ((rv = MapErr ((*Iface->ReadBinary) (
                                 Iface,
                                 P,
                                 0,
                                 V->TypeVal.Prim.Integer.Val.Val
                                 ))) != CKR_OK) {
      FreeMem (P);
      break; /* "try/finally emulation" throw (raise) statement */
    }

    *Data = P;
    *Len  = V->TypeVal.Prim.Integer.Val.Val;
  } while (CK_FALSE); /* "try/finally emulation" finally block starts below */

  FreeASN1 (&Fci);
  return rv;
}

static CK_RV AcquireDir (CCID_SLOT *Slot)
{
  /* "Registered Application Provider Identifier": PKCS-15 v1.1, 5.7.2 */
  CK_BYTE         RAPI[]    = PKCS15_RAPI_DEFAULT_VALUE;

  /* Model value for PKCS-15 application */
  CK_UTF8CHAR     Model[]   = PKCS15_MODEL_NAME_DEFAULT_VALUE;

  /* Application DIR: PKCS-15 v1.1, 5.6 */
  CK_BYTE       DIRPath[] = PKCS15_DIR_PATH_DEFAULT_VALUE;
  CK_BYTE_PTR   Data      = NULL_PTR;
  CK_ULONG      Len       = 0;

  FFM_INITIALIZE_AUTO (
    ASN1_TYPE_VAL,
    DIRRecord,
    2,
    (
      .Def     = &PKCS15_DIRRecord,
      .Decoded = CK_FALSE
    )
  );

  ASN1_TYPE_VAL *V        = &DIRRecord;
  CK_RV          rv;

  if ((rv = ReadTokenFile (
              Slot->Interface,
              DIRPath,
              sizeof DIRPath,
              &Data,
              &Len)) != CKR_OK) {
    return rv;
  }

  if (Len == 0) {
    return rv;
  }

  do { /* "try/finally emulation" try block starts here */
    if ((rv = Decode (&DIRRecord, Data, Len)) != CKR_OK) {
      break; /* "try/finally emulation" throw (raise) statement */
    }

    do { /* "try/finally emulation" try block starts here */
      CK_ULONG Len;

      if ((rv = GetValByOrd (&V, DIRRECORD_AID_ORD)) != CKR_OK) {
        break;
      }

      /* App ID field ASN1 object should have appropriate attributes */
      if (V                           == NULL_PTR                    ||
          V->Def->Type                != ASN1_PRIM_CLASS_TYPE        ||
          V->Def->TypeRef.Prim->Type  != ASN1_OCTET_STRING_PRIM_TYPE) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if ((Len = V->TypeVal.Prim.OctetString.Len) < sizeof RAPI ||
          CompareMem (V->TypeVal.Prim.OctetString.Val, RAPI, sizeof RAPI) != 0) {
        DEBUG ((EFI_D_ERROR, "PKCS#15 application is NOT found on the token\n"));
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      CopyMem (Slot->TokenInfo.model, Model, sizeof Model);

      V = &DIRRecord;

      if ((rv = GetValByOrd (&V, DIRRECORD_LABEL_ORD)) != CKR_OK) {
        break;
      }

      if (V != NULL_PTR) { /* If the optional label field was specified */
        if (V->Def->Type                   != ASN1_PRIM_CLASS_TYPE       ||
            V->Def->TypeRef.Prim->Type     != ASN1_UTF8_STRING_PRIM_TYPE ||
            (Len = V->TypeVal.Prim.Utf8String.Len) == 0) {
          rv = CKR_FUNCTION_FAILED;
          break; /* "try/finally emulation" throw (raise) statement */
        }

        CopyMem (
          Slot->TokenInfo.label,
          V->TypeVal.Prim.Utf8String.Val,
          Len < sizeof Slot->TokenInfo.label ? Len : sizeof Slot->TokenInfo.label
          );

        if (Len < sizeof Slot->TokenInfo.label) {
          SetMem (
            Slot->TokenInfo.label + Len,
            sizeof Slot->TokenInfo.label - Len,
            ' '
            );
        }
      }

      V = &DIRRecord;

      if ((rv = GetValByOrd (&V, DIRRECORD_PATH_ORD)) != CKR_OK) {
        break;
      }

      if (V                               == NULL_PTR                    ||
          V->Def->Type                    != ASN1_PRIM_CLASS_TYPE        ||
          V->Def->TypeRef.Prim->Type      != ASN1_OCTET_STRING_PRIM_TYPE ||
          (Len = V->TypeVal.Prim.OctetString.Len) == 0) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      Slot->Data.AppPath = V->TypeVal.Prim.OctetString;
      V->Decoded         = CK_FALSE;
    } while (CK_FALSE); /* "try/finally emulation" finally block starts below */

    FreeASN1 (&DIRRecord);
  } while (CK_FALSE); /* "try/finally emulation" finally block starts below */

  FreeMem (Data);
  return rv;
}

static CK_RV AcquireTokenInfo (CCID_SLOT *Slot)
{
  /* PKCS#15 v1.1, paragraph 6.9, TokenFlags */
  enum { readonly, loginRequired, prnGeneration, eidCompliant };

  CK_BYTE_PTR    Data;
  CK_ULONG       Len;
  CK_RV          rv;

  if ((rv = ReadTokenFile (
              Slot->Interface,
              Slot->Data.TokenInfoPath.Val,
              Slot->Data.TokenInfoPath.Len,
              &Data,
              &Len
              )) != CKR_OK) {
    return rv;
  }

  if (Len == 0) {
    return rv;
  }

  do { /* "try/finally emulation" try block starts here */
    FFM_INITIALIZE_AUTO (
      ASN1_TYPE_VAL,
      TokenInfo,
      2,
      (
        .Def     = &PKCS15_TokenInfo,
        .Decoded = CK_FALSE
      )
    );

    ASN1_TYPE_VAL *V        = &TokenInfo;

    if ((rv = Decode (&TokenInfo, Data, Len)) != CKR_OK) {
      break; /* "try/finally emulation" throw (raise) statement */
    }

    do { /* "try/finally emulation" try block starts here */
      CK_ULONG                 I;
      static CK_UTF8CHAR CONST Xlat[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
      };

      if ((rv = GetValByOrd (&V, TOKEN_INFO_SERIAL_NUMBER_ORD)) != CKR_OK) {
        DEBUG ((EFI_D_ERROR, "Serial Number is NOT found on the TokenInfo\n"));
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if (V                               == NULL_PTR                    ||
          V->Def->Type                    != ASN1_PRIM_CLASS_TYPE        ||
          V->Def->TypeRef.Prim->Type      != ASN1_OCTET_STRING_PRIM_TYPE ||
          (Len = V->TypeVal.Prim.OctetString.Len) == 0) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      /* Convert binary represented octets into textually represented ones */
      for (I = 0; I < V->TypeVal.Prim.OctetString.Len; I++) {
        Slot->TokenInfo.serialNumber[2 * I + 0] =
          Xlat[V->TypeVal.Prim.OctetString.Val[I] / sizeof Xlat % sizeof Xlat];
        Slot->TokenInfo.serialNumber[2 * I + 1] =
          Xlat[V->TypeVal.Prim.OctetString.Val[I] % sizeof Xlat];
      }

      V = &TokenInfo;

      if ((rv = GetValByOrd (&V, TOKEN_INFO_MANUFACTURER_ID_ORD)) != CKR_OK) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if (V != NULL_PTR) { /* If the optional label field was specified */
        if (V->Def->Type                   != ASN1_PRIM_CLASS_TYPE       ||
            V->Def->TypeRef.Prim->Type     != ASN1_UTF8_STRING_PRIM_TYPE ||
            (Len = V->TypeVal.Prim.Utf8String.Len) == 0                          ||
            Len                            >  sizeof Slot->TokenInfo.
                                                       manufacturerID) {
          rv = CKR_FUNCTION_FAILED;
          break; /* "try/finally emulation" throw (raise) statement */
        }

        CopyMem (
          Slot->TokenInfo.manufacturerID,
          V->TypeVal.Prim.Utf8String.Val,
          V->TypeVal.Prim.Utf8String.Len
          );

        if(V->TypeVal.Prim.Utf8String.Len < sizeof Slot->TokenInfo.manufacturerID) {
          SetMem (
            Slot->TokenInfo.manufacturerID + V->TypeVal.Prim.Utf8String.Len,
            sizeof Slot->TokenInfo.manufacturerID - V->TypeVal.Prim.Utf8String.Len,
            ' '
            );
        }
      }

      V = &TokenInfo;

      if ((rv = GetValByOrd (&V, TOKEN_INFO_LABEL_ORD)) != CKR_OK) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if (V != NULL_PTR) { /* If the optional label field was specified */
        if (V->Def->Type                   != ASN1_PRIM_CLASS_TYPE       ||
            V->Def->TypeRef.Prim->Type     != ASN1_UTF8_STRING_PRIM_TYPE ||
            (Len = V->TypeVal.Prim.Utf8String.Len) == 0                          ||
            Len                            >  sizeof Slot->TokenInfo.label) {
          rv = CKR_FUNCTION_FAILED;
          break; /* "try/finally emulation" throw (raise) statement */
        }

        CopyMem (
          Slot->TokenInfo.label,
          V->TypeVal.Prim.Utf8String.Val,
          V->TypeVal.Prim.Utf8String.Len
          );

        if(V->TypeVal.Prim.Utf8String.Len < sizeof Slot->TokenInfo.label) {
          SetMem (
            Slot->TokenInfo.label + V->TypeVal.Prim.Utf8String.Len,
            sizeof Slot->TokenInfo.label - V->TypeVal.Prim.Utf8String.Len,
            ' '
            );
        }
      }

      V = &TokenInfo;

      if ((rv = GetValByOrd (&V, TOKEN_INFO_TOKEN_FLAGS_ORD)) != CKR_OK) {
        DEBUG ((EFI_D_ERROR, "Token Flags field is NOT found on the TokenInfo\n"));
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if (V                          == NULL_PTR                    ||
          V->Def->Type               != ASN1_PRIM_CLASS_TYPE        ||
          V->Def->TypeRef.Prim->Type != ASN1_BIT_STRING_PRIM_TYPE) {
        rv = CKR_FUNCTION_FAILED;
        break; /* "try/finally emulation" throw (raise) statement */
      }

      if (V->TypeVal.Prim.BitString.Val[readonly]) {
        Slot->TokenInfo.flags |= CKF_WRITE_PROTECTED;
      }

      if (V->TypeVal.Prim.BitString.Val[loginRequired]) {
        Slot->TokenInfo.flags |= CKF_LOGIN_REQUIRED;
      }

      if (V->TypeVal.Prim.BitString.Val[prnGeneration]) {
        Slot->TokenInfo.flags |= CKF_RNG;
      }
    } while (CK_FALSE); /* "try/finally emulation" finally block starts below */

    FreeASN1 (&TokenInfo);
  } while (CK_FALSE); /* "try/finally emulation" finally block starts below */

  FreeMem (Data);
  return rv;
}

CK_BYTE_PTR ParseCertfile( CK_BYTE_PTR Data,CK_ULONG_PTR Len)
{
  CK_BYTE_PTR Data23          = NULL_PTR;
  int i23;
  char find = 0;
  Data23 = Data;
  Data23+=2;
  *Len =0;
  *Len = (*Data23<<8);
  Data23++;
  *Len+=*Data23;
  LOG((EFI_D_ERROR, " len= %X\n",*Len));
  Data23+=2;
   
  for(i23=0;i23<*Len;i23++)
  { 
	  if(*Data23==0x30)
	  {
		  Data23++;
		  if(*Data23==0x82){
			  find++;
			  Data23+=2;		  
		  }
		  else
			  find = 0;
	  }
	  else
	   Data23++;
	  
	  if(find == 2){
		  find = 0;
		  //LOG((EFI_D_ERROR, " i23= %d\n",i23));
		  break;
	  }
  }
 
  Data23-=5;
  *Len =0;
  *Len = (*Data23<<8);
  Data23++;
  *Len+=*Data23;
  *Len+=4;
  Data23-=3;  
  LOG((EFI_D_ERROR, " len= %X\n",*Len));
 
  return Data23;
}

CK_RV SetRSF(CCID_SLOT *Slot)
{
	CK_RV       rv              = CKR_OK;
	UINT8         Info[TRANS_MAX_LEN];
    UINTN         InfoLen  = sizeof Info;
	//CK_BYTE PubKeyPath[]		   = {0x10,0x00,0x10,0x00,0x60,0x01};
	CK_BYTE XCAPubKeyPath[]        = {0x10,0x00,0x10,0x00,0x60,0x01,0x00,0x01};
	CK_BYTE CSPPubKeyPath[]        = {0x10,0x00,0x10,0x00,0x60,0x01,0x00,0x02};
	/*
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               PubKeyPath,
                               sizeof PubKeyPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
			return rv;
		}
	*/
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               XCAPubKeyPath,
                               sizeof XCAPubKeyPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               CSPPubKeyPath,
                               sizeof CSPPubKeyPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
			return rv;
		}
		Slot->Interface->RSFRef=0x02;
		Slot->Session.KeyRef=0x02;
		return rv;
	}
	Slot->Interface->RSFRef=0x01;
	Slot->Session.KeyRef=0x01;
	return rv;
}

CK_RV CSPINIT(CCID_SLOT *Slot)
{
	CK_RV       rv              = CKR_OK;
	CK_BYTE_PTR Data23          = NULL_PTR;
	CK_BYTE_PTR Data            = NULL_PTR;
	CK_ULONG    Len             = 0;
	UINT8         Info[TRANS_MAX_LEN];
    UINTN         InfoLen  = sizeof Info;
	
	CK_BYTE AppPath[]           = {0x50,0x00}; 
	CK_BYTE ODFPath[]           = {0x50,0x00,0x50,0x31};
	CK_BYTE XcaCertPath[]       = {0x50,0x00,0x03,0x00};
	CK_BYTE CspCertPath[]       = {0x3f,0x00,0x10,0x00,0x10,0x04,0x00,0x02,0x00,0x03};
	CK_BYTE PubKeyPath[]        = {0x3f,0x00,0x10,0x00,0x10,0x00,0x60,0x01,0x00,0x02};
	CK_BYTE XcaPubKeyPath[]     = {0x50,0x00,0x02,0x00};
	CK_BYTE PrivKeypointerPath[]= {0x50,0x00,0x60,0x02};
	CK_BYTE PubKeypointerPath[] = {0x50,0x00,0x60,0x01};
	CK_BYTE CertpointerPath[]   = {0x50,0x00,0x60,0x04};

	CK_BYTE XcaPubKeyFCP[]      = {0x6F ,0x1D ,0x80 ,0x02 ,0x00 ,0x42 ,0x82 ,0x02 ,0x01 ,0x00 ,0x83 ,0x02 ,0x02 ,0x00 ,0x86 ,0x0F ,0x43 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00};//увеличь потом до 514
	CK_BYTE PubKeypointerFCP[]  = {0x6F ,0x1D ,0x80 ,0x02 ,0x08 ,0x00 ,0x82 ,0x02 ,0x01 ,0x00 ,0x83 ,0x02 ,0x60 ,0x01 ,0x86 ,0x0F ,0x43 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00};
	CK_BYTE PrivKeypointerFCP[] = {0x6F ,0x1D ,0x80 ,0x02 ,0x08 ,0x00 ,0x82 ,0x02 ,0x01 ,0x00 ,0x83 ,0x02 ,0x60 ,0x02 ,0x86 ,0x0F ,0x43 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00};
	CK_BYTE XcaCertFCP[]        = {0x6F ,0x1D ,0x80 ,0x02 ,0x03 ,0x5e ,0x82 ,0x02 ,0x01 ,0x00 ,0x83 ,0x02 ,0x03 ,0x00 ,0x86 ,0x0F ,0x43 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00};
	CK_BYTE CertpointerFCP[]    = {0x6F ,0x1D ,0x80 ,0x02 ,0x08 ,0x00 ,0x82 ,0x02 ,0x01 ,0x00 ,0x83 ,0x02 ,0x60 ,0x04 ,0x86 ,0x0F ,0x43 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00};

	CK_BYTE PubKeypointerData[] = {0xA3 ,0x38 ,0x30 ,0x0E ,0x0C ,0x05 ,0x61 ,0x64 ,0x6D ,0x69 ,0x6E ,0x03 ,0x02 ,0x06 ,0x40 ,0x04 ,0x01 ,0x02 ,0x30 ,0x0D ,0x04 ,0x01 ,0x00 ,0x03 ,0x02 ,0x05 ,0x20 ,0x01 ,0x01 ,0x00 ,0x02,
		                           0x01 ,0x00 ,0xA0 ,0x00 ,0xA1 ,0x15 ,0x30 ,0x13 ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F ,0x00 ,0x50 ,0x00 ,0x02 ,0x00 ,0x02 ,0x01 ,0x01 ,0x02 ,0x01 ,0x00 ,0x02 ,0x01 ,0x00};
	CK_BYTE PrivKeypointerData[]= {0xA3 ,0x39 ,0x30 ,0x0E ,0x0C ,0x05 ,0x61 ,0x64 ,0x6D ,0x69 ,0x6E ,0x03 ,0x02 ,0x06 ,0xC0 ,0x04 ,0x01 ,0x02 ,0x30 ,0x0A ,0x04 ,0x01 ,0x00 ,0x03 ,0x02 ,0x02 ,0x64 ,0x02 ,0x01 ,0x01 ,0xA0, 
		                           0x00 ,0xA1 ,0x19 ,0x30 ,0x17 ,0x30 ,0x0C ,0x04 ,0x0A ,0x3F ,0x00 ,0x10 ,0x00 ,0x10 ,0x00 ,0x60 ,0x02 ,0x00 ,0x02 ,0x02 ,0x01 ,0x01 ,0x02 ,0x01 ,0x00 ,0x02 ,0x01 ,0x00};
	CK_BYTE CertpointerData[]   = {0x30 ,0x20 ,0x30 ,0x0B ,0x0C ,0x05 ,0x61 ,0x64 ,0x6D ,0x69 ,0x6E ,0x03 ,0x02 ,0x06 ,0x40 ,0x30 ,0x03 ,0x04 ,0x01 ,0x00 ,0xA1 ,0x0C ,0x30 ,0x0A ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F ,0x00 ,0x50,
								   0x00 ,0x03 ,0x00}; 
	CK_BYTE ODFData[]			= {0xA8 ,0x0A ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F ,0x00 ,0x50 ,0x00 ,0x60 ,0x05 ,0xA0 ,0x0A ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F ,0x00 ,0x50 ,0x00 ,0x60 ,0x02 ,0xA1 ,0x0A ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F, 
		                           0x00 ,0x50 ,0x00 ,0x60 ,0x01 ,0xA4 ,0x0A ,0x30 ,0x08 ,0x04 ,0x06 ,0x3F ,0x00 ,0x50 ,0x00 ,0x60 ,0x04 , 
								   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	//создали файл с публичны ключом
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               AppPath,
							   sizeof AppPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	
	if((rv = MapErr ((Slot->Interface->CreateFile) (  
                               Slot->Interface,
                               XcaPubKeyFCP,
							   sizeof XcaPubKeyFCP
                               ))) != CKR_OK) {
		return rv;
	}

	if ((rv = ReadTokenFile (
              Slot->Interface,
              PubKeyPath,
              sizeof PubKeyPath,
              &Data,
              &Len
              )) != CKR_OK) {
    return rv;
  }

	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               XcaPubKeyPath,
                               sizeof XcaPubKeyPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	/* Allocate memory for binary data */
    if ((rv = MapErr (gBS->AllocatePool (
                             EfiBootServicesData,
                             Len+2,
                             &Data23
                             ))) != CKR_OK) {
      return rv; /* "try/finally emulation" throw (raise) statement */
    }

	Data23[0] = 0x04;
	Data23[1] = (CK_BYTE)Len;
	CopyMem (&Data23[2],Data,Len);

	if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   Data23,
							   Len+2
                               ))) != CKR_OK) {
								  
		return rv;
	
    }
	FreeMem (Data23);
	FreeMem (Data);
    Data = NULL_PTR;
    Data23 = NULL_PTR;
    Len = 0;
	//создали указатель на публичный ключ
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               AppPath,
							   sizeof AppPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}
	if((rv = MapErr ((Slot->Interface->CreateFile) (  
                               Slot->Interface,
                               PubKeypointerFCP,
							   sizeof PubKeypointerFCP
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               PubKeypointerPath,
                               sizeof PubKeypointerPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   PubKeypointerData,
							   sizeof PubKeypointerData
                               ))) != CKR_OK) {
								  
		return rv;
	
    }
	//создали указатель на приватный ключ
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               AppPath,
							   sizeof AppPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->CreateFile) (  
                               Slot->Interface,
                               PrivKeypointerFCP,
							   sizeof PrivKeypointerFCP
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               PrivKeypointerPath,
                               sizeof PrivKeypointerPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   PrivKeypointerData,
							   sizeof PrivKeypointerData
                               ))) != CKR_OK) {
								  
		return rv;
	
    }
	//создали файл с сертификатом
	if ((rv = ReadTokenFile (
              Slot->Interface,
              CspCertPath,
              sizeof CspCertPath,
              &Data23,
              &Len
              )) != CKR_OK) {
    
	return rv;//csp файла нет. из прошлой проверки - нет xca, токен не инициализирован.
   }
	Data = ParseCertfile(Data23,&Len);//достали сертификат
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               AppPath,
							   sizeof AppPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}
	
	if((rv = MapErr ((Slot->Interface->CreateFile) (  
                               Slot->Interface,
                               XcaCertFCP,
							   sizeof XcaCertFCP
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               XcaCertPath,
                               sizeof XcaCertPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   Data,
							   Len
                               ))) != CKR_OK) {
								  
		return rv;
	
    }
	//создать ссылку на сертификат
	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               AppPath,
							   sizeof AppPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->CreateFile) (  
                               Slot->Interface,
                               CertpointerFCP,
							   sizeof CertpointerFCP
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               CertpointerPath,
                               sizeof CertpointerPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}

	if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   CertpointerData,
							   sizeof CertpointerData
                               ))) != CKR_OK) {
								  
		return rv;
	
    }

  FreeMem (Data23);
  Data = NULL_PTR;
  Data23 = NULL_PTR;
  Len = 0;
  //записали в файл указатели на все вышесозданое
  if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               ODFPath,
                               sizeof ODFPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		return rv;
	}
  if((rv = MapErr ((Slot->Interface->WriteBinary) (
                               Slot->Interface,
							   ODFData,
							   sizeof ODFData
                               ))) != CKR_OK) {
								  
		return rv;
	
    }

  return rv;
}

static CK_RV AcquireAndParseODF (CCID_SLOT *Slot)
{
  /* PKCS#15 v1.1, paragraph 6.2 */
  CK_BYTE_PTR Data23          = NULL_PTR;
  //int i23;
  CK_BYTE_PTR Data            = NULL_PTR;
  CK_ULONG    Len             = 0;
  CK_RV       rv              = CKR_OK;
  CK_ULONG    I;
  UINT8         Info[TRANS_MAX_LEN];
  UINTN         InfoLen  = sizeof Info;
  CK_BYTE XcaCertPath[]       = {0x50,0x00,0x03,0x00};
  FFM_INITIALIZE_AUTO (
    ASN1_TYPE_VAL,
    PKCS15Objects,
    2,
    (
      .Def     = &PKCS15_PKCS15ObjectsSequenceOf,
      .Decoded = CK_FALSE
    )
  );

  if (Slot->Data.ODFPath.Val == NULL_PTR) {
    return CKR_FUNCTION_FAILED;
  }

  //СМОТРЮ 50 00 03 00
  if((rv = MapErr ((Slot->Interface->SelectFileByPath) (  
                               Slot->Interface,
                               XcaCertPath,
							   sizeof XcaCertPath,
                               CK_TRUE,
                               Info,
                               &InfoLen
                               ))) != CKR_OK) {
		 
		if((rv = CSPINIT(Slot)) != CKR_OK)
			 return rv;
	}

	
  if((rv = SetRSF(Slot)) != CKR_OK)
			 return rv;
  
    //LOG((EFI_D_ERROR, "Slot->Interface->RSFRef=%d\n",Slot->Interface->RSFRef));
	//LOG((EFI_D_ERROR, " Slot->Session->KeyRef=%d\n",Slot->Session.KeyRef));
	
  if ((rv = ReadTokenFile (
              Slot->Interface,
              Slot->Data.ODFPath.Val,
              Slot->Data.ODFPath.Len,
              &Data,
              &Len
              )) != CKR_OK) {
    return rv;
  }

  if (Len == 0) {
    return rv;
  }

  Data23 = Data;
  /*LOG((EFI_D_ERROR, " START!!!!\n"));
  for(i23=0;i23<Len;Data23++,i23++)
	LOG((EFI_D_ERROR, " 0x%X", *Data23));
  LOG((EFI_D_ERROR, " STOP!!!!\n"));*/
  /* ODF is to decode as SEQUENCE OF PKCS15Objects */
  rv = DecodePayload (&PKCS15Objects, Data, Len);
  FreeMem (Data);
  Data = NULL_PTR;
  Len  = 0;

  if (rv != CKR_OK) {
    goto Finalize;
  }

  /* Walk through the items of SEQUENCE OF PKCS15Objects */
  for (I = 0; I < PKCS15Objects.TypeVal.SequenceOf.Cnt; I++) {
    CK_ULONG      J;
    ASN1_TYPE_VAL *P = &PKCS15Objects.TypeVal.SequenceOf.Item[I];
    ASN1_TYPE_VAL *T; /* TypeAttributes */
    ASN1_TYPE_VAL *V; /* ObjectValue */
    ASN1_TYPE_VAL *W; /* Destination (SEQUENCE OF objects) */
    ASN1_TYPE_VAL *O; /* SEQUENCE OF objects, each is of a particular type */
    ASN1_TYPE_VAL *X; /* PathOrObjects */
    ASN1_TYPE_VAL *Y; /* Either 'path' or 'objects' */
    ASN1_TYPE_VAL *Z; /* Path type 'path' field (OCTET STRING) */

    /* Check whether the ASN.1 definition of 'PKCS15Objects' is well-formed */
    if (P->Def->Type                != ASN1_CHOICE_CLASS_TYPE &&
        P->Def->TypeRef.Choice->Cnt != PKCS15_OBJECTS_CHOICE_ITEM_ORD_ITEMS) {
      rv = CKR_FUNCTION_FAILED;
      goto Finalize;
    }

    /* Check the object type encoded in the 'PKCS15Objects' CHOICE */
    switch (P->TypeVal.Choice.Item->Ord) {
    case PKCS15_OBJECTS_PRIVATE_KEYS_ORD:
    case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
    case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
    case PKCS15_OBJECTS_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
      break; /* These objects will be decoded later */
    case PKCS15_OBJECTS_SECRET_KEYS_ORD:
    case PKCS15_OBJECTS_DATA_OBJECTS_ORD:
    case PKCS15_OBJECTS_AUTH_OBJECTS_ORD:
      continue; /* Decoding of these objects is skipped (NOT supported yet) */
    default:
      rv = CKR_GENERAL_ERROR; /* Should not get to here */
      goto Finalize;
    }

    /* A particular object type which to decode into/assign to */
    W = &Slot->Data.Objects[P->TypeVal.Choice.Item->Ord][TOKEN_OBJECT];
    X = &P->TypeVal.Choice.Item->Val; /* PathOrObjects */

    /* Check that type characteristics are the same of those of PathOrObjects */
    if (X->Def->Type                != ASN1_CHOICE_CLASS_TYPE &&
        X->Def->TypeRef.Choice->Cnt != PATH_OR_OBJECTS_CHOICE_ITEM_ORD_ITEMS) {
      rv = CKR_FUNCTION_FAILED;
      goto Finalize;
    }

    /* Y is either 'path' of 'objects' */
    Y = &X->TypeVal.Choice.Item->Val;

    /* Branch by means objects are encoded */
    switch (X->TypeVal.Choice.Item->Ord) {
    case PATH_OR_OBJECTS_PATH_ORD: /* Y is the 'path' */
      /* Check that type characteristics are proper for the Path type */
      if (!Y->Decoded                                 ||
          Y->Def->Type    != ASN1_SEQUENCE_CLASS_TYPE ||
          !(PATH_PATH_ORD <  Y->TypeVal.Sequence.Cnt)) {
        rv = CKR_FUNCTION_FAILED;
        goto Finalize;
      }

      /* Path type 'path' field */
      Z = &Y->TypeVal.Sequence.Item[PATH_PATH_ORD].Val;

      if (!Z->Decoded                                        ||
          Z->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
          Z->Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
        rv = CKR_FUNCTION_FAILED;
        goto Finalize;
      }
	  //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      /* Read objects from the 'path' */
      if ((rv = ReadTokenFile (
                  Slot->Interface,
                  Z->TypeVal.Prim.OctetString.Val,
                  Z->TypeVal.Prim.OctetString.Len,
                  &Data,
                  &Len
                  )) != CKR_OK) {
        goto Finalize;
      }

      /* Decode objects into W */
      rv = DecodePayload (W, Data, Len);
      FreeMem (Data);
      Data = NULL_PTR;
      Len  = 0;
      break;
    case PATH_OR_OBJECTS_OBJECTS_ORD: /* Y is the 'objects' */
      /* The objects are already decoded into Y, just reassign them to W */
#ifdef _MSC_VER
      CopyMem (W, Y, sizeof *Y);
#else /* _MSC_VER */
      *W   = *Y;
#endif /* _MSC_VER */

      /* Prevent from freeing of PKCS15Objects subobjects
         when calling FreeASN1(&PKCS15Objects) later */
      Y->Decoded = CK_FALSE; /* Note that 'W->Decoded' remains CK_TRUE */
      break;

    /* FIXME: These choices should be implemented */
#if 0    
    case PATH_OR_OBJECTS_INDIRECT_PROTECTED_ORD:
    case PATH_OR_OBJECTS_DIRECT_PROTECTED_ORD:
#endif
    default:
      DEBUG ((
        EFI_D_ERROR,
        "Only 'path' or 'objects' choices "
        "for 'PathOrObjects' ASN.1 encoding are supported\n"
        ));
      rv = CKR_FUNCTION_FAILED;
      goto Finalize;
    }

    if (!W->Decoded ||
        W->Def->Type != ASN1_SEQUENCE_OF_CLASS_TYPE) {
      rv = CKR_FUNCTION_FAILED;
      goto Finalize;
    }

    /* Check the object type encoded in the 'PKCS15Objects' CHOICE */
    switch (P->TypeVal.Choice.Item->Ord) {
    case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
    case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
    case PKCS15_OBJECTS_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:

      /* Iterate trough particular type objects */
      for (J = 0; J < W->TypeVal.SequenceOf.Cnt; J++) {
        CK_ULONG K;

        O = &W->TypeVal.SequenceOf.Item[J]; /* ObjectType (CHOICE) */

        if (!O->Decoded || O->Def->Type != ASN1_CHOICE_CLASS_TYPE) {
          rv = CKR_FUNCTION_FAILED;
          goto Finalize;
        }

        Y = &O->TypeVal.Choice.Item->Val; /* PKCS15Object (SEQUENCE) */

        if (!Y->Decoded                              ||
            Y->Def->Type != ASN1_SEQUENCE_CLASS_TYPE ||
            Y->Def->TypeRef.Sequence->Cnt !=
              PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS) {
          rv = CKR_FUNCTION_FAILED;
          goto Finalize;
        }

/* The outrageous Microsoft compiler 'thinks' it is very smart reporting
   'potentially uninitialized local variable' for T in '!T->Decoded'
   expression in if statement below, so damn on Microsoft because
   the C programming language is not for housewifes!
*/
#ifdef _MSC_VER
        T = NULL_PTR;
#endif

        /* Find the TypeAttributes filed of the PKCS15Object SEQUENCE */
        for (K = 0; K < Y->TypeVal.Sequence.Cnt; K++) {
          if (Y->TypeVal.Sequence.Item[K].Ord ==
                PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD) {
            T = &Y->TypeVal.Sequence.Item[K].Val; /* TypeAttributes */
            break;
          }
        }

        /* Check that TypeAttributes is found and it is a SEQUENCE */
        if (!(K < Y->TypeVal.Sequence.Cnt) ||
            !T->Decoded                    ||
            T->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
          rv = CKR_FUNCTION_FAILED;
          goto Finalize;
        }

        V = &T->TypeVal.Sequence.Item[0].Val; /* The 'value' field (ObjectValue) */

        /* Check that ObjectValue is of the CHOICE type and has the proper Cnt */
        if (!V->Decoded                                           ||
            V->Def->Type                != ASN1_CHOICE_CLASS_TYPE ||
            V->Def->TypeRef.Choice->Cnt != OBJECT_VALUE_CHOICE_ITEM_ORD_ITEMS) {
          rv = CKR_FUNCTION_FAILED;
          goto Finalize;
        }

        switch (V->TypeVal.Choice.Item->Ord) {
        case OBJECT_VALUE_INDIRECT_ORD:
          /* The 'indirect' field (ReferencedValue) */
          X = &V->TypeVal.Choice.Item->Val;

          /* Whether ReferencedValue is of the CHOICE type with the proper Cnt */
          if (!X->Decoded                                           ||
              X->Def->Type                != ASN1_CHOICE_CLASS_TYPE ||
              X->Def->TypeRef.Choice->Cnt !=
                REFERENCED_VALUE_CHOICE_ITEM_ORD_ITEMS) {
            rv = CKR_FUNCTION_FAILED;
            goto Finalize;
          }

          switch (X->TypeVal.Choice.Item->Ord) {
          case REFERENCED_VALUE_PATH_ORD:
            Y = &X->TypeVal.Choice.Item->Val; /* The 'path' field (Path) */

            /* Check that the 'path' filed of the Path type is the SEQUENCE */
            if (!Y->Decoded ||
                Y->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
              rv = CKR_FUNCTION_FAILED;
              goto Finalize;
            }

            Z = &Y->TypeVal.Sequence.Item[0].Val; /* 'path' (OCTET STRING) */

            /* Check that the 'path' filed is OCTET STRING */
            if (!Z->Decoded                          ||
                Z->Def->Type != ASN1_PRIM_CLASS_TYPE ||
                Z->Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
              rv = CKR_FUNCTION_FAILED;
              goto Finalize;
            }

            /* Read objects from the 'path' */
            if ((rv = ReadTokenFile (
                        Slot->Interface,
                        Z->TypeVal.Prim.OctetString.Val,
                        Z->TypeVal.Prim.OctetString.Len,
                        &Data,
                        &Len
                        )) != CKR_OK) {
              goto Finalize;
            }

            /* Free ASN.1 CHOICE instance with 'indirect' field */
            FreeASN1 (V);

            /* Create new ASN.1 CHOICE instance with 'direct' field */
            if ((rv = AddConsTypeItem (
                        &V->TypeVal.Choice.Item,
                        &X,
                        &V->Def->TypeRef.Choice->Item[OBJECT_VALUE_DIRECT_ORD],
                        0,
                        OBJECT_VALUE_DIRECT_ORD
                        )) != CKR_OK) {
              V->Decoded = CK_FALSE;
              return rv;
            }

            switch (P->TypeVal.Choice.Item->Ord) {
            case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
            case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
              if (X->Def->Type != ASN1_CHOICE_CLASS_TYPE) {
                INTERNAL_ERROR;
                return CKR_GENERAL_ERROR;
              }

              V->Decoded = CK_TRUE;

              switch (O->TypeVal.Choice.Item->Ord) {
              case PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY:
                if ((rv = AddConsTypeItem (
                            &X->TypeVal.Choice.Item,
                            &Y,
                            &X->Def->TypeRef.Choice->Item[RSA_PUBLIC_KEY_CHOICE_RAW],
                            0,
                            RSA_PUBLIC_KEY_CHOICE_RAW
                            )) != CKR_OK) {
                  X->Decoded = CK_FALSE;
                  return rv;
                }

                if (Y->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
                  INTERNAL_ERROR;
                  return CKR_GENERAL_ERROR;
                }

                X->Decoded = CK_TRUE;
                break;
              case PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY:
                if ((rv = AddConsTypeItem (
                            &X->TypeVal.Choice.Item,
                            &Y,
                            &X->Def->TypeRef.Choice->Item[KEA_PUBLIC_KEY_CHOICE_RAW],
                            0,
                            KEA_PUBLIC_KEY_CHOICE_RAW
                            )) != CKR_OK) {
                  X->Decoded = CK_FALSE;
                  return rv;
                }

                if (Y->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
                    Y->Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
                  INTERNAL_ERROR;
                  return CKR_GENERAL_ERROR;
                }

                X->Decoded = CK_TRUE;
                break;
              default:
                rv = CKR_FUNCTION_FAILED;
                goto Finalize;
              }

              rv = Decode (Y, Data, Len);
              break;
            case PKCS15_OBJECTS_CERTIFICATES_ORD:
            case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
            case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
              if (X->Def->Type == ASN1_SEQUENCE_CLASS_TYPE) {
                FFM_INITIALIZE_AUTO (
                  ASN1_TAG_INFO,
                  TI,
                  5,
                  (
                    .SucNum.Suc = CK_FALSE,
                    .Tag        = ASN1_NO_TAG,
                    .Pld        = Data,
                    .Len        = Len,
                    .ASN1       = Data
                  )
                );

                V->Decoded = CK_TRUE;

                if ((rv = GetTagInfo (&TI, TI.Pld, TI.Len)) == CKR_OK) {
                  rv = DecodeSubtype (X, &TI);
                }
              } else {
                INTERNAL_ERROR;
                return CKR_GENERAL_ERROR;
              }

              break;
            default: /* Should not get to here */
              rv = CKR_FUNCTION_FAILED;
              goto Finalize;
            }

            FreeMem (Data);
            Data = NULL_PTR;
            Len  = 0;

            if (rv != CKR_OK) {
              goto Finalize;
            }

            break;
          case REFERENCED_VALUE_URL_ORD:
            /* This is not implemented yet */
          default:
            rv = CKR_FUNCTION_FAILED;
            goto Finalize;
          }

          break;
        case OBJECT_VALUE_DIRECT_ORD:
          break; /* Nothing to do: object value is already decoded */
        case OBJECT_VALUE_INDIRECT_PROTECTED_ORD:
        case OBJECT_VALUE_DIRECT_PROTECTED_ORD:
          /* These are not implemented yet */
        default:
          rv = CKR_FUNCTION_FAILED; /* Should not get to here */
          goto Finalize;
        }
      }

      break;
    default:
      break;
    }
  }

Finalize:
  /* Decoded ODF ASN.1 representation is no longer needed */
  FreeASN1 (&PKCS15Objects);
  return rv;
}

static CK_RV ObjOrdsToHandle (
  CK_OBJECT_HANDLE *Handle,
  PKCS15_DATA      *Data,
  CK_ULONG         ObjOrd,  /* PKCS#15 Object type index (Key, Cert, etc) */
  OBJECT_TYPE      ObjType, /* SESSION/TOKEN object                       */
  CK_ULONG         ItemOrd  /* Item index within the SEQUENCE OF objects  */
  )
{
  if (ObjOrd < ARRAY_ITEMS (Data->Objects) &&
      ObjType < ARRAY_ITEMS (Data->Objects[ObjOrd])) {
    ASN1_TYPE_VAL *V = &Data->Objects[ObjOrd][ObjType];

    if (V->Def->Type != ASN1_SEQUENCE_OF_CLASS_TYPE                     ||
        !V->Decoded                                                     ||
        !(ItemOrd < V->TypeVal.SequenceOf.Cnt)                          ||
        V->TypeVal.SequenceOf.Item[ItemOrd].Def->Type != ASN1_CHOICE_CLASS_TYPE ||
        !V->TypeVal.SequenceOf.Item[ItemOrd].Decoded) {
      return CKR_GENERAL_ERROR;
    }
  } else {
    return CKR_GENERAL_ERROR;
  }

  /* The formula is: Handle = (ItemOrd * Types + ObjType) * Objects + ObjOrd */
  *Handle = (ItemOrd * ARRAY_ITEMS (Data->Objects[ObjOrd]) + ObjType)
                     * ARRAY_ITEMS (Data->Objects) + ObjOrd
                     + 1; /* Handle value must NOT be 0, see a comment below */
  return CKR_OK;
}

static CK_RV HandleToObjOrds (
  CK_ULONG         *ObjOrd,
  OBJECT_TYPE      *ObjType,
  CK_ULONG         *ItemOrd,
  PKCS15_DATA      *Data,
  CK_OBJECT_HANDLE Handle
  )
{
  /* As mentioned in PKCS#11 v2-30b-d6, paragraph 9.4, page 44,
     'Valid object handles in Cryptoki always have nonzero values',
     so the 1 is added/subtracted to/from the computed as zero-based
     value of a handle when it is passed to/from a user */
  if (Handle != 0) { /* Ensure that the handle is NOT obviously invalid */
    CK_ULONG    H          = Handle - 1;

    /* The formula is: Handle = (ItemOrd * TYPES + ObjType) * OBJECTS + ObjOrd */
    CK_ULONG    ObjOrdTmp  = H % ARRAY_ITEMS (Data->Objects);
    OBJECT_TYPE ObjTypeTmp = (H / ARRAY_ITEMS (Data->Objects))
                                % ARRAY_ITEMS (Data->Objects[ObjOrdTmp]);
    CK_ULONG    ItemOrdTmp = (H / ARRAY_ITEMS (Data->Objects))
                                / ARRAY_ITEMS (Data->Objects[ObjOrdTmp]);

    ASN1_TYPE_VAL *V = &Data->Objects[ObjOrdTmp][ObjTypeTmp];

    /* Check found object ASN1 type validity */
    if (V->Decoded                                             &&
        V->Def->Type == ASN1_SEQUENCE_OF_CLASS_TYPE            &&
        ItemOrdTmp < V->TypeVal.SequenceOf.Cnt                 &&
        (V = &V->TypeVal.SequenceOf.Item[ItemOrdTmp])->Decoded &&
        V->Def->Type == ASN1_CHOICE_CLASS_TYPE) {
      *ObjOrd  = ObjOrdTmp;
      *ObjType = ObjTypeTmp;
      *ItemOrd = ItemOrdTmp;
      return CKR_OK;
    }
  }

  return CKR_OBJECT_HANDLE_INVALID;
}


/* Implementation of Cryptoki functions */

#ifdef _MSC_VER

#define DOT_NAME(name)
#define DOT_VERSION
#define DOT_MAJOR
#define DOT_MINOR

#else /* _MSC_VER */

#define DOT_NAME(name) .name    =
#define DOT_VERSION    .version = 
#define DOT_MAJOR      .major   =
#define DOT_MINOR      .minor   =

#endif /* _MSC_VER */

/* This macro is used in further 'pkcs11f.h' inclusion */
#define CK_PKCS11_FUNCTION_INFO(name) \
  DOT_NAME (name) &name,

static CK_FUNCTION_LIST FunctionList = {
  DOT_VERSION {
    DOT_MAJOR CRYPTOKI_VERSION_MAJOR,
    DOT_MINOR CRYPTOKI_VERSION_MINOR
  },
#include <Library/pkcs11f.h> /* The list of PKCS#11 functions */
};

#undef CK_PKCS11_FUNCTION_INFO


/* General purpose functions */

/* C_GetFunctionList() implementation */
CK_DEFINE_FUNCTION (CK_RV, C_GetFunctionList) (
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
  )
{
  if (ppFunctionList == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  *ppFunctionList = &FunctionList;
  return CKR_OK;
}

/* C_GetInfo() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
  CK_INFO_PTR pInfo
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  pInfo->cryptokiVersion.major = FunctionList.version.major;
  pInfo->cryptokiVersion.minor = FunctionList.version.minor;
  pInfo->flags                 = 0;
  pInfo->libraryVersion.major  = 0;
  pInfo->libraryVersion.minor  = 1;

  CopyMem (pInfo->manufacturerID,     Id,   sizeof pInfo->manufacturerID);
  CopyMem (pInfo->libraryDescription, Desc, sizeof pInfo->libraryDescription);
  return CKR_OK;
}

STATIC
CK_RV 
InitWithoutSmartCard (
  VOID
  )
{
  CK_RV rv;
  CK_ULONG I;
  
  if ((rv = AllocMem (
                (CK_VOID_PTR_PTR)&Cryptoki.Slots,
                sizeof *Cryptoki.Slots
                )) != CKR_OK) {
    return rv;
  }

  I = 0;
  /* Initialize paths and objects */
  InitializePKCS15Data (&Cryptoki.Slots[I].Data);

  /* The handle is needed to be saved */
  Cryptoki.Slots[I].Handle = (EFI_HANDLE)(UINTN)0xAA55AA55;

  /* Setting it slightly in advance for proper rollback */
  Cryptoki.SlotNum = 1;

  /* Cryptoki session state */
  Cryptoki.Slots[I].Session.Handle      = CK_INVALID_HANDLE;
  Cryptoki.Slots[I].Session.State       = CKS_RO_PUBLIC_SESSION;
  Cryptoki.Slots[I].Session.Flags       = 0;

  /* Cryptoki C_FindObjects template */
  Cryptoki.Slots[I].Session.Search.Initialized = CK_FALSE;
  Cryptoki.Slots[I].Session.Search.SearchType  = ANY_OBJECT;
  Cryptoki.Slots[I].Session.Search.ObjOrd      = 0;
  Cryptoki.Slots[I].Session.Search.ObjType     = SESSION_OBJECT;
  Cryptoki.Slots[I].Session.Search.ItemOrd     = 0;
  Cryptoki.Slots[I].Session.Search.pTemplate   = NULL_PTR;
  Cryptoki.Slots[I].Session.Search.ulCount     = 0;

  /* Cryptoki logical state */
  Cryptoki.Slots[I].Operations          = OPERATION_NONE;
  Cryptoki.Slots[I].DigestMechanism     = CKM_GOSTR3411;
  Cryptoki.Slots[I].ProcessingState     = PROCESSING_STATE_NONE;
  Cryptoki.Slots[I].DecryptionMechanism = CKM_GOSTR3410;
  Cryptoki.Slots[I].DecryptionParamSet  = CRYPTO_PRO_A;
  Cryptoki.Slots[I].DigestCount         = 0;
  Cryptoki.Slots[I].VerifyKey           = NULL_PTR;

  InitializeInfo (&Cryptoki.Slots[I].TokenInfo);

  Cryptoki.NextSessionHandle = CK_INVALID_HANDLE + 1;
  Cryptoki.bWithoutToken = TRUE;
  return CKR_OK;
}


CK_RV
FillScInfo (
  IN CK_ULONG I
  )
{
  CK_TOKEN_INFO *Info  = &Cryptoki.Slots[I].TokenInfo;
  CK_RV rv;
  FFM_INITIALIZE_AUTO (
              TOKEN_IDENTIFYING_DATA,
              TIData,
              1,
              (
                .Type = 0
              )
            );

  Info->flags |= CKF_TOKEN_INITIALIZED;

  /* FIXME: should be initialized from AODF */
  Info->flags |= CKF_USER_PIN_INITIALIZED;

  /* Default tagging for PKCS#15 ASN.1 definitions is IMPLICIT */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  SetDefaultTagging (CK_FALSE);

  /* Get PKCS15 DIR: application label and path (on success call) */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  AcquireDir (&Cryptoki.Slots[I]); /* DIR is NOT mandatory */

  /* If the previous call did NOT set AppPath, use its default value */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = SetAppPath (&Cryptoki.Slots[I].Data)) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  /* Do the same for the TokenInfoPath */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = SetTokenInfoPath (&Cryptoki.Slots[I].Data)) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  /* Get PKCS15 TokenInfo: serial number, manufacturer ID, label... */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = AcquireTokenInfo (&Cryptoki.Slots[I])) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv; /* Failed to get token info: cause rolling back */
  }

  /* Getting data for hardware/firmware versions */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->    
                        TokenIdentifyingData) (
                          Cryptoki.Slots[I].Interface,
                          &TIData
                          ))) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }
  /* Setting hardware/firmware versions */
  Info->hardwareVersion.major = TIData.HwVer.Major;
  Info->hardwareVersion.minor = TIData.HwVer.Minor;
  Info->firmwareVersion.major = TIData.OSVer.Major;
  Info->firmwareVersion.minor = TIData.OSVer.Minor;

  if(Info->firmwareVersion.major >=23)   
	  Info->Model = Rutoken_2_0;							
  else
	  Info->Model = Rutoken_older_2_0;
  //DEBUG ((EFI_D_ERROR, "Token Model ===== %d\n",Info->Model));

  if(Info->Model != Rutoken_2_0)
	  Cryptoki.Slots[I].Interface->WorkMode = 1;//RUTOKEN_MODE_GOST_2001;

  //DEBUG ((EFI_D_ERROR, "Token WorkMode ===== %d\n",Cryptoki.Slots[I].Interface->WorkMode));

  /* Construct the ODF path */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = SetODFPath (&Cryptoki.Slots[I].Data)) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  /* Get PKCS#15 ODF: PrKDF, PuKDFs, SKDF, CDFs, DODF, and AODF */
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if ((rv = AcquireAndParseODF (&Cryptoki.Slots[I])) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv; /* Failed to decode ODF: cause rolling back */
  }
   
  return CKR_OK;
}


/* C_Initialize() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
  CK_VOID_PTR pInitArgs
  )
{
  CK_RV      rv;
  EFI_HANDLE *H = NULL_PTR;
  CK_ULONG   N  = 0;

  if (Cryptoki.Initialized) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  PKCS11_InitializeStatics();
  PKCS15_InitializeStatics();

  Cryptoki.bScInfoReaded = FALSE;

  if (pInitArgs != NULL) {
    BOOLEAN *pB = (BOOLEAN *)pInitArgs;
    if (*pB) {
      rv = InitWithoutSmartCard();
      Cryptoki.bScInfoReaded = TRUE;
      goto Done;
    }
  }

  if ((rv = FindHandles (&H, &N)) != CKR_OK) {
    return rv;
  }

  /* If some such handles are found yet, process them */
  if (N > 0) {
    if ((rv = AllocMem (
                (CK_VOID_PTR_PTR)&Cryptoki.Slots,
                N * sizeof *Cryptoki.Slots
                )) == CKR_OK) {
      CK_ULONG I;

      for (I = 0; I < N; I++) {
        /* Initialize paths and objects */
        InitializePKCS15Data (&Cryptoki.Slots[I].Data);

        /* The handle is needed to be saved */
        Cryptoki.Slots[I].Handle = H[I];

        /* Setting it slightly in advance for proper rollback */
        Cryptoki.SlotNum = I + 1;

        /* Get Smart Card Protocol API entries */
        if ((rv = OpenProtocol(
                    &Cryptoki.Slots[I].Interface,
                    Cryptoki.Slots[I].Handle
                    )) == CKR_OK) {
          TOKEN_SYSTEM_STATUS Tss       = TssFullyFunctional;

          /* Cryptoki session state */
          Cryptoki.Slots[I].Session.Handle      = CK_INVALID_HANDLE;
          Cryptoki.Slots[I].Session.State       = CKS_RO_PUBLIC_SESSION;
          Cryptoki.Slots[I].Session.Flags       = 0;

          /* Cryptoki C_FindObjects template */
          Cryptoki.Slots[I].Session.Search.Initialized = CK_FALSE;
          Cryptoki.Slots[I].Session.Search.SearchType  = ANY_OBJECT;
          Cryptoki.Slots[I].Session.Search.ObjOrd      = 0;
          Cryptoki.Slots[I].Session.Search.ObjType     = SESSION_OBJECT;
          Cryptoki.Slots[I].Session.Search.ItemOrd     = 0;
          Cryptoki.Slots[I].Session.Search.pTemplate   = NULL_PTR;
          Cryptoki.Slots[I].Session.Search.ulCount     = 0;

          /* Cryptoki logical state */
          Cryptoki.Slots[I].Operations          = OPERATION_NONE;
          Cryptoki.Slots[I].DigestMechanism     = CKM_GOSTR3411;
          Cryptoki.Slots[I].ProcessingState     = PROCESSING_STATE_NONE;
          Cryptoki.Slots[I].DecryptionMechanism = CKM_GOSTR3410;
          Cryptoki.Slots[I].DecryptionParamSet  = CRYPTO_PRO_A;
          Cryptoki.Slots[I].DigestCount         = 0;
          Cryptoki.Slots[I].VerifyKey           = NULL_PTR;

          InitializeInfo (&Cryptoki.Slots[I].TokenInfo);

          /* Get the token system status */
          if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->TokenSystemStatus) (
                                                            Cryptoki.Slots[I].
                                                              Interface,
                                                            &Tss
                                                            ))) != CKR_OK) {
            break; /* Failed to get token system status: cause rolling back */
          }
          if (Tss == TssFullyFunctional) {
            FillScInfo (I);
#if 0
            if (rv == CKR_OK) {
              Cryptoki.bScInfoReaded = TRUE;
            }
#endif
          } else {
            if (Tss != TssFormatIncomplete) {
              rv = CKR_DEVICE_ERROR;
              break; /* Bad token */
            }
          }
        } else {
          break; /* Stop opening protocol on handles and cause rolling back */
        }
      }

      if (I == N) { /* Protocol is successfuly opened an all the handles */
        Cryptoki.NextSessionHandle = CK_INVALID_HANDLE + 1;
      } else { /* Rolling back because of an error */
        for (I++; I > 0; I--) {
          FreePKCS15Data (&Cryptoki.Slots[I - 1].Data);
          CloseProtocol (Cryptoki.Slots[I - 1].Handle);
        }

        FreeMem (Cryptoki.Slots);
        Cryptoki.Slots             = NULL;
        Cryptoki.SlotNum           = 0;
        Cryptoki.NextSessionHandle = CK_INVALID_HANDLE;
      }
    }

    FreeMem (H);
  }
  
Done:
  Cryptoki.Initialized =
#ifdef _MSC_VER
    (BOOLEAN)
#endif /* _MSC_VER */
    (rv == CKR_OK);
  return rv;
}

/* C_Finalize() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
  )
{
  CK_ULONG I;

  if (pReserved != NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  for (I = Cryptoki.SlotNum; I > 0; I--) {
    CK_ULONG J = I - 1;

    FreePKCS15Data (&Cryptoki.Slots[J].Data);
    CloseProtocol (Cryptoki.Slots[J].Handle);
    if (Cryptoki.Slots[J].Handle) {
      CloseProtocol (Cryptoki.Slots[J].Handle);
    }
    Cryptoki.Slots[J].Handle = NULL;

    if (Cryptoki.Slots[J].Session.Search.pTemplate != NULL_PTR) {
      FreeTemplate (&Cryptoki.Slots[J].Session.Search);
    }
  }

  Cryptoki.SlotNum = 0;

  if (Cryptoki.Slots != NULL) {
    FreeMem (Cryptoki.Slots);

    Cryptoki.Slots      = NULL;
  }

  Cryptoki.NextSessionHandle = CK_INVALID_HANDLE;
  Cryptoki.Initialized       = FALSE;
  Cryptoki.bWithoutToken     = FALSE;
  return CKR_OK;
}

/* Slot and token management functions */

/* C_GetSlotList() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
  CK_BBOOL       tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR   pulCount
  )
{
  CK_RV rv = CKR_OK;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  /* FIXME: tokenPresent is NOT taken into account */
  if (pSlotList != NULL_PTR) {
    if (*pulCount >= Cryptoki.SlotNum) {
      CK_ULONG I;

      for(I = 0; I < Cryptoki.SlotNum; I++)
        pSlotList[I] = I;
    } else {
      rv = CKR_BUFFER_TOO_SMALL;
    }
  }

  *pulCount = Cryptoki.SlotNum;
  return rv;
}

/* C_GetSlotInfo() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
  CK_SLOT_ID       slotID,
  CK_SLOT_INFO_PTR pInfo
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  /* FIXME: Non-fake implementation is needed */
  pInfo->flags                 = CKF_HW_SLOT |
                                 CKF_REMOVABLE_DEVICE |
                                 CKF_TOKEN_PRESENT;

  /* FIXME: Real information should be filled in */
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;

  SetMem (pInfo->slotDescription, sizeof pInfo->slotDescription, ' ');
  SetMem (pInfo->manufacturerID,  sizeof pInfo->manufacturerID,  ' ');
  return CKR_OK;
}

/* C_GetTokenInfo() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID        slotID,
  CK_TOKEN_INFO_PTR pInfo
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  CopyMem (pInfo, &Cryptoki.Slots[slotID].TokenInfo, sizeof *pInfo);
  return CKR_OK;
}

/* C_GetMechanismList() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR          pulCount
  )
{
  CK_RV rv = CKR_OK;

  /* The list of mechanisms is hardcoded */
  static CK_MECHANISM_TYPE Mechanisms[] = {
    CKM_RSA_PKCS,
    CKM_GOSTR3410,
    CKM_GOSTR3411,
	CKM_GOSTR3410_2012,
	CKM_GOSTR3411_2012
  };

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  /* FIXME: Non-hardcoded implementation is needed */
  if (pMechanismList != NULL_PTR) {
    if (*pulCount >= sizeof Mechanisms / sizeof *Mechanisms) {
      CopyMem (pMechanismList, Mechanisms, sizeof Mechanisms);
    } else {
      rv = CKR_BUFFER_TOO_SMALL;
    }
  }

  *pulCount = sizeof Mechanisms / sizeof *Mechanisms;
  return rv;
}

/* C_GetMechanismInfo() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE     type,
  CK_MECHANISM_INFO_PTR pInfo
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  /* FIXME: Non-hardcoded implementation is needed */
  switch (type) {
  case CKM_RSA_PKCS:
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 2048;
    pInfo->flags        = CKF_HW | CKF_DECRYPT;
    break;
  case CKM_GOSTR3410:
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 256;
    pInfo->flags        = CKF_HW | CKF_DECRYPT;
    break;
  case CKM_GOSTR3410_2012:
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 256;
    pInfo->flags        = CKF_HW | CKF_DECRYPT;
    break;
  case CKM_GOSTR3411:
    pInfo->ulMinKeySize = 0;
    pInfo->ulMaxKeySize = 0;
    pInfo->flags        = CKF_HW | CKF_DIGEST;
    break;
  case CKM_GOSTR3411_2012:
    pInfo->ulMinKeySize = 0;
    pInfo->ulMaxKeySize = 0;
    pInfo->flags        = CKF_HW | CKF_DIGEST;
    break;
  default:
    return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

/* C_InitToken() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
  CK_SLOT_ID      slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG        ulPinLen,
  CK_UTF8CHAR_PTR pLabel
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPin == NULL_PTR || pLabel == NULL_PTR || ulPinLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_InitPIN() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pPin,
  CK_ULONG          ulPinLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPin == NULL_PTR || ulPinLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetPIN() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pOldPin,
  CK_ULONG          ulOldLen,
  CK_UTF8CHAR_PTR   pNewPin,
  CK_ULONG          ulNewLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pOldPin == NULL_PTR || ulOldLen == 0 ||
      pNewPin == NULL_PTR || ulNewLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Session management functions */

CK_RV
Pkcs11_GetSlotSession (
  CK_SLOT_ID            slotID,
  CK_SESSION_HANDLE_PTR phSession
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  if (Cryptoki.Slots[slotID].Session.Handle == CK_INVALID_HANDLE) {
    return CKR_SESSION_CLOSED; /* Only one session is currently supported */
  }
  *phSession = Cryptoki.Slots[slotID].Session.Handle;
  return CKR_OK;
}

/* C_OpenSession() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
  CK_SLOT_ID            slotID,
  CK_FLAGS              flags,
  CK_VOID_PTR           pApplication,
  CK_NOTIFY             Notify,
  CK_SESSION_HANDLE_PTR phSession
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  if (!(flags & CKF_SERIAL_SESSION)) {
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

#if !defined CRYPTOKI_RW_SESSIONS_ALLOWED
  if ((flags & CKF_RW_SESSION)) {
    return CKR_TOKEN_WRITE_PROTECTED;
  }
#endif

  if (Cryptoki.Slots[slotID].Session.Handle != CK_INVALID_HANDLE) {
	  LOG((EFI_D_ERROR, "!!!CK_INVALID_HANDLE \n"));
    return CKR_SESSION_COUNT; /* Only one session is currently supported */
  }

  
  Cryptoki.Slots[slotID].Operations     = OPERATION_NONE;
  Cryptoki.Slots[slotID].Session.Handle = Cryptoki.NextSessionHandle++;
  Cryptoki.Slots[slotID].Session.State  = flags & CKF_RW_SESSION ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
  Cryptoki.Slots[slotID].Session.Flags  = flags & (CKF_RW_SESSION | CKF_SERIAL_SESSION);
  *phSession = Cryptoki.Slots[slotID].Session.Handle;

  /* Adjust actual session count value */
  Cryptoki.Slots[slotID].TokenInfo.ulSessionCount   = 1;
  Cryptoki.Slots[slotID].TokenInfo.ulRwSessionCount = (flags & CKF_RW_SESSION)
                                                      ? 1  : 0;

  /* Notification callback is not supported */
  return CKR_OK;
}

/* C_CloseSession() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
  )
{
  CK_ULONG           I;
  CK_RV           rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* If we are currently logged in then logout */
  switch (Cryptoki.Slots[I].Session.State) {
  case CKS_RO_USER_FUNCTIONS:
  case CKS_RW_USER_FUNCTIONS:
  case CKS_RW_SO_FUNCTIONS:
    if (C_Logout(hSession) != CKR_OK) {
      return CKR_FUNCTION_FAILED;
    }

    break;
  }

  Cryptoki.Slots[I].Operations     = OPERATION_NONE;
  Cryptoki.Slots[I].Session.Handle = CK_INVALID_HANDLE;

  /* Adjust actual session count value */
  Cryptoki.Slots[I].TokenInfo.ulSessionCount   = 0;
  Cryptoki.Slots[I].TokenInfo.ulRwSessionCount = 0;

  /* Avoid memory leak in case of FindObjectsFinal is NOT called */
  return FreeTemplate (&Cryptoki.Slots[I].Session.Search);
}

/* C_CloseAllSessions() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= Cryptoki.SlotNum) {
    return CKR_SLOT_ID_INVALID;
  }

  /* Only one session per slot is supported */
  return C_CloseSession(Cryptoki.Slots[slotID].Session.Handle);
}

/* C_GetSessionInfo() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE   hSession,
  CK_SESSION_INFO_PTR pInfo
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  pInfo->slotID = I;
  pInfo->state  = Cryptoki.Slots[I].Session.State;
  pInfo->flags  = Cryptoki.Slots[I].Session.Flags;
  return CKR_OK;
}

/* C_GetOperationState() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pOperationState,
  CK_ULONG_PTR      pulOperationStateLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulOperationStateLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetOperationState() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR      pOperationState,
  CK_ULONG         ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pOperationState == NULL_PTR || ulOperationStateLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Login() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Login)(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE      userType, /* CKU_SO and CKU_USER only supported */
  CK_UTF8CHAR_PTR   pPin,
  CK_ULONG          ulPinLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPin == NULL_PTR || ulPinLen == 0 || ulPinLen > UINT8_MAX) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  switch (userType) {
  case CKU_SO:
    switch (Cryptoki.Slots[I].Session.State) {
    case CKS_RO_PUBLIC_SESSION: /* SO login requires RW session type */
      return CKR_SESSION_READ_ONLY_EXISTS;
    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    case CKS_RW_PUBLIC_SESSION:
      break;
    case CKS_RW_SO_FUNCTIONS:
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    break;
  case CKU_USER:
    switch (Cryptoki.Slots[I].Session.State) {
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
      break;
    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
      return CKR_USER_ALREADY_LOGGED_IN;
    case CKS_RW_SO_FUNCTIONS:
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    break;
  /* CKU_CONTEXT_SPECIFIC user type is not currently supported */
  case CKU_CONTEXT_SPECIFIC:
  default:
    return CKR_USER_TYPE_INVALID;
  }

  /* FIXME: Implementation is needed */
  if (Cryptoki.bWithoutToken == FALSE) {
    switch ((*Cryptoki.Slots[I].Interface->Login) (
                                             Cryptoki.Slots[I].Interface,
                                             userType == CKU_SO ?
                                               TRUE : /* Administrator */
                                               FALSE, /* User */
                                             (UINT8 *)pPin,
                                             (UINT8)ulPinLen /* Range is checked */
                                             )) {
    case EFI_SUCCESS:
      break;
    case EFI_ACCESS_DENIED:
      return CKR_PIN_INCORRECT;
    default:
      return CKR_GENERAL_ERROR;
    }
  }

  switch (userType) {
  case CKU_SO:
    Cryptoki.Slots[I].Session.State = CKS_RW_SO_FUNCTIONS;
    break;
  case CKU_USER:
    switch (Cryptoki.Slots[I].Session.State) {
    case CKS_RO_PUBLIC_SESSION:
      Cryptoki.Slots[I].Session.State = CKS_RO_USER_FUNCTIONS;
      break;
    case CKS_RW_PUBLIC_SESSION:
      Cryptoki.Slots[I].Session.State = CKS_RW_USER_FUNCTIONS;
      break;
    }

    break;
  }

  if (!Cryptoki.bScInfoReaded) {
    FillScInfo (I);
    Cryptoki.bScInfoReaded = TRUE;
  }

  return CKR_OK;
}

/* C_Logout() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  switch (Cryptoki.Slots[I].Session.State) {
  case CKS_RO_PUBLIC_SESSION:
  case CKS_RW_PUBLIC_SESSION:
    return CKR_USER_NOT_LOGGED_IN;
  case CKS_RO_USER_FUNCTIONS:
  case CKS_RW_USER_FUNCTIONS:
    if ((*Cryptoki.Slots[I].Interface->Logout) (
                                         Cryptoki.Slots[I].Interface,
                                         FALSE /* User */
                                         ) != EFI_SUCCESS) {
      return CKR_FUNCTION_FAILED;
    }

    break;
  case CKS_RW_SO_FUNCTIONS:
    if ((*Cryptoki.Slots[I].Interface->Logout) (
                                         Cryptoki.Slots[I].Interface,
                                         TRUE /* Administrator */
                                         ) != EFI_SUCCESS) {
      return CKR_FUNCTION_FAILED;
    }

    break;
  }

  switch (Cryptoki.Slots[I].Session.State) {
  case CKS_RO_USER_FUNCTIONS:
    Cryptoki.Slots[I].Session.State = CKS_RO_PUBLIC_SESSION;
    break;
  case CKS_RW_USER_FUNCTIONS:
  case CKS_RW_SO_FUNCTIONS:
    Cryptoki.Slots[I].Session.State = CKS_RW_PUBLIC_SESSION;
    break;
  }

  return CKR_OK;
}

static CK_RV CreateObject (
  CK_ULONG         TypeOrd,
  CK_ULONG         *ItemOrd,
  ASN1_TYPE_VAL    **V
  )
{
  ASN1_TYPE_VAL       *W    = *V;
  ASN1_TYPE_VAL       *X    = NULL_PTR;
  ASN1_TYPE_VAL       *Y    = NULL_PTR;
  ASN1_TYPE_DEF CONST *Def1;
  ASN1_TYPE_DEF CONST *Def2;
  ASN1_TYPE_DEF CONST *Def3;
  CK_RV               rv;

  /* Check subtypes of PKCS15Objects */
  if ((Def1 = W->Def)->Type                   != ASN1_SEQUENCE_OF_CLASS_TYPE ||
      (Def2 = Def1->TypeRef.SequenceOf)->Type != ASN1_CHOICE_CLASS_TYPE      ||
      TypeOrd                                 >= Def2->TypeRef.Choice->Cnt   ||
      (Def3 = &Def2->TypeRef.
                 Choice->Item[TypeOrd])->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* If it is the first use of the SEQUENCE OF objects then initialize it */
  if (!W->Decoded) {
    W->TypeVal.SequenceOf.Item = NULL_PTR;
    W->TypeVal.SequenceOf.Cnt  = 0;
    W->ASN1.Val                = NULL_PTR;
    W->ASN1.Len                = 0;
    W->Decoded                 = CK_TRUE;
  }

  /* Add CHOICE item */
  if ((rv = AddTypeItem (
              &W->TypeVal.SequenceOf.Item,
              &X,
              Def2,
              W->TypeVal.SequenceOf.Cnt
              )) != CKR_OK) {
    return rv;
  }

  /* Add SEQUENCE item */
  if ((rv = AddConsTypeItem (
              &X->TypeVal.Choice.Item,
              &Y,
              Def3,
              0,
              TypeOrd
              )) != CKR_OK) {
    FreeMem (W->TypeVal.SequenceOf.Item);
    W->TypeVal.SequenceOf.Item = NULL_PTR;
    return rv;
  }

  /* The ord of the SEQUENCE OF */
  *ItemOrd                 = W->TypeVal.SequenceOf.Cnt++;

  /* Set CHOICE item decoded */
  X->Decoded               = CK_TRUE;

  /* Initialize SEQUENCE item and set it decoded */
  Y->TypeVal.Sequence.Item = NULL_PTR;
  Y->TypeVal.Sequence.Cnt  = 0;
  Y->Decoded               = CK_TRUE;

  /* Return SEQUENCE item */
  *V                       = Y;
  return CKR_OK;
}

static CK_RV CreateCommonObjectAttrs (
  CK_VOID_PTR      pLabel,
  CK_ULONG         ulLabelLen,
  ASN1_TYPE_VAL    *V
  )
{
  ASN1_TYPE_VAL       *X  = NULL_PTR;
  ASN1_TYPE_VAL       *Y  = NULL_PTR;
  ASN1_TYPE_DEF CONST *Def1;
  ASN1_TYPE_DEF CONST *Def2;
  ASN1_TYPE_DEF CONST *Def3;
  CK_VOID_PTR         Ptr = NULL_PTR;
  CK_RV               rv;

  /* Check Label value parameters and PKCS15Object subtypes */
  if (pLabel                             == NULL_PTR                    ||
      ulLabelLen                         == 0                           ||
      (Def1 = V->Def)->Type              != ASN1_SEQUENCE_CLASS_TYPE    ||
      PKCS15_OBJECT_COMMON_OBJECT_ATTRIBUTES_ORD >=
        Def1->TypeRef.Sequence->Cnt                                     ||
      (Def2 = &Def1->TypeRef.Sequence->
                 Item[PKCS15_OBJECT_COMMON_OBJECT_ATTRIBUTES_ORD].
                   Val)->Type            != ASN1_SEQUENCE_CLASS_TYPE    ||
      COMMON_OBJECT_ATTRIBUTES_LABEL_ORD >= Def2->TypeRef.Sequence->Cnt ||
      (Def3 = &Def2->TypeRef.Sequence->
                 Item[COMMON_OBJECT_ATTRIBUTES_LABEL_ORD].
                   Val)->Type            != ASN1_PRIM_CLASS_TYPE        ||
      Def3->TypeRef.Prim->Type           != ASN1_UTF8_STRING_PRIM_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* Add CommonObjectAttributes item */
  if ((rv = AddConsTypeItem (
              &V->TypeVal.Sequence.Item,
              &X,
              Def2,
              V->TypeVal.Sequence.Cnt,
              PKCS15_OBJECT_COMMON_OBJECT_ATTRIBUTES_ORD
              )) != CKR_OK) {
    return rv;
  }

  V->TypeVal.Sequence.Cnt++;
  X->TypeVal.Sequence.Item = NULL_PTR;
  X->TypeVal.Sequence.Cnt  = 0;
  X->Decoded               = CK_TRUE;

  /* Add Label attribute */
  if ((rv = AddConsTypeItem (
              &X->TypeVal.Sequence.Item,
              &Y,
              Def3,
              X->TypeVal.Sequence.Cnt,
              COMMON_OBJECT_ATTRIBUTES_LABEL_ORD
              )) != CKR_OK) {
    return rv;
  }

  X->TypeVal.Sequence.Cnt++;

  /* Allocate memory for Label */
  if ((rv = AllocMem (&Ptr, ulLabelLen)) != CKR_OK) {
    return rv;
  }

  /* Fill just allocated memory with Label value */
  CopyMem (
    Y->TypeVal.Prim.Utf8String.Val = Ptr,
    pLabel,
    Y->TypeVal.Prim.Utf8String.Len = ulLabelLen
    );

  /* Set Label decoded */
  Y->Decoded = CK_TRUE;
  return CKR_OK;
}

static CK_RV CreateClassAttrs (
  CK_VOID_PTR      pId,
  CK_ULONG         ulIdLen,
  CK_ULONG         ClassOrd,
  CK_BBOOL         Certificate,
  ASN1_TYPE_VAL    *V
  )
{
  enum { USAGE_VERIFY = 6 };

  ASN1_TYPE_VAL       *X    = NULL_PTR;
  ASN1_TYPE_VAL       *Y    = NULL_PTR;
  ASN1_TYPE_DEF CONST *Def1 = V->Def;
  ASN1_TYPE_DEF CONST *Def2=0;
  ASN1_TYPE_DEF CONST *Def3=0;
  ASN1_TYPE_DEF CONST *Def4=0;
  CK_VOID_PTR         Ptr = NULL_PTR;
  CK_RV               rv;

  /* Check Id value parameters and PKCS15Object subtypes */
  if (pId                                  == NULL_PTR                    ||
      ulIdLen                              == 0                           ||
      Def1->Type                           != ASN1_SEQUENCE_CLASS_TYPE    ||
      PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD   >= Def1->TypeRef.Sequence->Cnt ||
      (Def2 = &Def1->TypeRef.Sequence->
                 Item[PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD].
                   Val)->Type              != ASN1_SEQUENCE_CLASS_TYPE    ||
      ClassOrd                             >= Def2->TypeRef.Sequence->Cnt ||
      (Def3 = &Def2->TypeRef.Sequence->
                 Item[ClassOrd].Val)->Type != ASN1_PRIM_CLASS_TYPE        ||
       Def3->TypeRef.Prim->Type            != ASN1_OCTET_STRING_PRIM_TYPE ||
       (!Certificate &&
        (COMMON_KEY_ATTRIBUTES_USAGE       >= Def2->TypeRef.Sequence->Cnt ||
         (Def4 = &Def2->TypeRef.Sequence->
                          Item[COMMON_KEY_ATTRIBUTES_USAGE].
                            Val)->Type     != ASN1_PRIM_CLASS_TYPE        ||
         Def4->TypeRef.Prim->Type          != ASN1_BIT_STRING_PRIM_TYPE))) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* Add ClassAttributes item */
  if ((rv = AddConsTypeItem (
              &V->TypeVal.Sequence.Item,
              &X,
              Def2,
              V->TypeVal.Sequence.Cnt,
              PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD
              )) != CKR_OK) {
    return rv;
  }

  V->TypeVal.Sequence.Cnt++;
  X->TypeVal.Sequence.Item = NULL_PTR;
  X->TypeVal.Sequence.Cnt  = 0;
  X->Decoded               = CK_TRUE;

  /* Add Id attribute */
  if ((rv = AddConsTypeItem (
              &X->TypeVal.Sequence.Item,
              &Y,
              Def3,
              X->TypeVal.Sequence.Cnt,
              ClassOrd
              )) != CKR_OK) {
    return rv;
  }

  X->TypeVal.Sequence.Cnt++;

  /* Allocate memory for Id */
  if ((rv = AllocMem (&Ptr, ulIdLen)) != CKR_OK) {
    return rv;
  }

  /* Fill just allocated memory with Id value */
  CopyMem (
    Y->TypeVal.Prim.OctetString.Val = Ptr,
    pId,
    Y->TypeVal.Prim.OctetString.Len = ulIdLen
    );

  /* Set Id decoded */
  Y->Decoded = CK_TRUE;

  /* If it is NOT a Public Key then further processing is NOT needed */
  if (Certificate) {
    return CKR_OK;
  }

  /* Add Usage attribute */
  if ((rv = AddConsTypeItem (
              &X->TypeVal.Sequence.Item,
              &Y,
              Def4,
              X->TypeVal.Sequence.Cnt,
              COMMON_KEY_ATTRIBUTES_USAGE
              )) != CKR_OK) {
    return rv;
  }

  X->TypeVal.Sequence.Cnt++;

  /* Set Id decoded */
  Y->TypeVal.Prim.BitString.Hex = NULL_PTR;
  Y->TypeVal.Prim.BitString.Val = NULL_PTR;
  Y->Decoded                    = CK_TRUE;

  /* Allocate memory for Usage */
  if ((rv = AllocMem (&Ptr, (USAGE_VERIFY + 7) / 8)) != CKR_OK) {
    return rv;
  }

  /* Fill just allocated memory for hex representation with 0 values */
  if ((USAGE_VERIFY + 7) / 8 > 0) {
    SetMem (Y->TypeVal.Prim.BitString.Hex = Ptr, USAGE_VERIFY / 8, 0);
  }

  /* Set Usage field hex representation into 'verify' value */
  Y->TypeVal.Prim.BitString.Hex[USAGE_VERIFY / 8] = 1 << USAGE_VERIFY;

  /* Allocate memory for Usage */
  if ((rv = AllocMem (&Ptr, USAGE_VERIFY + 1)) != CKR_OK) {
    return rv;
  }

  /* Fill just allocated memory with 0 values */
  SetMem (
    Y->TypeVal.Prim.BitString.Val = Ptr,
    Y->TypeVal.Prim.BitString.Len = USAGE_VERIFY + 1,
    0
    );

  /* Set Usage field into 'verify' value */
  Y->TypeVal.Prim.BitString.Val[USAGE_VERIFY] = 1;

  return CKR_OK;
}

static CK_RV CreateTypeAttrs (
  CK_VOID_PTR      pId,
  CK_ULONG         ulIdLen,
  CK_ULONG         AttrValueOrd,
  ASN1_TYPE_VAL    **V
  )
{
  ASN1_TYPE_VAL       *W  = *V;
  ASN1_TYPE_VAL       *X  = NULL_PTR;
  ASN1_TYPE_VAL       *Y  = NULL_PTR;
  ASN1_TYPE_DEF CONST *Def1;
  ASN1_TYPE_DEF CONST *Def2;
  ASN1_TYPE_DEF CONST *Def3;
  CK_RV               rv;

  /* Check PKCS15Object subtypes */
  if ((Def1 = W->Def)->Type             != ASN1_SEQUENCE_CLASS_TYPE    ||
      PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD >= Def1->TypeRef.Sequence->Cnt ||
      (Def2 = &Def1->TypeRef.Sequence->
                 Item[PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD].
                   Val)->Type           != ASN1_SEQUENCE_CLASS_TYPE    ||
      AttrValueOrd                      >= Def2->TypeRef.Sequence->Cnt ||
      (Def3 = &Def2->TypeRef.Sequence->
                 Item[AttrValueOrd].
                   Val)->Type           != ASN1_CHOICE_CLASS_TYPE      ||
      OBJECT_VALUE_DIRECT_ORD           >= Def3->TypeRef.Choice->Cnt) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* Add TypeAttributes item */
  if ((rv = AddConsTypeItem (
              &W->TypeVal.Sequence.Item,
              &X,
              Def2,
              W->TypeVal.Sequence.Cnt,
              PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD
              )) != CKR_OK) {
    return rv;
  }

  W->TypeVal.Sequence.Cnt++;
  X->TypeVal.Sequence.Item = NULL_PTR;
  X->TypeVal.Sequence.Cnt  = 0;
  X->Decoded               = CK_TRUE;

  /* Add ObjectValue item */
  if ((rv = AddConsTypeItem (
              &X->TypeVal.Sequence.Item,
              &Y,
              Def3,
              X->TypeVal.Sequence.Cnt,
              AttrValueOrd
              )) != CKR_OK) {
    return rv;
  }

  X->TypeVal.Sequence.Cnt++;

  /* Create CHOICE as 'direct' field of ObjectValue */
  if ((rv = AddConsTypeItem (
              &Y->TypeVal.Choice.Item,
              V, /* A particular TypeAttributes object is returned via V */
              &Def3->TypeRef.Choice->Item[OBJECT_VALUE_DIRECT_ORD],
              0,
              OBJECT_VALUE_DIRECT_ORD
              )) != CKR_OK) {
    return rv;
  }

  /* Set ObjectValue decoded */
  Y->Decoded = CK_TRUE;
  return CKR_OK;
}

static CK_RV CreatePublicKey_RSA (
  PKCS15_DATA      *Data,
  CK_VOID_PTR      pLabel,
  CK_ULONG         ulLabelLen,
  CK_VOID_PTR      pId,
  CK_ULONG         ulIdLen,
  CK_VOID_PTR      pValue,
  CK_ULONG         ulValueLen,
  CK_OBJECT_HANDLE *phObject
  )
{
  PKCS15_OBJECTS_CHOICE_ITEM_ORD const ObjOrd  = PKCS15_OBJECTS_PUBLIC_KEYS_ORD;
  OBJECT_TYPE                    const ObjType = SESSION_OBJECT;
  ASN1_TYPE_VAL                        *V      = &Data->Objects[ObjOrd][ObjType];
  ASN1_TYPE_VAL                        *W      = V;
  CK_ULONG                             ItemOrd;
  ASN1_TYPE_DEF                  CONST *Def;

  CK_RV rv = CreateObject (
               PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY,
               &ItemOrd,
               &W
               );

  if (rv          != CKR_OK ||
      (rv = CreateCommonObjectAttrs (
              pLabel,
              ulLabelLen,
              W
              )) != CKR_OK ||
      (rv = CreateClassAttrs (
              pId,
              ulIdLen,
              COMMON_KEY_ATTRIBUTES_ID,
              CK_FALSE, /* NOT Certificate */
              W
              )) != CKR_OK ||
      (rv = CreateTypeAttrs (
              pId,
              ulIdLen,
              PUBLIC_RSA_KEY_ATTRIBUTES_VALUE,
              &W
              )) != CKR_OK) {
    FreeASN1 (V);
    return rv;
  }

  if (W->Def->Type              != ASN1_CHOICE_CLASS_TYPE      ||
      RSA_PUBLIC_KEY_CHOICE_RAW >= W->Def->TypeRef.Choice->Cnt ||
      (Def = &W->Def->TypeRef.Choice->
                Item[RSA_PUBLIC_KEY_CHOICE_RAW]
                  )->Type       != ASN1_SEQUENCE_CLASS_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  W->TypeVal.Choice.Item = NULL_PTR;
  W->Decoded             = CK_TRUE;

  if ((rv = AddConsTypeItem (
              &W->TypeVal.Choice.Item,
              &W,
              Def,
              0,
              RSA_PUBLIC_KEY_CHOICE_RAW
              ))                            != CKR_OK ||
      (rv = Decode (W, pValue, ulValueLen)) != CKR_OK) {
    FreeASN1 (V);
    return rv;
  }

  return ObjOrdsToHandle (phObject, Data, ObjOrd, ObjType, ItemOrd);
}

static CK_RV CreatePublicKey_GOSTR3410 (
  PKCS15_DATA      *Data,
  CK_VOID_PTR      pLabel,
  CK_ULONG         ulLabelLen,
  CK_VOID_PTR      pId,
  CK_ULONG         ulIdLen,
  CK_VOID_PTR      pValue,
  CK_ULONG         ulValueLen,
  CK_OBJECT_HANDLE *phObject
  )
{
  PKCS15_OBJECTS_CHOICE_ITEM_ORD const ObjOrd  = PKCS15_OBJECTS_PUBLIC_KEYS_ORD;
  OBJECT_TYPE                    const ObjType = SESSION_OBJECT;
  ASN1_TYPE_VAL                        *V      = &Data->Objects[ObjOrd][ObjType];
  ASN1_TYPE_VAL                        *W      = V;
  CK_ULONG                             ItemOrd;
  ASN1_TYPE_DEF                  CONST *Def;

  CK_RV rv = CreateObject (
               PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY,
               &ItemOrd,
               &W
               );

  if (rv          != CKR_OK ||
      (rv = CreateCommonObjectAttrs (
              pLabel,
              ulLabelLen,
              W
              )) != CKR_OK ||
      (rv = CreateClassAttrs (
              pId,
              ulIdLen,
              COMMON_KEY_ATTRIBUTES_ID,
              CK_FALSE, /* NOT Certificate */
              W
              )) != CKR_OK ||
      (rv = CreateTypeAttrs (
              pId,
              ulIdLen,
              PUBLIC_KEA_KEY_ATTRIBUTES_VALUE,
              &W
              )) != CKR_OK) {
    FreeASN1 (V);
    return rv;
  }

  if (W->Def->Type != ASN1_CHOICE_CLASS_TYPE ||
      KEA_PUBLIC_KEY_CHOICE_RAW >= W->Def->TypeRef.Choice->Cnt ||
      (Def = &W->Def->TypeRef.Choice->Item[KEA_PUBLIC_KEY_CHOICE_RAW])->Type != ASN1_PRIM_CLASS_TYPE ||
      Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  W->TypeVal.Choice.Item = NULL_PTR;
  W->Decoded             = CK_TRUE;

  if ((rv = AddConsTypeItem (
              &W->TypeVal.Choice.Item,
              &W,
              Def,
              0,
              KEA_PUBLIC_KEY_CHOICE_RAW
              ))                            != CKR_OK ||
      (rv = Decode (W, pValue, ulValueLen)) != CKR_OK) {
    FreeASN1 (V);
    return rv;
  }

  return ObjOrdsToHandle (phObject, Data, ObjOrd, ObjType, ItemOrd);
}

static CK_RV CreateCertificate_X509 (
  CK_SESSION_HANDLE hSession,
  PKCS15_DATA       *Data,
  CK_VOID_PTR       pLabel,
  CK_ULONG          ulLabelLen,
  CK_VOID_PTR       pId,
  CK_ULONG          ulIdLen,
  CK_VOID_PTR       pValue,
  CK_ULONG          ulValueLen,
  CK_OBJECT_HANDLE  *phObject
  )
{
  PKCS15_OBJECTS_CHOICE_ITEM_ORD const ObjOrd  = PKCS15_OBJECTS_CERTIFICATES_ORD;
  OBJECT_TYPE                    const ObjType = SESSION_OBJECT;
  ASN1_TYPE_VAL                        *W      = &Data->Objects[ObjOrd][ObjType];
  STATIC CK_BBOOL                      Token   = CK_FALSE;
  STATIC CK_OBJECT_CLASS               PKClass = CKO_PUBLIC_KEY;
  CK_ULONG                             ItemOrd;
  CK_OBJECT_HANDLE                     hObject;
  CK_ULONG                             Count;
  CK_RV                                rv;

  CK_ATTRIBUTE Template[] = {
    { CKA_TOKEN, &Token,   sizeof Token   },
    { CKA_CLASS, &PKClass, sizeof PKClass },
    { CKA_ID,    NULL_PTR, 0              },
    { CKA_LABEL, NULL_PTR, 0              }
  };

  FFM_INITIALIZE_AUTO (
    ASN1_TYPE_VAL,
    V,
    6,
    (
      .Def                     = &PKCS15_Certificate,
      .Decoded                 = CK_TRUE,
      .TypeVal.SequenceOf.Item = NULL_PTR,
      .TypeVal.SequenceOf.Cnt  = 0,
      .ASN1.Val                = NULL_PTR,
      .ASN1.Len                = 0
    )
  );

  FFM_INITIALIZE_AUTO (
    ASN1_TAG_INFO,
    TI,
    5,
    (
      .SucNum.Suc = CK_FALSE,
      .Tag        = ASN1_NO_TAG,
      .Pld        = pValue,
      .Len        = ulValueLen,
      .ASN1       = pValue
    )
  );

  /* Initialize here because of Microsoft antique compiler */
  Template[2].pValue     = pId;
  Template[2].ulValueLen = ulIdLen;
  Template[3].pValue     = pLabel;
  Template[3].ulValueLen = ulLabelLen;

  /* Perform ASN.1 decoding of the supplied Certificate into V */
  if ((rv = GetTagInfo (&TI, TI.Pld, TI.Len)) != CKR_OK ||
      (rv = DecodeSubtype (&V, &TI))          != CKR_OK) {
    return rv;
  }

  /* Try to find a Public Key with the same Label/Id as those of the Certificate */
  if ((rv = C_FindObjectsInit (
              hSession,
              &Template[0], /* If pLabel == NULL then ignore the last item */
              ARRAY_ITEMS (Template) - (pLabel == NULL_PTR)
              ))                                           != CKR_OK ||
      (rv = C_FindObjects (hSession, &hObject, 1, &Count)) != CKR_OK ||
      (rv = C_FindObjectsFinal (hSession))                 != CKR_OK) {
    FreeASN1 (&V);
    return rv;
  }

  /* If the Public Key was NOT found on the previous step, create it */
  if (Count == 0) {
    static CK_ULONG id_GostR3410_2001[] = { 1, 2, 643,      2, 2, 19 };
    static CK_ULONG rsaEncryption[]     = { 1, 2, 840, 113549, 1,  1, 1 };

    static struct {
      CK_KEY_TYPE  KeyType;
      CK_ULONG     *Val;
      CK_ULONG     Len;
    }               Keys[]              = {
      { CKK_RSA,       &rsaEncryption[0],     ARRAY_ITEMS (rsaEncryption)     },
      { CKK_GOSTR3410, &id_GostR3410_2001[0], ARRAY_ITEMS (id_GostR3410_2001) }
    };

    ASN1_TYPE_VAL              *W;
    ASN1_TYPE_VAL              *X;
    ASN1_OBJECT_IDENTIFIER_VAL *O;
    CK_ULONG                   I;

    /* Check Certificate subtypes & get CERTIFICATE_CERTIFICATE_CONTENT field */
    if (V.Def->Type                     != ASN1_SEQUENCE_CLASS_TYPE           ||
        V.Def->TypeRef.Sequence->Cnt    != CERTIFICATE_ITEM_ORD_ITEMS         ||
        CERTIFICATE_CERTIFICATE_CONTENT >= V.TypeVal.Sequence.Cnt             ||
        (W = &V.TypeVal.Sequence.
                Item[CERTIFICATE_CERTIFICATE_CONTENT].
                  Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE           ||
        W->Def->TypeRef.Sequence->Cnt   != CERTIFICATE_CONTENT_ITEM_ORD_ITEMS ||
        CERTIFICATE_CONTENT_SUBJECT_PUBLIC_KEY_INFO >= W->TypeVal.Sequence.Cnt) {
      INTERNAL_ERROR;
      FreeASN1 (&V);
      return CKR_GENERAL_ERROR;
    }

    /* If CERTIFICATE_CONTENT_SUBJECT_PUBLIC_KEY_INFO field is NOT found */
    for (I = 0; I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS; I++) {
      if (W->TypeVal.Sequence.Item[I].Ord ==
            CERTIFICATE_CONTENT_SUBJECT_PUBLIC_KEY_INFO) {
        W = &W->TypeVal.Sequence.Item[I].Val; /* Put the field into W */
        break;
      }
    }

    /* Check that the field is found and that subtypes are correct */
    if (!(I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS)                               ||
        W->Def->Type                  != ASN1_SEQUENCE_CLASS_TYPE               ||
        W->Def->TypeRef.Sequence->Cnt != SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD_ITEMS ||
        W->TypeVal.Sequence.Cnt       != W->Def->TypeRef.Sequence->Cnt          ||
        (X = &W->TypeVal.Sequence.
                Item[SUBJECT_PUBLIC_KEY_INFO_ALGORITHM].
                  Val)->Def->Type     != ASN1_SEQUENCE_CLASS_TYPE               ||
        X->Def->TypeRef.Sequence->Cnt != SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD_ITEMS ||
        X->TypeVal.Sequence.Cnt       != W->Def->TypeRef.Sequence->Cnt          ||
        (X = &X->TypeVal.Sequence.
                Item[SUBJECT_PUBLIC_KEY_INFO_ALGORITHM].
                  Val)->Def->Type     != ASN1_PRIM_CLASS_TYPE                   ||
        X->Def->TypeRef.Prim->Type    != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE) {
      INTERNAL_ERROR;
      FreeASN1 (&V);
      return CKR_GENERAL_ERROR;
    }

    /* Check that Object Identifier is NOT fake */
    if ((O = &X->TypeVal.Prim.ObjectIdentifier)->Len > 0) {

      /* Try to find a particular Object Identifier among known ones */
      for (I = 0; I < ARRAY_ITEMS (Keys); I++) {
        if (O->Len == Keys[I].Len) {
          CK_ULONG J;

          /* Compare Object Identifier against each other */
          for (J = 0; J < Keys[I].Len; J++) {
            if (O->Val[J] != Keys[I].Val[J]) {
              break;
            }
          }

          /* If a particular Object Identifier is found */
          if (!(J < Keys[I].Len)) {
            STATIC CK_BBOOL        Token = CK_FALSE;
            STATIC CK_OBJECT_CLASS Class = CKO_PUBLIC_KEY;

            CK_ATTRIBUTE    Template[]   = {
              { CKA_TOKEN,    &Token,   sizeof Token },
              { CKA_CLASS,    &Class,   sizeof Class },
              { CKA_KEY_TYPE, NULL_PTR, 0            },
              { CKA_VALUE,    NULL_PTR, 0            },
              { CKA_ID,       NULL_PTR, 0            },
              { CKA_LABEL,    NULL_PTR, 0            }
            };

            /* Initialize here because of Microsoft antique compiler */
            Template[2].pValue     = &Keys[I].KeyType;
            Template[2].ulValueLen = sizeof Keys[I].KeyType;
            Template[4].pValue     = pId;
            Template[4].ulValueLen = ulIdLen;
            Template[5].pValue     = pLabel;
            Template[5].ulValueLen = ulLabelLen;

            /* Get the BIT STRING of the ASN.1 encoded Public Key */
            if ((X = &W->TypeVal.Sequence.
                        Item[SUBJECT_PUBLIC_KEY_INFO_SUBJECT_PUBLIC_KEY].
                          Val)->Def->Type     != ASN1_PRIM_CLASS_TYPE ||
                X->Def->TypeRef.Prim->Type    != ASN1_BIT_STRING_PRIM_TYPE) {
              INTERNAL_ERROR;
              FreeASN1 (&V);
              return CKR_GENERAL_ERROR;
            }

            /* Find and initialize CK_VALUE item of Template */
            for (I = 0; I < ARRAY_ITEMS (Template); I++) {
              if (Template[I].type == CKA_VALUE) {
                Template[I].pValue     = X->TypeVal.Prim.BitString.Hex;
                Template[I].ulValueLen = X->TypeVal.Prim.BitString.Len / 8;
                break;
              }
            }

            /* If the item was oddly NOT found */
            if (!(I < ARRAY_ITEMS (Template))) {
              INTERNAL_ERROR;
              FreeASN1 (&V);
              return CKR_GENERAL_ERROR;
            }

            if ((rv = C_CreateObject (
                        hSession,
                        &Template[0], /* If pLabel == NULL then ignore the last item */
                        ARRAY_ITEMS (Template) - (pLabel == NULL_PTR),
                        &hObject
                        )) != CKR_OK) {
              FreeASN1 (&V);
              return rv;
            }
          }
        }
      }
    }
  }

  if ((rv = CreateObject (
              CERTIFICATE_TYPE_X509_CERTIFICATE,
              &ItemOrd,
              &W
              )) != CKR_OK) {
    FreeASN1 (&V);
    return rv;
  }

  if ((rv = CreateCommonObjectAttrs (
              pLabel,
              ulLabelLen,
              W
              )) != CKR_OK ||
      (rv = CreateClassAttrs (
              pId,
              ulIdLen,
              COMMON_CERTIFICATE_ATTRIBUTES_ID,
              CK_TRUE, /* Certificate */
              W
              )) != CKR_OK ||
      (rv = CreateTypeAttrs (
              pId,
              ulIdLen,
              X509_CERTIFICATE_ATTRIBUTES_VALUE,
              &W
              )) != CKR_OK) {
    FreeASN1 (&V);
    FreeASN1 (W);
    return rv;
  }

  if (W->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    FreeASN1 (&V);
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  W->Decoded                 = V.Decoded;
  W->TypeVal.SequenceOf.Item = V.TypeVal.SequenceOf.Item;
  W->TypeVal.SequenceOf.Cnt  = V.TypeVal.SequenceOf.Cnt;
  W->ASN1.Val                = V.ASN1.Val;
  W->ASN1.Len                = V.ASN1.Len;

  return ObjOrdsToHandle (phObject, Data, ObjOrd, ObjType, ItemOrd);
}

/* Object management functions */

/* C_CreateObject() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
  CK_SESSION_HANDLE    hSession,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phObject
  )
{
  enum {
    CKA_TOKEN_F            = 1,
    CKA_CLASS_F            = CKA_TOKEN              << 1,
    CKA_KEY_TYPE_F         = CKA_CLASS_F            << 1,
    CKA_CERTIFICATE_TYPE_F = CKA_KEY_TYPE_F         << 1,
    CKA_VALUE_F            = CKA_CERTIFICATE_TYPE_F << 1,
    CKA_LABEL_F            = CKA_VALUE_F            << 1,
    CKA_ID_F               = CKA_LABEL_F            << 1
  };

  CK_OBJECT_HANDLE    hObject    = CK_INVALID_HANDLE;
  CK_OBJECT_CLASS     Class      = CKO_VENDOR_DEFINED;
  CK_KEY_TYPE         KeyType    = CKK_VENDOR_DEFINED;
  CK_CERTIFICATE_TYPE CertType   = CKC_VENDOR_DEFINED;
  CK_VOID_PTR         pValue     = NULL_PTR;
  CK_ULONG            ulValueLen = 0;
  CK_VOID_PTR         pLabel     = NULL_PTR;
  CK_ULONG            ulLabelLen = 0;
  CK_VOID_PTR         pId        = NULL_PTR;
  CK_ULONG            ulIdLen    = 0;
  CK_ULONG            Flags      = 0;
  CK_ULONG            I;
  CK_ULONG            J;
  CK_RV               rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL_PTR || ulCount == 0 || phObject == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* R/W session type is supposed when creating objects */
  if (!(Cryptoki.Slots[I].Session.Flags & CKF_RW_SESSION)) {
    return CKR_SESSION_READ_ONLY;
  }

  if (Cryptoki.Slots[I].Session.Search.Initialized) {
    DEBUG ((
      EFI_D_ERROR,
      "C_CreateObject() canNOT be called "
      "when find operation is NOT finished\n"));
    return CKR_OPERATION_ACTIVE;
  }

  for (J = 0; J < ulCount; J++) {
    CK_BBOOL        Token   = CK_FALSE;

    switch (pTemplate[J].type) {
    case CKA_TOKEN:
      if ((Flags & CKA_TOKEN_F)) {
        DEBUG ((EFI_D_ERROR, "CKA_TOKEN attribute is specified multiply\n"));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_TOKEN_F;
      }

      if (pTemplate[J].ulValueLen != sizeof Token) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_TOKEN attribute has invalid size (MUST have size of %d)\n",
          sizeof Token));
        return CKR_FUNCTION_FAILED;
      }

      CopyMem (&Token, pTemplate[J].pValue, sizeof Token);

      if (Token) {
        DEBUG ((EFI_D_ERROR, "Creation of TOKEN objects is NOT supported\n"));
        return CKR_FUNCTION_FAILED;
      }

      break;
    case CKA_CLASS:
      if ((Flags & CKA_CLASS_F)) {
        DEBUG ((EFI_D_ERROR, "CKA_CLASS attribute is specified multiply\n"));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_CLASS_F;
      }

      if (pTemplate[J].ulValueLen != sizeof Class) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_CLASS attribute has invalid size (MUST have size of %d)\n",
          sizeof Class));
        return CKR_FUNCTION_FAILED;
      }

      CopyMem (&Class, pTemplate[J].pValue, sizeof Class);
      break;
    case CKA_KEY_TYPE:
      if ((Flags & CKA_KEY_TYPE_F)) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_KEY_TYPE attribute is specified multiply\n"
          ));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_KEY_TYPE_F;
      }

      if (pTemplate[J].ulValueLen != sizeof KeyType) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_KEY_TYPE attribute has invalid size (MUST have size of %d)\n",
          sizeof KeyType));
        return CKR_FUNCTION_FAILED;
      }

      CopyMem (&KeyType, pTemplate[J].pValue, sizeof KeyType);
      break;
    case CKA_CERTIFICATE_TYPE:
      if ((Flags & CKA_CERTIFICATE_TYPE_F)) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_CERTIFICATE_TYPE attribute is specified multiply\n"
          ));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_CERTIFICATE_TYPE_F;
      }

      if (pTemplate[J].ulValueLen != sizeof CertType) {
        DEBUG ((
          EFI_D_ERROR,
          "CKA_CERTIFICATE_TYPE attribute has invalid size (MUST be %d)\n",
          sizeof CertType));
        return CKR_FUNCTION_FAILED;
      }

      CopyMem (&CertType, pTemplate[J].pValue, sizeof CertType);
      break;
    case CKA_VALUE:
      if ((Flags & CKA_VALUE_F)) {
        DEBUG ((EFI_D_ERROR, "CKA_VALUE attribute is specified multiply\n"));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_VALUE_F;
      }

      pValue     = pTemplate[J].pValue;
      ulValueLen = pTemplate[J].ulValueLen;
      break;
    case CKA_LABEL:
      if ((Flags & CKA_LABEL_F)) {
        DEBUG ((EFI_D_ERROR, "CKA_LABEL attribute is specified multiply\n"));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_LABEL_F;
      }

      pLabel     = pTemplate[J].pValue;
      ulLabelLen = pTemplate[J].ulValueLen;
      break;
    case CKA_ID:
      if ((Flags & CKA_ID_F)) {
        DEBUG ((EFI_D_ERROR, "CKA_ID attribute is specified multiply\n"));
        return CKR_FUNCTION_FAILED;
      } else {
        Flags |= CKA_ID_F;
      }

      pId     = pTemplate[J].pValue;
      ulIdLen = pTemplate[J].ulValueLen;
      break;
    default:
      continue; /* Bypass unknown/irrelevant attributes silently */
    }
  }

  if (!(Flags & CKA_CLASS_F)) {
    DEBUG ((
      EFI_D_ERROR,
      "CKA_CLASS attribute must be specified while calling C_CreateObject()\n"
      ));
    return CKR_TEMPLATE_INCOMPLETE;
  }

  switch (Class) {
  case CKO_PUBLIC_KEY:
    if (!(Flags & CKA_KEY_TYPE_F)) {
      DEBUG ((
        EFI_D_ERROR,
        "CKA_KEY_TYPE attribute must be specified "
        "while calling C_CreateObject()\n"
        ));
      return CKR_TEMPLATE_INCOMPLETE;
    }

    if (!(Flags & CKA_VALUE_F)) {
      DEBUG ((
        EFI_D_ERROR,
        "CKA_VALUE attribute must be specified "
        "while calling C_CreateObject()\n"
        ));
      return CKR_TEMPLATE_INCOMPLETE;
    }

    switch (KeyType) {
    case CKK_RSA:
      rv = CreatePublicKey_RSA (
             &Cryptoki.Slots[I].Data,
             pLabel,
             ulLabelLen,
             pId,
             ulIdLen,
             pValue,
             ulValueLen,
             &hObject
             );
      break;
    case CKK_GOSTR3410:
      rv = CreatePublicKey_GOSTR3410 (
             &Cryptoki.Slots[I].Data,
             pLabel,
             ulLabelLen,
             pId,
             ulIdLen,
             pValue,
             ulValueLen,
             &hObject
             );
      break;
    default:
      DEBUG ((
        EFI_D_ERROR,
        "Unsupported key type (GOSTR3410 is supported only)\n"
        ));
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    break;
  case CKO_CERTIFICATE:
    if (!(Flags & CKA_CERTIFICATE_TYPE_F)) {
      DEBUG ((
        EFI_D_ERROR,
        "CKA_CERTIFICATE_TYPE attribute must be specified "
        "while calling C_CreateObject()\n"
        ));
      return CKR_TEMPLATE_INCOMPLETE;
    }

    if (!(Flags & CKA_VALUE_F)) {
      DEBUG ((
        EFI_D_ERROR,
        "CKA_VALUE attribute must be specified "
        "while calling C_CreateObject()\n"
        ));
      return CKR_TEMPLATE_INCOMPLETE;
    }

    switch (CertType) {
    case CKC_X_509:
      rv = CreateCertificate_X509 (
             hSession,
             &Cryptoki.Slots[I].Data,
             pLabel,
             ulLabelLen,
             pId,
             ulIdLen,
             pValue,
             ulValueLen,
             &hObject
             );

      break;
    default:
      DEBUG ((
        EFI_D_ERROR,
        "Unsupported Certificate type (CKC_X_509 is supported only)\n"
        ));
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    break;
  default:
    DEBUG ((
      EFI_D_ERROR,
      "Unsupported CKA_CLASS attribute value "
      "(CKO_PUBLIC_KEY or CKO_CERTIFICATE are supported only)\n"
      ));
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  if (rv == CKR_OK) {
    *phObject = hObject;
  }

  return rv;
}

/* C_CopyObject() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE     hObject,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL_PTR || ulCount == 0 || phNewObject == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Forward declarations */
static CK_RV GetCommonObjAttrLabel (ASN1_UTF8_STRING_VAL **W, ASN1_TYPE_VAL *V);
static CK_RV GetCommonCertAttrID (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V);

/* C_DestroyObject() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject
  )
{
  CK_ULONG                  ObjOrd  = 0;
  OBJECT_TYPE               ObjType = ANY_OBJECT;
  CK_ULONG                  ItemOrd = 0;
  ASN1_TYPE_VAL             *V      = NULL_PTR;
  ASN1_SEQUENCE_OF_TYPE_VAL *Seq    = NULL_PTR;
  CK_VOID_PTR               Tmp     = NULL_PTR; /* Important initialization! */
  CK_ULONG                  I;
  CK_RV                     rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* R/W session type is supposed when destroying objects */
  if (!(Cryptoki.Slots[I].Session.Flags & CKF_RW_SESSION)) {
    return CKR_SESSION_READ_ONLY;
  }

  /* Ensure there is no active search operation */
  if (Cryptoki.Slots[I].Session.Search.Initialized) {
    DEBUG ((
      EFI_D_ERROR,
      "C_DestroyObject() canNOT be called "
      "when find operation is NOT finished\n"));
    return CKR_OPERATION_ACTIVE;
  }

  /* Ensure there is no active crypto operation */
  if (Cryptoki.Slots[I].Operations != OPERATION_NONE) {
    DEBUG ((
      EFI_D_ERROR,
      "C_DestroyObject() canNOT be called "
      "when any crypto operation (Digest, Decrypt, Verify) is NOT finished\n"));
    return CKR_OPERATION_ACTIVE;
  }

  /* Convert object handle to the triple of indices */
  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hObject)) != CKR_OK) {
    return rv;
  }

  if (ObjType != SESSION_OBJECT) {
    DEBUG ((EFI_D_ERROR, "Destruction of TOKEN objects is NOT supported\n"));
    return CKR_FUNCTION_FAILED;
  }

  /* Getting SEQUENCE OF PKCS15Objects for a particular object type */
  V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType];

  if (V->Def->Type                  != ASN1_SEQUENCE_OF_CLASS_TYPE         ||
      ItemOrd                       >= (Seq = &V->TypeVal.SequenceOf)->Cnt) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  switch (ObjOrd) {
  case PKCS15_OBJECTS_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
    /* FIXME: Check whether a Public Key with the same Label/Id exists and destroy it first */
    {
      STATIC CK_BBOOL        Token     = CK_FALSE;
      STATIC CK_OBJECT_CLASS Class     = CKO_PUBLIC_KEY;
      CK_ULONG               Count     = 0;
      ASN1_UTF8_STRING_VAL   *L        = NULL_PTR;
      ASN1_OCTET_STRING_VAL  *I        = NULL_PTR;

      CK_ATTRIBUTE          Template[] = {
        { CKA_TOKEN, &Token,   sizeof Token },
        { CKA_CLASS, &Class,   sizeof Class },
        { CKA_ID,    NULL_PTR, 0            },
        { CKA_LABEL, NULL_PTR, 0            }
      };

      if ((V = &Seq->Item[ItemOrd])->Def->Type != ASN1_CHOICE_CLASS_TYPE ||
          V->Def->TypeRef.Choice->Cnt != CERTIFICATE_TYPE_CHOICE_ITEM_ORD_ITEMS) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      V = &V->TypeVal.Choice.Item->Val;

      /* Get Id and Label fields of PKCS#15 Certificate object */
      if ((rv = GetCommonCertAttrID (&I, V))   != CKR_OK ||
          (rv = GetCommonObjAttrLabel (&L, V)) != CKR_OK ||
          rv != CKR_VENDOR_DEFINED) {
      }

      /* Find and initialize ID */
      for (Count = 0; Count < ARRAY_ITEMS (Template); Count++) {
        if (Template[Count].type == CKA_ID) {
          Template[Count].pValue     = I->Val;
          Template[Count].ulValueLen = I->Len;
          break;
        }
      }

        /* If item was oddly NOT found */
      if (!(Count < ARRAY_ITEMS (Template))) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      /* If Label field is present in PKCS#15 Certificate object */
      if (rv != CKR_VENDOR_DEFINED) {

        /* Find and initialize Label */
        for (Count = 0; Count < ARRAY_ITEMS (Template); Count++) {
          if (Template[Count].type == CKA_LABEL) {
            Template[Count].pValue     = L->Val;
            Template[Count].ulValueLen = L->Len;
            break;
          }
        }

        /* If item was oddly NOT found */
        if (!(Count < ARRAY_ITEMS (Template))) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }
      }

      /* Try to find a Public Key with the same Label and Id */
      if ((rv = C_FindObjectsInit (
                  hSession,
                  &Template[0], /* If NO Label Attr then ignore the last item */
                  ARRAY_ITEMS (Template) - (rv == CKR_VENDOR_DEFINED)
                  ))                                           != CKR_OK ||
          (rv = C_FindObjects (hSession, &hObject, 1, &Count)) != CKR_OK ||
          (rv = C_FindObjectsFinal (hSession))                 != CKR_OK) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      /* Since Public Key SEQUENCE OF is different the recursive call is safe */
      if (Count == 1 && (rv = C_DestroyObject (hSession, hObject)) != CKR_OK) {
          return rv;
      }
    }

    break;
  default:
    break;
  }

  /* Free ASN.1 subobjects of the object being deleted */
  if ((rv = FreeASN1 (&Seq->Item[ItemOrd])) != CKR_OK) {
    return rv;
  }

  /* If deleted object is NOT last in the vector then allocate a new vector */
  if (Seq->Cnt                                                   >  1 &&
      (rv = AllocMem (&Tmp, (Seq->Cnt - 1) * sizeof *Seq->Item)) != CKR_OK) {
      return rv;
  }

  /* If the first part of the old vector is to copy */
  if (ItemOrd > 0) {
    CopyMem (Tmp, &Seq->Item[0], ItemOrd * sizeof *Seq->Item);
  }

  /* If the last part of the old vector is to copy */
  if (ItemOrd + 1 < Seq->Cnt) {
    CopyMem (
      (CK_BYTE *)Tmp + ItemOrd * sizeof *Seq->Item,
      &Seq->Item[ItemOrd + 1],
      (Seq->Cnt - ItemOrd - 1) * sizeof *Seq->Item);
  }

  /* Free the old vector */
  if ((rv = FreeMem (Seq->Item)) != CKR_OK) {
    FreeMem (Tmp); /* Ignore possible error here */
    return rv;
  }

  /* Set the new vector up and correct the number of items in it */
  Seq->Item = Tmp;
  Seq->Cnt--;
  return CKR_OK;
}

/* C_GetObjectSize() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ULONG_PTR      pulSize
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulSize == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetAttributeValue/C_FindObjects helper functions */

static CK_RV GetSequenceField (ASN1_TYPE_VAL **V, CK_ULONG Ord)
{
  CK_ULONG I;

  /* Supplied object must be decoded and be a SEQUENCE, Ord must be valid */
  if (V               == NULL_PTR                 ||
      !(*V)->Decoded                              ||
      (*V)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE ||
      !(Ord           <  (*V)->Def->TypeRef.Sequence->Cnt)) {
    return CKR_FUNCTION_FAILED;
  }

  /* Find the index of the SEQUENCE field specified by the Ord ordinal number */
  for (I = 0; I < (*V)->TypeVal.Sequence.Cnt; I++) {
    if ((*V)->TypeVal.Sequence.Item[I].Ord == Ord) {
      break;
    }
  }

  /* If the field is NOT found */
  if (!(I < (*V)->TypeVal.Sequence.Cnt)) {
    if ((*V)->Def->TypeRef.Sequence->Item[Ord].Type != ASN1_ITEM_OPTIONAL) {
      return CKR_FUNCTION_FAILED;
    }

    *V = NULL_PTR;
  } else {
    *V = &(*V)->TypeVal.Sequence.Item[I].Val;
  }

  return CKR_OK;
}

static CK_RV GetChoiceField (ASN1_TYPE_VAL **V, CK_ULONG Ord)
{
  /* Supplied object must be decoded and be a CHOICE, Ord must be valid */
  if (V               == NULL_PTR                        ||
      !(*V)->Decoded                                     ||
      (*V)->Def->Type != ASN1_CHOICE_CLASS_TYPE          ||
      !(Ord           <  (*V)->Def->TypeRef.Choice->Cnt) ||
      Ord             != (*V)->TypeVal.Choice.Item->Ord) {
    return CKR_FUNCTION_FAILED;
  }

  *V = &(*V)->TypeVal.Choice.Item->Val;
  return CKR_OK;
}

static CK_RV GetPKCS15ObjField (
  ASN1_TYPE_VAL                   **V, /* PKCS15 object */
  PKCS15_OBJECT_SEQUENCE_ITEM_ORD Ord  /* Filed ordinal number */
  )
{
  return GetSequenceField (V, Ord);
}

static CK_RV GetCommonObjAttrField (
  ASN1_TYPE_VAL                              **V, /* CommonObjAttr object */
  COMMON_OBJECT_ATTRIBUTES_SEQUENCE_ITEM_ORD Ord  /* Field ordinal number */
  )
{
  /* Get the PKCS15 object CommonObjectAttributes field */
  CK_RV rv = GetPKCS15ObjField (V, PKCS15_OBJECT_COMMON_OBJECT_ATTRIBUTES_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  /* Get the CommonObjectAttributes object field by the Ord ordinal number */
  return GetSequenceField (V, Ord);
}

static CK_RV GetCommonKeyAttrField (
  ASN1_TYPE_VAL                           **V, /* CommonKeyAttr object */
  COMMON_KEY_ATTRIBUTES_SEQUENCE_ITEM_ORD Ord  /* Field ordinal number */
  )
{
  /* Get the PKCS15 object ClassAttributes field */
  CK_RV rv = GetPKCS15ObjField (V, PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  /* Get the CommonObjectAttributes object field by the Ord ordinal number */
  return GetSequenceField (V, Ord);
}

static CK_RV GetCommonCertAttrField (
  ASN1_TYPE_VAL                                   **V, /* CommonCertAttr object */
  COMMON_CERTIFICATE_ATTRIBUTES_SEQUENCE_ITEM_ORD Ord  /* Field ordinal number */
  )
{
  /* Get the PKCS15 object ClassAttributes field */
  CK_RV rv = GetPKCS15ObjField (V, PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  /* Get the CommonObjectAttributes object field by the Ord ordinal number */
  return GetSequenceField (V, Ord);
}

static CK_RV GetCommonObjAttrLabel (ASN1_UTF8_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the CommonObjectAttributes object Label field */
  CK_RV rv = GetCommonObjAttrField (&V, COMMON_OBJECT_ATTRIBUTES_LABEL_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  /* If an optional field encountered and it was NOT found */
  if (V == NULL_PTR) {
    return CKR_FUNCTION_FAILED;
  }

  /* The CommonObjectAttributes Label field must be of the UTF8 STRING type */
  if (V->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type != ASN1_UTF8_STRING_PRIM_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->TypeVal.Prim.Utf8String;
  return CKR_OK;
}

static CK_RV GetCommonObjAttrFlags (ASN1_BIT_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the CommonObjectAttributes object Flags field */
  CK_RV rv = GetCommonObjAttrField (&V, COMMON_OBJECT_ATTRIBUTES_FLAGS_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  /* If an optional field encountered and it was NOT found */
  if (V == NULL_PTR) {
    return CKR_VENDOR_DEFINED;
  }

  /* The CommonObjectAttributes Label field must be of the BIT STRING type */
  if (V->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type != ASN1_BIT_STRING_PRIM_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->TypeVal.Prim.BitString;
  return CKR_OK;
}

static CK_RV GetCommonKeyAttrID (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the CommonObjectAttributes object Flags field */
  CK_RV rv = GetCommonKeyAttrField (&V, COMMON_KEY_ATTRIBUTES_ID);

  if (rv != CKR_OK) {
    return rv;
  }

  /* If an optional field encountered and it was NOT found */
  if (V == NULL_PTR) {
    return CKR_FUNCTION_FAILED;
  }

  /* The CommonObjectAttributes Label field must be of the OCTET STRING type */
  if (V->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->TypeVal.Prim.OctetString;
  return CKR_OK;
}

static CK_RV GetCommonKeyAttrUsage (ASN1_BIT_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the CommonObjectAttributes object Flags field */
  CK_RV rv = GetCommonKeyAttrField (&V, COMMON_KEY_ATTRIBUTES_USAGE);

  if (rv != CKR_OK) {
    return rv;
  }

  /* If an optional field encountered and it was NOT found */
  if (V == NULL_PTR) {
    return CKR_FUNCTION_FAILED;
  }

  /* The CommonObjectAttributes Label field must be of the BIT STRING type */
  if (V->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type != ASN1_BIT_STRING_PRIM_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->TypeVal.Prim.BitString;
  return CKR_OK;
}

static CK_RV GetCommonCertAttrID (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the CommonObjectAttributes object Flags field */
  CK_RV rv = GetCommonCertAttrField (&V, COMMON_CERTIFICATE_ATTRIBUTES_ID);

  if (rv != CKR_OK) {
    return rv;
  }

  /* If an optional field encountered and it was NOT found */
  if (V == NULL_PTR) {
    return CKR_FUNCTION_FAILED;
  }

  /* The CommonObjectAttributes Label field must be of the OCTET STRING type */
  if (V->Def->Type               != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type != ASN1_OCTET_STRING_PRIM_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->TypeVal.Prim.OctetString;
  return CKR_OK;
}

static CK_RV GetTypeAttrCertField (ASN1_TYPE_VAL **V)
{
  /* Get the PKCS15 object TypeAttributes field */
  CK_RV rv = GetPKCS15ObjField (V, PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD);

  /* Get the X509 Certificate field */
  if (rv                                                             != CKR_OK ||
      (rv = GetSequenceField (V, CERTIFICATE_TYPE_X509_CERTIFICATE)) != CKR_OK) {
    return rv;
  }

  /* Direct CHOICE in X509 Certificate type MUST be prevously decoded */
  return GetChoiceField (V, OBJECT_VALUE_DIRECT_ORD);
}

static CK_RV GetTypeAttrPublicKeyValue (
               ASN1_OCTET_STRING_VAL **W,
               ASN1_TYPE_VAL         *V,
               CK_ULONG              Ord
               )
{
  /* Get the PKCS15 object TypeAttributes field */
  CK_RV rv = GetPKCS15ObjField (&V, PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD);

  if (rv != CKR_OK) {
    return rv;
  }

  switch (Ord) {
  case PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY:
    rv = GetSequenceField (&V, PUBLIC_RSA_KEY_ATTRIBUTES_VALUE);
    break;
  case PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY:
    rv = GetSequenceField (&V, PUBLIC_KEA_KEY_ATTRIBUTES_VALUE);
    break;
  default:
    return CKR_FUNCTION_FAILED;
  }

  if (rv != CKR_OK) {
    return rv;
  }

  if ((rv = GetChoiceField (&V, OBJECT_VALUE_DIRECT_ORD)) != CKR_OK) {
    return rv;
  }

  switch (Ord) {
  case PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY:
    /* The RSA Public Key TypeAttributes field must be of the CHOICE type */
    if ((rv = GetChoiceField (&V, RSA_PUBLIC_KEY_CHOICE_RAW)) != CKR_OK) {
      return rv;
    }

    /* The RSA Public Key must be of the SEQUENCE type */
    if (V->Def->Type != ASN1_SEQUENCE_CLASS_TYPE || !V->Def->ASN1 ||
        V->ASN1.Val  == NULL_PTR                 || V->ASN1.Len  == 0) {
      return CKR_FUNCTION_FAILED;
    }

    break;
  case PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY:
    /* The GOST Public Key TypeAttributes field must be of the CHOICE type */
    if ((rv = GetChoiceField (&V, KEA_PUBLIC_KEY_CHOICE_RAW)) != CKR_OK) {
      return rv;
    }

    /* A GOST Public Key must be of the OCTET STRING type */
    if (V->Def->Type                    != ASN1_PRIM_CLASS_TYPE        ||
        V->Def->TypeRef.Prim->Type      != ASN1_OCTET_STRING_PRIM_TYPE ||
        V->TypeVal.Prim.OctetString.Val == NULL_PTR                    ||
        V->TypeVal.Prim.OctetString.Len != 64                          ||
        !V->Def->ASN1                                                  ||
        V->ASN1.Val                     == NULL_PTR                    ||
        V->ASN1.Len                     == 0) {
      return CKR_FUNCTION_FAILED;
    }

    break;
  default:
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->ASN1;
  return CKR_OK;
}

static CK_RV GetTypeAttrCertValue (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the TypeAttributes Certificate field */
  CK_RV rv = GetTypeAttrCertField (&V);

  if (rv != CKR_OK) {
    return rv;
  }

  /* The TypeAttributes Certificate field must be of the SEQUENCE type */
  if (V->Def->Type != ASN1_SEQUENCE_CLASS_TYPE || !V->Def->ASN1 ||
      V->ASN1.Val  == NULL_PTR                 || V->ASN1.Len  == 0) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->ASN1;
  return CKR_OK;
}

static CK_RV GetTypeAttrCertContField (
  ASN1_TYPE_VAL                **V, /* TypeAttrCert object */
  CERTIFICATE_CONTENT_ITEM_ORD Ord  /* Field ordinal number */
  )
{
  /* Get the PKCS15 object TypeAttributes Certificate field */
  CK_RV rv = GetTypeAttrCertField (V);

  if (rv                                                           != CKR_OK ||
      (rv = GetSequenceField (V, CERTIFICATE_CERTIFICATE_CONTENT)) != CKR_OK) {
    return rv;
  }

  /* Get a particular field by the Ord ordinal number */
  return GetSequenceField (V, Ord);
}

static CK_RV GetTypeAttrCertContSerNumber(ASN1_INTEGER_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the Certificate Contents field */
  CK_RV rv = GetTypeAttrCertContField (&V, CERTIFICATE_CONTENT_SERIAL_NUMBER);
  
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
  /*
  if (V->Def->Type != ASN1_PRIM_CLASS_TYPE || 
      V->TypeVal.Prim.Integer.Val.Long.Val  == NULL_PTR ||
      V->TypeVal.Prim.Integer.Val.Long.Len  == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Not a PRIM type or empty\n", __FUNCTION__, __LINE__));
    return CKR_FUNCTION_FAILED;
  }
  */
  if (V->Def->Type != ASN1_PRIM_CLASS_TYPE)
	  DEBUG((EFI_D_ERROR, "%a.%d Not a PRIM type or empty  1\n", __FUNCTION__, __LINE__));
  else if(V->TypeVal.Prim.Integer.Val.Long.Val  == NULL_PTR)
	  DEBUG((EFI_D_ERROR, "%a.%d Not a PRIM type or empty  2\n", __FUNCTION__, __LINE__));
  else if(V->TypeVal.Prim.Integer.Long  == 0)
	  DEBUG((EFI_D_ERROR, "%a.%d Not a PRIM type or empty  3\n", __FUNCTION__, __LINE__));
  else if(V->TypeVal.Prim.Integer.Val.Long.Len  == 0)
	  DEBUG((EFI_D_ERROR, "%a.%d Not a PRIM type or empty  3.1\n", __FUNCTION__, __LINE__));

  *W = &V->TypeVal.Prim.Integer;

  return CKR_OK;
}

static CK_RV GetTypeAttrCertContIssuer (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the Certificate Contents field */
  CK_RV rv = GetTypeAttrCertContField (&V, CERTIFICATE_CONTENT_ISSUER);

  if (rv != CKR_OK || (rv = GetChoiceField (&V, NAME_RDN_SEQUENCE)) != CKR_OK) {
    return rv;
  }

  /* The rdnSequence field must be of the SEQUENCE OF type */
  if (V->Def->Type != ASN1_SEQUENCE_OF_CLASS_TYPE || !V->Def->ASN1 ||
      V->ASN1.Val  == NULL_PTR                    || V->ASN1.Len  == 0) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->ASN1;
  return CKR_OK;
}

static CK_RV GetTypeAttrCertContSubject (ASN1_OCTET_STRING_VAL **W, ASN1_TYPE_VAL *V)
{
  /* Get the Certificate Contents field */
  CK_RV rv = GetTypeAttrCertContField (&V, CERTIFICATE_CONTENT_SUBJECT);

  if (rv != CKR_OK || (rv = GetChoiceField (&V, NAME_RDN_SEQUENCE)) != CKR_OK) {
    return rv;
  }

  /* The rdnSequence field must be of the SEQUENCE OF type */
  if (V->Def->Type != ASN1_SEQUENCE_OF_CLASS_TYPE || !V->Def->ASN1 ||
      V->ASN1.Val  == NULL_PTR                    || V->ASN1.Len  == 0) {
    return CKR_FUNCTION_FAILED;
  }

  *W = &V->ASN1;
  return CKR_OK;
}

static CK_RV GetTypeAttrCertContValidity (ASN1_TYPE_VAL **V)
{
  /* Get the Certificate Contents field */
  CK_RV rv = GetTypeAttrCertContField (V, CERTIFICATE_CONTENT_VALIDITY);

  if (rv != CKR_OK) {
    return rv;
  }

  /* The Validity field must be of the OCTET STRING type */
  if ((*V)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

static CK_RV GetStartEndDates (ASN1_TYPE_VAL *V, CK_DATE *SDate, CK_DATE *EDate)
{
  CK_ULONG I;
  CK_DATE  *Dates[] = { NULL_PTR, NULL_PTR };
  CK_RV    rv       = GetTypeAttrCertContValidity (&V);

  /* Initialize here because of Microsoft antique compiler */
  Dates[0] = SDate;
  Dates[1] = EDate;

  if (rv != CKR_OK) {
    return rv;
  }

  if (V->TypeVal.Sequence.Cnt != ARRAY_ITEMS (Dates)) {
    DEBUG ((EFI_D_ERROR, "Invalid certificate start/end date storage\n"));
    return CKR_FUNCTION_FAILED;
  }

  for (I = 0; I < ARRAY_ITEMS (Dates); I++) {
    ASN1_UTC_TIME_VAL *T = NULL_PTR;
    ASN1_TYPE_VAL     *W = &V->TypeVal.Sequence.Item[I].Val;

    if (W->Def->Type != ASN1_CHOICE_CLASS_TYPE) {
      DEBUG ((EFI_D_ERROR, "Invalid certificate start/end date storage type\n"));
      return CKR_FUNCTION_FAILED;
    }

    if (W->TypeVal.Choice.Item->Ord != TIME_UTC_TIME) {
      DEBUG ((EFI_D_ERROR, "Unsupported certificate start/end date format\n"));
      return CKR_FUNCTION_FAILED;
    }

    W = &W->TypeVal.Choice.Item->Val; /* W becomes UTCTime */

    if (W->Def->Type                        != ASN1_PRIM_CLASS_TYPE    ||
        W->Def->TypeRef.Prim->Type          != ASN1_UTC_TIME_PRIM_TYPE ||
        (T = &W->TypeVal.Prim.UTCTime)->Val == NULL_PTR                ||
        T->Len                              == 0) {
      DEBUG ((EFI_D_ERROR, "Invalid certificate start/end date format\n"));
      return CKR_FUNCTION_FAILED;
    }

    if (T->Val[T->Len - 1] != 'Z') {
      DEBUG ((EFI_D_ERROR, "Unsupported non-UTC date format\n"));
      return CKR_FUNCTION_FAILED;
    }

    switch (T->Len) {
    case 8 + 1: /* Four-digit year format */
      Dates[I]->year[0]  = T->Val[0];
      Dates[I]->year[1]  = T->Val[1];
      Dates[I]->year[2]  = T->Val[2];
      Dates[I]->year[3]  = T->Val[3];
      Dates[I]->month[0] = T->Val[4];
      Dates[I]->month[1] = T->Val[5];
      Dates[I]->day[0]   = T->Val[6];
      Dates[I]->day[1]   = T->Val[7];
        break;
    case 12 + 1: /* Two-digit year format */
      Dates[I]->year[0]  = '2'; /* Start forming '20' of 20XX year */
      Dates[I]->year[1]  = '0'; /* Stop  forming '20' of 20XX year */
      Dates[I]->year[2]  = T->Val[0]; /* Start forming 'XX' of 20XX year */
      Dates[I]->year[3]  = T->Val[1]; /* Stop  forming 'XX' of 20XX year */
      Dates[I]->month[0] = T->Val[2];
      Dates[I]->month[1] = T->Val[3];
      Dates[I]->day[0]   = T->Val[4];
      Dates[I]->day[1]   = T->Val[5];
      break;
    default:
      DEBUG ((EFI_D_ERROR, "Unsupported UTC date format\n"));
      return CKR_FUNCTION_FAILED;
    }
  }

  return CKR_OK;
}

static inline CK_BBOOL BitVal (ASN1_BIT_STRING_VAL *V, CK_ULONG N)
{
  return
#ifdef _MSC_VER
    (CK_BBOOL)
#endif /* _MSC_VER */
    (V->Len >= N && V->Val[N] != 0);
}

/* Cases mentioned below are from PKCS#11 v2-30b-d6, page 131 */
static CK_RV AssignAttrValue (
  CK_ATTRIBUTE_PTR  pTmpl,
  VOID CONST        *Val,
  CK_ULONG          Len,
  CK_RV             rv
  )
{
  if (pTmpl->pValue == NULL_PTR) { /* Case 3 */
    pTmpl->ulValueLen = Len;
    return rv;
  }

  if (Len <= pTmpl->ulValueLen) { /* Case 4 */
    CopyMem (pTmpl->pValue, Val, pTmpl->ulValueLen = Len);
    return rv;
  }

  pTmpl->ulValueLen = (CK_ULONG)-1; /* Case 5 */
  return rv != CKR_OK ? rv : CKR_BUFFER_TOO_SMALL;
}

/* C_GetAttributeValue() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
  )
{
  enum { FLAGS_PRIVATE, FLAGS_MODIFIABLE };
  enum { USAGE_ENCRYPT, USAGE_DECRYPT, USAGE_SIGN, USAGE_SIGN_RECOVER,
         USAGE_WRAP, USAGE_UNWRAP, USAGE_VERIFY, USAGE_VERIFY_RECOVER,
         USAGE_DERIVE, USAGE_NON_REPUDIATION };

  ASN1_TYPE_VAL *V;
  CK_ULONG      ObjOrd  = 0;
  CK_ULONG      Ord     = 0;
  OBJECT_TYPE   ObjType = ANY_OBJECT;
  CK_ULONG      ItemOrd = 0;
  CK_ULONG      I;
  CK_ULONG      J;
  CK_RV         rv;

  ASN1_UTF8_STRING_VAL  *Label   = NULL_PTR;
  ASN1_BIT_STRING_VAL   *Flags   = NULL_PTR;
  ASN1_OCTET_STRING_VAL *ID      = NULL_PTR;
  ASN1_BIT_STRING_VAL   *Usage   = NULL_PTR;
  ASN1_OCTET_STRING_VAL *Issuer  = NULL_PTR;
  ASN1_INTEGER_VAL      *SerNum  = NULL_PTR;
  ASN1_OCTET_STRING_VAL *Subject = NULL_PTR;
  ASN1_OCTET_STRING_VAL *Value   = NULL_PTR;

  CK_DATE               StartDate;
  CK_DATE               EndDate;

  CK_KEY_TYPE     KT = (CK_KEY_TYPE)-1;
  CK_OBJECT_CLASS CL = (CK_OBJECT_CLASS)-1;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL_PTR || ulCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hObject
              )) != CKR_OK) {
    return rv;
  }

  /* If object is NOT decoded, then invalid hObject value is supplied */
  if (!(V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType].TypeVal.
               SequenceOf.Item[ItemOrd])->Decoded) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Keep a particular CHOICE in the local variable */
  Ord = V->TypeVal.Choice.Item->Ord;
  //LOG((EFI_D_ERROR, "%a.%d 1\n", __FUNCTION__, __LINE__));
  /* Find out an object class and a key type if it is a private/public key */
  switch (ObjOrd) {
  case PKCS15_OBJECTS_PRIVATE_KEYS_ORD:
    switch (Ord) {
    case PRIVATE_KEY_TYPE_PRIVATE_RSA_KEY:
      KT = CKK_RSA;
      break;
    case PRIVATE_KEY_TYPE_PRIVATE_KEA_KEY:
      KT = CKK_GOSTR3410;
      break;
    default:
      break;
    }

    CL = CKO_PRIVATE_KEY;
    break;
  case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
  case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
    /* RSA and GOST2001 (used instead of KEA) Public Keys are supported only */
    switch (Ord) {
    case PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY:
      KT = CKK_RSA;
      break;
    case PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY:
      KT = CKK_GOSTR3410;
      break;
    default:
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    CL = CKO_PUBLIC_KEY;
    break;
  case PKCS15_OBJECTS_SECRET_KEYS_ORD:
    CL = CKO_SECRET_KEY;
    break;
  case PKCS15_OBJECTS_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
    /* X509Certificates are supported only */
    switch (Ord) {
    case CERTIFICATE_TYPE_X509_CERTIFICATE:
      break;
    default:
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    CL = CKO_CERTIFICATE;
    break;
  case PKCS15_OBJECTS_DATA_OBJECTS_ORD:
    CL = CKO_DATA;
    break;
  case PKCS15_OBJECTS_AUTH_OBJECTS_ORD:
    break;
  default:
    break;
  }
  //LOG((EFI_D_ERROR, "%a.%d 2\n", __FUNCTION__, __LINE__));
  V = &V->TypeVal.Choice.Item->Val;

  if ((rv = GetCommonObjAttrLabel (&Label, V)) != CKR_OK &&
      rv                                       != CKR_VENDOR_DEFINED) {
    return rv;
  }
  //LOG((EFI_D_ERROR, "%a.%d 3\n", __FUNCTION__, __LINE__));

  if ((rv = GetCommonObjAttrFlags (&Flags, V)) != CKR_OK &&
      rv                                       != CKR_VENDOR_DEFINED) {
    return rv;
  }
  //LOG((EFI_D_ERROR, "%a.%d 4\n", __FUNCTION__, __LINE__));
  if (Flags != NULL_PTR             &&
      BitVal (Flags, FLAGS_PRIVATE) &&
      !(Cryptoki.Slots[I].Session.State != CKS_RO_USER_FUNCTIONS ||
        Cryptoki.Slots[I].Session.State != CKS_RW_USER_FUNCTIONS)) {
    /* Illegal hObject (could not be obtained over C_FindObjects) */
    return CKR_ARGUMENTS_BAD;
  }
  //LOG((EFI_D_ERROR, "%a.%d 5\n", __FUNCTION__, __LINE__));
  switch (ObjOrd) {
  case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
  case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
    if ((rv = GetTypeAttrPublicKeyValue (&Value, V, Ord)) != CKR_OK) {
      return rv;
    }
    /* Intentional pass through */
  case PKCS15_OBJECTS_PRIVATE_KEYS_ORD://LOG((EFI_D_ERROR, "%a.%d 5.1\n", __FUNCTION__, __LINE__));
  case PKCS15_OBJECTS_SECRET_KEYS_ORD://LOG((EFI_D_ERROR, "%a.%d 5.2\n", __FUNCTION__, __LINE__));
    if ((rv = GetCommonKeyAttrID (&ID, V))       != CKR_OK ||
        (rv = GetCommonKeyAttrUsage (&Usage, V)) != CKR_OK) {
      return rv;
    }

    break;
  case PKCS15_OBJECTS_CERTIFICATES_ORD://LOG((EFI_D_ERROR, "%a.%d 5.3\n", __FUNCTION__, __LINE__));
  case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD://LOG((EFI_D_ERROR, "%a.%d 5.4\n", __FUNCTION__, __LINE__));
  case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD://LOG((EFI_D_ERROR, "%a.%d 5.5\n", __FUNCTION__, __LINE__));
    if ((rv = GetCommonCertAttrID (&ID, V))               != CKR_OK ||
        (rv = GetTypeAttrCertContIssuer (&Issuer, V))     != CKR_OK ||
        (rv = GetTypeAttrCertContSerNumber (&SerNum, V))  != CKR_OK ||
        (rv = GetTypeAttrCertContSubject (&Subject, V))   != CKR_OK ||
        (rv = GetTypeAttrCertValue (&Value, V))           != CKR_OK ||
        (rv = GetStartEndDates (V, &StartDate, &EndDate)) != CKR_OK) {
      return rv;
    }

    break;
  default:
    break;
  }
  //LOG((EFI_D_ERROR, "%a.%d 6\n", __FUNCTION__, __LINE__));
  /* Processing all the attributes specified in the template */
  for (J = 0; J < ulCount; J++) {
    CK_ATTRIBUTE_PTR pTmpl = &pTemplate[J];
    CK_BBOOL CONST   Token = (CK_BBOOL)(ObjType == TOKEN_OBJECT);
    CK_BBOOL         B;

    /* Cases mentioned below are from PKCS#11 v2-30b-d6, page 131 */
    switch (pTmpl->type) {
    case CKA_TOKEN: /* The general attribute */
      rv = AssignAttrValue (pTmpl, &Token, sizeof Token, rv);
      break;
    case CKA_CLASS: /* The general attribute */
      rv = AssignAttrValue (pTmpl, &CL, sizeof CL, rv);
      break;
    case CKA_LABEL: /* The CommonObjectAttributes attribute */
      rv = Label != NULL_PTR ?
             AssignAttrValue (pTmpl, Label->Val, Label->Len, rv):
             AssignAttrValue (pTmpl, "", 0, rv);
      break;
    case CKA_PRIVATE: /* The CommonObjectAttributes attribute */
      rv = Flags != NULL_PTR ?
             (B = BitVal (Flags, FLAGS_PRIVATE),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
               CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_MODIFIABLE: /* The CommonObjectAttributes attribute */
      rv = Flags != NULL_PTR ?
             (B  = BitVal (Flags, FLAGS_MODIFIABLE),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
               CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_KEY_TYPE: /* The CommonKeyAttributes only attribute */
      rv = KT != (CK_KEY_TYPE)-1 ?
             AssignAttrValue (pTmpl, &KT, sizeof KT, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_ID: /* The Common(Key/Certificate)Attributes only attributes */
      rv = ID != NULL_PTR ?
             AssignAttrValue (pTmpl, ID->Val, ID->Len, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_ENCRYPT: /* The CommonKeyAttributes only attribute */
      rv = Usage != NULL_PTR ?
             (B = BitVal (Usage, USAGE_ENCRYPT),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_DECRYPT: /* The CommonKeyAttributes only attribute */
      rv = Usage != NULL_PTR ?
             (B = BitVal (Usage, USAGE_DECRYPT),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_SIGN: /* The CommonKeyAttributes only attribute */
      rv = Usage != NULL_PTR ?
             (B = BitVal (Usage, USAGE_SIGN),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_VERIFY: /* The CommonKeyAttributes only attribute */
      rv = Usage != NULL_PTR ?
             (B = BitVal (Usage, USAGE_VERIFY),
               AssignAttrValue (pTmpl, &B, sizeof B, rv)) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_SERIAL_NUMBER: /* The Certificate only attribute */
      rv = SerNum != NULL_PTR ?
             AssignAttrValue (pTmpl, SerNum->Val.Long.Val, SerNum->Val.Long.Len, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_ISSUER: /* The Certificate only attribute */
      rv = Issuer != NULL_PTR ?
             AssignAttrValue (pTmpl, Issuer->Val, Issuer->Len, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_SUBJECT: /* The Certificate only attribute */
      rv = Subject != NULL_PTR ?
             AssignAttrValue (pTmpl, Subject->Val, Subject->Len, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_VALUE: /* The Certificate/Private Key/Public Key only attribute */
      rv = Value != NULL_PTR ?
             AssignAttrValue (pTmpl, Value->Val, Value->Len, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;
      break;
    case CKA_START_DATE: /* The Certificate only attribute */
      rv = ObjOrd == PKCS15_OBJECTS_CERTIFICATES_ORD         ||
           ObjOrd == PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD ||
           ObjOrd == PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD ?
             AssignAttrValue (pTmpl, &StartDate, sizeof StartDate, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    case CKA_END_DATE: /* The Certificate only attribute */
      rv = ObjOrd == PKCS15_OBJECTS_CERTIFICATES_ORD         ||
           ObjOrd == PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD ||
           ObjOrd == PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD ?
             AssignAttrValue (pTmpl, &EndDate, sizeof EndDate, rv) :
             CKR_ATTRIBUTE_TYPE_INVALID;

      break;
    default: /* Case 2 (see details in PKCS#11 v2-30b-d6, page 131) */
      pTmpl->ulValueLen = (CK_ULONG)-1;
	  //LOG((EFI_D_ERROR, "%a.%d 7\n", __FUNCTION__, __LINE__));
      if (rv == CKR_OK) {
        rv = CKR_ATTRIBUTE_TYPE_INVALID;
      }
    }
  }
  //LOG((EFI_D_ERROR, "%a.%d 8\n", __FUNCTION__, __LINE__));
  return rv;
}

/* C_SetAttributeValue() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL_PTR || ulCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjectsInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
  )
{
  CK_ULONG        I;
  CK_ULONG        J;
  CK_RV           rv;
  PKCS11_TEMPLATE *pTmpl;
  OBJECT_TYPE     SearchType = ANY_OBJECT;
  CK_VOID_PTR     pPtr       = NULL_PTR;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Avoid memory leak in case of repeated call */
  if ((rv = FreeTemplate (
              pTmpl = &Cryptoki.Slots[I].Session.Search
              )) != CKR_OK) {
      return rv;
  }

  /* Check templates */
  for (J = 0; J < ulCount; J++) {
    CK_ATTRIBUTE_PTR T = &pTemplate[J];

    if (T->pValue == NULL_PTR || T->ulValueLen == 0) {
      return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    switch (T->type) {
    case CKA_LABEL:
    case CKA_ID:
      break;
    case CKA_VALUE:
      break;
    case CKA_CLASS:
      if (T->ulValueLen != sizeof (CK_OBJECT_CLASS)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      switch (*(CK_OBJECT_CLASS *)T->pValue) {
      case CKO_DATA:
      case CKO_CERTIFICATE:
      case CKO_PUBLIC_KEY:
      case CKO_PRIVATE_KEY:
      case CKO_SECRET_KEY:
        break;
      default:
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;
    case CKA_KEY_TYPE:
      if (T->ulValueLen != sizeof (CK_KEY_TYPE)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      switch (*(CK_KEY_TYPE *)T->pValue) {
      case CKK_RSA:
      case CKK_GOSTR3410:
        break;
      default:
        DEBUG ((EFI_D_ERROR, "Unsupported key type\n"));
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;
    case CKA_CERTIFICATE_TYPE:
      if (T->ulValueLen != sizeof (CK_CERTIFICATE_TYPE)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      switch (*(CK_CERTIFICATE_TYPE *)T->pValue) {
      case CKC_X_509:
        break;
      default:
        DEBUG ((EFI_D_ERROR, "Unsupported certificate type\n"));
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_MODIFIABLE:
      if (T->ulValueLen != sizeof (CK_BBOOL)) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      if (T->type == CKA_TOKEN) {
        SearchType = *(CK_BBOOL *)T->pValue ? TOKEN_OBJECT : SESSION_OBJECT;
      }

      break;
    default:
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (ulCount > 0) {
    if (pTemplate == NULL_PTR) {
      return CKR_ARGUMENTS_BAD;
    }

    if ((rv = AllocMem (&pPtr, ulCount * sizeof *pTmpl->pTemplate)) != CKR_OK) {
      return rv;
    }

    CopyMem (
      pTmpl->pTemplate = pPtr,
      pTemplate,
      (pTmpl->ulCount = ulCount) * sizeof *pTmpl->pTemplate
      );
  }
 
  pTmpl->Initialized = CK_TRUE;
  pTmpl->SearchType  = SearchType;
  pTmpl->ObjOrd      = 0;
  pTmpl->ObjType     = SearchType == ANY_OBJECT ? SESSION_OBJECT : SearchType;
  pTmpl->ItemOrd     = 0;
  return CKR_OK;
}

/* C_FindObjects helper functions */

static inline CK_BBOOL LogicXor (CK_BBOOL B1, CK_BBOOL B2)
{
  return (B1 && !B2) || (!B1 && B2);
}

static CK_RV IsObjectMatches (
  CK_BBOOL                       *M,
  PKCS15_OBJECTS_CHOICE_ITEM_ORD Ord,
  ASN1_TYPE_VAL                  *V,
  PKCS11_TEMPLATE                *T,
  CK_BBOOL                       Pub /* CK_TRUE if the session is public */
  )
{
  enum { FLAGS_PRIVATE, FLAGS_MODIFIABLE };
  enum { USAGE_ENCRYPT, USAGE_DECRYPT, USAGE_SIGN, USAGE_SIGN_RECOVER,
         USAGE_WRAP, USAGE_UNWRAP, USAGE_VERIFY, USAGE_VERIFY_RECOVER,
         USAGE_DERIVE, USAGE_NON_REPUDIATION };

  CK_RV rv = CKR_OK;

  if (T->pTemplate != NULL_PTR) {
    CK_BBOOL        CK = CK_FALSE; /* The CommonKeyAttributes sign         */
    CK_BBOOL        CC = CK_FALSE; /* The CommonCertificateAttributes sign */
    CK_KEY_TYPE     KT = (CK_KEY_TYPE)-1;
    CK_OBJECT_CLASS CL = (CK_OBJECT_CLASS)-1;
    CK_ULONG        I;
    ASN1_UTF8_STRING_VAL  *Label = NULL_PTR;
    ASN1_BIT_STRING_VAL   *Flags = NULL_PTR;
    ASN1_OCTET_STRING_VAL *ID    = NULL_PTR;
    ASN1_BIT_STRING_VAL   *Usage = NULL_PTR;

    switch (Ord) {
    case PKCS15_OBJECTS_PRIVATE_KEYS_ORD:
      switch (V->TypeVal.Choice.Item->Ord) {
      case PRIVATE_KEY_TYPE_PRIVATE_RSA_KEY:
        KT = CKK_RSA;
        break;
      case PRIVATE_KEY_TYPE_PRIVATE_KEA_KEY:
        KT = CKK_GOSTR3410;
        break;
      default:
        break;
      }

      CK = CK_TRUE;
      CL = CKO_PRIVATE_KEY;
      break;
    case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
    case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
      switch (V->TypeVal.Choice.Item->Ord) {
      case PUBLIC_KEY_TYPE_PUBLIC_RSA_KEY:
        KT = CKK_RSA;
        break;
      case PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY:
        KT = CKK_GOSTR3410;
        break;
      default:
        break;
      }

      CK = CK_TRUE;
      CL = CKO_PUBLIC_KEY;
      break;
    /* FIXME: More complete implementation is needed */
    case PKCS15_OBJECTS_SECRET_KEYS_ORD:
      CK = CK_TRUE;
      CL = CKO_SECRET_KEY;
      break;
    case PKCS15_OBJECTS_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
    case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
      CC = CK_TRUE;
      CL = CKO_CERTIFICATE;
      break;
    case PKCS15_OBJECTS_DATA_OBJECTS_ORD:
      CL = CKO_DATA;
      break;
    case PKCS15_OBJECTS_AUTH_OBJECTS_ORD:
      break;
    default:
      break;
    }

    V = &V->TypeVal.Choice.Item->Val;

    if ((rv = GetCommonObjAttrLabel (&Label, V)) != CKR_OK &&
        rv != CKR_VENDOR_DEFINED) {
      return rv;
    }

    if ((rv = GetCommonObjAttrFlags (&Flags, V)) == CKR_OK) {
      /* If the session is public then private objects are invisible */
      if (Pub && BitVal (Flags, FLAGS_PRIVATE)) {
        *M = CK_FALSE;
        return CKR_OK;
      }
    } else {
      if (rv != CKR_VENDOR_DEFINED) {
        return rv;
      }
    }

    if (CK) {
      if ((rv = GetCommonKeyAttrID (&ID, V)) != CKR_OK) {
        return rv;
      }

      if ((rv = GetCommonKeyAttrUsage (&Usage, V)) != CKR_OK) {
        return rv;
      }
    }

    if (CC) {
      if ((rv = GetCommonCertAttrID (&ID, V)) != CKR_OK) {
        return rv;
      }
    }

    for (I = 0; I < T->ulCount; I++) {
      /* Get a value into a temporary variable */
      switch (T->pTemplate[I].type) {
      case CKA_CLASS: /* The general attribute */
        if (CL != *(CK_OBJECT_CLASS *)T->pTemplate[I].pValue) {
          *M = CK_FALSE;
          return CKR_OK;
        }

        break;
      case CKA_LABEL: /* The CommonObjectAttributes attribute */
        if (Label->Len != T->pTemplate[I].ulValueLen ||
            CompareMem (Label->Val, T->pTemplate[I].pValue, Label->Len) != 0) {
          *M = CK_FALSE;
          return CKR_OK;
        }

        break;
      case CKA_PRIVATE: /* The CommonObjectAttributes attribute */
        if (LogicXor (BitVal (Flags, FLAGS_PRIVATE),
                      *(CK_BBOOL *)T->pTemplate[I].pValue)) {
          *M = CK_FALSE;
          return CKR_OK;
        }

        break;
      case CKA_MODIFIABLE: /* The CommonObjectAttributes attribute */
        if (LogicXor (BitVal (Flags, FLAGS_MODIFIABLE),
                      *(CK_BBOOL *)T->pTemplate[I].pValue)) {
          *M = CK_FALSE;
          return CKR_OK;
        }

        break;
      case CKA_KEY_TYPE: /* The CommonKeyAttributes only attribute */
        if (CK && KT != *(CK_KEY_TYPE *)T->pTemplate[I].pValue) {
          *M = CK_FALSE;
          return CKR_OK;
        }

        break;
      case CKA_ID: /* The CommonKeyAttributes only attribute */
        if (CK && ID != NULL_PTR) {
          if (ID->Len != T->pTemplate[I].ulValueLen ||
              CompareMem (ID->Val, T->pTemplate[I].pValue, ID->Len) != 0) {
            *M = CK_FALSE;
            return CKR_OK;
          }
        }

        break;
      case CKA_ENCRYPT: /* The CommonKeyAttributes only attribute */
        if (CK && Usage != NULL_PTR) {
          if (LogicXor (BitVal (Usage, USAGE_ENCRYPT),
                        *(CK_BBOOL *)T->pTemplate[I].pValue)) {
            *M = CK_FALSE;
            return CKR_OK;
          }
        }

        break;
      case CKA_DECRYPT: /* The CommonKeyAttributes only attribute */
        if (CK && Usage != NULL_PTR) {
          if (LogicXor (BitVal (Usage, USAGE_DECRYPT),
                        *(CK_BBOOL *)T->pTemplate[I].pValue)) {
            *M = CK_FALSE;
            return CKR_OK;
          }
        }

        break;
      case CKA_SIGN: /* The CommonKeyAttributes only attribute */
        if (CK && Usage != NULL_PTR) {
          if (LogicXor (BitVal (Usage, USAGE_SIGN),
                        *(CK_BBOOL *)T->pTemplate[I].pValue)) {
            *M = CK_FALSE;
            return CKR_OK;
          }
        }

        break;
      case CKA_VERIFY: /* The CommonKeyAttributes only attribute */
        if (CK && Usage != NULL_PTR) {
          if (LogicXor (BitVal (Usage, USAGE_VERIFY),
                        *(CK_BBOOL *)T->pTemplate[I].pValue)) {
            *M = CK_FALSE;
            return CKR_OK;
          }
        }

        break;
      }
    }
  }

  *M = CK_TRUE;
  return CKR_OK;
}

static CK_BBOOL IsNotUserFunctions (CK_ULONG I) /* I must be correct from caller */
{
  return
#ifdef _MSC_VER
    (CK_BBOOL)
#endif /* _MSC_VER */
    !(Cryptoki.Slots[I].Session.State == CKS_RO_USER_FUNCTIONS ||
      Cryptoki.Slots[I].Session.State == CKS_RW_USER_FUNCTIONS);
}

/* C_FindObjects() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG             ulMaxObjectCount,
  CK_ULONG_PTR         pulObjectCount
  )
{
  CK_ULONG        I;
  PKCS11_TEMPLATE *pTmpl;
  CK_RV           rv;
  CK_ULONG        ulObjectCount = 0;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulObjectCount == NULL_PTR || ulMaxObjectCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }
  
  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  if (!(pTmpl = &Cryptoki.Slots[I].Session.Search)->Initialized) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Continue search within groups of objects of different types */
  DEBUG((EFI_D_ERROR, "%a.%d pTmpl->ObjOrd=%d {%d}\n", 
    __FUNCTION__, __LINE__, pTmpl->ObjOrd, 
    ARRAY_ITEMS (Cryptoki.Slots[I].Data.Objects)));
  for (;
       pTmpl->ObjOrd < ARRAY_ITEMS (Cryptoki.Slots[I].Data.Objects);
       pTmpl->ObjOrd++) {
    /* Continue search between token/session objects depending on search type */
    for (;
         pTmpl->SearchType == ANY_OBJECT ?
           pTmpl->ObjType < ANY_OBJECT : pTmpl->ObjType == pTmpl->SearchType;
         pTmpl->ObjType++) {
      ASN1_TYPE_VAL *V = &Cryptoki.Slots[I].Data.Objects[pTmpl->ObjOrd]
                                                        [pTmpl->ObjType];

      /* SEQUENCE OF a particular type (PrivateKeyType, PublicKeyType, etc) */
      if (V->Def->Type != ASN1_SEQUENCE_OF_CLASS_TYPE) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return CKR_FUNCTION_FAILED;
      }

      /* If it was NOT decoded then it is absent from a token/session */
      if (!V->Decoded) {
        continue;
      }

      /* Continue search within objects of a particular type */
      for (; pTmpl->ItemOrd < V->TypeVal.SequenceOf.Cnt; pTmpl->ItemOrd++) {
        ASN1_TYPE_VAL *W = &V->TypeVal.SequenceOf.Item[pTmpl->ItemOrd];
        CK_BBOOL      M  = CK_FALSE;

        /* CHOICE of a particluar subtype (RSA Key, KEA Key, etc) */
        if (W->Def->Type != ASN1_CHOICE_CLASS_TYPE) {
          DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          return CKR_FUNCTION_FAILED;
        }

        /* If number of currently matched objects has reached its Max */
        if (!(ulObjectCount < ulMaxObjectCount)) {
          DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          goto Finish; /* Just goto that exits from inner blocks forward */
        }

        /* Check whether an object matches the FindObjects template */
        if ((rv = IsObjectMatches (
                    &M,
                    pTmpl->ObjOrd,
                    W,
                    pTmpl,
                    IsNotUserFunctions (I)
                    )) != CKR_OK) {
          DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          return rv;
        }

        if (M) { /* If the object matches */
          /* Object handle is constructed as ItemNum * ObjectCount + ObjectNum */
          if ((rv = ObjOrdsToHandle (
                      &phObject[ulObjectCount++],
                      &Cryptoki.Slots[I].Data,
                      pTmpl->ObjOrd,
                      pTmpl->ObjType,
                      pTmpl->ItemOrd
                      )) != CKR_OK) {
            DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
            return rv;
          }
        }
      }

      /* If iterating within the SEQUENCE OF is over, restart it */
      pTmpl->ItemOrd = 0;
    }

    /* If iterating between session/token objects is over, restart it */
    pTmpl->ObjType =
      pTmpl->SearchType == ANY_OBJECT ? SESSION_OBJECT : pTmpl->SearchType;
   }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

Finish:
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  *pulObjectCount = ulObjectCount;
  return CKR_OK;
}

/* C_FindObjectsFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
  )
{
  CK_ULONG           I;
  CK_RV           rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  return FreeTemplate (&Cryptoki.Slots[I].Session.Search);
}

/* Encryption functions */

/* C_EncryptInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Encrypt() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG_PTR      pulEncryptedDataLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pData == NULL_PTR || ulDataLen == 0 ||
      pEncryptedData == NULL_PTR || pulEncryptedDataLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPart == NULL_PTR || ulPartLen == 0 ||
      pEncryptedPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastEncryptedPart,
  CK_ULONG_PTR      pulLastEncryptedPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pLastEncryptedPart == NULL_PTR || pulLastEncryptedPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Decryption functions */

/* C_DecryptInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  ASN1_TYPE_VAL *V;
  CK_ULONG      ObjOrd;
  OBJECT_TYPE   ObjType;
  CK_ULONG      ItemOrd;
  CK_ULONG      I;
  CK_ULONG      J;
  CK_RV         rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Check that the any operation is NOT in progress */
  if (Cryptoki.Slots[I].Operations) {
    return CKR_OPERATION_ACTIVE;
  }

  Cryptoki.Slots[I].Interface->WorkMode = 0;
  switch (pMechanism->mechanism) {
  case CKM_GOSTR3410_2012://check23
	  if(Cryptoki.Slots[I].TokenInfo.Model==Rutoken_older_2_0)
	  {
		  //DEBUG ((EFI_D_ERROR, "%a.%d Rutoken_older_2_0\n", __FUNCTION__, __LINE__));
		  rv = CKR_ALGORITM_UNSUPPORT;
		  break;
	  }
	  Cryptoki.Slots[I].Interface->WorkMode = 2;
  case CKM_RSA_PKCS:
  case CKM_GOSTR3410:
	  if(!Cryptoki.Slots[I].Interface->WorkMode)
		Cryptoki.Slots[I].Interface->WorkMode = 1;
    break;
  default: /* Only 'cased' above mechanisms are supported */
    return CKR_ARGUMENTS_BAD;
  }

  if (Cryptoki.Slots[I].Operations) {
    Cryptoki.Slots[I].Operations = OPERATION_NONE;
    return CKR_OPERATION_ACTIVE;
  }

  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hKey
              )) != CKR_OK) {
    return rv;
  }

  /* Getting PKCS#11 'PKCS#15 object', checking validity on the fly */
  if ((V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType].TypeVal.
              SequenceOf.Item[ItemOrd].TypeVal.
                Choice.Item->Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    return CKR_GENERAL_ERROR;
  }

  /* Getting PKCS#11 CommonKeyAttributes, checking validity on the fly */
  if ((V = &V->TypeVal.Sequence.Item[PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD].
              Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    return CKR_GENERAL_ERROR;
  }

  /* Trying to find optional CommonKeyattributes KeyReference field */
  for (J = 0; J < V->TypeVal.Sequence.Cnt; J++) {
    if (V->TypeVal.Sequence.Item[J].Ord == COMMON_KEY_ATTRIBUTES_KEY_REFERENCE) {
      break;
    }
  }

  /* If NOT found */
  if (!(J < V->TypeVal.Sequence.Cnt)) {
    DEBUG ((EFI_D_ERROR, "Cannot find key reference value\n"));
    return CKR_FUNCTION_FAILED;
  }

  if ((V = &V->TypeVal.Sequence.Item[J].Val)->Def->Type != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type                != ASN1_INTEGER_PRIM_TYPE) {
    return CKR_GENERAL_ERROR;
  }

  if (V->TypeVal.Prim.Integer.Long || V->TypeVal.Prim.Integer.Val.Val > 255) {
    DEBUG ((EFI_D_ERROR, "Invalid key reference value supplied from token\n"));
    return CKR_GENERAL_ERROR;
  }
                                    /* Since value here is NOT MORE than 255 */
  Cryptoki.Slots[I].Session.KeyRef = (CK_BYTE)V->TypeVal.Prim.Integer.Val.Val;

  if ((rv = MapErr (
              (*Cryptoki.Slots[I].Interface->DecryptInit) (
                                               Cryptoki.Slots[I].Interface,
                                               Cryptoki.Slots[I].Session.KeyRef,
											   Cryptoki.Slots[I].Interface->WorkMode
                                               ))) != CKR_OK) {
    return rv;
  }

  Cryptoki.Slots[I].Operations          = OPERATION_DECRYPT;
  Cryptoki.Slots[I].ProcessingState     = PROCESSING_STATE_INIT;
  Cryptoki.Slots[I].DecryptionMechanism = pMechanism->mechanism;

  /* FIXME: Must be taken from the mechanism parameters */
  Cryptoki.Slots[I].DecryptionParamSet  = CRYPTO_PRO_A;
  Cryptoki.Slots[I].DigestCount         = 0;
  return CKR_OK;
}

/* C_Decrypt() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG          ulEncryptedDataLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
  )
{
  UINTN    ulDataLen;
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pEncryptedData == NULL_PTR || ulEncryptedDataLen == 0 ||
      pulDataLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DecryptInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DECRYPT)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if (pData == NULL_PTR || (ulDataLen = *pulDataLen) < ulEncryptedDataLen) {
    *pulDataLen = ulEncryptedDataLen;
    return pData != NULL_PTR ? CKR_BUFFER_TOO_SMALL : CKR_OK;
  }

  /* According to PKCS#11 v2-30b-d6, paragraph 11.9, page 143:
     C_Decrypt always terminates the active decryption operation
     unless it returns CKR_BUFFER_TOO_SMALL or is a successful call
     (i.e., one which returns CKR_OK) to determine the length
     of the buffer needed to hold the plaintext */

  /* Decryption operation must be in the INIT state */
  if (Cryptoki.Slots[I].ProcessingState != PROCESSING_STATE_INIT) {
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  if ((rv = MapErr (
              (*Cryptoki.Slots[I].Interface->Decrypt) (
                                               Cryptoki.Slots[I].Interface,
                                               pEncryptedData,
                                               ulEncryptedDataLen,
                                               pData,
                                               &ulDataLen
                                               ))) == CKR_OK) {
    *pulDataLen =
#ifdef _MSC_VER
      (CK_ULONG)
#endif /* _MSC_VER */
      ulDataLen;
  }

Finalize: /* The active decrypt operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return rv;
}

/* C_DecryptUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pEncryptedPart == NULL_PTR || ulEncryptedPartLen == 0 ||
      pPart == NULL_PTR || pulPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DecryptInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DECRYPT)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Decrypt operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:   /* In this case switch the state      */
    Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_UPDATE;
  case PROCESSING_STATE_UPDATE: /* In this case keep the state intact */
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto OnError;
  }

  if (ulEncryptedPartLen == 0) {
    return CKR_OK;
  }

  /* FIXME: Implementation is needed */
  rv = CKR_FUNCTION_NOT_SUPPORTED;

OnError: /* On error the active decrypt operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastPart,
  CK_ULONG_PTR      pulLastPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pLastPart == NULL_PTR || pulLastPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DecryptIit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DECRYPT)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Decrypt operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:
  case PROCESSING_STATE_UPDATE:
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  /* FIXME: Implementation is needed */
  rv = CKR_FUNCTION_NOT_SUPPORTED;

Finalize: /* The active decrypt operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  /* FIXME: Implementation is needed */
  return rv;
}

/* Message digesting functions */

/* C_DigestInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism
  )
{
  CK_ULONG I;
  CK_RV    rv;

  enum {
    CKA_TOKEN_F     = 1 << 0,
    CKA_LABEL_F     = 1 << 1,
    CKA_OBJECT_ID_F = 1 << 2,
  };

  CK_ULONG            u;
  CK_BBOOL            Token    = CK_FALSE;
  CK_BYTE             *oid     = NULL;
  CK_ULONG            oid_len  = 0;
  CK_ULONG            defined  = 0;          /** Flags for redefinition check */
  GOSTR3411_PARAM_SET ParamSet = CRYPTO_PRO_H; /** Default parameter set      */

  /* GostR3411-94-TestParamSet */
  static CK_BYTE CONST oidTestH[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.30.0
     * (id-GostR3411-94-TestParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x00
  };

  /* GostR3411-94-CryptoProParamSet */
  static CK_BYTE CONST oidProH[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.30.1
     * (id-GostR3411-94-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01
  };

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR ||
      (pMechanism->ulParameterLen != 0 && pMechanism->pParameter == NULL)) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Check that the any operation is NOT in progress */
  if (Cryptoki.Slots[I].Operations) {
    return CKR_OPERATION_ACTIVE;
  }

  /* Check mechanism type and set the default values of parameters */
  switch (pMechanism->mechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:

    /* The rule for all the code below (that is within the function) is:
     * in case of an error the rv value must be set appropriately
     * and a jump to Finalize label must be performed in order to release
     * resources that might be taken before the error has taken place
     */
    for (u = 0; u < pMechanism->ulParameterLen; u++) {
      CK_VOID_PTR val = ((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].pValue;
      CK_ULONG    len = ((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].ulValueLen;

      if (val == NULL || len == 0) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto Finalize;
      }

      switch (((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].type) {
      case CKA_TOKEN:

        if (defined & CKA_TOKEN_F || /* redefinition check */
            len != sizeof Token) {
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        CopyMem (&Token, val, len);

        defined |= CKA_TOKEN_F;
        break;
      case CKA_LABEL:

        if (defined & CKA_LABEL_F) { /* redefinition check */
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        /* FIXME: Implementation is probably needed (currently is silently ignored) */

        defined |= CKA_LABEL_F;
        break;
      case CKA_OBJECT_ID:

        if (defined & CKA_OBJECT_ID_F) { /* redefinition check */
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        if (gBS->AllocatePool (
                   EfiBootServicesData,
                   len,
                   (VOID **)&oid
                   ) != EFI_SUCCESS) {
          rv = CKR_HOST_MEMORY;
          goto Finalize;
        }

        CopyMem (oid, val, oid_len = len);

        defined |= CKA_OBJECT_ID_F;
        break;
      default:
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto Finalize;
      }
    }

    /* By default a token is already initialized with Crypto Pro */
    if ((defined & CKA_OBJECT_ID_F)) {
      if (oid_len == sizeof oidProH && CompareMem (oid, oidProH, oid_len) == 0) {
          break; /* Token is already initialized with Crypto Pro H parameters */
      }

      if (oid_len == sizeof oidTestH && CompareMem (oid, oidTestH, oid_len) == 0) {
          ParamSet = TEST_H; /* Token initialization with Test parameters */
          break;
      }

      rv = CKR_MECHANISM_PARAM_INVALID;
      goto Finalize;
    }

    break;
  default:
    rv = CKR_MECHANISM_INVALID;
    goto Finalize;
  }

  /* Mechanisms outside token (software ones) are not supported at all */
  if (!Token) {
    rv = CKR_MECHANISM_INVALID;
    goto Finalize;
  }

  /* Check initialized values of parameters */
  Cryptoki.Slots[I].Interface->WorkMode = 0;
  switch (pMechanism->mechanism) {
  case CKM_GOSTR3411_2012: 
	  if(Cryptoki.Slots[I].TokenInfo.Model==Rutoken_older_2_0)
	  {
		  DEBUG ((EFI_D_ERROR, "%a.%d Rutoken_older_2_0\n", __FUNCTION__, __LINE__));
		  rv = CKR_ALGORITM_UNSUPPORT;
		  break;
	  }
	  Cryptoki.Slots[I].Interface->WorkMode = 2;
  case CKM_GOSTR3411:
	  if(!Cryptoki.Slots[I].Interface->WorkMode)
		  Cryptoki.Slots[I].Interface->WorkMode = 1;

    rv = MapErr ((*Cryptoki.Slots[I].Interface->DigestInit) (
                                                   Cryptoki.Slots[I].Interface,
                                                   ParamSet,
												   Cryptoki.Slots[I].Interface->WorkMode));
    break;
  default: /* Should not get to this point!!! */
    rv = CKR_MECHANISM_INVALID;
  }

Finalize:
  if (oid != NULL) {
    FreeMem (oid);
  }

  if (rv == CKR_OK) {
    Cryptoki.Slots[I].Operations      = OPERATION_DIGEST;
    Cryptoki.Slots[I].DigestMechanism = pMechanism->mechanism;
    Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_INIT;
  }

  return rv;
}

/* C_Digest() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DigestInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DIGEST)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.10:
   * A call to C_Digest always terminates the active digest
   * operation unless it returns CKR_BUFFER_TOO_SMALL
   */

  /* Digest operation must be in the INIT state */
  if (Cryptoki.Slots[I].ProcessingState != PROCESSING_STATE_INIT) {
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  /* The primary validity of parameters is checked */
  if ((pData == NULL_PTR && ulDataLen > 0) ||
      pDigest == NULL_PTR || pulDigestLen == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto Finalize;
  }

  switch (Cryptoki.Slots[I].DigestMechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    if (*pulDigestLen < 32) {
      return CKR_BUFFER_TOO_SMALL; /* The active digest op is NOT terminated */
    }

    if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->
                          Digest) (
                            Cryptoki.Slots[I].Interface,
                            pData,
                            ulDataLen,
                            pDigest))) == CKR_OK) {
      *pulDigestLen = 32;
    }

    break;
  default: /* If get to this point then inconsistent with C_DigestInit() */
    rv = CKR_FUNCTION_FAILED;
    break;
  }

Finalize: /* The active digest operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return rv;
}

/* C_DigestUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DigestInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DIGEST)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.10:
   * A call to C_DigestUpdate which results in an error
   * terminates the current digest operation
   */

  /* The primary validity of parameters is checked */
  if (pPart == NULL_PTR && ulPartLen > 0) {
    rv = CKR_ARGUMENTS_BAD;
    goto OnError;
  }

  /* Digest operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:   /* In this case switch the state      */
    Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_UPDATE;
  case PROCESSING_STATE_UPDATE: /* In this case keep the state intact */
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto OnError;
  }

  if (ulPartLen == 0) {
    return CKR_OK;
  }

  switch (Cryptoki.Slots[I].DigestMechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    if ((rv = MapErr((*Cryptoki.Slots[I].Interface->
                         Digest) (
                           Cryptoki.Slots[I].Interface,
                           pPart,
                           ulPartLen,
                           NULL))) != CKR_OK) {
      goto OnError;
    }

    break;
  default: /* If get to this point then inconsistent with C_DigestInit() */
    rv = CKR_FUNCTION_FAILED;
    goto OnError;
  }

  return CKR_OK;

OnError: /* On error the active digest operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return rv;
}

/* C_DigestKey() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Check that the digest operation is in progress */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DIGEST)) {
    Cryptoki.Slots[I].Operations = OPERATION_NONE;
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* The active digest operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pDigest == NULL_PTR || pulDigestLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_DigestInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_DIGEST)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.10:
   * A call to C_DigestFinal always terminates the active
   * digest operation unless it returns CKR_BUFFER_TOO_SMALL
   */

  /* Digest operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:
  case PROCESSING_STATE_UPDATE:
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  /* The primary validity of parameters is checked */
  if (pDigest == NULL_PTR || pulDigestLen == NULL_PTR) {
    rv = CKR_ARGUMENTS_BAD;
    goto Finalize;
  }

  switch (Cryptoki.Slots[I].DigestMechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    if (*pulDigestLen < 32) {
      return CKR_BUFFER_TOO_SMALL; /* The active digest op is NOT terminated */
    }

    if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->Digest) (
                                             Cryptoki.Slots[I].Interface,
                                             NULL,
                                             0,
                                             pDigest))) == CKR_OK) {
      *pulDigestLen = 32;
    }

    break;
  default: /* If get to this point then inconsistent with C_DigestInit() */
    rv = CKR_FUNCTION_FAILED;
    break;
  }

Finalize: /* The active digest operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return rv;
}

/* Signing and MACing functions */

/* C_SignInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  ASN1_TYPE_VAL *V;
  CK_ULONG      ObjOrd;
  OBJECT_TYPE   ObjType;
  CK_ULONG      ItemOrd;
  CK_ULONG      I;
  CK_ULONG      J;
  CK_RV         rv;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (!Cryptoki.Initialized) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  /* Check that the any operation is NOT in progress */
  if (Cryptoki.Slots[I].Operations) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_OPERATION_ACTIVE;
  }

  switch (pMechanism->mechanism) {
  case CKM_RSA_PKCS:
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    break;
  default: /* Only 'cased' above mechanisms are supported */
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_ARGUMENTS_BAD;
  }

  if (Cryptoki.Slots[I].Operations) {
    Cryptoki.Slots[I].Operations = OPERATION_NONE;
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_OPERATION_ACTIVE;
  }

  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hKey
              )) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  /* Getting PKCS#11 'PKCS#15 object', checking validity on the fly */
  if ((V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType].TypeVal.
              SequenceOf.Item[ItemOrd].TypeVal.
                Choice.Item->Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_GENERAL_ERROR;
  }

  /* Getting PKCS#11 CommonKeyAttributes, checking validity on the fly */
  if ((V = &V->TypeVal.Sequence.Item[PKCS15_OBJECT_CLASS_ATTRIBUTES_ORD].
              Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_GENERAL_ERROR;
  }

  /* Trying to find optional CommonKeyattributes KeyReference field */
  for (J = 0; J < V->TypeVal.Sequence.Cnt; J++) {
    if (V->TypeVal.Sequence.Item[J].Ord == COMMON_KEY_ATTRIBUTES_KEY_REFERENCE) {
      break;
    }
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  /* If NOT found */
  if (!(J < V->TypeVal.Sequence.Cnt)) {
    DEBUG ((EFI_D_ERROR, "Cannot find key reference value\n"));
    return CKR_FUNCTION_FAILED;
  }

  if ((V = &V->TypeVal.Sequence.Item[J].Val)->Def->Type != ASN1_PRIM_CLASS_TYPE ||
      V->Def->TypeRef.Prim->Type                != ASN1_INTEGER_PRIM_TYPE) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_GENERAL_ERROR;
  }

  if (V->TypeVal.Prim.Integer.Long || V->TypeVal.Prim.Integer.Val.Val > 255) {
    DEBUG ((EFI_D_ERROR, "Invalid key reference value supplied from token\n"));
    return CKR_GENERAL_ERROR;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
#if 0                                    /* Since value here is NOT MORE than 255 */
  Cryptoki.Slots[I].Session.KeyRef = (CK_BYTE)V->TypeVal.Prim.Integer.Val.Val;
#endif

  Cryptoki.Slots[I].Operations          = OPERATION_SIGN;
  Cryptoki.Slots[I].ProcessingState     = PROCESSING_STATE_INIT;
  Cryptoki.Slots[I].DecryptionMechanism = pMechanism->mechanism;

#if 0
  Cryptoki.Slots[I].Interface->RSFRef = 
    (CK_BYTE)V->TypeVal.Prim.Integer.Val.Val;
#endif

  DEBUG ((EFI_D_ERROR, "%a.%d RSFRef=0x%X\n",    
    __FUNCTION__, __LINE__, Cryptoki.Slots[I].Interface->RSFRef));

  switch (pMechanism->mechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    rv = MapErr ((*Cryptoki.Slots[I].Interface->EcpInit) (
                                                   Cryptoki.Slots[I].Interface
                                                   ));
    break;
  default: /* Should not get to this point!!! */
    rv = CKR_MECHANISM_INVALID;
  }
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return rv;
}

/* C_Sign() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
  )
{
  CK_ULONG I;
  CK_RV    rv;
  UINT8 *Ecp = NULL;
  UINTN EcpLen = 0;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pData == NULL_PTR || ulDataLen == 0 ||
      pSignature == NULL_PTR || pulSignatureLen == NULL_PTR) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return rv;
  }

  if (Cryptoki.Slots[I].Operations != OPERATION_SIGN) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return CKR_FUNCTION_REJECTED;
  }

  switch (Cryptoki.Slots[I].DecryptionMechanism) {
  case CKM_GOSTR3411_2012:
  case CKM_GOSTR3411:
    rv = MapErr ((*Cryptoki.Slots[I].Interface->Ecp) (
                       Cryptoki.Slots[I].Interface,
                       (UINT8*)pData,
                       (UINTN)ulDataLen,
                       &Ecp,
                       &EcpLen
                       ));
    break;
  default: /* Should not get to this point!!! */
    rv = CKR_MECHANISM_INVALID;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d EcpLen=%d\n", 
    __FUNCTION__, __LINE__, EcpLen));
  if (rv == CKR_OK) {
    if (Ecp != NULL) {
      if (*pulSignatureLen >= EcpLen) {
        CopyMem (pSignature, Ecp, EcpLen);
        *pulSignatureLen = EcpLen;
      } else {
        rv = CKR_FUNCTION_CANCELED;
        DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      }      
    }
  }

  if (Ecp) {
    FreeMem (Ecp);
  }
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  /* Intentionally left unsupported */
  return rv;
}

/* C_SignUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPart == NULL_PTR || ulPartLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSignature == NULL_PTR || pulSignatureLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecoverInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecover() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pData == NULL_PTR || ulDataLen == 0 ||
      pSignature == NULL_PTR || pulSignatureLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Functions for verifying signatures and MACs */

/* C_VerifyInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  enum {
    CKA_TOKEN_F            = 1 << 0,
    CKA_LABEL_F            = 1 << 1,
    CKA_GOSTR3411_PARAMS_F = 1 << 2,
    CKA_GOSTR3410_PARAMS_F = 1 << 3
  };

  CK_ULONG            u;
  CK_BBOOL            Token     = CK_FALSE;
  CK_BYTE             *oidh     = NULL;
  CK_ULONG            oidh_len  = 0;
  CK_BYTE             *oidc     = NULL;
  CK_ULONG            oidc_len  = 0;
  CK_ULONG            defined   = 0;        /** Flags for redefinition check */
  GOSTR3411_PARAM_SET ParamSetH = CRYPTO_PRO_H; /** Default Hash */
  GOSTR3410_PARAM_SET ParamSetC = CRYPTO_PRO_A; /** Default Crypto */
  CK_ULONG            ObjOrd    = 0;
  OBJECT_TYPE         ObjType   = 0;
  CK_ULONG            ItemOrd   = 0;
  ASN1_TYPE_VAL       *V;
  CK_ULONG            Ord;

  /* GostR3411-94-TestParamSet */
  static CK_BYTE CONST oidTestH[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.30.0
     * (id-GostR3411-94-TestParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x00
  };

  /* GostR3411-94-CryptoProParamSet */
  static CK_BYTE CONST oidProH[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.30.1
     * (id-GostR3411-94-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01
  };

  /* GostR3410-2001-TestParamSet */
  static CK_BYTE CONST oidTestC[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.35.0
     * (id-GostR3410-2001-TestParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x00
  };

  /* GostR3410-2001-CryptoPro-A-ParamSet */
  static CK_BYTE CONST oidProA[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.35.1
     * (id-GostR3410-2001-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01
  };

  /* GostR3410-2001-CryptoPro-B-ParamSet */
  static CK_BYTE CONST oidProB[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.35.2
     * (id-GostR3410-2001-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02
  };

  /* GostR3410-2001-CryptoPro-C-ParamSet */
  static CK_BYTE CONST oidProC[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.35.3
     * (id-GostR3410-2001-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03
  };

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Convert object handle into the triple of ObjOrd, ObjType, and ItemOrd */
  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hKey)) != CKR_OK) {
    return rv;
  }

  /* Access the object specified by hKey handle */
  V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType].TypeVal.SequenceOf.Item[ItemOrd];

  /* Keep a particular CHOICE in the local variable */
  Ord = V->TypeVal.Choice.Item->Ord;

  switch (ObjOrd) {
  case PKCS15_OBJECTS_PUBLIC_KEYS_ORD:
  case PKCS15_OBJECTS_TRUSTED_PUBLIC_KEYS_ORD:
    break;
  default:
    return CKR_ARGUMENTS_BAD;
  }

  /* Check that the any operation is NOT in progress */
  if (Cryptoki.Slots[I].Operations) {
    return CKR_OPERATION_ACTIVE;
  }

  /* Check mechanism type and set the default values of parameters */
  switch (pMechanism->mechanism) {
  case CKM_GOSTR3410_2012:
  case CKM_GOSTR3410:
  case CKM_GOSTR3410_WITH_GOSTR3411:
    if (Ord != PUBLIC_KEY_TYPE_PUBLIC_KEA_KEY) {
      DEBUG ((
        EFI_D_ERROR,
        "Key type does NOT match one of the supplied mechanizm\n"
        ));
      return CKR_ARGUMENTS_BAD;
    }

    if ((V = &V->TypeVal.Choice.Item->
                Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE ||
        V->Def->TypeRef.
          Sequence->Cnt         != PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    for (u = 0; u < PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS; u++) {
      if (V->TypeVal.Sequence.Item[u].Ord == PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD) {
        V = &V->TypeVal.Sequence.Item[u].Val;
        break;
      }
    }

    if (!(u < PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS)) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    /* Descent through subtypes, checking them and finally getting the key */
    if (V->Def->Type            != ASN1_SEQUENCE_CLASS_TYPE ||
        V->Def->
          TypeRef.Sequence->Cnt != PUBLIC_KEA_KEY_ATTRIBUTES_ITEM_ORD_ITEMS ||
        (V = &V->TypeVal.Sequence.Item[PUBLIC_KEA_KEY_ATTRIBUTES_VALUE].
                Val)->Def->Type != ASN1_CHOICE_CLASS_TYPE                   ||
        V->Def->
          TypeRef.Choice->Cnt   != OBJECT_VALUE_CHOICE_ITEM_ORD_ITEMS       ||
        V->TypeVal.
          Choice.Item->Ord      != OBJECT_VALUE_DIRECT_ORD                  ||
        (V = &V->TypeVal.Choice.Item->
                Val)->Def->Type != ASN1_CHOICE_CLASS_TYPE                   ||
        V->Def->
          TypeRef.Choice->Cnt   != KEA_PUBLIC_KEY_CHOICE_ITEM_ORD_ITEMS     ||
        V->TypeVal.
          Choice.Item->Ord      != KEA_PUBLIC_KEY_CHOICE_RAW                ||
        (V = &V->TypeVal.Choice.Item->
                Val)->Def->Type != ASN1_PRIM_CLASS_TYPE ||
        V->Def->
          TypeRef.Prim->Type    != ASN1_OCTET_STRING_PRIM_TYPE) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    /* The rule for all the code below (that is within the function) is:
     * in case of an error the rv value must be set appropriately
     * and a jump to Finalize label must be performed in order to release
     * resources that might be taken before the error has taken place
     */
    for (u = 0; u < pMechanism->ulParameterLen; u++) {
      CK_VOID_PTR val = ((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].pValue;
      CK_ULONG    len = ((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].ulValueLen;

      if (val == NULL || len == 0) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto Finalize;
      }

      switch (((CK_ATTRIBUTE_PTR)pMechanism->pParameter)[u].type) {
      case CKA_TOKEN:
        if (defined & CKA_TOKEN_F || /* redefinition check */
            len != sizeof Token) {
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        CopyMem (&Token, val, len);

        defined |= CKA_TOKEN_F;
        break;
      case CKA_LABEL:
        if (defined & CKA_LABEL_F) { /* redefinition check */
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        /* FIXME: Implementation is probably needed (currently is silently ignored) */

        defined |= CKA_LABEL_F;
        break;
      case CKA_GOSTR3411_PARAMS:
        if (defined & CKA_GOSTR3411_PARAMS_F || /* redefinition check */
            pMechanism->mechanism == CKM_GOSTR3410) {
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        if (gBS->AllocatePool (
                   EfiBootServicesData,
                   len,
                   (VOID **)&oidh
                   ) != EFI_SUCCESS) {
          rv = CKR_HOST_MEMORY;
          goto Finalize;
        }

        CopyMem (oidh, val, oidh_len = len);

        defined |= CKA_GOSTR3411_PARAMS_F;
        break;
      case CKA_GOSTR3410_PARAMS:
        if (defined & CKA_GOSTR3410_PARAMS_F) { /* redefinition check */
          rv = CKR_MECHANISM_PARAM_INVALID;
          goto Finalize;
        }

        if (gBS->AllocatePool (
                   EfiBootServicesData,
                   len,
                   (VOID **)&oidc
                   ) != EFI_SUCCESS) {
          rv = CKR_HOST_MEMORY;
          goto Finalize;
        }

        CopyMem (oidc, val, oidc_len = len);

        defined |= CKA_GOSTR3410_PARAMS_F;
        break;
      default:
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto Finalize;
      }
    }

    /* By default a token is already initialized with Crypto Pro */
    if (defined & CKA_GOSTR3411_PARAMS_F) {
      if (oidh_len == sizeof oidProH &&
          CompareMem (oidh, oidProH, oidh_len) == 0) {
          break; /* Token is already initialized with Crypto Pro parameters */
      }

      if (oidh_len == sizeof oidTestH &&
          CompareMem (oidh, oidTestH, oidh_len) == 0) {
          ParamSetH = TEST_H; /* Token initialization with Test parameters */
          break;
      }

      rv = CKR_MECHANISM_PARAM_INVALID;
      goto Finalize;
    }

    /* By default a token is already initialized with Crypto Pro A */
    if (defined & CKA_GOSTR3410_PARAMS_F) {
      if (oidc_len == sizeof oidProA &&
          CompareMem (oidc, oidProA, oidc_len) == 0) {
          break; /* Token is already initialized with Crypto Pro A parameters */
      }

      if (oidc_len == sizeof oidProB &&
          CompareMem (oidc, oidProB, oidc_len) == 0) {
          ParamSetC = CRYPTO_PRO_B; /* Token initialization with CryptoPro B */
          break;
      }

      if (oidc_len == sizeof oidProC &&
          CompareMem (oidc, oidProC, oidc_len) == 0) {
          ParamSetC = CRYPTO_PRO_C; /* Token initialization with CryptoPro C */
          break;
      }

      if (oidc_len == sizeof oidTestC &&
          CompareMem (oidc, oidTestC, oidc_len) == 0) {
          ParamSetC = TEST_C; /* Token initialization with Test parameters */
          break;
      }

      rv = CKR_MECHANISM_PARAM_INVALID;
      goto Finalize;
    }

    break;
  default:
    rv = CKR_MECHANISM_PARAM_INVALID;
    goto Finalize;
  }

  /* Mechanisms outside token (software ones) are not supported at all */
  if (!Token) {
    rv = CKR_MECHANISM_INVALID;
    goto Finalize;
  }

  /* Check initialized values of parameters */
  Cryptoki.Slots[I].Interface->WorkMode = 0;
  switch (pMechanism->mechanism) {
  case CKM_GOSTR3410_WITH_GOSTR3411:
    /* First the digest is to compute in this case */
    rv = MapErr ((*Cryptoki.Slots[I].Interface->DigestInit) (
                                                  Cryptoki.Slots[I].Interface,
                                                  ParamSetH,
											      0));
    break;
  case CKM_GOSTR3410_2012://check23
	  if(Cryptoki.Slots[I].TokenInfo.Model==Rutoken_older_2_0)
	  {
		  DEBUG ((EFI_D_ERROR, "%a.%d Rutoken_older_2_0\n", __FUNCTION__, __LINE__));
		  rv = CKR_ALGORITM_UNSUPPORT;
		  break;
	  }
	  Cryptoki.Slots[I].Interface->WorkMode = 2;
  case CKM_GOSTR3410:
	  if(!Cryptoki.Slots[I].Interface->WorkMode)
		  Cryptoki.Slots[I].Interface->WorkMode = 1;

    rv = MapErr ((*Cryptoki.Slots[I].Interface->VerifySignatureInit) (
                                                  Cryptoki.Slots[I].Interface,
											      Cryptoki.Slots[I].Interface->WorkMode));
    break;
  default: /* Should not get to this point!!! */
    rv = CKR_MECHANISM_INVALID;
  }

Finalize:
  if (oidh != NULL) {
    FreeMem (oidh);
  }

  if (oidc != NULL) {
    FreeMem (oidc);
  }

  if (rv == CKR_OK) {
    Cryptoki.Slots[I].Operations          = OPERATION_VERIFY;
    Cryptoki.Slots[I].ProcessingState     = PROCESSING_STATE_INIT;
    Cryptoki.Slots[I].DecryptionMechanism = pMechanism->mechanism;
    Cryptoki.Slots[I].DecryptionParamSet  = ParamSetC;
    Cryptoki.Slots[I].DigestCount         = 0;
    Cryptoki.Slots[I].VerifyKey           = V;
  }

  return rv;
}

/* C_Verify() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
  )
{
  CK_ULONG      I;
  CK_RV         rv;
  CK_BBOOL      Success = CK_FALSE;
  ASN1_TYPE_VAL *V;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pData == NULL_PTR || ulDataLen == 0 ||
      pSignature == NULL_PTR || ulSignatureLen != 64) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_VerifyInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_VERIFY)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.12:
   * A call to C_Verify always terminates the active verification operation.
   */

  /* Decryption operation must be in the INIT state */
  if (Cryptoki.Slots[I].ProcessingState != PROCESSING_STATE_INIT) {
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  /* Get and check Verify Key ASN.1 object saved previously by VerifyInit() */
  if ((V = Cryptoki.Slots[I].VerifyKey) == NULL_PTR                    ||
      V->Def->Type                      != ASN1_PRIM_CLASS_TYPE        ||
      V->Def->TypeRef.Prim->Type        != ASN1_OCTET_STRING_PRIM_TYPE ||
      V->TypeVal.Prim.OctetString.Val   == NULL_PTR                    ||
      V->TypeVal.Prim.OctetString.Len   == 0){
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  switch (Cryptoki.Slots[I].DecryptionMechanism) {
  case CKM_GOSTR3410_WITH_GOSTR3411:
    /* First the digest is to be computed on the data supplied */
    if ((rv = MapErr((*Cryptoki.Slots[I].Interface->
                         Digest) (
                           Cryptoki.Slots[I].Interface,
                           pData,
                           ulDataLen,
                           &Cryptoki.Slots[I].Digest[0]))) != CKR_OK) {
      goto Finalize;
    }

    /* Initialize signature operation */
    if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->
                            VerifySignatureInit) (
                              Cryptoki.Slots[I].Interface,
											   Cryptoki.Slots[I].Interface->WorkMode))) != CKR_OK) {
      goto Finalize;
    }

    pData = &Cryptoki.Slots[I].Digest[0];
    ulDataLen = sizeof Cryptoki.Slots[I].Digest;
    /* Intentional pass through here (no 'break' statement) */
  case CKM_GOSTR3410_2012:
  case CKM_GOSTR3410:
    if (ulDataLen != sizeof Cryptoki.Slots[I].Digest) {
      return CKR_DATA_LEN_RANGE;
    }

    if ((rv = MapErr ((*Cryptoki.Slots[I].
                          Interface->VerifySignature) (
                                       Cryptoki.Slots[I].Interface,
                                       Cryptoki.Slots[I].DecryptionParamSet,
                                       pData,
                                       ulDataLen,
                                       pSignature,
                                       ulSignatureLen,
                                       V->TypeVal.Prim.OctetString.Val,
                                       V->TypeVal.Prim.OctetString.Len,
                                       &Success))) == CKR_OK && !Success) {
      rv = CKR_SIGNATURE_INVALID;
    }

    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

Finalize: /* The active verify operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;
  Cryptoki.Slots[I].VerifyKey       = NULL_PTR;

  return rv;
}

/* C_VerifyUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_VerifyInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_VERIFY)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.12:
   * A call to C_VerifyUpdate which results in an error terminates the current
   * verification operation.
   */

  /* The primary validity of parameters is checked */
  if (pPart == NULL_PTR && ulPartLen > 0) {
    rv = CKR_ARGUMENTS_BAD;
    goto OnError;
  }

  /* Verify operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:   /* In this case switch the state      */
    Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_UPDATE;
  case PROCESSING_STATE_UPDATE: /* In this case keep the state intact */
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto OnError;
  }

  if (ulPartLen == 0) {
    return CKR_OK;
  }

  switch (Cryptoki.Slots[I].DecryptionMechanism) {
  case CKM_GOSTR3410_WITH_GOSTR3411:
    /* First the digest is to be computed on the data supplied */
    if ((rv = MapErr((*Cryptoki.Slots[I].Interface->
                         Digest) (
                           Cryptoki.Slots[I].Interface,
                           pPart,
                           ulPartLen,
                           NULL))) != CKR_OK) {
      goto OnError;
    }

    break;
  case CKM_GOSTR3410_2012:
  case CKM_GOSTR3410:
    if (Cryptoki.Slots[I].DigestCount + ulPartLen >
        sizeof Cryptoki.Slots[I].Digest) {
      rv = CKR_DATA_LEN_RANGE;
      goto OnError;
    }

    CopyMem (
      Cryptoki.Slots[I].Digest + Cryptoki.Slots[I].DigestCount,
      pPart,
      ulPartLen
      );

    Cryptoki.Slots[I].DigestCount += ulPartLen;
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto OnError;
  }

  return CKR_OK;

OnError: /* On error the active verify operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;

  return rv;
}

/* C_VerifyFinal() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
  )
{
  CK_ULONG      I;
  CK_RV         rv;
  CK_BBOOL      Success;
  ASN1_TYPE_VAL *V;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSignature == NULL_PTR || ulSignatureLen != 64) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Operation must be initialized previously by C_VerifyInit() */
  if (!(Cryptoki.Slots[I].Operations & OPERATION_VERIFY)) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if ((V = Cryptoki.Slots[I].VerifyKey) == NULL_PTR                    ||
      V->Def->Type                      != ASN1_PRIM_CLASS_TYPE        ||
      V->Def->TypeRef.Prim->Type        != ASN1_OCTET_STRING_PRIM_TYPE ||
      V->TypeVal.Prim.OctetString.Val   == NULL_PTR                    ||
      V->TypeVal.Prim.OctetString.Len   == 0){
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* Starting from this point, according to PKCS#11v2-30b-d6, paragraph 11.12:
   * A call to C_VerifyFinal always terminates the active verification operation.
   */

  /* Verify operation should be in either INIT or UPDATE state */
  switch (Cryptoki.Slots[I].ProcessingState) {
  case PROCESSING_STATE_INIT:
  case PROCESSING_STATE_UPDATE:
    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

  switch (Cryptoki.Slots[I].DecryptionMechanism) {
  case CKM_GOSTR3410_WITH_GOSTR3411:
    /* First the digest is to be computed on the data supplied */
    if ((rv = MapErr((*Cryptoki.Slots[I].Interface->
                         Digest) (
                           Cryptoki.Slots[I].Interface,
                           NULL,
                           0,
                           &Cryptoki.Slots[I].Digest[0]))) != CKR_OK) {
      goto Finalize;
    }

    /* Initialize signature operation */
    if ((rv = MapErr ((*Cryptoki.Slots[I].Interface->
                            VerifySignatureInit) (
                              Cryptoki.Slots[I].Interface,
											   Cryptoki.Slots[I].Interface->WorkMode))) != CKR_OK) {
      goto Finalize;
    }

    Cryptoki.Slots[I].DigestCount = sizeof Cryptoki.Slots[I].Digest;
    /* Intentional pass through here (no 'break' statement) */
  case CKM_GOSTR3410_2012:
  case CKM_GOSTR3410:
    if (Cryptoki.Slots[I].DigestCount != sizeof Cryptoki.Slots[I].Digest) {
      rv = CKR_DATA_LEN_RANGE;
      break;
    }

    if ((rv = MapErr ((*Cryptoki.Slots[I].
                          Interface->VerifySignature) (
                                       Cryptoki.Slots[I].Interface,
                                       Cryptoki.Slots[I].DecryptionParamSet,
                                       &Cryptoki.Slots[I].Digest[0],
                                       Cryptoki.Slots[I].DigestCount,
                                       pSignature,
                                       ulSignatureLen,
                                       V->TypeVal.Prim.OctetString.Val,
                                       V->TypeVal.Prim.OctetString.Len,
                                       &Success))) == CKR_OK && !Success) {
      rv = CKR_SIGNATURE_INVALID;
    }

    break;
  default:
    rv = CKR_FUNCTION_FAILED;
    goto Finalize;
  }

Finalize: /* The active verify operation is explicitly terminated */
  Cryptoki.Slots[I].Operations      = OPERATION_NONE;
  Cryptoki.Slots[I].ProcessingState = PROCESSING_STATE_NONE;
  Cryptoki.Slots[I].VerifyKey       = NULL_PTR;

  return rv;
}

/* C_VerifyRecoverInit() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyRecover() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSignature == NULL_PTR || ulSignatureLen == 0 ||
      pData == NULL_PTR || pulDataLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Dual-purpose cryptographic functions */

/* C_DigestEncryptUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPart == NULL_PTR || ulPartLen == 0 ||
      pEncryptedPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptDigestUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pEncryptedPart == NULL_PTR || ulEncryptedPartLen == 0 ||
      pPart == NULL_PTR || pulPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignEncryptUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pPart == NULL_PTR || ulPartLen == 0 ||
      pEncryptedPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptVerifyUpdate() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pEncryptedPart == NULL_PTR || ulEncryptedPartLen == 0 ||
      pPart == NULL_PTR || pulPartLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Key management functions */

/* C_GenerateKey() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR || pTemplate == NULL_PTR || ulCount == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateKeyPair() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
  CK_ULONG             ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
  CK_ULONG             ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR || pPublicKeyTemplate == NULL_PTR || pPrivateKeyTemplate == NULL_PTR ||
      ulPublicKeyAttributeCount == 0 || ulPrivateKeyAttributeCount == 0 ||
      phPublicKey == NULL_PTR || phPrivateKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_WrapKey() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hWrappingKey,
  CK_OBJECT_HANDLE  hKey,
  CK_BYTE_PTR       pWrappedKey,
  CK_ULONG_PTR      pulWrappedKeyLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR || pWrappedKey == NULL_PTR || pulWrappedKeyLen == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_UnwrapKey() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hUnwrappingKey,
  CK_BYTE_PTR          pWrappedKey,
  CK_ULONG             ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR || pWrappedKey == NULL_PTR || pTemplate == NULL_PTR ||
      ulAttributeCount == 0 || phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DeriveKey() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hBaseKey,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pMechanism == NULL_PTR || pTemplate == NULL_PTR ||
      ulAttributeCount == 0 || phKey == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random number generation functions */

/* C_SeedRandom() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSeed,
  CK_ULONG          ulSeedLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSeed == NULL_PTR || ulSeedLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateRandom() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pRandomData,
  CK_ULONG          ulRandomLen
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pRandomData == NULL_PTR || ulRandomLen == 0) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  /* FIXME: Implementation is needed */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Parallel function management functions */

/* C_GetFunctionStatus() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
  CK_SESSION_HANDLE hSession
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  return CKR_FUNCTION_NOT_PARALLEL;
}

/* C_CancelFunction() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
  CK_SESSION_HANDLE hSession
  )
{
  CK_ULONG I;
  CK_RV    rv;

  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK) {
    return rv;
  }

  return CKR_FUNCTION_NOT_PARALLEL;
}

/* C_WaitForSlotEvent() implementation */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
  CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pRserved
  )
{
  if (!Cryptoki.Initialized) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSlot == NULL_PTR || pRserved != NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  /* Intentionally left unsupported */
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Auxiliary functions for getting particular certificate fields */

static CK_RV GetCert (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               ASN1_TYPE_VAL **V
               )
{
  ASN1_TYPE_VAL *W;
  CK_ULONG      ObjOrd  = 0;
  OBJECT_TYPE   ObjType = SESSION_OBJECT;
  CK_ULONG      ItemOrd = 0;
  CK_ULONG      I;
  CK_RV         rv      = FindSlotBySession(&I, hSession);

  if (rv != CKR_OK) {
    return rv;
  }

  if ((rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hCert)) != CKR_OK) {
    return rv;
  }

  switch (ObjOrd) {
  case PKCS15_OBJECTS_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_TRUSTED_CERTIFICATES_ORD:
  case PKCS15_OBJECTS_USEFUL_CERTIFICATES_ORD:
    break;
  default:
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  if ((W = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType].
              TypeVal.SequenceOf.Item[ItemOrd])->
              Def->Type             != ASN1_CHOICE_CLASS_TYPE               ||
      W->Def->TypeRef.Choice->Cnt != CERTIFICATE_TYPE_CHOICE_ITEM_ORD_ITEMS ||
      W->TypeVal.Choice.Item->Ord != CERTIFICATE_TYPE_X509_CERTIFICATE      ||
      (W = &W->TypeVal.Choice.Item->Val)->
              Def->Type             != ASN1_SEQUENCE_CLASS_TYPE             ||
      W->Def->TypeRef.Sequence->Cnt != PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS; I++) {
    if (W->TypeVal.Sequence.Item[I].Ord == PKCS15_OBJECT_TYPE_ATTRIBUTES_ORD) {
      break;
    }
  }

  if (!(I < PKCS15_OBJECT_SEQUENCE_ITEM_ORD_ITEMS)) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  if ((W = &W->TypeVal.Sequence.Item[I].
              Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE                   ||
      W->Def->TypeRef.
        Sequence->Cnt         != X509_CERTIFICATE_ATTRIBUTES_ITEM_ORD_ITEMS ||
      W->TypeVal.Sequence.Cnt <= X509_CERTIFICATE_ATTRIBUTES_VALUE          ||
      W->TypeVal.Sequence.Item[X509_CERTIFICATE_ATTRIBUTES_VALUE].
        Ord                   != X509_CERTIFICATE_ATTRIBUTES_VALUE          ||
      (W = &W->TypeVal.Sequence.Item[X509_CERTIFICATE_ATTRIBUTES_VALUE].
              Val)->Def->Type != ASN1_CHOICE_CLASS_TYPE                     ||
      W->Def->TypeRef.
        Sequence->Cnt         != OBJECT_VALUE_CHOICE_ITEM_ORD_ITEMS         ||
      W->TypeVal.
        Choice.Item->Ord      != OBJECT_VALUE_DIRECT_ORD                    ||
      (W = &W->TypeVal.Choice.Item->
              Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE                   ||
      W->Def->TypeRef.
        Sequence->Cnt         != CERTIFICATE_ITEM_ORD_ITEMS                 ||
      W->TypeVal.Sequence.Cnt != CERTIFICATE_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  *V = W;
  return CKR_OK;
}

static CK_RV AuxGetIssuerField (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ULONG_PTR      pOI,
               CK_ULONG          ulOI,
               CK_ATTRIBUTE_PTR  pField
               )
{
  ASN1_TYPE_VAL *V;
  CK_ULONG      I;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_CERTIFICATE_CONTENT].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE            ||
      V->Def->TypeRef.Sequence->Cnt != CERTIFICATE_CONTENT_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS; I++) {
    if (V->TypeVal.Sequence.Item[I].
          Ord == CERTIFICATE_CONTENT_ISSUER) {
      break;
    }
  }

  if (!(I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS)) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  if ((V = &V->TypeVal.Sequence.Item[I].
              Val)->Def->Type     != ASN1_CHOICE_CLASS_TYPE ||
      V->Def->TypeRef.Choice->Cnt != NAME_ITEM_ORD_ITEMS    ||
      V->TypeVal.Choice.Item->Ord != NAME_RDN_SEQUENCE      ||
      (V = &V->TypeVal.Choice.Item->
              Val)->Def->Type     != ASN1_SEQUENCE_OF_CLASS_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < V->TypeVal.SequenceOf.Cnt; I++) {
    ASN1_TYPE_VAL *X;
    ASN1_TYPE_VAL *W = &V->TypeVal.SequenceOf.Item[I];
    CK_ULONG      J  = 0;

    if (W->Def->Type                      != ASN1_SET_OF_CLASS_TYPE           ||
        W->TypeVal.SetOf.Cnt              != 1                                ||
        (W = &W->TypeVal.
                SetOf.Item[0])->Def->Type != ASN1_SEQUENCE_CLASS_TYPE         ||
        W->Def->TypeRef.Sequence->Cnt     !=
          ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_ITEM_ORD_ITEMS               ||
        (X = &W->TypeVal.Sequence.
                Item[ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_TYPE].
                  Val)->Def->Type         != ASN1_PRIM_CLASS_TYPE             ||
        X->Def->TypeRef.Prim->Type        != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE ||
        X->TypeVal.Prim.
          ObjectIdentifier.Val            == NULL_PTR                         ||
        X->TypeVal.Prim.
          ObjectIdentifier.Len            == 0) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    if (X->TypeVal.Prim.ObjectIdentifier.Len == ulOI) {
      for (; J < ulOI; J++) {
        if (X->TypeVal.Prim.ObjectIdentifier.Val[J] != pOI[J]) {
          break;
        }
      }
    }

    /* If desired Object Identifier is found */
    if (!(J < ulOI)) {
      if ((X = &W->TypeVal.Sequence.
                  Item[ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_VALUE].
                    Val)->Def->Type   != ASN1_CHOICE_CLASS_TYPE          ||
          X->Def->TypeRef.Choice->Cnt != 
            ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_ITEM_ORD_ITEMS ||
          X->TypeVal.Choice.
            Item->Val.Def->Type       != ASN1_PRIM_CLASS_TYPE) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      switch (X->TypeVal.Choice.Item->Ord) {
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_PRINTABLE_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_PRINTABLE_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                PrintableString.Val   == NULL_PTR                        ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                PrintableString.Len   == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type       = CKA_CHAR_STRING;
        pField->pValue     = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.PrintableString.Val;
        pField->ulValueLen = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.PrintableString.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_IA5_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_IA5_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                IA5String.Val         == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                IA5String.Len         == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type        = CKA_CHAR_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.IA5String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.IA5String.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_UTF8_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_UTF8_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type        = CKA_UTF8_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Len;
        return CKR_OK;
        
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_TELETEXT_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_TELETEXT_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type        = CKA_UTF8_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_BMP_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_BMP_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                BmpString.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                BmpString.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type        = CKA_BMP_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.BmpString.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.BmpString.Len * 2;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_NUMERIC_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_NUMERIC_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                NumericString.Val   == NULL_PTR                        ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                NumericString.Len   == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	pField->type       = CKA_CHAR_STRING;
        pField->pValue     = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.NumericString.Val;
        pField->ulValueLen = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.NumericString.Len;
        return CKR_OK;
      default:
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

    }
  }

  /* The next code is returned to indicate the case when a Certificate field is NOT found */
  return CKR_FUNCTION_REJECTED;
}

extern CK_RV C_AuxGetIssuerCommonName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pCN
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 3 };
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pCN);
}

extern CK_RV C_AuxGetIssuerEmail (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pEmail
               )
{
  static CK_ULONG OI[] = { 1, 2, 840, 113549, 1, 9, 1 };
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pEmail);
}

extern CK_RV C_AuxGetIssuerOrganizationName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 10};
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pOrganizationName);
}

extern CK_RV C_AuxGetIssuerOrganizationUnitName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationUnitName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 11};
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pOrganizationUnitName);
}

extern CK_RV C_AuxGetIssuerLocalityName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pLocalityName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 7};
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pLocalityName);
}

extern CK_RV C_AuxGetIssuerStateOrProvinceName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pStateOrProvinceName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 8};
  return AuxGetIssuerField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pStateOrProvinceName);
}

static CK_RV AuxGetSubjectField (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ULONG_PTR      pOI,
               CK_ULONG          ulOI,
               CK_ATTRIBUTE_PTR  pField
               )
{
  ASN1_TYPE_VAL *V;
  CK_ULONG      I;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_CERTIFICATE_CONTENT].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE            ||
      V->Def->TypeRef.Sequence->Cnt != CERTIFICATE_CONTENT_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS; I++) {
    if (V->TypeVal.Sequence.Item[I].
          Ord == CERTIFICATE_CONTENT_SUBJECT) {
      break;
    }
  }

  if (!(I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS)) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  if ((V = &V->TypeVal.Sequence.Item[I].
              Val)->Def->Type     != ASN1_CHOICE_CLASS_TYPE ||
      V->Def->TypeRef.Choice->Cnt != NAME_ITEM_ORD_ITEMS    ||
      V->TypeVal.Choice.Item->Ord != NAME_RDN_SEQUENCE      ||
      (V = &V->TypeVal.Choice.Item->
              Val)->Def->Type     != ASN1_SEQUENCE_OF_CLASS_TYPE) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < V->TypeVal.SequenceOf.Cnt; I++) {
    ASN1_TYPE_VAL *X;
    ASN1_TYPE_VAL *W = &V->TypeVal.SequenceOf.Item[I];
    CK_ULONG      J  = 0;

    if (W->Def->Type                      != ASN1_SET_OF_CLASS_TYPE           ||
        W->TypeVal.SetOf.Cnt              != 1                                ||
        (W = &W->TypeVal.
                SetOf.Item[0])->Def->Type != ASN1_SEQUENCE_CLASS_TYPE         ||
        W->Def->TypeRef.Sequence->Cnt     !=
          ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_ITEM_ORD_ITEMS               ||
        (X = &W->TypeVal.Sequence.
                Item[ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_TYPE].
                  Val)->Def->Type         != ASN1_PRIM_CLASS_TYPE             ||
        X->Def->TypeRef.Prim->Type        != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE ||
        X->TypeVal.Prim.
          ObjectIdentifier.Val            == NULL_PTR                         ||
        X->TypeVal.Prim.
          ObjectIdentifier.Len            == 0) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    if (X->TypeVal.Prim.ObjectIdentifier.Len == ulOI) {
      for (; J < ulOI; J++) {
        if (X->TypeVal.Prim.ObjectIdentifier.Val[J] != pOI[J]) {
          break;
        }
      }
    }

    /* If desired Object Identifier is found */
    if (!(J < ulOI)) {
      BOOLEAN bCn;

      bCn = IsFieldIsCN(X->TypeVal.Prim.ObjectIdentifier.Val, ulOI);
      DEBUG ((EFI_D_ERROR, "%a.%d bCn=%X I=%X V->TypeVal.SequenceOf.Cnt=%X\n", 
        __FUNCTION__, __LINE__, bCn, I, V->TypeVal.SequenceOf.Cnt));
#if 0      
      if ((bCn == TRUE) &&
        (V->TypeVal.SequenceOf.Cnt != I + 1) && I != 0) {
        /* CN of the subject has to be last or first in the sequence */
        continue;
      }
#endif      
      if ((X = &W->TypeVal.Sequence.
                  Item[ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_VALUE].
                    Val)->Def->Type   != ASN1_CHOICE_CLASS_TYPE          ||
          X->Def->TypeRef.Choice->Cnt != 
            ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_ITEM_ORD_ITEMS ||
          X->TypeVal.Choice.
            Item->Val.Def->Type       != ASN1_PRIM_CLASS_TYPE) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      switch (X->TypeVal.Choice.Item->Ord) {
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_PRINTABLE_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_PRINTABLE_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                PrintableString.Val   == NULL_PTR                        ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                PrintableString.Len   == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type       = CKA_CHAR_STRING;
        pField->pValue     = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.PrintableString.Val;
        pField->ulValueLen = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.PrintableString.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_IA5_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_IA5_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                IA5String.Val         == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                IA5String.Len         == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type        = CKA_CHAR_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.IA5String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.IA5String.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_UTF8_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_UTF8_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type        = CKA_UTF8_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Len;
        return CKR_OK;
        
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_TELETEXT_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_TELETEXT_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                Utf8String.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type        = CKA_UTF8_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.Utf8String.Len;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_BMP_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_BMP_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                BmpString.Val        == NULL_PTR                  ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                BmpString.Len        == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type        = CKA_BMP_STRING;
        pField->pValue      = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.BmpString.Val;
        pField->ulValueLen  = X->TypeVal.Choice.
                                Item->Val.TypeVal.Prim.BmpString.Len * 2;
        return CKR_OK;
      case ATTRIBUTE_TYPE_AND_DISTINGUISHED_VALUE_CHOICE_NUMERIC_STRING:
        if (X->TypeVal.Choice.Item->Val.
              Def->TypeRef.Prim->Type != ASN1_NUMERIC_STRING_PRIM_TYPE ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                NumericString.Val   == NULL_PTR                        ||
            X->TypeVal.Choice.Item->Val.
              TypeVal.Prim.
                NumericString.Len   == 0) {
          INTERNAL_ERROR;
          return CKR_GENERAL_ERROR;
        }

	      pField->type       = CKA_CHAR_STRING;
        pField->pValue     = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.NumericString.Val;
        pField->ulValueLen = X->TypeVal.Choice.
                               Item->Val.TypeVal.Prim.NumericString.Len;
        return CKR_OK;
      default:
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

    }
  }

  /* The next code is returned to indicate the case when a Certificate field is NOT found */
  return CKR_FUNCTION_REJECTED;
}

extern CK_RV C_AuxGetSubjectCommonName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pCN
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 3 };
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pCN);
}

extern CK_RV C_AuxGetSubjectUid (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pUid
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 45 };
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pUid);
}

extern CK_RV C_AuxGetSubjectTitle (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pTitle
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 12 };
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pTitle);
}

extern CK_RV C_AuxGetBasicConstraints (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pBasicConstr
               )
{
  static CK_ULONG OI[] = { 2, 5, 29, 19 };
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pBasicConstr);
}

extern CK_RV C_AuxGetSubjectEmail (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pEmail
               )
{
  static CK_ULONG OI[] = { 1, 2, 840, 113549, 1, 9, 1 };
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), pEmail);
}

extern CK_RV C_AuxGetSubjectOrganizationName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 10};
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pOrganizationName);
}

extern CK_RV C_AuxGetSubjectOrganizationUnitName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationUnitName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 11};
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pOrganizationUnitName);
}

extern CK_RV C_AuxGetSubjectLocalityName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pLocalityName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 7};
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pLocalityName);
}

extern CK_RV C_AuxGetSubjectStateOrProvinceName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pStateOrProvinceName
               )
{
  static CK_ULONG OI[] = { 2, 5, 4, 8};
  return AuxGetSubjectField (hSession, hCert, &OI[0], ARRAY_ITEMS (OI), 
    pStateOrProvinceName);
}

extern CK_RV C_AuxGetSignatureAlgorithm (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_MECHANISM_TYPE *M
               )
{
  static struct {
    CK_MECHANISM_TYPE Type;
    CK_ULONG          Val[8];
    CK_ULONG          Len;
  } Mechs[] = {
    /* Mechanism id-GostR3411-94-with-GostR3410-2001 */
    { CKM_GOSTR3410_WITH_GOSTR3411, { 1, 2, 643, 2, 2, 3 }, 6 }
  };

  ASN1_TYPE_VAL *V;
  CK_ULONG      I;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if (M == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_SIGNATURE_ALGORITHM].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE            ||
      V->Def->TypeRef.Sequence->Cnt != ALGORITHM_IDENTIFIER_ITEM_ORD_ITEMS ||
      V->TypeVal.Sequence.Cnt       != ALGORITHM_IDENTIFIER_ITEM_ORD_ITEMS ||
      (V = &V->TypeVal.Sequence.Item[ALGORITHM_IDENTIFIER_ALGORITHM].
              Val)->Def->Type       != ASN1_PRIM_CLASS_TYPE                ||
      V->Def->TypeRef.Prim->Type    != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE    ||
      V->TypeVal.Prim.ObjectIdentifier.Val == NULL_PTR ||
      V->TypeVal.Prim.ObjectIdentifier.Len == 0) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < ARRAY_ITEMS (Mechs); I++) {
    if (V->TypeVal.Prim.ObjectIdentifier.Len == Mechs[I].Len) {
      CK_ULONG J;

      for (J = 0; J < Mechs[I].Len; J++) {
        if (V->TypeVal.Prim.ObjectIdentifier.Val[J] != Mechs[I].Val[J]) {
          break;
        }
      }

      /* Equal (found) */
      if (!(J < Mechs[I].Len)) {
        break;
      }
    }
  }

  if (!(I < ARRAY_ITEMS (Mechs))) {
    DEBUG ((EFI_D_ERROR, "Unsupported signature algorithm\n"));
    return CKR_FUNCTION_FAILED;
  }

  *M = Mechs[I].Type;
  return CKR_OK;
}

extern CK_RV C_AuxGetSignatureAlgorithmParamSet (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *PS
               )
{
  /* 1.2.643.2.2.19: (id-GostR3410-2001) */
  static CK_ULONG GOSTR3410[] = { 1, 2, 643, 2, 2, 19 };

  /* GostR3410-2001-CryptoPro-A-ParamSet */
  static CK_BYTE oidProA[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.35.1
     * (id-GostR3410-2001-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01
  };

  /* GostR3411-94-CryptoProParamSet */
  static CK_BYTE oidProH[]    = {
    /* ASN.1 OBJECTIDENTIFIER 1.2.643.2.2.30.1
     * (id-GostR3411-94-CryptoProParamSet)
     */
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01
  };

  ASN1_TYPE_VAL *V;
  ASN1_TYPE_VAL *W;
  CK_ATTRIBUTE  PST[ALGORITHM_PARAMETER_SET_ITEM_ORD_ITEMS];
  CK_ULONG      I;
  CK_ULONG      J;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if (PS == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_CERTIFICATE_CONTENT].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE            ||
      V->Def->TypeRef.Sequence->Cnt != CERTIFICATE_CONTENT_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  for (I = 0; I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS; I++) {
    if (V->TypeVal.Sequence.Item[I].
          Ord == CERTIFICATE_CONTENT_SUBJECT_PUBLIC_KEY_INFO) {
      break;
    }
  }

  if (!(I < CERTIFICATE_CONTENT_ITEM_ORD_ITEMS)) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  if ((V = &V->TypeVal.Sequence.Item[I].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE               ||
      V->Def->TypeRef.Sequence->Cnt != SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD_ITEMS ||
      V->TypeVal.Sequence.Cnt       != SUBJECT_PUBLIC_KEY_INFO_ITEM_ORD_ITEMS ||
      (V = &V->TypeVal.Sequence.Item[SUBJECT_PUBLIC_KEY_INFO_ALGORITHM].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE               ||
      V->Def->TypeRef.Sequence->Cnt != ALGORITHM_IDENTIFIER_ITEM_ORD_ITEMS    ||
      V->TypeVal.Sequence.Cnt       != ALGORITHM_IDENTIFIER_ITEM_ORD_ITEMS    ||
      (W = &V->TypeVal.Sequence.Item[ALGORITHM_IDENTIFIER_ALGORITHM].
              Val)->Def->Type       != ASN1_PRIM_CLASS_TYPE                   ||
      W->Def->TypeRef.Prim->Type    != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE       ||
      W->TypeVal.
        Prim.ObjectIdentifier.Val   == NULL_PTR                               ||
      W->TypeVal.
        Prim.ObjectIdentifier.Len   == 0) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  I = 0;

  if (W->TypeVal.Prim.ObjectIdentifier.Len == ARRAY_ITEMS (GOSTR3410)) {
    for (; I < ARRAY_ITEMS (GOSTR3410); I++) {
      if (W->TypeVal.Prim.ObjectIdentifier.Val[I] != GOSTR3410[I]) {
        break;
      }
    }
  }

  if (I < ARRAY_ITEMS (GOSTR3410)) {
    DEBUG ((EFI_D_ERROR, "Unsupported algorithm\n"));
    return CKR_FUNCTION_FAILED;
  }

  if ((V = &V->TypeVal.Sequence.Item[ALGORITHM_IDENTIFIER_PARAMETERS].
              Val)->Def->Type       != ASN1_CHOICE_CLASS_TYPE ||
      V->Def->TypeRef.Choice->Cnt   != ALGORITHM_PARAMETERS_ITEM_ORD_ITEMS) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  /* Default Cipher parameter set */
  PST[0].type       = CKA_GOSTR3410_PARAMS;
  PST[0].pValue     = &oidProA[0];
  PST[0].ulValueLen = ARRAY_ITEMS (oidProA);

  /* Default Hash parameter set */
  PST[1].type       = CKA_GOSTR3411_PARAMS;
  PST[1].pValue     = &oidProH[0];
  PST[1].ulValueLen = ARRAY_ITEMS (oidProH);

  switch (V->TypeVal.Choice.Item->Ord) {
  case ALGORITHM_PARAMETERS_NULL:
    break; /* Here default paramer set is used */
  case ALGORITHM_PARAMETERS_SEQUENCE:
    if ((V = &V->TypeVal.Choice.Item->
               Val)->Def->Type != ASN1_SEQUENCE_CLASS_TYPE ||
        V->Def->TypeRef.
          Sequence->Cnt        != ALGORITHM_PARAMETER_SET_ITEM_ORD_ITEMS) {
      INTERNAL_ERROR;
      return CKR_GENERAL_ERROR;
    }

    for (I = J = 0; I < V->TypeVal.Sequence.Cnt; I++, J++) {
      if ((W = &V->TypeVal.Sequence.Item[I].
                  Val)->Def->Type     != ASN1_PRIM_CLASS_TYPE             ||
          W->Def->TypeRef.Prim->Type  != ASN1_OBJECT_IDENTIFIER_PRIM_TYPE ||
          W->TypeVal.
            Prim.ObjectIdentifier.Val == NULL_PTR                         ||
          W->TypeVal.
            Prim.ObjectIdentifier.Len == 0                                ||
          !W->Def->ASN1                                                   ||
          W->ASN1.Val                 == NULL_PTR                         ||
          W->ASN1.Len                 == 0) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      if (!(J < ARRAY_ITEMS (PST))) {
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      switch (V->TypeVal.Sequence.Item[I].Ord) {
      case ALGORITHM_PARAMETER_SET_CIPHER_PARAMETER_SET:
        PST[J].type = CKA_GOSTR3410_PARAMS;
        break;
      case ALGORITHM_PARAMETER_SET_HASH_PARAMETER_SET:
        PST[J].type = CKA_GOSTR3411_PARAMS;
        break;
      default:
        INTERNAL_ERROR;
        return CKR_GENERAL_ERROR;
      }

      PST[J].pValue     = W->ASN1.Val;
      PST[J].ulValueLen = W->ASN1.Len;
    }

    break;
  default:
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  CopyMem (PS, &PST[0], sizeof PST);
  return CKR_OK;
}

extern CK_RV C_AuxGetCertContent (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *CC
               )
{
  ASN1_TYPE_VAL *V;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if (CC == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_CERTIFICATE_CONTENT].
              Val)->Def->Type       != ASN1_SEQUENCE_CLASS_TYPE           ||
      V->Def->TypeRef.Sequence->Cnt != CERTIFICATE_CONTENT_ITEM_ORD_ITEMS ||
      !V->Def->ASN1                                                       ||
      V->ASN1.Val                   == NULL_PTR                           ||
      V->ASN1.Len                   == 0) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  CC->type       = CKA_VENDOR_DEFINED;
  CC->pValue     = V->ASN1.Val;
  CC->ulValueLen = V->ASN1.Len;
  return CKR_OK;
}

extern CK_RV C_AuxGetSignatureValue (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *SV
               )
{
  ASN1_TYPE_VAL *V;
  CK_RV         rv = GetCert (hSession, hCert, &V);

  if (rv != CKR_OK) {
    return rv;
  }

  if (SV == NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  if ((V = &V->TypeVal.Sequence.Item[CERTIFICATE_SIGNATURE_VALUE].
              Val)->Def->Type           != ASN1_PRIM_CLASS_TYPE      ||
      V->Def->TypeRef.Prim->Type        != ASN1_BIT_STRING_PRIM_TYPE ||
      V->TypeVal.Prim.BitString.Hex     == NULL_PTR                  ||
      V->TypeVal.Prim.BitString.Len     == 0                         ||
      V->TypeVal.Prim.BitString.Len % 8 != 0) {
    INTERNAL_ERROR;
    return CKR_GENERAL_ERROR;
  }

  SV->type       = CKA_VENDOR_DEFINED;
  SV->pValue     = V->TypeVal.Prim.BitString.Hex;
  SV->ulValueLen = V->TypeVal.Prim.BitString.Len / 8;
  return CKR_OK;
}

/* This is a testing part for debug purposes */

#ifdef INCLUDE_TESTING

/* ASN.1 Tree */

/* This is an executive part */
static CK_RV ShowASN1TreeExecutive(ASN1_TYPE_VAL const *V, CK_ULONG Index)
{
  CK_RV           rv     = CKR_OK;
  CK_RV           rvtmp  = rv;
  CK_ULONG        I;
  static CK_ULONG Indent = 0;
  static struct
  {
    CK_ULONG Val[7];
    CK_ULONG Len;
    CHAR16   *Str;
  } OIDs[] = {
    { { 2,  5,   4,      3 },
      4,
      L"Common name" },
    { { 2,  5,   4,      7 },
      4,
      L"Locality Name" },
    { { 2,  5,   4,      8 },
      4,
      L"State or Province name" },
    { { 2,  5,   4,     10 },
      4,
      L"Organization name" },
    { { 2,  5,   4,     11 },
      4,
      L"Organization unit name" },
    { { 2,  5,  29,     19 },
      4,
      L"Basic constraints" },
    { { 1,  2, 643,      2,      2,  3 },
      6,
      L"id-GostR3411-94-with-GostR3410-2001" },
    { { 1,  2, 643,      2,      2, 19 },
      6,
      L"id-GostR3410-2001" },
    { { 1,  2, 643,      2,      2, 30, 1 },
      7,
      L"id-GostR3411-94-CryptoProParamSet" },
    { { 1,  2, 643,      2,      2, 35, 1 },
      7,
      L"id-GostR3410-2001-CryptoPro-A-ParamSet" },
    { { 1,  2, 840, 113549,      1,  1, 1 },
      7,
      L"RSA (PKCS #1 v1.5) key transport algorithm" },
    { { 1,  2, 840, 113549,      1,  9, 1 },
      7,
      L"PKCS #9 Email Address attribute for use in signatures" },
    { { 2, 16, 840,      1, 113730,  1, 1 },
      7,
      L"Netscape certificate type" }
  };


  DEBUG ((EFI_D_ERROR, "%2ld", Indent));

  Indent++;

  for (I = 0; I < Indent; I++) {
    DEBUG ((EFI_D_ERROR, ">"));
  }

  DEBUG ((EFI_D_ERROR, Index != (CK_ULONG)-1 ? "[%d]" : "[ ]", Index));

  if (!V->Decoded) {
    DEBUG ((EFI_D_ERROR, " NOT decoded (skipped?)\n"));
    Indent--;
    return CKR_OK;
  }

  DEBUG ((EFI_D_ERROR, "'%s': ", V->Def->Name != NULL_PTR ? V->Def->Name : L""));

  switch (V->Def->Type) {
  case ASN1_PRIM_CLASS_TYPE:
    switch (V->Def->TypeRef.Prim->Type) {
    case ASN1_BOOLEAN_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "BOOLEAN\n"));
      DEBUG ((EFI_D_ERROR, "%s\n", V->TypeVal.Prim.Boolean ? L"TRUE" : L"FALSE"));

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_INTEGER_PRIM_TYPE:
      DEBUG ((
        EFI_D_ERROR,
        "INTEGER (%s)\n",
        V->TypeVal.Prim.Integer.Long ? L"long" : L"native"
        ));

      if (V->TypeVal.Prim.Integer.Long) {
        DUMP (
          V->TypeVal.Prim.Integer.Val.Long.Val,
          V->TypeVal.Prim.Integer.Val.Long.Len
          );
      } else {
        DEBUG ((EFI_D_ERROR, "%d\n", V->TypeVal.Prim.Integer.Val.Val));
      }

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_BIT_STRING_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "BIT STRING (%d)\n", V->TypeVal.Prim.BitString.Len));
      if (V->TypeVal.Prim.BitString.Len % 8 ||
          V->TypeVal.Prim.BitString.Len < 16) {
        for (I = 0; I < V->TypeVal.Prim.BitString.Len; I++) {
          DEBUG ((EFI_D_ERROR, V->TypeVal.Prim.BitString.Val[I] ? "1" : "0"));
        }

        DEBUG ((EFI_D_ERROR, "\n"));
      } else {
        DUMP (
          V->TypeVal.Prim.BitString.Hex,
          (V->TypeVal.Prim.BitString.Len + 7) / 8
          );
      }

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_OCTET_STRING_PRIM_TYPE:
      DEBUG ((
        EFI_D_ERROR,
        "OCTET STRING (%d)\n",
        V->TypeVal.Prim.OctetString.Len
        ));
      DUMP (V->TypeVal.Prim.OctetString.Val, V->TypeVal.Prim.OctetString.Len);

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_NULL_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "NULL\n"));
      DEBUG ((EFI_D_ERROR, "null\n"));

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_OBJECT_IDENTIFIER_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "OBJECT IDENTIFIER\n"));

      for (I = 0; I < V->TypeVal.Prim.ObjectIdentifier.Len; I++) {
          DEBUG ((
            EFI_D_ERROR,
            "%s%d",
            I ? L"." : L"",
            V->TypeVal.Prim.ObjectIdentifier.Val[I]
            ));
      }

      for (I = 0; I < ARRAY_ITEMS (OIDs); I++) {
        if (V->TypeVal.Prim.ObjectIdentifier.Len == OIDs[I].Len &&
            CompareMem (
              V->TypeVal.Prim.ObjectIdentifier.Val,
              OIDs[I].Val,
              sizeof *OIDs[I].Val * OIDs[I].Len
              )                                  == 0) {
          DEBUG ((EFI_D_ERROR, ": (%s)", OIDs[I].Str));
          break;
        }
      }

      DEBUG ((EFI_D_ERROR, "\n"));

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_ENUMERATED_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "ENUMERATED\n"));
      DEBUG ((EFI_D_ERROR, "%d\n", V->TypeVal.Prim.Enumerated));

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_TELETEXT_STRING_PRIM_TYPE:
    case ASN1_UTF8_STRING_PRIM_TYPE:
      DEBUG ((
        EFI_D_ERROR,
        "UTF8 STRING (%d)\n",
        V->TypeVal.Prim.Utf8String.Len
        ));
      DUMP (V->TypeVal.Prim.Utf8String.Val, V->TypeVal.Prim.Utf8String.Len);

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_PRINTABLE_STRING_PRIM_TYPE:
      DEBUG ((
        EFI_D_ERROR,
        "PRINTABLE STRING (%d)\n",
        V->TypeVal.Prim.PrintableString.Len
        ));
      DUMP (
        V->TypeVal.Prim.PrintableString.Val,
        V->TypeVal.Prim.PrintableString.Len
        );

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_IA5_STRING_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "IA5 STRING (%d)\n", V->TypeVal.Prim.IA5String.Len));
      DUMP (V->TypeVal.Prim.IA5String.Val, V->TypeVal.Prim.IA5String.Len);

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_UTC_TIME_PRIM_TYPE:
      DEBUG ((EFI_D_ERROR, "UTC TIME (%d)\n", V->TypeVal.Prim.UTCTime.Len));
      DUMP (V->TypeVal.Prim.UTCTime.Val, V->TypeVal.Prim.UTCTime.Len);

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    case ASN1_GENERALIZED_TIME_PRIM_TYPE:
      DEBUG ((
        EFI_D_ERROR,
        "GENERALIZED TIME (%d)\n",
        V->TypeVal.Prim.GeneralizedTime.Len
        ));
      DUMP (
        V->TypeVal.Prim.GeneralizedTime.Val,
        V->TypeVal.Prim.GeneralizedTime.Len
        );

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    default:
      DEBUG ((EFI_D_ERROR, "Unknown\n"));

      if (V->Def->ASN1) {
        DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
        DUMP (V->ASN1.Val, V->ASN1.Len);
      }

      break;
    }

    break;
  case ASN1_SEQUENCE_CLASS_TYPE:
    DEBUG ((
      EFI_D_ERROR,
      "SEQUENCE (%d/%d):\n",
      V->TypeVal.Sequence.Cnt,
      V->Def->TypeRef.Sequence->Cnt
      ));

    for (I = 0; I < V->TypeVal.Sequence.Cnt; I++) {
      rvtmp = ShowASN1TreeExecutive (&V->TypeVal.Sequence.Item[I].Val, I);

      if (rv == CKR_OK) {
        rv = rvtmp;
      }
    }

    if (V->Def->ASN1) {
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 of '%s':\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  case ASN1_SEQUENCE_OF_CLASS_TYPE:
    DEBUG ((EFI_D_ERROR, "SEQUENCE OF (%d):\n", V->TypeVal.SequenceOf.Cnt));

    for (I = 0; I < V->TypeVal.SequenceOf.Cnt; I++) {
      rvtmp = ShowASN1TreeExecutive (&V->TypeVal.SequenceOf.Item[I], I);

      if (rv == CKR_OK) {
        rv = rvtmp;
      }
    }

    if (V->Def->ASN1) {
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 of '%s':\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  case ASN1_SET_CLASS_TYPE:
    DEBUG ((
      EFI_D_ERROR,
      "SET (%d/%d):\n",
      V->TypeVal.Set.Cnt,
      V->Def->TypeRef.Set->Cnt
      ));

    for (I = 0; I < V->TypeVal.Set.Cnt; I++) {
      rvtmp = ShowASN1TreeExecutive (&V->TypeVal.Set.Item[I].Val, I);

      if (rv == CKR_OK) {
        rv = rvtmp;
      }
    }

    if (V->Def->ASN1) {
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 of '%s':\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  case ASN1_SET_OF_CLASS_TYPE:
    DEBUG ((EFI_D_ERROR, "SET OF (%d):\n", V->TypeVal.SetOf.Cnt));

    for (I = 0; I < V->TypeVal.SetOf.Cnt; I++) {
      rvtmp = ShowASN1TreeExecutive (&V->TypeVal.SetOf.Item[I], I);

      if (rv == CKR_OK) {
        rv = rvtmp;
      }
    }

    if (V->Def->ASN1) {
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 of '%s':\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  case ASN1_CHOICE_CLASS_TYPE:
    DEBUG ((
      EFI_D_ERROR,
      "CHOICE (%d/%d):\n",
      V->TypeVal.Choice.Item->Ord,
      V->Def->TypeRef.Choice->Cnt - 1
      ));
    rvtmp = ShowASN1TreeExecutive (&V->TypeVal.Choice.Item->Val, (CK_ULONG)-1);

    if (rv == CKR_OK) {
      rv = rvtmp;
    }

    if (V->Def->ASN1) {
      DEBUG ((
        EFI_D_ERROR,
        "ASN.1 of '%s':\n",
        V->Def->Name != NULL_PTR ? V->Def->Name : L""
        ));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  default:
    DEBUG ((EFI_D_ERROR, "Unknown\n"));

    if (V->Def->ASN1) {
      DEBUG ((EFI_D_ERROR, "ASN.1:\n"));
      DUMP (V->ASN1.Val, V->ASN1.Len);
    }

    break;
  }

  Indent--;
  return rv;
}

/* Show ASN.1 tree starting from the specified object */
CK_RV ShowASN1Tree(ASN1_TYPE_VAL const *V)
{
  CK_RV rv;

  DEBUG ((
    EFI_D_ERROR,
    "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
    "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"
    ));

  rv = ShowASN1TreeExecutive (V, (CK_ULONG)-1);

  DEBUG ((
    EFI_D_ERROR,
    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
    ));

  return rv;
}

CK_RV ShowASN1TreeByHandle (CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hObject)
{
  CK_ULONG      ObjOrd;
  OBJECT_TYPE   ObjType;
  CK_ULONG      ItemOrd;
  CK_ULONG      I;
  ASN1_TYPE_VAL *V;
  CK_RV         rv;

  if ((rv = FindSlotBySession(&I, hSession)) != CKR_OK ||
      (rv = HandleToObjOrds (
              &ObjOrd,
              &ObjType,
              &ItemOrd,
              &Cryptoki.Slots[I].Data,
              hObject
              )) != CKR_OK) {
    if (rv == CKR_OBJECT_HANDLE_INVALID) {
      DEBUG ((EFI_D_ERROR, "ShowASN1TreeByHandle(): Invalid object handle\n"));
    }

    return rv;
  }

  V = &Cryptoki.Slots[I].Data.Objects[ObjOrd][ObjType];

  /* Check found object ASN1 type validity */
  if (V->Decoded                                          &&
      V->Def->Type == ASN1_SEQUENCE_OF_CLASS_TYPE         &&
      ItemOrd      <  V->TypeVal.SequenceOf.Cnt           &&
      (V = &V->TypeVal.SequenceOf.Item[ItemOrd])->Decoded &&
      V->Def->Type == ASN1_CHOICE_CLASS_TYPE) {
    ShowASN1Tree (V);
  } else {
    return CKR_GENERAL_ERROR;
  }

  return rv;
}

#endif /* INCLUDE_TESTING */
