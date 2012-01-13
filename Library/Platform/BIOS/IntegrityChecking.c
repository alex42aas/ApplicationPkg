/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/IntegrityChecking.h>
#include <Guid/SignFvGuidedSectionExtractionLite.h>
#include <Library/BootMngrLib.h>

#define LOG(MSG)          DEBUG(MSG)

STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC BOOLEAN bFormExit;
STATIC MULTIBOOT_CONFIG *MbConfig;

typedef struct {
  EFI_GUID_DEFINED_SECTION  GuidedSectionHeader; ///< EFI guided section header
  UINT8                     Type;
  UINT8                     DataLen[3];
  UINT8                     SignData[32];
} SIGN_FV_SECTION_HEADER;

typedef struct {
  EFI_GUID Guid;
  CHAR8    DigestStr[65];
  UINTN    SignDataLen;
  UINT32   Flags;
} INTEGRITY_REPORT;

#define F_HASH_OK                     (1 << 0)

#define REPORT_BASE_MAX_RECORDS       256


typedef struct {
  EFI_GUID Guid;
  CHAR16   Name[50];
} WELL_KNOWN_MODULES;


STATIC
VOID
DestroyHiiResources(
  VOID
  )
{
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }
}

STATIC
EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_INTEGRITY_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = INTEGRITY_PAGE_ID;
  
  DestroyHiiResources();
  
  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (StartOpCodeHandle == NULL) {
    goto _exit;
  }

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (EndOpCodeHandle == NULL) {
    goto _exit;
  }

  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      StartOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_INTEGRITY_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_INTEGRITY_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


EFI_STATUS
IntegrityPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;

  (VOID)Status;
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bFormExit = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }
  
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
ShowBiosInfo(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId
  )
{
  CHAR16 Str16BiosBuild[50], Str16Platform[50];
  CHAR16 Str16SystemGuid[60];
  T_FIRMWARE_INFO FwInfo;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID SysGuid;

  GetFirmwareInfo(&FwInfo);
  GetSystemGuidFromVolume (&SysGuid);
  
  UnicodeSPrint(Str16SystemGuid, sizeof(Str16SystemGuid), L"%s %g", 
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_SYSTEM_GUID), NULL),
      &SysGuid);
            
  UnicodeSPrint(Str16Platform, sizeof(Str16Platform), L"%s %g", 
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PLATFORM_GUID), NULL),
      &FwInfo.PlatformGuid);
  UnicodeSPrint(Str16BiosBuild, sizeof(Str16BiosBuild), L"%s %a", 
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_BIOS_BUILD), NULL),
      FwInfo.FwBuildStr);

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  Token = HiiSetString (HiiHandle, 0, Str16SystemGuid, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, /*EFI_IFR_FLAG_READ_ONLY |*/ EFI_IFR_FLAG_CALLBACK, 0);
  
  Token = HiiSetString (HiiHandle, 0, Str16Platform, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, /*EFI_IFR_FLAG_READ_ONLY |*/ EFI_IFR_FLAG_CALLBACK, 0);

  Token = HiiSetString (HiiHandle, 0, Str16BiosBuild, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, /*EFI_IFR_FLAG_READ_ONLY |*/ EFI_IFR_FLAG_CALLBACK, 0);
  return EFI_SUCCESS;
}



EFI_STATUS 
CheckAllLoadingComponents(
  IN struct tMainFvInfo *pmfvi
  )
{
  UINT8 *TmpPtr;
  UINTN ObjCount, Idx, ObjPresentCnt;
  struct tHashRecord *pCheckedObjs = NULL, *ObjPtr;
  BOOLEAN bRestart;
  EFI_GUID *pGuid;
  EFI_STATUS Status = EFI_ABORTED;
  MULTIBOOT_MODULE *Module;
  CHAR8 FileName[255];

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (pmfvi == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (MbConfig == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  ObjCount = GetObjDescCount();
  LOG((EFI_D_ERROR, "%a.%d ObjCount=%d\n", __FUNCTION__, __LINE__, ObjCount));
  if (ObjCount == 0) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  pCheckedObjs = AllocateZeroPool(ObjCount * 
    (sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN));
  if (pCheckedObjs == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  ObjPtr = pCheckedObjs;
  for (Idx = 0, bRestart = TRUE, ObjPresentCnt = 0; Idx < ObjCount; Idx++) {
    pGuid = GetNextObjDescGuid(bRestart);
    if (pGuid == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
    
    LOG((EFI_D_ERROR, "%a.%d pGuid=%g\n", __FUNCTION__, __LINE__, pGuid));
    
    bRestart = FALSE;
    TmpPtr = FindInfoRecordByGuid(pmfvi, pGuid);
    if (TmpPtr == NULL) {
      continue;
    }
    CopyMem((UINT8*)ObjPtr, TmpPtr, 
      sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN);

    TmpPtr = (UINT8*)ObjPtr + ObjPtr->Size;
    ObjPtr = (struct tHashRecord*)TmpPtr;
    
    ObjPresentCnt++;
  }
  LOG((EFI_D_ERROR, "%a.%d ObjPresentCnt=%d\n", 
    __FUNCTION__, __LINE__, ObjPresentCnt));
  /*
    this counter may be 0 if it is DEBUG build i.e.
    */
  if (ObjPresentCnt == 0) {
    if (CheckPcdDebugPropertyMask()) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = EFI_SUCCESS;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Status = EFI_NOT_FOUND;
    }
    goto _exit;
  }

  
  for (Idx = 0, ObjPtr = pCheckedObjs; Idx < ObjPresentCnt; Idx++) {
    EFI_GUID TmpGuid;
    UINTN Cnt;

    TmpGuid.Data1 = ObjPtr->Guid.Data1;
    TmpGuid.Data2 = ObjPtr->Guid.Data2;
    TmpGuid.Data3 = ObjPtr->Guid.Data3;
    for (Cnt = 0; Cnt < 8; Cnt++) {
      TmpGuid.Data4[Cnt] = ObjPtr->Guid.Data4[Cnt];
    }
    Module = FindModuleByGuid(MbConfig, (EFI_GUID*)&TmpGuid);
    if (Module) {
      LOG((EFI_D_ERROR, "%a.%d {DevPath=%s}!\n", __FUNCTION__, __LINE__,
        Module->DevPath));
      AsciiSPrint(FileName, sizeof(FileName) - 1, "%s", Module->DevPath);
      
      Status = CheckFile(FileName, ObjPtr->HashType, ObjPtr->HashData);
     
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        goto _exit;
      }
    }
    TmpPtr = (UINT8*)ObjPtr + ObjPtr->Size;
    ObjPtr = (struct tHashRecord*)TmpPtr;
  }
  Status = EFI_SUCCESS;
  
_exit:
  if (pCheckedObjs) {
    FreePool(pCheckedObjs);
  }
  return Status;
}

STATIC
EFI_STATUS
IcflCheck(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId,
  IN UINTN ModeIdx
  )
{
  LIST_ENTRY *Link;
  ICFL_LIST *List;
  CHAR16 *DevPath, *Ptr16;
  CHAR16 *FilePath;
  EFI_DEVICE_PATH_PROTOCOL *Dp;
  EFI_FILE_HANDLE File;
  CHAR8 HashData[MAX_HASH_LEN];
  EFI_STATUS Status;  
  LIST_ENTRY *IcflList, IcflListTmp;
  CHAR16 *FileName = NULL, *DeviceName = NULL;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  CHAR16 Str16Files[255];
  CHAR16 Str16Help[255];
  CHAR16 HashStr[(MAX_HASH_LEN + 1) * sizeof(CHAR16)];
  UINT8 Res = 0;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitializeListHead(&IcflListTmp);
  IcflList = &IcflListTmp;
  Status = GetIcfl(IcflList);
  /* this case: list not exist */
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  }

  if (IsListEmpty(IcflList)) {
    LOG((EFI_D_ERROR, "%a.%d List empty!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  Token = HiiSetString (HiiHandle, 0, BootMngrGetVarsDesc(ModeIdx), NULL);
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);

  for (Link = GetFirstNode(IcflList); 
       !IsNull(IcflList, Link); 
       ) {
    Status = EFI_SUCCESS;
    List = (ICFL_LIST*)Link;
    Link = GetNextNode (IcflList, Link);

    LOG((EFI_D_ERROR, "%a.%d List->FileName=\"%s\"\n", 
      __FUNCTION__, __LINE__, List->FileName));
    
    
    DevPath = List->FileName;
    Ptr16 = StrStr(List->FileName, ICFL_SEPARATOR);
    if (!Ptr16) {
      LOG((EFI_D_ERROR, "%a.%d EFI_INVALID_PARAMETER\n", 
        __FUNCTION__, __LINE__));
      Status = EFI_INVALID_PARAMETER;
      goto Done;
    }
    *Ptr16 = 0;

    DeviceName = AllocateCopyPool(StrSize(List->FileName), List->FileName);
    if (DeviceName == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    
    /* skip separator */
    FilePath = Ptr16 + StrLen(ICFL_SEPARATOR);
    LOG((EFI_D_ERROR, "DevPath=%s FilePath=%s\n", DevPath, FilePath));
    FileName = AllocateCopyPool(StrSize(FilePath), FilePath);
    if (FileName == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    Dp = StrToDevicePath(DevPath);
    *Ptr16 = L'|';

    ZeroMem(HashData, sizeof(HashData));
    if (IsLegacyBootDevPath(List->FileName)) {
      Status = CalcHashForMbr(List->FileName, CS_TYPE_CRC32, HashData);
    } else {    
      File = LibFsOpenFileByDevPath(Dp, FilePath, EFI_FILE_MODE_READ, 0);
      Status = CalcHashCsOnFileWithHandle(File, CS_TYPE_CRC32, HashData);
      LOG((EFI_D_ERROR, "%a.%d Status=%r\n", 
          __FUNCTION__, __LINE__, Status));
    }
    
    if (!EFI_ERROR(Status)) {
      if (CompareMem(HashData, List->Hash, GetHashLen(CS_TYPE_CRC32))) {
        LOG((EFI_D_ERROR, "%a.%d EFI_CRC_ERROR\n", 
          __FUNCTION__, __LINE__));
        Status = EFI_CRC_ERROR;
      }
    }

    if (EFI_ERROR(Status)) {
      Res |= (1 << 1);
    }

    UnicodeSPrint(Str16Files, sizeof(Str16Files), L"    %s  ...  %s",
      FileName, HiiGetString(CurrentHiiHandle, 
                  EFI_ERROR(Status) ? 
                    STRING_TOKEN(STR_ERROR) : STRING_TOKEN(STR_SUCCESS), 
                  NULL)
      );
    Token = HiiSetString (HiiHandle, 0, Str16Files, NULL);


    GetDigestStr16(HashStr, List->Hash, CS_TYPE_CRC32);
    UnicodeSPrint(Str16Help, sizeof(Str16Help), L"DevPath: %s\nHash: %s",
      DeviceName, HashStr);
    
    HelpToken = HiiSetString (HiiHandle, 0, Str16Help, NULL);
    QuestionId = (EFI_QUESTION_ID)*QId;
    ++*QId;
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    
    if (FileName) {
      FreePool(FileName);
      FileName = NULL;
    }
    if (DeviceName) {
      FreePool(DeviceName);
      DeviceName = NULL;
    }
  }
  Status = EFI_SUCCESS;
Done:
  if (!IsListEmpty(IcflList)) {
    DestroyIcflList(IcflList);
  }
  if (FileName) {
    FreePool(FileName);
  }
  if (DeviceName) {
    FreePool(DeviceName);
  }
  if (EFI_ERROR(Status)) {
    return Status;
  }
  return Res ? EFI_CRC_ERROR : EFI_SUCCESS;
}


STATIC
EFI_STATUS
CheckFiles(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId
  )
{
  UINT8 ResFlags = 0;
  CHAR16 Str16Files[255];
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_STATUS Status;
  UINTN Idx;

  Str16Files[0] = '\0';
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  Status = CheckAllLoadingComponents(&MainFvInfo);
  if (EFI_ERROR(Status)) {
    if (Status == EFI_NOT_FOUND && PcdGetBool(bDisableCheckOSComponents)) {
      
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      ResFlags |= (1 << 1);
    }
  }
  
  if (-1 == CheckAllObjWithPath(&MainFvInfo)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ResFlags |= (1 << 1); 
  }

  UnicodeSPrint(Str16Files, sizeof(Str16Files), L"%s %s",
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_FILE_HASH_CHECK), NULL),
    HiiGetString(CurrentHiiHandle, 
      ResFlags ? 
        STRING_TOKEN(STR_ERROR) : STRING_TOKEN(STR_SUCCESS), 
      NULL)
    );
  Token = HiiSetString (HiiHandle, 0, Str16Files, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

  for (Idx = 0; Idx < MAX_VARS_GUIDS; Idx++) {
    if (NULL == BootMngrGetVarsDesc(Idx)) {
      continue;
    }
    
    BootMngrSetVarsGuidIdx(Idx);
    Status = IcflCheck(HiiHandle, QId, Idx);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      if (Status != EFI_NOT_FOUND) {
        ResFlags |= (1 << 2);
      }
    }
  }

  return ResFlags ? EFI_CRC_ERROR : EFI_SUCCESS;
}


STATIC
EFI_STATUS
CheckUsers(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId
  )
{
  UINT8 ResFlags = 0;
  CHAR16 Str16Users[50];
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_STATUS Status;

  Str16Users[0] = 0;

  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    ResFlags |= (1 << 2); 
  }

  UnicodeSPrint(Str16Users, sizeof(Str16Users), L"%s %s",
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_BIOS_USERS_INTEGRITY_CHECK), NULL),
    HiiGetString(CurrentHiiHandle, 
      ResFlags & 0x08 ? 
        STRING_TOKEN(STR_ERROR) : STRING_TOKEN(STR_SUCCESS), 
      NULL)
    );
  Token = HiiSetString (HiiHandle, 0, Str16Users, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

  return ResFlags ? EFI_CRC_ERROR : EFI_SUCCESS;
}


STATIC
EFI_STATUS
CheckHistory(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId
  )
{
  UINT8 ResFlags = 0;
  CHAR16 Str16Log[50];
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_STATUS Status;

  Str16Log[0] = 0;
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  Status = HistoryStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    ResFlags |= (1 << 3); 
  }

  UnicodeSPrint(Str16Log, sizeof(Str16Log), L"%s %s",
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_BIOS_LOG_INTEGRITY_CHECK), NULL),
    HiiGetString(CurrentHiiHandle, 
      ResFlags & 0x08 ? 
        STRING_TOKEN(STR_ERROR) : STRING_TOKEN(STR_SUCCESS), 
      NULL)
    );
  Token = HiiSetString (HiiHandle, 0, Str16Log, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

  return ResFlags ? EFI_CRC_ERROR : EFI_SUCCESS;
}


STATIC
EFI_STATUS
CheckBios(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_QUESTION_ID *QId
  )
{
  UINT8 ResFlags = 0;
  CHAR16 Str16Bios[50];
  CHAR16 Str16BiosHash[128];
  CHAR8 Str8BiosHash[128];
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  struct tHashRecord *pRec = NULL;
  EFI_GUID GuidVal;
  EFI_STATUS Status;
  UINTN RestSize;

  Str16Bios[0] = 0;
  Str16BiosHash[0] = 0;
  Str8BiosHash[0] = 0;
  
  if (-1 == CheckMainFvHashCs(MAIN_GUID_STR, &MainFvInfo)) {
    ResFlags |= (1 << 0); 
  }

  Status = StringToGuid_L(MAIN_GUID_STR, &GuidVal);  
  if (!EFI_ERROR(Status)) {
      pRec = (struct tHashRecord *)FindPlaceInExtHdr(&GuidVal,
        &MainFvInfo, &RestSize);      
  }

  UnicodeSPrint(Str16Bios, sizeof(Str16Bios), L"%s %s",
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_BIOS_HASH_CHECK), NULL),
    HiiGetString(CurrentHiiHandle, 
      ResFlags & 0x01 ? 
        STRING_TOKEN(STR_ERROR) : STRING_TOKEN(STR_SUCCESS), 
      NULL)
    );

  if (pRec) {
    ByteBufToStringRev (
      pRec->HashData,
      GetHashLen(pRec->HashType),
      Str8BiosHash,
      sizeof(Str8BiosHash)
      );
    UnicodeSPrint (
      Str16BiosHash,
      sizeof (Str16BiosHash),
      L"%a",
      Str8BiosHash
      );
  }
  
  Token = HiiSetString (HiiHandle, 0, Str16Bios, NULL);
  HelpToken = HiiSetString (HiiHandle, 0, Str16BiosHash, NULL);
  QuestionId = (EFI_QUESTION_ID)*QId;
  ++*QId;
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
    HelpToken, EFI_IFR_FLAG_CALLBACK, 0);   
  
  return ResFlags ? EFI_CRC_ERROR : EFI_SUCCESS; 
}

#define GET_OCCUPIED_SIZE(ActualSize, Alignment) \
  (ActualSize) + (((Alignment) - ((ActualSize) & ((Alignment) - 1))) & ((Alignment) - 1))

BOOLEAN
IsBufferErased (
  IN UINT8    ErasePolarity,
  IN VOID     *InBuffer,
  IN UINTN    BufferSize
  )
{
  UINTN   Count;
  UINT8   EraseByte;
  UINT8   *Buffer;

  if(ErasePolarity == 1) {
    EraseByte = 0xFF;
  } else {
    EraseByte = 0;
  }

  Buffer = InBuffer;
  for (Count = 0; Count < BufferSize; Count++) {
    if (Buffer[Count] != EraseByte) {
      return FALSE;
    }
  }

  return TRUE;
}


STATIC
EFI_FFS_FILE_STATE
GetFileState(
  IN UINT8                ErasePolarity,
  IN EFI_FFS_FILE_HEADER  *FfsHeader
  )
{
  EFI_FFS_FILE_STATE  FileState;
  EFI_FFS_FILE_STATE  HighestBit;

  FileState = FfsHeader->State;

  if (ErasePolarity != 0) {
    FileState = (EFI_FFS_FILE_STATE)~FileState;
  }

  HighestBit = 0x80;
  while (HighestBit != 0 && (HighestBit & FileState) == 0) {
    HighestBit >>= 1;
  }

  return HighestBit;
} 

EFI_STATUS
FindFileEx (
  IN  CONST EFI_FIRMWARE_VOLUME_HEADER  *FvHandle,
  IN  CONST EFI_GUID                    *FileName,   OPTIONAL
  IN        EFI_FV_FILETYPE             SearchType,
  IN OUT    EFI_FFS_FILE_HEADER         **FileHandle
  )
{
  EFI_FIRMWARE_VOLUME_HEADER           *FwVolHeader;
  EFI_FFS_FILE_HEADER                   **FileHeader;
  EFI_FFS_FILE_HEADER                   *FfsFileHeader;
  EFI_FIRMWARE_VOLUME_EXT_HEADER        *FwVolExHeaderInfo;
  UINT32                                FileLength;
  UINT32                                FileOccupiedSize;
  UINT32                                FileOffset;
  UINT64                                FvLength;
  UINT8                                 ErasePolarity;
  UINT8                                 FileState;

  FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)FvHandle;
  FileHeader  = (EFI_FFS_FILE_HEADER **)FileHandle;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_ERROR, "FileSystemGuid=%g\n", &FwVolHeader->FileSystemGuid));

  FvLength = FwVolHeader->FvLength;
  if (FwVolHeader->Attributes & EFI_FVB2_ERASE_POLARITY) {
    ErasePolarity = 1;
  } else {
    ErasePolarity = 0;
  }

  //
  // If FileHeader is not specified (NULL) or FileName is not NULL,
  // start with the first file in the firmware volume.  Otherwise,
  // start from the FileHeader.
  //
  if ((*FileHeader == NULL) || (FileName != NULL)) {
    FfsFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)FwVolHeader + FwVolHeader->HeaderLength);
    if (FwVolHeader->ExtHeaderOffset != 0) {
      FwVolExHeaderInfo = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)(((UINT8 *)FwVolHeader) + FwVolHeader->ExtHeaderOffset);
      FfsFileHeader = (EFI_FFS_FILE_HEADER *)(((UINT8 *)FwVolExHeaderInfo) + FwVolExHeaderInfo->ExtHeaderSize);
    }
  } else {
    //
    // Length is 24 bits wide so mask upper 8 bits
    // FileLength is adjusted to FileOccupiedSize as it is 8 byte aligned.
    //
    FileLength = *(UINT32 *)(*FileHeader)->Size & 0x00FFFFFF;
    FileOccupiedSize = GET_OCCUPIED_SIZE (FileLength, 8);
    FfsFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)*FileHeader + FileOccupiedSize);
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  FileOffset = (UINT32) ((UINT8 *)FfsFileHeader - (UINT8 *)FwVolHeader);
  ASSERT (FileOffset <= 0xFFFFFFFF);

  while (FileOffset < (FvLength - sizeof (EFI_FFS_FILE_HEADER))) {

    if (IsBufferErased (ErasePolarity, FfsFileHeader, sizeof (EFI_FFS_FILE_HEADER))) {
      //
      // We have found the free space so we are done!
      //
      break;
    }

    //
    // Get FileState which is the highest bit of the State 
    //
    FileState = GetFileState (ErasePolarity, FfsFileHeader);

    switch (FileState) {

    case EFI_FILE_HEADER_INVALID:
      FileOffset += sizeof(EFI_FFS_FILE_HEADER);
      FfsFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)FfsFileHeader + sizeof(EFI_FFS_FILE_HEADER));
      break;
        
    case EFI_FILE_DATA_VALID:
    case EFI_FILE_MARKED_FOR_UPDATE:
      FileLength = *(UINT32 *)(FfsFileHeader->Size) & 0x00FFFFFF;
      FileOccupiedSize = GET_OCCUPIED_SIZE(FileLength, 8);

      if (FileName != NULL) {
        if (CompareGuid (&FfsFileHeader->Name, (EFI_GUID*)FileName)) {
          *FileHeader = FfsFileHeader;
          return EFI_SUCCESS;
        }
      } else if (((SearchType == FfsFileHeader->Type) || (SearchType == EFI_FV_FILETYPE_ALL)) && 
                 (FfsFileHeader->Type != EFI_FV_FILETYPE_FFS_PAD)) { 
        *FileHeader = FfsFileHeader;
        LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
        return EFI_SUCCESS;
      }

      FileOffset += FileOccupiedSize; 
      FfsFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)FfsFileHeader + FileOccupiedSize);
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      break;
    
    case EFI_FILE_DELETED:
      FileLength = *(UINT32 *)(FfsFileHeader->Size) & 0x00FFFFFF;
      FileOccupiedSize = GET_OCCUPIED_SIZE(FileLength, 8);
      FileOffset += FileOccupiedSize;
      FfsFileHeader = (EFI_FFS_FILE_HEADER *)((UINT8 *)FfsFileHeader + FileOccupiedSize);
      break;

    default:
      FileOffset++;
      FfsFileHeader = (EFI_FFS_FILE_HEADER*)((UINT8*)FfsFileHeader + 1);
    } 
  }

  
  *FileHeader = NULL;
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;  
}


STATIC
UINT32
GetLength (
  IN UINT8     *ThreeByteLength
  )
{
  UINT32  Length;

  if (ThreeByteLength == NULL) {
    return 0;
  }

  Length  = *((UINT32 *) ThreeByteLength);
  Length  = Length & 0x00FFFFFF;

  return Length;
}


STATIC
EFI_STATUS
FindNextSection (
  IN VOID *SectionsStart,
  IN UINTN TotalSectionsSize,
  IN OUT UINTN *Key,
  OUT VOID **Section
  )
{
  EFI_COMMON_SECTION_HEADER *sectionHdr;
  UINTN sectionSize;

  *Key = (UINTN)ALIGN_POINTER (*Key, 4); // Sections are DWORD aligned

  if ((*Key + sizeof (*sectionHdr)) > TotalSectionsSize) {
    return EFI_NOT_FOUND;
  }

  sectionHdr = (EFI_COMMON_SECTION_HEADER*)((UINT8*)SectionsStart + *Key);
  sectionSize = GetLength (sectionHdr->Size);

  if (sectionSize < sizeof (EFI_COMMON_SECTION_HEADER)) {
    return EFI_NOT_FOUND;
  }

  if ((*Key + sectionSize) > TotalSectionsSize) {
    return EFI_NOT_FOUND;
  }

  *Section = (UINT8*)sectionHdr;
  *Key = *Key + sectionSize;
  return EFI_SUCCESS;

}


STATIC
EFI_STATUS
GetGuidedSection(
  IN UINT8 *SectionData,
  IN UINTN SectionDataLen,
  OUT UINT8 **GuiededSec
  )
{
  UINTN SecKey;
  EFI_COMMON_SECTION_HEADER *SectionDesc;
  EFI_STATUS Status;

  SecKey = 0;

  while (1) {
    Status = FindNextSection (
      (VOID*)SectionData,
      SectionDataLen, //
      &SecKey,
      (VOID**)&SectionDesc
      );

    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }

    if (SectionDesc == NULL) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      break;
    }

    LOG((EFI_D_ERROR, "%a.%d SectionDesc->Type=%X\n", 
      __FUNCTION__, __LINE__, SectionDesc->Type));
    
    if (SectionDesc->Type == EFI_SECTION_GUID_DEFINED) {
      *GuiededSec = (UINT8*)SectionDesc;
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

EFI_STATUS
ObtainModulesSignReport(
  IN OUT INTEGRITY_REPORT **Report,
  IN OUT UINTN *NumRecords
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_FIRMWARE_VOLUME_HEADER  *VolumeHandle;
  EFI_FFS_FILE_HEADER         *FileHandle;
  EFI_STATUS                  Status;
  UINTN                       Size;
  SIGN_FV_SECTION_HEADER      *GuidDefHdr;
  UINT8                       TmpData[256];
  struct tHashRecord          *HashRecord;
  UINT8                       *Data;
  UINTN                       DataLen;
  CHAR8                       HashStr[256];
  int                         RetVal;
  UINTN                       Idx, SecDataLen;
  UINTN                       MaxRecords;
  UINT8                       *SecData, *GuidedSec;
  EFI_COMMON_SECTION_HEADER   *pSecHdr;
  INTEGRITY_REPORT            *OldReport;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Report == NULL || NumRecords == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    return EFI_ABORTED;
  }

  MaxRecords = REPORT_BASE_MAX_RECORDS;
  *Report = AllocatePool (sizeof(INTEGRITY_REPORT) * MaxRecords);
  if (*Report == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  *NumRecords = 0;
  FileHandle = NULL;
  Idx = 0;
  do {
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, Hob.Raw);
    FileHandle = NULL;
    if (Hob.Raw != NULL) {      
      VolumeHandle = (EFI_FIRMWARE_VOLUME_HEADER*)(UINTN)(Hob.FirmwareVolume->BaseAddress);
      LOG((EFI_D_ERROR, "VolumeHandle = %p\n", VolumeHandle));
      LOG((EFI_D_ERROR, "VolumeHandle->FvLength = 0x%X\n", VolumeHandle->FvLength));
      
      while (1) {
        Status = FindFileEx (VolumeHandle, NULL, EFI_FV_FILETYPE_ALL, 
          &FileHandle);
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%.d Status=%X\n", 
            __FUNCTION__, __LINE__, Status));
          break;
        }
        LOG((EFI_D_ERROR, "Name %g\n", &FileHandle->Name));
        ZeroMem(&Size, sizeof(Size));
        CopyMem(&Size, FileHandle->Size, sizeof(FileHandle->Size));

        SecData = (UINT8 *) ((UINT8*) FileHandle + sizeof (EFI_FFS_FILE_HEADER));
        SecDataLen = GetLength (FileHandle->Size) - sizeof (EFI_FFS_FILE_HEADER);

        pSecHdr = (EFI_COMMON_SECTION_HEADER*)SecData;

        if (FileHandle->Type == EFI_FV_FILETYPE_FFS_PAD) {
          LOG((EFI_D_ERROR, "%a.%.d EFI_FV_FILETYPE_FFS_PAD\n", 
            __FUNCTION__, __LINE__));
          continue;
        }
        if (pSecHdr->Type != EFI_SECTION_GUID_DEFINED) {
          Status = GetGuidedSection(SecData, SecDataLen, &GuidedSec);
          LOG((EFI_D_ERROR, "Status = %X\n", Status));
          if (EFI_ERROR(Status)) {
            continue;
          }
          GuidDefHdr = (SIGN_FV_SECTION_HEADER*)GuidedSec;
        } else {
          GuidDefHdr = (SIGN_FV_SECTION_HEADER*)pSecHdr;
        }

        if (!CompareGuid (&gEfiSignFvGuidedSectionExtractionLiteGuid, 
            &GuidDefHdr->GuidedSectionHeader.SectionDefinitionGuid)) {
          continue;
        }
        
        ZeroMem(TmpData, sizeof(TmpData));
        HashRecord = (struct tHashRecord*)TmpData;
        HashRecord->HashType = GuidDefHdr->Type;        

        Data = (UINT8 *) GuidDefHdr + GuidDefHdr->GuidedSectionHeader.DataOffset;
        DataLen   = *(UINT32 *) GuidDefHdr->DataLen & 0xFFFFFF;
        
        LOG ((EFI_D_ERROR, "%a.%d HashRecord->HashType=%d\n",
              __FUNCTION__, __LINE__, HashRecord->HashType));
        if (DataLen < sizeof (EFI_COMMON_SECTION_HEADER)) {
          Status = EFI_CRC_ERROR;
        } else {
          Status = CalcHashCs(
                    HashRecord->HashType, 
                    Data + sizeof (EFI_COMMON_SECTION_HEADER), 
                    DataLen - sizeof (EFI_COMMON_SECTION_HEADER),
                    CALC_CS_RESET | CALC_CS_FINALIZE, 
                    HashRecord->HashData
                    );
        }
        RetVal = -1;
        if (!EFI_ERROR(Status)) {
          if (CompareMem(HashRecord->HashData, GuidDefHdr->SignData,
                GetHashLen(HashRecord->HashType)) == 0) {
            RetVal = 0;
          } else {
            /* may be old-style hash of whole ffs? */
            LOG ((EFI_D_ERROR, "%a.%d HashRecord->HashType=%d\n",
              __FUNCTION__, __LINE__, HashRecord->HashType));
            Status = CalcHashCs(
                    HashRecord->HashType, 
                    Data, 
                    DataLen,
                    CALC_CS_RESET | CALC_CS_FINALIZE, 
                    HashRecord->HashData
                    );
            if (!EFI_ERROR(Status)) {
              if (CompareMem(HashRecord->HashData, GuidDefHdr->SignData,
                GetHashLen(HashRecord->HashType)) == 0) {
                RetVal = 0;
              } else {
                DEBUG ((EFI_D_ERROR, " ==================================== \n"));
                DumpBytes(HashRecord->HashData, GetHashLen(HashRecord->HashType));
                DEBUG ((EFI_D_ERROR, " ==================================== \n"));
                DumpBytes(GuidDefHdr->SignData, GetHashLen(HashRecord->HashType));
              }
            }
          }
        }
        AsciiSPrint(HashStr, sizeof(HashStr), "--- HASH ERROR ---");
        GetDigestStr(HashStr, HashRecord);
        CopyMem(&(*Report)[Idx].Guid, &FileHandle->Name, sizeof(EFI_GUID));
        AsciiStrCpy((*Report)[Idx].DigestStr, HashStr);
        (*Report)[Idx].SignDataLen = GetHashLen(HashRecord->HashType);
        (*Report)[Idx].Flags |= (RetVal == -1 ? 0 : F_HASH_OK);
        Idx++;
        *NumRecords = Idx;
        if (Idx == MaxRecords) {
          OldReport = *Report;
          MaxRecords *= 2;
          LOG((EFI_D_ERROR, "%a.%d MaxRecords = %d -> %d\n", __FUNCTION__, __LINE__, Idx, MaxRecords));
          *Report = AllocatePool (sizeof(INTEGRITY_REPORT) * MaxRecords);
          if (*Report == NULL) {
            LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
            FreePool (OldReport);
            return EFI_OUT_OF_RESOURCES;
          }
          CopyMem (*Report, OldReport, sizeof(INTEGRITY_REPORT) * Idx);
          FreePool (OldReport);
        }
      }
      
      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);
  LOG((EFI_D_ERROR, "%a.%d *NumRecords = %d\n", __FUNCTION__, __LINE__, *NumRecords));
  return EFI_SUCCESS;
}

EFI_STATUS
GetModuleName(
  IN  EFI_GUID *ModuleGuid,
  OUT CHAR16    **ModuleName
  )
{
  UINTN Index;
  EFI_STATUS Status;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *Fv;
  UINT32                        AuthenticationStatus;
  UINTN                         FvHandleCount;
  EFI_HANDLE                    *FvHandleBuffer;
  UINT8                         *Buffer;
  UINTN                         BufferSize;

  Fv = NULL;
  
  gBS->LocateHandleBuffer (
        ByProtocol,
        &gEfiFirmwareVolume2ProtocolGuid,
        NULL,
        &FvHandleCount,
        &FvHandleBuffer
        );

  Status = EFI_NOT_FOUND;

  for (Index = 0; Index < FvHandleCount; Index++) {
    gBS->HandleProtocol (
          FvHandleBuffer[Index],
          &gEfiFirmwareVolume2ProtocolGuid,
          (VOID **) &Fv
          );

    ASSERT( Fv != NULL );
    
    BufferSize = 0;
    Buffer = NULL;

    Status = Fv->ReadSection (
                Fv,
                ModuleGuid,
                EFI_SECTION_GUID_DEFINED,
                0,
                &Buffer,
                &BufferSize,
                &AuthenticationStatus
                );
    
    if (EFI_ERROR (Status)) {      
      continue;
    }
    if (Buffer != NULL) {
      FreePool(Buffer);
    }

    BufferSize = 0;
    Buffer = NULL;
    Status = Fv->ReadSection (
                Fv,
                ModuleGuid,
                EFI_SECTION_USER_INTERFACE,
                0,
                &Buffer,
                &BufferSize,
                &AuthenticationStatus
                );

    if (EFI_ERROR (Status)) {
      continue;
    }
    if (Buffer == NULL) {
      continue;
    }
    *ModuleName = AllocateZeroPool(BufferSize + 2);
    if (*ModuleName == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }
    CopyMem(*ModuleName, Buffer, BufferSize);
    FreePool(Buffer);
    Status = EFI_SUCCESS;
    break;
  }
  
  if (FvHandleCount != 0) {
    FreePool (FvHandleBuffer);
  }
  return Status;
}

STATIC
EFI_STATUS
ListPageStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STRING_ID Title,
  IN EFI_QUESTION_ID StartQId
  )
{
  EFI_STATUS Status;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_INTEGRITY_GUID;
  EFI_FORM_ID FormId = INTEGRITY_PAGE_ID;
  CHAR16 TmpStr16[255];
  UINTN NumRecords, Idx, ErrNum;
  INTEGRITY_REPORT *Report = NULL;

  (VOID)Status, (VOID)Token, (VOID)Idx, (VOID)TmpStr16, (VOID)NumRecords, 
    (VOID)Report;
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  QuestionId = (EFI_QUESTION_ID)StartQId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Title,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  QuestionId++;

  ShowBiosInfo(HiiHandle, &QuestionId);

  ErrNum = 0;

  Status = CheckBios(HiiHandle, &QuestionId);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    ErrNum++;
  }

  Status = CheckHistory(HiiHandle, &QuestionId);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    ErrNum++;
  }

  Status = CheckUsers(HiiHandle, &QuestionId);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    ErrNum++;
  }
  
  Status = CheckFiles(HiiHandle, &QuestionId);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", 
      __FUNCTION__, __LINE__, Status));
    ErrNum++;
  }

  HistoryAddRecord(HEVENT_FORCE_CHECK_INTEGRITY, GetCurrentUserId(),
    ErrNum ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
    ErrNum ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  
  
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

  NumRecords = 0;
  Status = ObtainModulesSignReport(&Report, &NumRecords);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  LOG((EFI_D_ERROR, "%a.%d NumRecords=%d\n", 
    __FUNCTION__, __LINE__, NumRecords));
  if (NumRecords == 0) {
    return EFI_SUCCESS;
  }
  
  for (Idx = 0; Idx < NumRecords; Idx++) {
    CHAR16 *ModuleName = NULL;

    GetModuleName(&Report[Idx].Guid, &ModuleName);
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%g %s",
      &Report[Idx].Guid,
      HiiGetString(HiiHandle, 
        Report[Idx].Flags & F_HASH_OK ? 
          STRING_TOKEN(STR_SUCCESS) : STRING_TOKEN(STR_ERROR),          
        NULL)
      );
        
    if (ModuleName != NULL) {
      HelpToken = HiiSetString (HiiHandle, 0, ModuleName, NULL);
      FreePool(ModuleName);
    } else {
      HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    }

    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;
  }
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

  if (Report != NULL) {
    FreePool(Report);  
  }

  return EFI_SUCCESS;
}


EFI_STATUS
IntegrityControlPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_INTEGRITY_GUID;
  EFI_FORM_ID FormId = INTEGRITY_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = ListPageStrings(HiiHandle, STRING_TOKEN(STR_INTEGRITY_CHECK_TITLE2),
    (EFI_QUESTION_ID)INTEGRITY_VIEW_RES_START);  
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
  if (EFI_ERROR (Status)) {
    goto _exit;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, FormId, NULL, &ActionRequest);      
    LOG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));  
    if (bFormExit) {
      Status = EFI_SUCCESS;
      break;
    }
  } while (1);
_exit:
  DestroyHiiResources();
  return Status;
}


EFI_STATUS
IntegrityCheckingPageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  CurrentHiiHandle = HiiHandle;
  
  CreatePopUp (
          EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, 
          NULL, 
          L"", 
          HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_INTEGRITY_CHECK), NULL),
          L"", 
          NULL
          );
  return IntegrityControlPage(HiiHandle, Language);
}

EFI_STATUS
CheckModulesIntegrity(
  VOID
  )
{
  INTEGRITY_REPORT *Report = NULL;
  UINTN NumRecords, Idx;
  EFI_STATUS Status = EFI_SUCCESS;

  MsgInfo(STRING_TOKEN(STR_MOD_INTEGRITY_CHECK));

  NumRecords = 0;
  Status = ObtainModulesSignReport(&Report, &NumRecords);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  for (Idx = 0; Idx < NumRecords; Idx++) {
    if ((Report[Idx].Flags & F_HASH_OK) == 0) {
      LOG((EFI_D_ERROR, "Module: %g corrupted!\n",
        &Report[Idx].Guid));
      Status = EFI_CRC_ERROR;
      goto _exit;
    }
  }
  Status = EFI_SUCCESS;
_exit:  
  if (Report != NULL) {
    FreePool(Report);
  }
  if(EFI_ERROR(Status)) {
    MsgInfo(STRING_TOKEN(STR_ERR_BIOS_INTEGRITY));  
  } else {
    MsgInfo( STRING_TOKEN(STR_DONE) );
  }  
  return Status;
}


VOID
IntegrityCheckingInit(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  MbConfig = Cfg;
}

