/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/ExtHdrUtilsLite.h>


static struct tHashRecord *pCorruptRecord;


EFI_STATUS
CalcHashCs(
  IN UINT8 cstype,
  IN UINT8 *pdata,  
  IN UINTN len,
  enum CALC_CS_FLAGS Flags,
  OUT VOID *outbuf)
{
  if (outbuf == NULL || pdata == NULL || len == 0) {
    return EFI_INVALID_PARAMETER;
  }

  switch (cstype) {
  case CS_TYPE_CRC32:
    if (Flags & CALC_CS_RESET) {
      ZeroMem(outbuf, sizeof(UINT32));
      CalculateCrc32Reset (outbuf);
    }
    if (EFI_SUCCESS != CalculateCrc32Update (pdata, len, (UINT32*)outbuf)) {
      return EFI_CRC_ERROR;
    }
    if (Flags & CALC_CS_FINALIZE) {
      if (EFI_SUCCESS != CalculateCrc32Finalize (outbuf)) {
        return EFI_CRC_ERROR;
      }
    }
    break;
    
  default:
    return EFI_CRC_ERROR;
  }
  return EFI_SUCCESS;
}


VOID 
UpdateMainFirmwareInfo(
  IN UINT8 *BufPtr,
  OUT struct tMainFvInfo *pmfvi
  )
{
  UINTN Idx, HeaderSize, FreeSpace;

  Idx = pmfvi->Fvh->ExtHeaderOffset + 
      sizeof(EFI_FIRMWARE_VOLUME_EXT_HEADER);
  HeaderSize = pmfvi->Fvh->ExtHeaderOffset + 
      pmfvi->FvhExt->ExtHeaderSize;
#if 0
  if (HeaderSize > RestLen) {
    return -1;
  }
#endif  
  pmfvi->FvhExtEntry = (EFI_FIRMWARE_VOLUME_EXT_ENTRY*) &BufPtr[Idx];
  FreeSpace = pmfvi->FvhExtEntry->ExtEntrySize - 
      sizeof(EFI_FIRMWARE_VOLUME_EXT_ENTRY);
  pmfvi->ExtDataPtr = BufPtr + HeaderSize - FreeSpace;
  pmfvi->ExtDataSize = FreeSpace;
  pmfvi->FvDataPtr = BufPtr + HeaderSize;
  pmfvi->FvLength = (UINTN)(pmfvi->Fvh->FvLength - HeaderSize);
}

EFI_STATUS
GetNextFvNoMatchWithGuid(
  IN CHAR8 *GuidStr, 
  OUT struct tMainFvInfo *pfvi,
  IN BOOLEAN bRestart
  )
{
  UINT8 *TmpPtr;
  EFI_GUID SearchGuid;
  static EFI_PEI_HOB_POINTERS FvHob;
  EFI_STATUS Status;
  static enum {ST_INIT, ST_NEXT} State = ST_INIT;  
  
  Status = StringToGuid_L(GuidStr, &SearchGuid);  
  if (EFI_ERROR(Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if (bRestart) {
    State = ST_INIT;
  }

  switch (State) {
  case ST_INIT:
    FvHob.Raw = GetHobList();
    State = ST_NEXT;

  case ST_NEXT:  
    while ((FvHob.Raw = GetNextHob (EFI_HOB_TYPE_FV, FvHob.Raw)) != NULL) {
      TmpPtr = (UINT8*)(UINTN)FvHob.FirmwareVolume->BaseAddress;
      pfvi->Fvh = (EFI_FIRMWARE_VOLUME_HEADER*) TmpPtr;
      if ( pfvi->Fvh->Signature != EFI_FVH_SIGNATURE || 
           !pfvi->Fvh->ExtHeaderOffset) {
        FvHob.Raw = GET_NEXT_HOB (FvHob);
        continue;
      }

      pfvi->FvhExt = (EFI_FIRMWARE_VOLUME_EXT_HEADER*) 
        &TmpPtr[pfvi->Fvh->ExtHeaderOffset];
      
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
      DEBUG((EFI_D_ERROR, "Compare: %g %g\n", 
        &SearchGuid, &pfvi->FvhExt->FvName));  
      
      if (CompareGuid_L(&SearchGuid, &pfvi->FvhExt->FvName)) {
        DEBUG((EFI_D_ERROR, "%a.%d: found FV %g\n", 
          __FUNCTION__, __LINE__, &pfvi->FvhExt->FvName));
        UpdateMainFirmwareInfo(TmpPtr, pfvi);
        FvHob.Raw = GET_NEXT_HOB (FvHob);
        return EFI_SUCCESS;
      }
      FvHob.Raw = GET_NEXT_HOB (FvHob);
    }
    State = ST_INIT;
  }
  return EFI_NOT_FOUND;
}


UINT8 *
FindBiosInfoRecord(
  IN struct tMainFvInfo *pmfvi
  )
{
  BiosInfoRecord *pBiosInfoRec; 
  UINTN RestSize;
  UINT8 *TmpPtr;
  
  TmpPtr =  pmfvi->ExtDataPtr;
  RestSize = pmfvi->ExtDataSize;
  
  do {
    pBiosInfoRec = (BiosInfoRecord*)TmpPtr;    
    
    if (pBiosInfoRec->Size == 0) {     
      break;
    }
    
    if (pBiosInfoRec->Type == FV_REC_TYPE_BIOS_INFO) {
      return TmpPtr;
    }
    
    if (RestSize < pBiosInfoRec->Size) {
      return NULL;
    }
    RestSize -= pBiosInfoRec->Size;
    TmpPtr += pBiosInfoRec->Size;
  } while (RestSize >= sizeof(pBiosInfoRec));

  return NULL;
}


UINT8 *
FindInfoRecordByGuid(
  IN struct tMainFvInfo *pmfvi,
  IN EFI_GUID *pGuid
  )
{
  struct tHashRecord *pRec;
  UINTN RestSize, Idx;
  UINT8 *TmpPtr;
  EFI_GUID TmpGuid;
  
  TmpPtr =  pmfvi->ExtDataPtr;
  RestSize = pmfvi->ExtDataSize;
  
  do {
    pRec = (struct tHashRecord*)TmpPtr;    
    
    if (pRec->Size == 0) {     
      break;
    }
    
    TmpGuid.Data1 = pRec->Guid.Data1;
    TmpGuid.Data2 = pRec->Guid.Data2;
    TmpGuid.Data3 = pRec->Guid.Data3;
    for (Idx = 0; Idx < 8; Idx++) {
      TmpGuid.Data4[Idx] = pRec->Guid.Data4[Idx];
    }
    if (CompareGuid_L(&TmpGuid, pGuid) == 0) {
      return TmpPtr;
    }    
    
    if (RestSize < pRec->Size) {
      return NULL;
    }
    RestSize -= pRec->Size;
    TmpPtr += pRec->Size;
  } while (RestSize >= sizeof(struct tHashRecord));

  return NULL;
}



EFI_STATUS 
FindMainFvInByteBuf(
  IN UINT8 *ByteBuf,
  IN UINTN BufSize,
  IN CHAR8 *GuidStr,
  IN OUT struct tMainFvInfo *pmfvi
  )
{
  UINTN RestLen;
  UINT8 *TmpPtr;
  EFI_GUID SearchGuid;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d GuidStr={%a}\n", __FUNCTION__, __LINE__, GuidStr));

  if (ByteBuf == NULL || BufSize == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  RestLen = BufSize;
  TmpPtr = ByteBuf;
  Status = StringToGuid_L(GuidStr, &SearchGuid);  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d RestLen=%d\n", __FUNCTION__, __LINE__, RestLen));
  DEBUG((EFI_D_ERROR, "%a.%d SearchGuid=%g\n", 
    __FUNCTION__, __LINE__, &SearchGuid));

  do {
    pmfvi->Fvh = (EFI_FIRMWARE_VOLUME_HEADER*) TmpPtr;
    if ( pmfvi->Fvh->Signature != EFI_FVH_SIGNATURE ||
         !pmfvi->Fvh->ExtHeaderOffset) {
      TmpPtr++;
      RestLen--;
      continue;
    }

    pmfvi->FvhExt = (EFI_FIRMWARE_VOLUME_EXT_HEADER*)
      &TmpPtr[pmfvi->Fvh->ExtHeaderOffset];
    DEBUG((EFI_D_ERROR, "%a.%d &pmfvi->FvhExt->FvName=%g\n", 
      __FUNCTION__, __LINE__, &pmfvi->FvhExt->FvName));
    if (CompareGuid_L(&SearchGuid, &pmfvi->FvhExt->FvName) == 0) {
      UpdateMainFirmwareInfo(TmpPtr, pmfvi);
      DEBUG((EFI_D_ERROR, "%a.%d EFI_SUCCESS\n", 
        __FUNCTION__, __LINE__));  
      return EFI_SUCCESS;
    }
    TmpPtr++;
    RestLen--;
  } while (RestLen >= sizeof(EFI_FIRMWARE_VOLUME_HEADER));
  DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", 
        __FUNCTION__, __LINE__)); 
  return EFI_NOT_FOUND;
}

int
FindMainFv(
  IN CHAR8 *GuidStr, 
  OUT struct tMainFvInfo *pmfvi)
{
  UINT8 *TmpPtr;
  EFI_GUID SearchGuid;
  static EFI_PEI_HOB_POINTERS FvHob;
  EFI_STATUS Status;
  
  FvHob.Raw = GetHobList();
  
  Status = StringToGuid_L(GuidStr, &SearchGuid);  
  if (EFI_ERROR(Status)) {
    return -1;
  }
  
  while ((FvHob.Raw = GetNextHob (EFI_HOB_TYPE_FV, FvHob.Raw)) != NULL) {
    TmpPtr = (UINT8*)(UINTN)FvHob.FirmwareVolume->BaseAddress;
    pmfvi->Fvh = (EFI_FIRMWARE_VOLUME_HEADER*) TmpPtr;
    if ( pmfvi->Fvh->Signature != EFI_FVH_SIGNATURE || 
         !pmfvi->Fvh->ExtHeaderOffset) {
      FvHob.Raw = GET_NEXT_HOB (FvHob);
      continue;
    }

    pmfvi->FvhExt = (EFI_FIRMWARE_VOLUME_EXT_HEADER*) 
      &TmpPtr[pmfvi->Fvh->ExtHeaderOffset];
      
    if (CompareGuid_L(&SearchGuid, &pmfvi->FvhExt->FvName) == 0) {
      UpdateMainFirmwareInfo(TmpPtr, pmfvi);
      return 0;
    }
    FvHob.Raw = GET_NEXT_HOB (FvHob);
  }
  
  return -1;
}

VOID *
FindPlaceInExtHdr(
  EFI_GUID *pGuid,
  IN struct tMainFvInfo *pmfvi,
  OUT UINTN *RestSize)
{
  struct tHashRecord *Prec;
  UINT8 *TmpPtr;
  
  if (pmfvi == NULL || RestSize == NULL) {
    return NULL;
  }
  
  TmpPtr =  pmfvi->ExtDataPtr;
  *RestSize = pmfvi->ExtDataSize;
  do {
    Prec = (struct tHashRecord*)TmpPtr;
    
    if (pGuid) {
      if (Prec->Size == 0) {
        return NULL;
      }
      if (CompareGuid(pGuid, (EFI_GUID*) &Prec->Guid.Data1)) {
        return TmpPtr;
      }
    } else if (Prec->Size == 0) {    
      return TmpPtr;
    }
    
    if (*RestSize < Prec->Size) {
      return NULL;
    }
    *RestSize -= Prec->Size;
    TmpPtr += Prec->Size;
  } while (*RestSize >= sizeof(struct tHashRecord));
  return NULL;  
}

UINTN 
GetHashLen(
  IN UINT8 HashType)
{
  UINTN HashLen;
  
  switch (HashType) {
  case CS_TYPE_CRC32:
    HashLen = sizeof(UINT32);
    break;
    
  default:
    return 0;
  }
  return HashLen;
}

static int
ByteBufToStringWithComma(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  OUT CHAR8 *Str,
  IN UINTN StrLen)
{
  UINTN i;
  CHAR8 *TmpPtr;

  if (ByteBuf == NULL || Str == NULL || StrLen == 0 || BufLen == 0) {
    return -1;
  }

  if (StrLen < BufLen * 3) {
    return -1;
  }

  for (i = 0, TmpPtr = Str; i < BufLen; i++) {
    AsciiSPrint (TmpPtr, (BufLen - i) * 2 + 1, "%02X%a", ByteBuf[i],
      i == (BufLen - 1) ? "" : ":");
    if (i == (BufLen - 1)) {
      TmpPtr += 2;
    } else {
      TmpPtr += 3;
    }
  }
  return 0;
}

static int
ByteBufToString(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  OUT CHAR8 *Str,
  IN UINTN StrLen)
{
  UINTN i;
  CHAR8 *TmpPtr;

  if (ByteBuf == NULL || Str == NULL || StrLen == 0 || BufLen == 0) {
    return -1;
  }

  if (StrLen < (BufLen << 1)) {
    return -1;
  }

  for (i = 0, TmpPtr = Str; i < BufLen; i++) {
    AsciiSPrint (TmpPtr, (BufLen - i) * 2 + 1, "%02X", ByteBuf[i]);
    TmpPtr += 2;
  }
  return 0;
}

int
ByteBufToStringRev(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  OUT CHAR8 *Str,
  IN UINTN StrLen
  )
{
  UINTN i;
  CHAR8 *TmpPtr;

  if (ByteBuf == NULL || Str == NULL || StrLen == 0 || BufLen == 0) {
    return -1;
  }

  if (StrLen < (BufLen << 1)) {
    return -1;
  }

  for (i = BufLen, TmpPtr = Str; i > 0; i--) {
    AsciiSPrint (TmpPtr, i * 2 + 1, "%02X", ByteBuf[i - 1]);
    TmpPtr += 2;
  }
  return 0;
}


int
GetDigestStr16(
  IN OUT CHAR16 *Str16,
  IN UINT8 *HashData,
  IN UINT8 HashType
  )
{
  UINT8 TmpStr[255];
  
  switch (HashType) {
  case CS_TYPE_CRC32:
    if (-1 == ByteBufToString(HashData, sizeof(UINT32), TmpStr,
        sizeof(UINT32) << 1)) {
      return -1;
    }
    break;

  default:
    return -1;
  }

  UnicodeSPrint(Str16, 255, L"%a", TmpStr);
  return 0;
}



int
GetDigestStr(
  IN OUT CHAR8 *Str,
  IN struct tHashRecord *Prec
  )
{
  switch (Prec->HashType) {
  case CS_TYPE_CRC32:
    if (-1 == ByteBufToString(Prec->HashData, sizeof(UINT32), Str,
        sizeof(UINT32) << 1)) {
      return -1;
    }
    break;

  default:
    return -1;
  }
  
  return 0;
}

int 
HashCsCompare(
  IN UINT8 HashType, 
  IN UINT8 *Val1, 
  IN UINT8 *Val2
  )
{
  UINTN i, HashLen;
  
  HashLen = GetHashLen(HashType);
  if (0 == HashLen) {
    return -1;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d: HashLen=%d\n", 
    __FUNCTION__, __LINE__, HashLen));
  
  for (i = 0; i < HashLen; i++) {
#if 0
    ShowVal((UINTN)Val1[i], 2);
    ShowVal((UINTN)Val2[i], 2);
#endif     
    if (Val1[i] != Val2[i]) {
      DEBUG((EFI_D_ERROR, "%a.%d: i=%d 0x%X != 0x%X\n", 
        __FUNCTION__, __LINE__, i, Val1[i], Val2[i]));    
      return -1;
    }
  }
  return 0;
}

CHAR16 * 
GetUnicodeObjPath(
  IN struct tHashRecord *Prec)
{
  UINTN HashLen;
  
  if (Prec == NULL || Prec->Type == 0) {
    return 0;
  }
  HashLen = GetHashLen(Prec->HashType);
  if (0 == HashLen) {
    return NULL;
  }
  return (CHAR16*)(&Prec->HashData[HashLen]);
}


int 
CalcHashCsOnFile(
  IN CHAR8 *InputFile,
  IN UINT8 CsType,
  IN UINT8 *HashData)
{
  EFI_FILE_HANDLE Pf = NULL;
  UINT8 FileData[1024];
  UINTN FileDataLen, Position;
  enum CALC_CS_FLAGS Flags = CALC_CS_RESET;
  EFI_STATUS Status;
  int retval = -1;
  
  Pf = LibFsOpenFile(InputFile, EFI_FILE_MODE_READ, 0);
  if (Pf == NULL) {
    goto _exit;
  }

  FileDataLen = LibFsSizeFile(Pf);
  Position = 0;
  
  while (FileDataLen) {
    UINTN TmpLen;
   
    TmpLen = sizeof(FileData);
    if (TmpLen > FileDataLen) {
      TmpLen = FileDataLen;
    }
    LibFsSetPosition(Pf, Position);
    Status = LibFsReadFile(Pf, &TmpLen, FileData);
    if (EFI_ERROR(Status)) {
      goto _exit;
    }
    
    Position += TmpLen;
    
    FileDataLen -= TmpLen;
    if (FileDataLen == 0) {
      Flags |= CALC_CS_FINALIZE;
    }
    
    Status = CalcHashCs(CsType, FileData, TmpLen, 
        Flags, HashData);
    if (EFI_ERROR(Status)) {
      goto _exit;
    }
    
    Flags = CALC_CS_UPDATE;
  }
  retval = 0;
  
_exit:
  if (Pf != NULL) {
    LibFsCloseFile(Pf);
  }
  
  return retval;
}


EFI_STATUS 
CalcHashCsOnFile16(
  IN CHAR16 *InputFile,
  IN UINT8 CsType,
  IN UINT8 *HashData
  )
{
  EFI_FILE_HANDLE Pf = NULL;
  EFI_STATUS Status = EFI_ABORTED;
  
  Pf = LibFsOpenFile16(InputFile, EFI_FILE_MODE_READ, 0);
  if (Pf == NULL) {
    goto _exit;
  }
  
  Status = CalcHashCsOnFileWithHandle(Pf, CsType, HashData);
  
_exit:
  if (Pf != NULL) {
    LibFsCloseFile(Pf);
  }
  
  return Status;
}

EFI_STATUS 
CalcHashCsOnFileWithHandle(
  IN EFI_FILE_HANDLE Pf,
  IN UINT8 CsType,
  IN UINT8 *HashData
  )
{
  UINT8 *FileData = NULL;
  UINTN FileDataLen, Position, TmpLen;
  enum CALC_CS_FLAGS Flags = CALC_CS_RESET;
  EFI_STATUS Status = EFI_ABORTED;

  if (Pf == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  FileDataLen = LibFsSizeFile(Pf);
  DEBUG((EFI_D_ERROR, "%a.%d FileDataLen=%d\n",
    __FUNCTION__, __LINE__, FileDataLen));
  if (FileDataLen == 0) {
    Status = EFI_ABORTED;
    goto _exit;
  }
  Position = 0;

  FileData = AllocateZeroPool(FileDataLen);
  if (FileData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n",
      __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
 
  LibFsSetPosition(Pf, Position);
  TmpLen = FileDataLen;
  Status = LibFsReadFile(Pf, &TmpLen, FileData);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  Flags |= CALC_CS_FINALIZE;
  
  Status = CalcHashCs(CsType, FileData, TmpLen, 
      Flags, HashData);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  Status = EFI_SUCCESS;
  
_exit:
  if (FileData != NULL) {
    FreePool(FileData);
  }
  
  return Status;
}




BOOLEAN
IsItFwUpdate(
  IN struct tMainFvInfo *pmfvi
  )
{
  struct tHashRecord *pRec;
  EFI_GUID GuidVal;
  EFI_STATUS Status;
  UINTN RestSize = 0;
  CHAR16 Str16[255];

  Status = StringToGuid_L(FW_UPDATE_GUID_STR, &GuidVal);  
  if (EFI_ERROR(Status)) {
    return FALSE;
  }
  pRec = (struct tHashRecord *)FindPlaceInExtHdr(&GuidVal,
    pmfvi, &RestSize);
  if (pRec == NULL) {
    return FALSE;
  }
  
  GetDigestStr16(Str16, pRec->HashData, pRec->HashType);
  if (StrCmp(FW_UPDATE_HASH_STR16, Str16) == 0) {
    return TRUE;
  }
  return FALSE;
}


int
CheckDataWithGuid(
  IN CHAR8 *Guid,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN struct tMainFvInfo *pmfvi)
{
  EFI_GUID GuidVal;
  EFI_STATUS Status;
  struct tHashRecord *pRec;
  UINTN RestSize, ChunkSize;
  UINT8 HashBuf[MAX_HASH_LEN];
  UINT8 Cache[1024];
  UINT8 Flags;
  int Result;

  if (Guid == NULL || Data == NULL || 
      DataLen == 0 || pmfvi == NULL) {
    return -1;
  }
  
  Status = StringToGuid_L(Guid, &GuidVal);  
  if (EFI_ERROR(Status)) {
    return -1;
  }

  pRec = (struct tHashRecord *)FindPlaceInExtHdr(&GuidVal,
    pmfvi, &RestSize);
  if (pRec == NULL) {
    return -1;
  }


#if 0
  (VOID)Cache, (VOID)ChunkSize, (VOID)Flags;
  
  Status = CalcHashCs(pRec->HashType, Data, DataLen, 
    CALC_CS_RESET | CALC_CS_FINALIZE, HashBuf);
  if (EFI_ERROR(Status)) {
    return -1;  
  }
#else
  Flags = CALC_CS_RESET;

  while (DataLen) {
    ChunkSize = DataLen > sizeof (Cache) ? sizeof (Cache) : DataLen;
    CopyMem (Cache, Data, ChunkSize);
    Data += ChunkSize;
    DataLen -= ChunkSize;

    if (DataLen == 0) {
      Flags |= CALC_CS_FINALIZE;
    }

    Status = CalcHashCs(pRec->HashType, Cache, ChunkSize, 
      Flags, HashBuf);
    if (EFI_ERROR(Status)) {
      return -1;  
    }
    Flags = CALC_CS_UPDATE;
  }
#endif

  Result = HashCsCompare(pRec->HashType, pRec->HashData, HashBuf);
  DEBUG ((EFI_D_ERROR, "%a.%d Result=%d\n", __FUNCTION__, __LINE__, Result));
  return Result;
}

int
CheckDataWithHash(
  IN UINT8 HashType,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *HashData
  )
{
  UINT8 HashBuf[MAX_HASH_LEN];

  if (EFI_SUCCESS != CalcHashCs(HashType, Data, DataLen,
    CALC_CS_RESET | CALC_CS_FINALIZE, HashBuf)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error while CalcHashCs!!!\n", 
      __FUNCTION__, __LINE__));
    return -1;
  }

  return HashCsCompare(HashType, HashData, HashBuf);
}

VOID
SaveCorruptRecord(
  IN struct tHashRecord *Prec
)
{
  pCorruptRecord = Prec;
}

struct tHashRecord *
GetCorruptRecord(
  VOID
)
{
  return pCorruptRecord;
}


int 
CheckAllObjWithPath(
  IN struct tMainFvInfo *pmfvi)
{
  struct tHashRecord *Prec;
  CHAR16 *ObjPath;
  UINT8 *TmpPtr, ObjPath8[1024], HashBuf[MAX_HASH_LEN];
  UINTN RestSize;
  
  if (pmfvi == NULL) {
    return -1;
  }
  
  TmpPtr =  pmfvi->ExtDataPtr;
  RestSize = pmfvi->ExtDataSize;
  do {
    Prec = (struct tHashRecord*)TmpPtr;
    if (Prec->Size == 0) {
      break;
    }
    if (Prec->Type == FV_REC_TYPE_HASH_CS_WITH_PATH) {
      ObjPath = GetUnicodeObjPath(Prec);
      if (ObjPath == NULL) {
        SaveCorruptRecord(Prec);
        return -1;
      }

      UnicodeStrToAsciiStr(ObjPath, ObjPath8);

      if (EFI_SUCCESS != CalcHashCsOnFile(ObjPath8, Prec->HashType, HashBuf)) {
        SaveCorruptRecord(Prec);
        return -1;
      }
      if (-1 == HashCsCompare(Prec->HashType, Prec->HashData, HashBuf)) {
        SaveCorruptRecord(Prec);
        return -1;
      }
    }
    
    RestSize -= Prec->Size;
    TmpPtr += Prec->Size;
  } while (RestSize >= sizeof(struct tHashRecord));
  return 0;
}


int 
CheckExternalObjHashCs(
  IN CHAR8 *Guid,
  IN CHAR8 *ObjPath,
  IN struct tMainFvInfo *pmfvi)
{
  EFI_GUID GuidVal;
  EFI_STATUS Status;
  struct tHashRecord *pRec;
  UINTN RestSize;
  UINT8 HashBuf[MAX_HASH_LEN];

  Status = StringToGuid_L(Guid, &GuidVal);  
  if (EFI_ERROR(Status)) {
    return -1;
  }
  
  pRec = (struct tHashRecord *)FindPlaceInExtHdr(&GuidVal,
    pmfvi, &RestSize);
  if (pRec == NULL) {
    return -1;
  }
  
  if (EFI_SUCCESS !=  CalcHashCsOnFile(ObjPath, pRec->HashType, HashBuf)) {
    return -1;  
  }
  
  return HashCsCompare(pRec->HashType, pRec->HashData, HashBuf);
}


int 
CheckMainFvHashCs(
  IN CHAR8 *Guid,
  IN struct tMainFvInfo *pmfvi)
{
  return CheckDataWithGuid(Guid, pmfvi->FvDataPtr, 
    pmfvi->FvLength, pmfvi);
}

EFI_STATUS
CheckFile(
  IN CHAR8 *FileName,
  IN UINT8 HashType,
  IN UINT8 *HashData 
  )
{
  UINT8 HashBuf[MAX_HASH_LEN];
  
  if (-1 == CalcHashCsOnFile(FileName, HashType, HashBuf)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  if (CompareMem(HashBuf, HashData, MAX_HASH_LEN)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  return EFI_SUCCESS;;
}

