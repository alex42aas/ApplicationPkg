/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/PcdLib.h>
#include <Library/Lib/History.h>
#include <Library/Lib/Users.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Library/UserManagerLib.h>
#include <Protocol/HiiDatabase.h>
#include <Library/HiiLib.h>
#include <Library/SynchronizationLib.h>
#include "HistoryDxe.h"

#define LOG(MSG)      DEBUG(MSG)

STATIC HISTORY_STORAGE gHistoryStorage;
STATIC UINT32 gRecId;
STATIC HISTORY_HANDLER_PRIVATE_DATA PrivateData;
STATIC HISTORY_RECORD *pLastFoundHistoryRecord;
STATIC SPIN_LOCK gHistoryLock;


STATIC
EFI_STATUS
GetData(
  IN OUT HISTORY_STORAGE *HistoryStrorage
  )
{
  EFI_STATUS Status;
  STORAGE_DATA StorageData;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  

  StorageData.Data = (UINT8*)&gHistoryStorage;
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageGetData2(&gHistoryStorageGuid, HISTORY_STORAGE_VAR_NAME,
    &StorageData, sizeof(HISTORY_STORAGE));  

  if (StorageData.DataLen < (sizeof(HISTORY_STORAGE) - HISTORY_SIZE)) {
    return EFI_ABORTED;
  }
  gHistoryStorage.DataLen = StorageData.DataLen - 
    (sizeof(HISTORY_STORAGE) - HISTORY_SIZE);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


STATIC
EFI_STATUS
SetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (RawData == NULL || RawDataLen > HISTORY_SIZE) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(gHistoryStorage.Data, RawData, RawDataLen);
  gHistoryStorage.DataLen = (UINT32)(RawDataLen & 0xFFFFFFFF);
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageSetRawData2(&gHistoryStorageGuid, HISTORY_STORAGE_VAR_NAME,
    (UINT8*)&gHistoryStorage,
    sizeof(HISTORY_STORAGE) - HISTORY_SIZE + gHistoryStorage.DataLen,
    (sizeof(HISTORY_STORAGE) + HISTORY_MAX_CARD_SIZE) / 
      HISTORY_MAX_CARD_SIZE + 1,
    sizeof(HISTORY_STORAGE),
    HISTORY_MAX_CARD_SIZE,
    FALSE);

  return Status; 
}

STATIC 
UINTN
CountUnloaded (
  VOID
  )
{
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  HISTORY_RECORD *pRec;
  UINTN Index, Count;

  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return 0;
  }
  
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data;
  
  
  Index = 0;
  Count = 0;

  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    RecordSize = sizeof(HISTORY_RECORD);

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) {

    } else {
      Count++;
    }
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    Index++;
  }

  return Count;
}

STATIC 
HISTORY_RECORD *
FindById (
  IN UINT32 Id
  )
{
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  HISTORY_RECORD *pRec;
  UINTN Index;

  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return NULL;
  }
  
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data;
  
  
  Index = 0;
  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    RecordSize = sizeof(HISTORY_RECORD);

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pRec->RecId == Id) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return pRec;
    }
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    Index++;
  }

  return NULL;
}


STATIC
BOOLEAN
Overflow(
  VOID
  )
{ 
  UINTN CntUnloaded, TotalRecords;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  CntUnloaded = CountUnloaded();
  TotalRecords = gHistoryStorage.DataLen / HISTORY_RECORD_SIZE;

  if (gHistoryStorage.Flags & HISTORY_FLAGS_OVERFLOW) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return TRUE;
  }
    
  if (TotalRecords >= HISTORY_RECORDS_AMOUNT) {
    if (CntUnloaded == TotalRecords) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return TRUE;
    }
    if ((gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN) == 0) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return TRUE;
    }
  }
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return FALSE;
}

STATIC
EFI_STATUS
GetRecordId (
  IN OUT UINT32 *pRecId
  )
{
  UINT32 i;
  BOOLEAN bHaveNewId;
  
  for (i = 0, bHaveNewId = FALSE; i <= 0xFFFFFFFF; i++) {
/* Zero value of gHistoryRecId will be reserved */
    if (gRecId == 0) {
      gRecId++;
    }
    if (FindById(gRecId) != NULL) {
      gRecId++;
    } else {
      bHaveNewId = TRUE;
      break;
    }
  }
  if (!bHaveNewId) {
    return EFI_OUT_OF_RESOURCES;
  }

  LOG((EFI_D_ERROR, "%a.%d: RecId=0x%02X\n", 
    __FUNCTION__, __LINE__, gRecId));
  
  *pRecId = gRecId;
  gRecId++;
  return EFI_SUCCESS;
}


EFI_STATUS
AddRec (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT16 EventCode,
  IN UINT8 Severity,
  IN UINT8 Flags
  ) 
{
  UINT8 UserId;
  UINT8 *Data = NULL;
  UINTN DataLen;
  EFI_STATUS Status = EFI_SUCCESS;
  HISTORY_RECORD NewRecord;
  UINTN StorageOffset;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    LOG ((EFI_D_ERROR, "%a.%d Locked!\n", __FUNCTION__, __LINE__));
    return EFI_ACCESS_DENIED;
  }
  
  Status = GetCurrentUserVar(&Data, &DataLen);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;;
  }

  if (Data == NULL || DataLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }

  UserId = *Data;
  FreePool (Data);
  Data = NULL;

  LOG ((EFI_D_ERROR, "%a.%d UserId=%X\n", __FUNCTION__, __LINE__, UserId));
  if (UserId == 0) {
    Status = EFI_SUCCESS; /* There are no logged users  */
    goto _exit;
  }

  Status = GetData(&gHistoryStorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.CurSeverity=0x%X\n", 
    __FUNCTION__, __LINE__, gHistoryStorage.CurSeverity));
  if ((gHistoryStorage.CurSeverity & Severity) == 0) {
    Status = EFI_SUCCESS; /* not allowed level, just skip */
    goto _exit;
  }

  LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.DataLen=%d\n", 
    __FUNCTION__, __LINE__, gHistoryStorage.DataLen));    

  if (Overflow()) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }

  Status = GetRecordId (&NewRecord.RecId);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  Status = GetU32TimeSec(&NewRecord.TimeStamp);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  NewRecord.EventCode = EventCode;
  NewRecord.UserId = UserId;
  NewRecord.Severity = Severity;
  NewRecord.Flags = Flags & ~HISTORY_RECORD_FLAG_CLEAN_EN;
  
  Data = AllocateZeroPool(sizeof(HISTORY_RECORD) + gHistoryStorage.DataLen);
  if (NULL == Data) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  if (gHistoryStorage.DataLen / HISTORY_RECORD_SIZE >= 
      HISTORY_RECORDS_AMOUNT) {
    StorageOffset = sizeof(HISTORY_RECORD);
    gHistoryStorage.DataLen -= (UINT32)StorageOffset;
  } else {
    StorageOffset = 0;
  }
  
  CopyMem(Data, gHistoryStorage.Data + StorageOffset, 
    gHistoryStorage.DataLen);
  CopyMem(Data + gHistoryStorage.DataLen, &NewRecord, 
    sizeof(HISTORY_RECORD));
  
  Status = SetRawData((UINT8*)Data, 
    gHistoryStorage.DataLen + sizeof(HISTORY_RECORD));

_exit:  
  if (Data != NULL) {
    FreePool(Data);
  }
  ReleaseSpinLock(&gHistoryLock);
  return Status;
}


EFI_STATUS
GetParams (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT UINT8 *Severity,
  IN OUT UINT8 *Flags
  )
{
  EFI_STATUS Status;

  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    LOG ((EFI_D_ERROR, "%a.%d Locked!\n", __FUNCTION__, __LINE__));
    return EFI_ACCESS_DENIED;
  }
  
  Status = GetData(&gHistoryStorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  *Severity = gHistoryStorage.CurSeverity;
  *Flags = (UINT8)(gHistoryStorage.Flags & 0xFF);

_exit:
  ReleaseSpinLock(&gHistoryLock);
  return Status;
}

EFI_STATUS
SetParams (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT8 Severity,
  IN UINT8 Flags
  )
{
  EFI_STATUS Status;

  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    LOG ((EFI_D_ERROR, "%a.%d Locked!\n", __FUNCTION__, __LINE__));
    return EFI_ACCESS_DENIED;
  }
  
  Status = GetData(&gHistoryStorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  gHistoryStorage.CurSeverity = Severity;
  gHistoryStorage.Flags = Flags;
  Status = SetRawData((UINT8*)gHistoryStorage.Data, 
    gHistoryStorage.DataLen);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
_exit:  
  ReleaseSpinLock(&gHistoryLock);
  return Status;
}

STATIC
HISTORY_RECORD *
HistoryDxeGetLastFoundedRecord(
  VOID
  )
{
  return pLastFoundHistoryRecord;
}

STATIC
EFI_STATUS
HistoryDxeFindRecordByFieldsMask(
  IN UINT32 Mask,
  IN VOID *Value
  )
{
  UINTN TotalLen, RecordSize;
  UINT32 *TmpPtr32;
  UINT16 *TmpPtr16;
  UINT8 *DataPtr, *TmpPtr8;
  HISTORY_RECORD *pRec;
  UINTN Index, *TmpPtrN;
  
  LOG((EFI_D_ERROR, "%a.%d Start Mask=0x%08X\n", 
    __FUNCTION__, __LINE__, Mask));
  
  pLastFoundHistoryRecord = NULL;

  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return EFI_NOT_FOUND;
  }
  
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data;
  
  TmpPtr8 = (UINT8*)Value;
  TmpPtr16 = (UINT16*)Value;
  TmpPtr32 = (UINT32*)Value;
  TmpPtrN = (UINTN*)Value;
  
  Index = 0;
  
  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    RecordSize = sizeof(HISTORY_RECORD);

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if ((Mask & HISTORY_FIELD_REC_ID) && pRec->RecId == *TmpPtr32) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_TIME_STAMP) && pRec->TimeStamp == *TmpPtr32) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_EVENT_CODE) && pRec->EventCode == *TmpPtr16) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_USER_ID) && pRec->UserId == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_SEVERITY) && pRec->Severity == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_FLAGS) && pRec->Flags == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    
    if ((Mask & HISTORY_SEARCH_BY_NUM) && Index == *TmpPtrN) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    Index++;
  }
  LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}


STATIC
EFI_STATUS
HistoryDxeFindRecordByRecNum(
  IN UINTN RecNum
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d RecNum=0x%X\n", __FUNCTION__, __LINE__, RecNum));
  Status = HistoryDxeFindRecordByFieldsMask(HISTORY_SEARCH_BY_NUM, &RecNum);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
EFI_STATUS
HistoryDxeFindRecordByRecId(
  IN UINT32 RecId
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d RecId=0x%X\n", __FUNCTION__, __LINE__, RecId));
  Status = HistoryDxeFindRecordByFieldsMask(HISTORY_FIELD_REC_ID, &RecId);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


STATIC
HISTORY_RECORD *
HistoryDxeGetNextRecord(
  IN BOOLEAN bRestart 
  )
{
  EFI_STATUS Status;
  STATIC UINTN i;

  if (bRestart) {
    i = 0;
  }
  Status = HistoryDxeFindRecordByRecNum (i);
  if (EFI_ERROR(Status)) {
    i = 0;
    return NULL;
  } else {
    i++;
  }
  return HistoryDxeGetLastFoundedRecord ();
}

STATIC 
USER_INFO *
GetUnknownUsrInfo(
  VOID
  )
{
  STATIC USER_INFO UnknownUsr;
  CHAR16 *StrPtr16;

  UnknownUsr.UserId = USER_UNKNOWN_ID;
  StrPtr16 = HiiGetString(PrivateData.HiiHandle, 
    STRING_TOKEN(STR_USR_NAME_UNKNOWN), NULL);
  StrCpy(UnknownUsr.UserName, StrPtr16);
  StrCpy(UnknownUsr.UserFIO, StrPtr16);
  
  UnknownUsr.AuthType = AUTH_TYPE_LOG_PASS;
  
  return &UnknownUsr;
}

STATIC 
USER_INFO *
GetSuUsrInfo(
  VOID
  )
{
  STATIC USER_INFO SuUsr;
  CHAR16 *StrPtr16;

  SuUsr.UserId = USER_SU_ID;
  StrPtr16 = HiiGetString(PrivateData.HiiHandle, 
    STRING_TOKEN(STR_USR_NAME_SUPER), NULL);
  StrCpy(SuUsr.UserName, StrPtr16);
  StrCpy(SuUsr.UserFIO, StrPtr16);
  
  SuUsr.AuthType = AUTH_TYPE_LOG_PASS;
  
  return &SuUsr;
}


STATIC 
USER_INFO *
GetLdapUsrInfo(
  VOID
  )
{
  STATIC USER_INFO LdapUsr;
  CHAR16 *StrPtr16;

  LdapUsr.UserId = USER_LDAP_LOG_ID;
  StrPtr16 = HiiGetString(PrivateData.HiiHandle, 
    STRING_TOKEN(STR_USR_NAME_LDAP_LOG), NULL);
  StrCpy(LdapUsr.UserName, StrPtr16);
  StrCpy(LdapUsr.UserFIO, StrPtr16);
  
  LdapUsr.AuthType = AUTH_TYPE_LDAP;
  
  return &LdapUsr;
}

STATIC
CHAR16 *
HistoryGetEventString16(
  IN UINT16 EventCode
  )
{
  STATIC CHAR16 Str16[255];
  
  UnicodeSPrint(Str16, sizeof(Str16), L"%s 0x%04X", 
    HiiGetString(PrivateData.HiiHandle, STRING_TOKEN(STR_EVENT), NULL), 
    EventCode);
  return Str16;
}

STATIC
UINT8 
GetHighestSetBitNum(
  IN UINT8 Val
  )
{
  if (Val & 0xF0) {
    if (Val & 0xC0) {
      return Val & 0x80 ? 7 : 6;
    } else {
      return Val & 0x20 ? 5 : 4;
    }
  } else if (Val &0x0C) {
    return Val & 0x8 ? 3 : 2;
  }
  return Val & 0x2 ? 1 : 0;
}


STATIC
EFI_STRING_ID
HistoryGetSeverityString(
  IN UINT8 Severity
  )
{
  EFI_STRING_ID SeverityStr[] = { 
    STRING_TOKEN(STR_SEVERITY_EMERGENCY),
    STRING_TOKEN(STR_SEVERITY_ALERT),
    STRING_TOKEN(STR_SEVERITY_CRITICAL),
    STRING_TOKEN(STR_SEVERITY_ERROR),
    STRING_TOKEN(STR_SEVERITY_WARNING),
    STRING_TOKEN(STR_SEVERITY_NOTICE),
    STRING_TOKEN(STR_SEVERITY_INFO),
    STRING_TOKEN(STR_SEVERITY_DEBUG)
  };
  UINT8 Num;
  
  Num = GetHighestSetBitNum(Severity);
  if (Num >= 8) {
    return STRING_TOKEN(STR_UNKNOWN_EVENT);
  }
  return SeverityStr[Num];
}

STATIC
EFI_STATUS
FindUserRecordByIdWrapper(
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  UsersStorageSetDummyReadFlag(TRUE);
  Status = UserFindRecordById(UserId);
  UsersStorageSetDummyReadFlag(FALSE);
  return Status;
}


STATIC
EFI_STATUS
GetHistoryDxeRecordCsv16 (
  IN HISTORY_RECORD *pRec,
  IN OUT CHAR16 **ResStr,
  IN OUT UINTN *ResSize,
  IN BOOLEAN bWithRecId
  )
{
  EFI_STATUS Status;
  UINTN Size, RestLen;
  STATIC CHAR16 Str16[HISTORY_STRING_LEN];
  CHAR16 *CurStrPtr16, *UserName, *UserFIO;
  CHAR16 *StrPtr16;
  EFI_TIME EfiTime;
  USER_INFO *pUser;  
  
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  if (pRec->UserId == USER_LDAP_LOG_ID) {
    pUser = GetLdapUsrInfo();
  } else if (pRec->UserId == USER_UNKNOWN_ID) {
    pUser = GetUnknownUsrInfo();
  } else if (pRec->UserId == USER_AMT_ID) {
    pUser = AmtUsrInfo ();
  } else if (pRec->UserId == USER_SU_ID) {
    pUser = GetSuUsrInfo ();
  } else {

    LOG((EFI_D_ERROR, "%a.%d pRec->UserId=%d\n", 
      __FUNCTION__, __LINE__, pRec->UserId));
    Status = FindUserRecordByIdWrapper(pRec->UserId);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      pUser = GetUnknownUsrInfo();
    } else {
      pUser = UserGetLastFoundedInfo();
    }
  }
  if (pUser == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  ConvU32ToEfiTime(pRec->TimeStamp, &EfiTime);

  CurStrPtr16 = Str16;
  RestLen = sizeof (Str16);
  if (bWithRecId) {
    UnicodeSPrint(CurStrPtr16, RestLen, L"%d;", pRec->RecId);
    Size = StrLen(CurStrPtr16);
    CurStrPtr16 += Size;
    RestLen -= (Size * 2);
  }
  UnicodeSPrint(CurStrPtr16, RestLen, L"%02d.%02d.%04d %02d:%02d:%02d;", 
    EfiTime.Day, EfiTime.Month, EfiTime.Year, EfiTime.Hour, EfiTime.Minute,
    EfiTime.Second);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  UserName = UserFIO = NULL;
  Status = ObtainProperCSVString16(pUser->UserName, &UserName);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  Status = ObtainProperCSVString16(pUser->UserFIO, &UserFIO);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    if (UserName) {
      FreePool (UserName);
    }
    return Status;
  }
  
  UnicodeSPrint(CurStrPtr16, RestLen, L"%s %s;", 
    UserName, UserFIO);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  if (UserName) {
    FreePool (UserName);
  }
  if (UserFIO) {
    FreePool (UserFIO);
  }
  
  //----------------------------------------------------------------------
  // Add Auth type of the user
  //----------------------------------------------------------------------
  StrPtr16 = UsersGetTypeString16(pUser->AuthType, PrivateData.HiiHandle);
  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;", 
    StrPtr16);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
  LOG((EFI_D_ERROR, "Auth type: %s\n", StrPtr16));
  
  StrPtr16 = HiiGetString(PrivateData.HiiHandle, 
    HistoryGetSeverityString(pRec->Severity),
    NULL);

  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;%s;", 
    StrPtr16,
    pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
      HiiGetString(PrivateData.HiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
      HiiGetString(PrivateData.HiiHandle, STRING_TOKEN(STR_ERROR), NULL));
  
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;", 
    HistoryGetEventString16(pRec->EventCode));
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
    
  //----------------------------------------------------------------------
  // Add DN for a ldap auth user or Comparison Data for a token guest user
  //----------------------------------------------------------------------
  if (((AUTH_TYPE_LDAP == pUser->AuthType) && (pUser->UserId != USER_LDAP_LOG_ID)) || 
      ((AUTH_TYPE_TOKEN == pUser->AuthType) && (pUser->Flags & USER_HIDDEN_FLAG) == USER_HIDDEN_FLAG))  {
    StrPtr16 = (CHAR16*)UserTokenExtData(CT_FLAG_CN, pUser);
    LOG((EFI_D_ERROR, "StrPtr16: %s\n", StrPtr16));
    if (StrPtr16 != NULL) {
      UnicodeSPrint(CurStrPtr16, RestLen, L"%s;\n", 
        StrPtr16);
      LOG((EFI_D_ERROR, "ExtData: %s\n", CurStrPtr16));
    } else {
      UserName = NULL;
      Status = ObtainProperCSVString16(pUser->UserName, &UserName);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return Status;
      }
      UnicodeSPrint(CurStrPtr16, RestLen, L"%s;\n",
        UserName);
      if (UserName) {
        FreePool (UserName);
      }
      LOG((EFI_D_ERROR, "ExtData: %s\n", CurStrPtr16));
    }
  } else {
    UnicodeSPrint(CurStrPtr16, RestLen, L";\n", 
      StrPtr16);
  }
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  *ResSize = StrLen (Str16) * 2;
  *ResStr = Str16;
  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
GetCsv16Internal (
  IN OUT CHAR16 **CsvStr16
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  HISTORY_RECORD *pRec;
  CHAR16 *ResStr = NULL;
  CHAR16 *TmpStr16 = NULL;
  CHAR16 *Str16 = NULL;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  /* just for updating storage */
  UserFindRecordById(1);
  
  pRec = HistoryDxeGetNextRecord(TRUE);
  if (!pRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  do {    
    UINTN TmpStr16Size, ResSize;
    if ((pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) == 0) {
      Status = GetHistoryDxeRecordCsv16 (pRec, &TmpStr16, &TmpStr16Size, TRUE);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      if (ResStr != NULL) {
        ResSize = StrSize (ResStr);
      } else {
        ResSize = 0;
      }
      Str16 = AllocateZeroPool (StrSize (TmpStr16) + ResSize);
      if (Str16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        break;
      }

      if (ResStr != NULL) {
        StrCpy (Str16, ResStr);
        ResSize = StrLen (ResStr);
        FreePool (ResStr);
      }

      StrCpy (&Str16[ResSize], TmpStr16);      

      ResStr = Str16;
      Str16 = NULL;
    }
    pRec = HistoryDxeGetNextRecord(FALSE);
  } while (pRec != NULL);
  
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }


  
_exit:
  if (EFI_ERROR(Status)) {
    if (ResStr) {
      FreePool (ResStr);
    }
    *CsvStr16 = NULL;
  } else {
    *CsvStr16 = ResStr;    
  }

  if (Str16) {
    FreePool (Str16);
  }
  
  return Status;
}

STATIC 
EFI_STATUS
GetCsv16 (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT CHAR16 **CsvStr16
  )
{
  EFI_STATUS Status;
  
  if (This == NULL || CsvStr16 == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  *CsvStr16 = NULL;
  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    LOG ((EFI_D_ERROR, "%a.%d Locked!\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  GetData(&gHistoryStorage);
  Status = GetCsv16Internal (CsvStr16);
  
  ReleaseSpinLock(&gHistoryLock);
  
  return Status;
}


STATIC
EFI_STATUS
MarkAsUnloaded (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT32 Num,
  IN UINT32 RecNum[]
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  HISTORY_RECORD *pRec;
  UINT32 Idx;

  if (Num == 0 || RecNum == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  LOG((EFI_D_ERROR, "%a.%d Start {Num=%d}\n", __FUNCTION__, __LINE__, Num));
    
/* Mark all records as clean enabled */
  pRec = HistoryDxeGetNextRecord(TRUE);
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  for (Idx = 0; Idx < Num; Idx++) {
    Status = HistoryDxeFindRecordByRecId (RecNum[Idx]);
    if (EFI_ERROR(Status)) {
      break;
    }
    pRec = HistoryDxeGetLastFoundedRecord ();
    if (NULL == pRec) {
      break;
    }
    pRec->Flags |= HISTORY_RECORD_FLAG_CLEAN_EN;
  }  
  
_exit:
  if (EFI_ERROR(Status)) {
    
  } else {    
    Status = SetRawData (
                gHistoryStorage.Data, 
                gHistoryStorage.DataLen
                );
  }

  return Status;
}



STATIC
EFI_STATUS
HistoryDxeGetCsv16MemFile (
  IN CHAR16 **Csv16Str
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  HISTORY_RECORD *pRec;
  CHAR16 *ResStr = NULL;
  CHAR16 *TmpStr16 = NULL;
  CHAR16 *Str16 = NULL;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  /* just for updating storage */
  UserFindRecordById(1);
  
  pRec = HistoryDxeGetNextRecord(TRUE);
  if (!pRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  do {    
    UINTN TmpStr16Size, ResSize;
    if ((pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) == 0) {
      Status = GetHistoryDxeRecordCsv16 (pRec, &TmpStr16, &TmpStr16Size, FALSE);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      if (ResStr != NULL) {
        ResSize = StrSize (ResStr);
      } else {
        ResSize = 0;
      }
      Str16 = AllocateZeroPool (StrSize (TmpStr16) + ResSize);
      if (Str16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        break;
      }

      if (ResStr != NULL) {
        StrCpy (Str16, ResStr);
        ResSize = StrLen (ResStr);
        FreePool (ResStr);
      }

      StrCpy (&Str16[ResSize], TmpStr16);      

      ResStr = Str16;
      Str16 = NULL;
    }
    pRec = HistoryDxeGetNextRecord(FALSE);
  } while (pRec != NULL);
  
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

/* Mark all records as clean enabled */
  pRec = HistoryDxeGetNextRecord(TRUE);
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  do {
    pRec->Flags |= HISTORY_RECORD_FLAG_CLEAN_EN;
    pRec = HistoryDxeGetNextRecord(FALSE);
  } while (pRec != NULL);
  
_exit:
  if (EFI_ERROR(Status)) {
    if (ResStr) {
      FreePool (ResStr);
    }
    *Csv16Str = NULL;
  } else {
    *Csv16Str = ResStr;
    if (ResStr) {
      Status = SetRawData (
                  gHistoryStorage.Data, 
                  gHistoryStorage.DataLen
                  );
    }
  }

  if (Str16) {
    FreePool (Str16);
  }
  
  return Status;
}

EFI_STATUS
UnloadCsv16 (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT CHAR16 **Csv16Str
  )
{
  EFI_STATUS Status;
  
  if (This == NULL || Csv16Str == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  *Csv16Str = NULL;
  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    LOG ((EFI_D_ERROR, "%a.%d Locked!\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  GetData(&gHistoryStorage);
  Status = HistoryDxeGetCsv16MemFile (Csv16Str);
  
  ReleaseSpinLock(&gHistoryLock);
  
  return Status;
}

EFI_STATUS
LockOp (
  IN HISTORY_HANDLER_PROTOCOL *This
  )
{  
  if (!AcquireSpinLockOrFail(&gHistoryLock)) {
    return EFI_ACCESS_DENIED;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
UnLockOp (
  IN HISTORY_HANDLER_PROTOCOL *This
  )
{  
  ReleaseSpinLock (&gHistoryLock);
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
HistoryHandlerInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  InitializeSpinLock (&gHistoryLock);

  PrivateData.HiiHandle = HiiAddPackages (
          &gHistoryHandlerProtocolGuid,
          ImageHandle,
          HistoryDxeStrings, 
          NULL
          );
  
  PrivateData.HandlerProtocol.AddRecord   = AddRec;
  PrivateData.HandlerProtocol.GetParams   = GetParams;
  PrivateData.HandlerProtocol.SetParams   = SetParams;
  PrivateData.HandlerProtocol.UnloadCsv16 = UnloadCsv16;
  PrivateData.HandlerProtocol.LockOp = LockOp;
  PrivateData.HandlerProtocol.UnLockOp = UnLockOp;
  PrivateData.HandlerProtocol.GetCsv16 = GetCsv16;
  PrivateData.HandlerProtocol.MarkAsUnloaded = MarkAsUnloaded;
  
  Status = gBS->InstallProtocolInterface( 
    &PrivateData.DriverHandle, 
    &gHistoryHandlerProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &PrivateData.HandlerProtocol
    );
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


