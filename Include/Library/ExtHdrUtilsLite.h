/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __EXT__HDR__UTILS__H
#define __EXT__HDR__UTILS__H


#include <PiDxe.h>
#include <Library/HobLib.h>
#include <Library/Crc32.h>
#include <Library/CommonUtils.h>
#include <Library/FsUtils.h>
#include <InternalErrDesc.h>
#include <Library/BiosInfo.h>



#define MAIN_GUID_STR         "ED43534D-1C23-4adc-AAFD-76D7A939048C"
#define DXE_FV_GUID_STR       "40E12513-14D1-4208-AB28-55634FD73417"
#define FW_UPDATE_GUID_STR    "96839B66-BCBF-42E0-B64F-67D31B95CD2C"
#define FW_UPDATE_HASH_STR16  L"B737CBDB"
#define MAX_HASH_LEN          32


enum E_CS_KNOWN_TYPES {
  CS_TYPE_CRC32, CS_TYPE_UNKNOWN
};

enum CALC_CS_FLAGS {
  CALC_CS_UPDATE,
  CALC_CS_RESET,
  CALC_CS_FINALIZE = (1 << 1),
  CALC_CS_ALLOC = (1 << 2)
};

enum {
  FV_REC_TYPE_HASH_CS, FV_REC_TYPE_HASH_CS_WITH_PATH, 
  FV_REC_TYPE_BIOS_INFO
};


#pragma pack(push)
#pragma pack(1)
struct tMainFvInfo {
  EFI_FIRMWARE_VOLUME_HEADER *Fvh;
  EFI_FIRMWARE_VOLUME_EXT_HEADER *FvhExt;
  EFI_FIRMWARE_VOLUME_EXT_ENTRY  *FvhExtEntry;
  UINT8 *ExtDataPtr;
  UINTN ExtDataSize;
  UINT8 *FvDataPtr;
  UINTN FvLength;
};

struct tHashRecord {
  UINT8 Type;           // 0 - Simple 1 - WithPath
  UINT16 Size;          // размер HashRecord в байтах  
  EFI_GUID Guid;
  UINT8 HashType;    
  UINT8 HashData[1];        
};

struct tCRC32Record {
  UINT32 Crc32;
  UINT16  Path[1];
};

#pragma pack(pop)

int
GetDigestStr16(
  IN OUT CHAR16 *Str16,
  IN UINT8 *HashData,
  IN UINT8 HashType
  );

int
GetDigestStr(
  IN OUT CHAR8 *Str,
  IN struct tHashRecord *Prec);

int
GetGostDigestStrWithComma(
  IN OUT CHAR8 *Str,
  IN UINT8 *HashData
  );


EFI_STATUS
CalcHashCs(
  IN UINT8 cstype,
  IN UINT8 *pdata,  
  IN UINTN len,
  enum CALC_CS_FLAGS Flags,
  OUT VOID *outbuf);
  
int
CheckDataWithGuid(
  IN CHAR8 *Guid,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN struct tMainFvInfo *pmfvi);

int
CheckDataWithHash(
  IN UINT8 HashType,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *HashData
  );
  
int 
CheckMainFvHashCs(
  IN CHAR8 *Guid,
  IN struct tMainFvInfo *pmfvi);  

EFI_STATUS
StringToGuid (
  IN CHAR8      *AsciiGuidBuffer,
  OUT EFI_GUID  *GuidBuffer
  );
  
VOID *
FindPlaceInExtHdr(
  EFI_GUID *pGuid,
  IN struct tMainFvInfo *pmfvi,
  OUT UINTN *RestSize);
  
VOID
SaveCorruptRecord(
  IN struct tHashRecord *Prec
);

struct tHashRecord *
GetCorruptRecord(
  VOID
);

EFI_STATUS
GetNextFvNoMatchWithGuid(
  IN CHAR8 *GuidStr, 
  OUT struct tMainFvInfo *pfvi,
  IN BOOLEAN bRestart
  );

EFI_STATUS 
FindMainFvInByteBuf(
  IN UINT8 *ByteBuf,
  IN UINTN BufSize,
  IN CHAR8 *GuidStr,
  IN OUT struct tMainFvInfo *pmfvi
  );

UINT8 *
FindBiosInfoRecord(
  IN struct tMainFvInfo *pmfvi
  );

int
FindMainFv(
  IN CHAR8 *GuidStr, 
  OUT struct tMainFvInfo *pmfvi);
  
int 
CheckExternalObjHashCs(
  IN CHAR8 *Guid,
  IN CHAR8 *ObjPath,
  IN struct tMainFvInfo *pmfvi);

int 
CheckAllObjWithPath(
  IN struct tMainFvInfo *pmfvi);

UINTN
GetHashLen(
  IN UINT8 HashType);

BOOLEAN
IsItFwUpdate(
  IN struct tMainFvInfo *pmfvi
  );

UINT8 *
FindInfoRecordByGuid(
  IN struct tMainFvInfo *pmfvi,
  IN EFI_GUID *pGuid
  );

EFI_STATUS
CheckFile(
  IN CHAR8 *FileName,
  IN UINT8 HashType,
  IN UINT8 *HashData 
  );

EFI_STATUS 
CalcHashCsOnFile16(
  IN CHAR16 *InputFile,
  IN UINT8 CsType,
  IN UINT8 *HashData
  );

EFI_STATUS 
CalcHashCsOnFileWithHandle(
  IN EFI_FILE_HANDLE Pf,
  IN UINT8 CsType,
  IN UINT8 *HashData
  );

#endif  /* #ifndef __EXT__HDR__UTILS__H */

