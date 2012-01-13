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
#include <Library/FwUpdate.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/PcdHelperProtocol.h>


#define MAIN_GUID_STR         "ED43534D-1C23-4ADC-AAFD-76D7A939048C"
#define FW_UPDATE_GUID_STR    "96839B66-BCBF-42E0-B64F-67D31B95CD2C"

#define FW_UPDATE_HASH_STR16  L"514023044881D7A8630100D0305461DE3ED79E18F2C040CB248026E6DBCB37B7"
#define HASH_TYPE_BIOS_INFO   2

#ifndef MAX_HASH_LEN
#define MAX_HASH_LEN          (32)
#endif // #ifndef MAX_HASH_LEN

enum E_CS_KNOWN_TYPES {
  CS_TYPE_CRC32, CS_TYPE_SHA1, CS_TYPE_SHA256, 
  CS_TYPE_MD5, CS_TYPE_GOST,CS_TYPE_GOST_2012, CS_TYPE_UNKNOWN
};

enum CALC_CS_FLAGS {
  CALC_CS_UPDATE,
  CALC_CS_RESET,
  CALC_CS_FINALIZE = (1 << 1),
  CALC_CS_ALLOC = (1 << 2)
};

enum {
  FV_REC_TYPE_HASH_CS, 
  FV_REC_TYPE_HASH_CS_WITH_PATH, 
  FV_REC_TYPE_BIOS_INFO,
  FV_REC_TYPE_DRM_RECORD
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
typedef struct tMainFvInfo MAIN_FV_INFO;

struct tHashRecord {
  UINT8 Type;           // 0 - Simple; 1 - With Path; 2 - BIOS info; 3 - DRM Record (MAC-address)
  UINT16 Size;          // размер HashRecord в байтах  
  EFI_GUID Guid;
  UINT8 HashType;    
  UINT8 HashData[1];        
};
typedef struct tHashRecord HASH_RECORD;

struct tCRC32Record {
  UINT32 Crc32;
  UINT16  Path[1];
};

struct tGostRecord {
  UINT8 hash[MAX_HASH_LEN];
  UINT16 Path[1];
};

#define MD5_DIGEST_SIZE 16 
typedef UINT8 MD5_DIGEST[MD5_DIGEST_SIZE];
struct tMD5Record {
  MD5_DIGEST hash;
  UINT16  Path[1];
};

#define SHA1_DIGEST_SIZE 20 
typedef UINT8 SHA1_DIGEST[SHA1_DIGEST_SIZE];
struct tSHA1Record {
  SHA1_DIGEST hash;
  UINT16  Path[1];
};

#define SHA256_DIGEST_SIZE 32 
typedef UINT8 SHA256_DIGEST[SHA256_DIGEST_SIZE];
struct tSHA256Record {
  SHA256_DIGEST hash;
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

int
GetDigestWithLenStr16 (
  IN OUT CHAR16 *Str16,
  IN UINT8 *HashData,
  IN UINT8 HashType,
  IN UINTN HashLen
  );

VOID 
UpdateMainFirmwareInfo (
  IN UINT8 *BufPtr,
  OUT struct tMainFvInfo *pmfvi
  );

int
ByteBufToString(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  OUT CHAR8 *Str,
  IN UINTN StrLen
  );

INTN
ByteBufToStringRev(
  IN UINT8 *ByteBuf,
  IN UINTN BufLen,
  OUT CHAR8 *Str,
  IN UINTN StrLen
  );
 
#endif  /* #ifndef __EXT__HDR__UTILS__H */

