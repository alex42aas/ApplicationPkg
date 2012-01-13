/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Multiboot.h"
#include "Linux.h"
#include "Loader.h"
#include <Library/HobLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/NetSetupLib/NetSetupLib.h>

#define ELFCLASS ELFCLASS64 
#include "Elf.h"

#define MULTIBOOT_INIT_VGA 1

#define DEFAULT_NID	NID_id_GostR3411_94

#include <IndustryStandard/Pci22.h>
#include <Protocol/LegacyRegion.h> 
#include <Protocol/LegacyBios.h>
#include <Protocol/SmartCard.h>
#include <Guid/Acpi.h>
#include <Protocol/PcdHelperProtocol.h>

#include <Protocol/OpensslProtocol.h>
#include <openssl/obj_mac.h>

#include <Protocol/RemoteCfgTlsProtocol.h>
#include <Protocol/ExitPmAuth.h>
#include <Protocol/DxeSmmReadyToLock.h>


typedef struct _EXIT_PM_AUTH_PROTOCOL  EXIT_PM_AUTH_PROTOCOL;
typedef struct _EXIT_PM_AUTH_PROTOCOL {
  UINTN   Dummy;
};

EFI_HANDLE                    mExitPmAuthProtocolHandle = NULL;

EXIT_PM_AUTH_PROTOCOL mExitPmAuthProtocol = {
  0
};

typedef struct _SMM_READY_TO_LOCK_PROTOCOL  SMM_READY_TO_LOCK_PROTOCOL;
typedef struct _SMM_READY_TO_LOCK_PROTOCOL {
  UINTN   Dummy;
};

EFI_HANDLE                    mSmmReadyToLockProtocolHandle = NULL;

SMM_READY_TO_LOCK_PROTOCOL mSmmReadyToLockProtocol = {
  0
};

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *mOutput;
MULTIBOOT_INFO                  *gMultibootInfo;
EFI_FORM_BROWSER2_PROTOCOL      *gFormBrowser2;
MULTIBOOT_DATA                  *gMultibootData;
struct tMainFvInfo MainFvInfo;
STATIC EFI_HANDLE MbImageHandle;
STATIC PCD_HELPER_PROTOCOL *gPcdHelperProtocol;

#define POOL_HEAD_SIGNATURE   SIGNATURE_32('p','h','d','0')

typedef struct {
  UINT32          Signature;
  UINT32          Reserved;
  EFI_MEMORY_TYPE Type;
  UINTN           Size;
  CHAR8           Data[1];
} POOL_HEAD;

typedef struct {
  UINT32      Signature;
  UINT32      Reserved;
  UINTN       Size;
} POOL_TAIL;

#define SIZE_OF_POOL_HEAD OFFSET_OF(POOL_HEAD,Data)

STATIC EFI_FREE_POOL TrueFreePoolFunc = NULL;

/**
  Calcualte the 32-bit CRC in a EFI table using the service provided by the
  gRuntime service.

  @param  Hdr                    Pointer to an EFI standard header

**/
STATIC
VOID
CalculateEfiHdrCrc (
  IN  OUT EFI_TABLE_HEADER    *Hdr
  )
{
  UINT32 Crc;

  Hdr->CRC32 = 0;

  //
  // If gBS->CalculateCrce32 () == CoreEfiNotAvailableYet () then
  //  Crc will come back as zero if we set it to zero here
  //
  Crc = 0;
  gBS->CalculateCrc32 ((UINT8 *)Hdr, Hdr->HeaderSize, &Crc);
  Hdr->CRC32 = Crc;
}

STATIC
EFI_STATUS
EFIAPI 
MultibootFreePoolHook(
  IN  VOID                         *Buffer
  )
{
  POOL_HEAD   *Head;

  if (Buffer != NULL) {
    Head = BASE_CR (Buffer, POOL_HEAD, Data);
    if (Head->Signature == POOL_HEAD_SIGNATURE) {
      if((Head->Size - SIZE_OF_POOL_HEAD - sizeof(POOL_TAIL)) < 0)
      {
        DEBUG((EFI_D_INFO, "%a.%d Head->Size = 0x%x\n", __FUNCTION__, __LINE__, Head->Size));
        DEBUG((EFI_D_INFO, "%a.%d sizeof(HEAD) = %d  sizeof(TAIL) = %d\n", __FUNCTION__, __LINE__, SIZE_OF_POOL_HEAD, sizeof(POOL_TAIL) ));
        ASSERT(0);
      }
      ZeroMem(Buffer, Head->Size - SIZE_OF_POOL_HEAD - sizeof(POOL_TAIL));
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d Head->Signature = 0x%X\n", __FUNCTION__, __LINE__, Head->Signature));
    }
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d Buffer = 0x%p\n", __FUNCTION__, __LINE__, Buffer));
  }

  return TrueFreePoolFunc(Buffer);
}

STATIC
EFI_STATUS
EFIAPI 
MultibootInstallFreePoolHook(
  VOID
  )
{
  EFI_TPL OldTpl;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  OldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

  if (TrueFreePoolFunc != NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d TrueFreePoolFunc = 0x%p\n", __FUNCTION__, __LINE__, TrueFreePoolFunc));
    gBS->RestoreTPL(OldTpl);
    return EFI_ALREADY_STARTED;
  }

  TrueFreePoolFunc = gBS->FreePool;
  gBS->FreePool = MultibootFreePoolHook;
  CalculateEfiHdrCrc(&gBS->Hdr);

  gBS->RestoreTPL(OldTpl);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
DoHash (
  IN VOID *Data,
  IN UINTN DataLen
  )
{
  STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;
  VOID *MdCtx = NULL;
  UINTN Nid;
  UINTN hash_len;
  int *d;

  EFI_STATUS Status;
  UINT8 Hash[32];

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pOpenSSLProtocol == NULL) {
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = gBS->LocateProtocol (
          &gOpenSSLProtocolGuid,
          NULL,
          (VOID **)&pOpenSSLProtocol
          );
    DEBUG ((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

    if (EFI_ERROR(Status)) {
      return Status;
    }
  }
  
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  pOpenSSLProtocol->Init();
  Nid = DEFAULT_NID;

  Status = pOpenSSLProtocol->EVP_New_MD_CTX (   
        pOpenSSLProtocol,
        &MdCtx
        );
  if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d: EVP_New_MD_CTX fail\n", __FUNCTION__, __LINE__));
	}


  d = (int *)pOpenSSLProtocol->EVP_get_digestbynid(pOpenSSLProtocol, Nid);
  if(!d)
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_get_digestbynid error\n", __FUNCTION__, __LINE__));

  Status = pOpenSSLProtocol->EVP_DigestInit (
		pOpenSSLProtocol,
		MdCtx,
		pOpenSSLProtocol->EVP_get_digestbynid (pOpenSSLProtocol, Nid)
		);
  if (EFI_ERROR (Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestInit error\n", __FUNCTION__, __LINE__));
    }

  Status = pOpenSSLProtocol->EVP_DigestUpdate (
    pOpenSSLProtocol,
    MdCtx,
    Data,//pdata
    DataLen //len
    );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestUpdate error\n", __FUNCTION__, __LINE__));
  }

  Status = pOpenSSLProtocol->EVP_DigestFinal (
    pOpenSSLProtocol,
    MdCtx,
    Hash,
    &hash_len
    );
   if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestFinal error\n", __FUNCTION__, __LINE__));
  }	

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  DumpBytes (Hash, sizeof(Hash));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
PcdHelperInit (
  VOID
  )
{
  EFI_STATUS Status;

  if (gPcdHelperProtocol) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (
        &gPcdHelperProtocolGuid,
        NULL,
        (VOID **)&gPcdHelperProtocol
        );
  if (EFI_ERROR(Status)) {
    gPcdHelperProtocol = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }
  return Status;
}


EFI_STATUS
MbAllocatePool (
    UINTN Size, 
    VOID** Buffer
    )
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS  Memory;

  if (Size > SIZE_128MB) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  Memory = SIZE_128MB;
  Status = gBS->AllocatePages (
      AllocateMaxAddress, 
      EfiLoaderData, 
      EFI_SIZE_TO_PAGES(Size), 
      &Memory 
      );

  ASSERT(Buffer != NULL);
  *Buffer = (VOID*) (UINTN) Memory;
  return Status;
}

EFI_STATUS
CheckBufferHash(
    EFI_PHYSICAL_ADDRESS Address,
    UINT64               Length,
    GOST_DIGEST          RightHash
    )
{
  STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;
  VOID *HashCtx = NULL;
  UINTN Nid;
  UINTN hash_len;
  int *d;
  EFI_STATUS Status;
  UINT8 Hash[32];
  UINT16                         Str[128];
  MULTIBOOT_CONFIG               *Config;

  Config = &gMultibootData->Config;

  UnicodeSPrint( Str, sizeof(Str), HiiGetString ( 
        gMultibootData->HiiHandle, 
        GetStringFileHashCheck(), 
        Config->Language) );
  mOutput->OutputString( mOutput, Str );


  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pOpenSSLProtocol == NULL) {
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = gBS->LocateProtocol (
          &gOpenSSLProtocolGuid,
          NULL,
          (VOID **)&pOpenSSLProtocol
          );
    DEBUG ((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

    if (EFI_ERROR(Status)) {
      return Status;
    }
  }
  
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  pOpenSSLProtocol->Init();
  Nid = DEFAULT_NID;

   Status = pOpenSSLProtocol->EVP_New_MD_CTX (   
        pOpenSSLProtocol,
        &HashCtx
        );
  if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d: EVP_New_MD_CTX error\n", __FUNCTION__, __LINE__));
	}


  d = (int *)pOpenSSLProtocol->EVP_get_digestbynid(pOpenSSLProtocol, Nid);

  if(!d)
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_get_digestbynid error\n", __FUNCTION__, __LINE__));

  Status = pOpenSSLProtocol->EVP_DigestInit (
		pOpenSSLProtocol,
		HashCtx,
		pOpenSSLProtocol->EVP_get_digestbynid (pOpenSSLProtocol, Nid)
		);
  if (EFI_ERROR (Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestInit error\n", __FUNCTION__, __LINE__));
    }

  Status = pOpenSSLProtocol->EVP_DigestUpdate (
    pOpenSSLProtocol,
    HashCtx,
    (VOID*) (UINTN) Address,//pdata
    (UINTN) Length //len
    );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestUpdate error\n", __FUNCTION__, __LINE__));
  }

  Status = pOpenSSLProtocol->EVP_DigestFinal (
    pOpenSSLProtocol,
    HashCtx,
    Hash,
    &hash_len
    );
   if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d: EVP_DigestFinal error\n", __FUNCTION__, __LINE__));
  }	

  if(CompareMem(Hash, RightHash, hash_len) != 0) {

    UnicodeSPrint( Str, sizeof(Str), HiiGetString ( 
          gMultibootData->HiiHandle, 
          GetStringError(),
          Config->Language) );
    mOutput->OutputString( mOutput, Str );
    mOutput->OutputString( mOutput, L"\n\r" );

    return EFI_ACCESS_DENIED;
  }

  UnicodeSPrint( Str, sizeof(Str), HiiGetString ( 
        gMultibootData->HiiHandle, 
        GetStringSuccess(),
        Config->Language) );
  mOutput->OutputString( mOutput, Str );
  mOutput->OutputString( mOutput, L"\n\r" );
  return EFI_SUCCESS;
}


VOID 
SendError(
  EFI_STRING_ID StringId, 
  EFI_STATUS Status 
  )
{

  UINT16 ErrorString[256];
  EFI_INPUT_KEY Key;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL   *Out;
  MULTIBOOT_CONFIG *Config;

  Config = &gMultibootData->Config;

  if(Config->ErrorLine) {
    UnicodeSPrint( ErrorString, 
        sizeof(ErrorString), 
        L" %s Line:%d Pos:%d Status:%r ", HiiGetString ( 
          gMultibootData->HiiHandle, 
          STRING_TOKEN (StringId), 
          Config->Language), 
        Config->ErrorLine,
        Config->ErrorPos,
        Status );

  } else {
    UnicodeSPrint( ErrorString, 
        sizeof(ErrorString), 
        L" %s\r\n", HiiGetString ( 
          gMultibootData->HiiHandle, 
          STRING_TOKEN (StringId), 
          Config->Language), Status );

  }

  DEBUG((EFI_D_ERROR, "SendError:%s %r\n", 
        ErrorString	));

  Out = mOutput;

  if( gMultibootData->Config.Interactive ) {
    CreatePopUp( EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, &Key, 
        L" ", ErrorString, L" ", L" ", NULL );
    Out->ClearScreen( Out );
  }
  Out->OutputString( Out, ErrorString );
  CpuDeadLoop();
}


EFI_STATUS
ProcessBinary(
  IN      EFI_PHYSICAL_ADDRESS  LoadAddress,
  IN OUT  EFI_PHYSICAL_ADDRESS *LowAddress,
  IN OUT  EFI_PHYSICAL_ADDRESS *UpAddress,
  IN OUT  UINT32               *EntryAddress
  )
{
    EFI_STATUS Status;
    UINTN Size = (UINTN) (*UpAddress - *LowAddress);
    
    Status = gBS->AllocatePages (
      AllocateAddress,
      EfiLoaderData,
      EFI_SIZE_TO_PAGES(Size),
      LowAddress
      );

  ASSERT_EFI_ERROR(Status);
  CopyMem( (VOID*) (UINTN) (*LowAddress), (VOID*) (UINTN) LoadAddress, Size );
  return EFI_SUCCESS;
}


EFI_STATUS
ProcessElf32(
  IN      Elf32_Ehdr *ElfHdr,
  IN OUT  EFI_PHYSICAL_ADDRESS *LowAddress,
  IN OUT  EFI_PHYSICAL_ADDRESS *UpAddress,
  IN OUT  UINT32 *EntryAddress
  )
{
  //  Elf32_Ehdr eHdr;
  Elf32_Phdr *pHdrs;
  //  EFI_STATUS Status;
  UINT16 pHdrNumber;
  UINTN Index;
  UINTN TotalSize;
  UINTN SegmentMemSize;
  UINT8 *LoadArea;
  EFI_STATUS Status;

  DEBUG((EFI_D_INFO, "ElfHdr:%p Magic:%x %x %x %x %x\n", 
        ElfHdr,
        ElfHdr->e_ident[0],
        ElfHdr->e_ident[1],
        ElfHdr->e_ident[2],
        ElfHdr->e_ident[3],
        ElfHdr->e_ident[4] ));

  if(ElfHdr->e_ident[0] != 0x7F  ||
      ElfHdr->e_ident[1] != 0x45 ||
      ElfHdr->e_ident[2] != 0x4C ) {
    return EFI_NOT_FOUND;
  }

  pHdrs = (Elf32_Phdr*) (((UINTN) ElfHdr) + ElfHdr->e_phoff);
  pHdrNumber = ElfHdr->e_phnum;

  *LowAddress = ~0U;
  *UpAddress = 0U;
  TotalSize = 0U;

  for(Index = 0; Index < pHdrNumber; Index++) {
    if( pHdrs[Index].p_type != PT_LOAD ) {
      continue;
    }

    if( pHdrs[Index].p_paddr < *LowAddress ) { 
      *LowAddress = pHdrs[Index].p_paddr;
    }

    SegmentMemSize = pHdrs[Index].p_memsz;
    if( (pHdrs[Index].p_paddr + SegmentMemSize) > *UpAddress ) { 
      *UpAddress = pHdrs[Index].p_paddr + SegmentMemSize;
    }
    TotalSize += SegmentMemSize;
  }

  *EntryAddress = ElfHdr->e_entry;

  DEBUG(( EFI_D_INFO, "ELF32 Start:%p End:%p Size:%x Entry:%x\n",
        *LowAddress,
        *UpAddress,
        TotalSize, 
        *EntryAddress
        ));

  Status = gBS->AllocatePages (
      AllocateAddress,
      EfiLoaderData,
      EFI_SIZE_TO_PAGES(TotalSize),
      LowAddress
      );

  ASSERT_EFI_ERROR(Status);

  LoadArea = (UINT8*) ElfHdr;

  for(Index = 0; Index < pHdrNumber; Index++) {
    UINTN Offset = pHdrs[Index].p_offset;
    UINT8 *DstAddress = NULL;
    if( Offset > TotalSize ) {      
      DEBUG(( EFI_D_ERROR, "ELF32 Wrong Program HDR %d Offset:0x%x\n", 
            Index,
            Offset ));

      return EFI_INVALID_PARAMETER;
    }
    DstAddress = (UINT8*) (UINTN) (pHdrs[Index].p_paddr);
    DEBUG(( EFI_D_INFO, "Copy PH:%d Dst:%p Src:%p FileSize:0x%x MemSize:0x%x\n",
          Index,
          DstAddress,
          &LoadArea[Offset],
          pHdrs[Index].p_filesz,
          pHdrs[Index].p_memsz
          ));

    ZeroMem( DstAddress, pHdrs[Index].p_memsz);
    CopyMem( DstAddress, &LoadArea[Offset], pHdrs[Index].p_filesz);
    if(CompareMem(  DstAddress, &LoadArea[Offset], pHdrs[Index].p_filesz )) {
      ASSERT(0);
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
LoadModule(
  IN      CHAR8* DevicePath,
  IN OUT  EFI_PHYSICAL_ADDRESS *BaseAddress,
  OUT     UINTN  *FileSize,
  IN      BOOLEAN bHashPresent,
  IN      GOST_DIGEST  RightHash,
  IN      CHAR8 *GuidStr
  )
{
  EFI_STATUS Status;
  EFI_FILE_HANDLE File;
  UINTN Size;
  UINT8* Buffer;
  CHAR8  *Language;
  
  DEBUG((EFI_D_INFO, "%a.%d DevicePath: %a\n", __FUNCTION__, __LINE__, DevicePath));

  Language = gMultibootData->Config.Language;
  
  File = LibFsOpenFile(DevicePath, EFI_FILE_MODE_READ, 0);
  if( File == NULL ) {
    DEBUG((EFI_D_ERROR, "Error while LibFsOpenFile!!!!\n"));
    return EFI_NOT_FOUND;
  }

  Size = LibFsSizeFile(File);

  Status = MbAllocatePool (Size, &Buffer);

  if(EFI_ERROR(Status)) {
    return Status;
  }

  Status = LibFsReadFile(File, &Size, Buffer);
  
  LibFsCloseFile(File);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }  

  *BaseAddress = (EFI_PHYSICAL_ADDRESS) (UINTN) Buffer;
  *FileSize = Size;
  
  DEBUG((EFI_D_INFO, "Read done: size=%d\n", Size));

  if (GuidStr != NULL) {
    DEBUG((EFI_D_ERROR, "Check for: %a %a", GuidStr, DevicePath));

    if (CheckDataWithGuid(GuidStr,(UINT8*)Buffer, Size,
          &MainFvInfo) == -1) {
      CHAR16 *ErrorDesc;
      EFI_GUID Guid;
      UINTN i;
      
      StringToGuid_L(GuidStr, &Guid);
      MsgInfo(GetStringErrorIntegrity());
      
      ErrorDesc = FindObjDescByGuid(&Guid);
       if (ErrorDesc) {
        MsgTextOut(ErrorDesc);
      } else {
        MsgDebugPrint("%a", GuidStr);
      }
      MsgTextOut(L"\n");
      
      Status = EFI_INVALID_PARAMETER;
    } else {
      Status = EFI_SUCCESS;
    }

  } else if(bHashPresent) {
    Status = CheckBufferHash(*BaseAddress, Size, RightHash ); 
  } 
  DEBUG((EFI_D_INFO, "LoadModule: Status:%r\n", Status));
  return Status;
}

EFI_STATUS
LoadFile(
  IN      CHAR8* DevicePath,
  IN OUT  VOID** FileBuffer,
  OUT     UINTN  *FileSize
  )
{
  EFI_STATUS Status;
  EFI_FILE_HANDLE File;
  UINTN Size;
  UINT8* Buffer;
  CHAR8  *Language;
  
  DEBUG((EFI_D_INFO, "%a.%d DevicePath: %a\n", __FUNCTION__, __LINE__, DevicePath));

  if (DevicePath == NULL || FileBuffer == NULL || FileSize == NULL) {
    Status = EFI_INVALID_PARAMETER;
    DEBUG((EFI_D_ERROR, "%a.%d Status = 0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Language = gMultibootData->Config.Language;
  
  File = LibFsOpenFile(DevicePath, EFI_FILE_MODE_READ, 0);
  if( File == NULL ) {
    DEBUG((EFI_D_ERROR, "Error while LibFsOpenFile!!!!\n"));
    return EFI_NOT_FOUND;
  }

  Size = LibFsSizeFile(File);

  Buffer = AllocatePool (Size);
  if(Buffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG((EFI_D_ERROR, "%a.%d Status = 0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = LibFsReadFile(File, &Size, Buffer);
  
  LibFsCloseFile(File);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    FreePool(Buffer);
    return Status;
  }  

  *FileBuffer = Buffer;
  *FileSize = Size;
  
  DEBUG((EFI_D_INFO, "Read done: size=%d\n", Size));
  DEBUG((EFI_D_INFO, "%a: Status = 0x%X\n", __FUNCTION__, Status));
  return Status;
}

EFI_STATUS
LoadConfig(
  MULTIBOOT_CONFIG *Config
  )
{
  CHAR8 *ConfigTest;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImageProtocol;
  CHAR8 *FilePath;
  STATIC CHAR8* DeviceNames[2] = {
    "newfv", //first try to search in the newfv
    "fv" //then in mainfv
  };
  STATIC VOID* FileNames[2] = {
    FixedPcdGetPtr(PcdLoaderConfFile),
    FixedPcdGetPtr(PcdMbConfigFile)    
  };
  UINTN Size, i;
  EFI_STATUS Status;
  VOID* ConfigBuffer;
  CONST CHAR8 DefaultConfigFilePath[] = "\\mbconf.xml";

  Status = gBS->OpenProtocol (
      gImageHandle,
      &gEfiLoadedImageProtocolGuid,
      (VOID **) &LoadedImageProtocol,
      gImageHandle,
      NULL,
      EFI_OPEN_PROTOCOL_GET_PROTOCOL
      );
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_INFO, "LoadedImageProtocol->DeviceHandle:%x\n",
        LoadedImageProtocol->DeviceHandle ));

  i = sizeof(DeviceNames)/sizeof(DeviceNames[0]);
  for (i = 0; i < sizeof(DeviceNames)/sizeof(DeviceNames[0]); i++) {
    Size = AsciiStrLen(DefaultConfigFilePath) +
      AsciiStrLen(DeviceNames[i]) + sizeof(UINT8)*64;

    FilePath = (CHAR8*) AllocateZeroPool( Size );
    if(FilePath == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    ConfigTest = NULL;
    ConfigBuffer = 0;

    if(NULL != AsciiStrStr(DeviceNames[i], "fv")) {
      AsciiSPrint( FilePath, Size, "%a:%g", DeviceNames[i], FileNames[i]);
    } else {
      AsciiSPrint( FilePath, Size, "%a:%a", DeviceNames[i], DefaultConfigFilePath);    
    }
    DEBUG((EFI_D_INFO, "%a.%d FilePath=%a\n", __FUNCTION__, __LINE__, FilePath));    
    Status = LoadFile( FilePath, &ConfigBuffer, &Size);
    if(!EFI_ERROR(Status)) {
      ConfigTest = (CHAR8*) ConfigBuffer;

      if(Size == 0) {
        Status = EFI_INVALID_PARAMETER;
      }

      if (!EFI_ERROR(Status)) {
        Status = XmlConfigRead(Config, ConfigTest, Size);
        DEBUG((EFI_D_INFO, "LoadConfig: XmlConfigRead: St:%r\n", Status)); 
        if(!EFI_ERROR(Status)) {
          Config->XmlConfigData = ConfigTest;
          Config->XmlConfigDataSize = Size;
          break;
        } else {
          Config->State = 0;
        }
      }

      FreePool(ConfigBuffer);
    }
  }
  return Status;
}


#define IS_NULL(a)                 ((a) == L'\0')
UINTN
StrnToAscii (
  IN     CHAR16 *Str,
  IN OUT CHAR8  *AsciiStr,
  IN     UINTN  AsciiStrBufLen
  )
{
  CHAR8 *Dest;
  UINTN Index;
  
  Index = 0;
  Dest = AsciiStr;

  while (!IS_NULL (*Str) && (Index < (AsciiStrBufLen - 1))) {
    *(Dest++) = (CHAR8) *(Str++);
    Index++;
  }
  *Dest = 0;

  //
  //  Return strlen
  //
  return Index;
}


#pragma pack(1)

/* Definitions for converting EFI memory map to E820 map for Linux 
 * These definitions are from include/linux/asm-x86_64/e820.h
 * The structure x86_64_boot_params below is updated to accommodate E820 map 
 * EFI memory map is converted to E820 map in this structure and passed
 * to Linux. This way the OS does not need to do the conversion.
 */
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3
#define E820_NVS        4
#define E820_EXEC_CODE  5
#define E820_MAX  1024

typedef struct _MULTIBOOT_E820_ENTRY {
  UINT32 Size;
  UINT64 BaseAddress; /* start of memory segment */
  UINT64 Length;          /* size of memory segment  */
  UINT32 Type;          /* type of memory segment  */
} MULTIBOOT_E820_ENTRY;

#pragma pack()

/* Convert EFI memory map to E820 map for the operating system 
 * This code is based on a Linux kernel patch submitted by Edgar Hucek
 */

/* Add a memory region to the e820 map */

typedef VOID (EFIAPI * ADD_E820_ENTRY) (
  IN  VOID  *E820MapAddr,
  OUT UINTN *NumberOfEntries,
  UINT64 Start,
  UINT64 Size,
  UINT32 Type );

VOID 
MultibootAddE820Entry (
  VOID  *E820MapAddr,
  UINTN *e820_nr_map,
  UINT64 start,
  UINT64 size,
  UINT32 type)
{
  MULTIBOOT_E820_ENTRY *e820_map = (MULTIBOOT_E820_ENTRY *) E820MapAddr;
  UINTN x = *e820_nr_map;
  
  if(x > E820_MAX) {
    return;
  }

  if ((x > 0) && ((e820_map[x-1].BaseAddress + e820_map[x-1].Length) == start)
      && (e820_map[x-1].Type == type))
    e820_map[x-1].Length += size;
  else {
    e820_map[x].BaseAddress = start;
    e820_map[x].Length = size;
    e820_map[x].Type = type;
    e820_map[x].Size = sizeof(MULTIBOOT_E820_ENTRY) - sizeof(e820_map->Size); 
    (*e820_nr_map)++;
    x = (*e820_nr_map) - 1;
  }

  DEBUG((EFI_D_INFO, "E820 %d Start:%llx Length:%llx Type:%d\n", 
        x, e820_map[x].BaseAddress, e820_map[x].Length, e820_map[x].Type));

}

VOID 
LinuxAddE820Entry (
  VOID  *E820MapAddr,
  UINTN *E820MapAddrSize,
  UINT64 Start,
  UINT64 Size,
  UINT32 Type)
{
  LINUX_E820_ENTRY *e820_map = (LINUX_E820_ENTRY *) E820MapAddr;
  UINTN x = *E820MapAddrSize;

  if(x > LINUX_E820_MAX_ENTRY) {
    return;
  }

  if ((x > 0) && ((e820_map[x-1].BaseAddress + e820_map[x-1].Length) == Start)
          && (e820_map[x-1].Type == Type))
    e820_map[x-1].Length += Size;
  else {
    e820_map[x].BaseAddress = Start;
    e820_map[x].Length = Size;
    e820_map[x].Type = Type;
    (*E820MapAddrSize)++;
    x = (*E820MapAddrSize) - 1;
  }
  DEBUG((EFI_D_INFO, "E820 %d Start:%llx Length:%llx Type:%d\n",
        x, e820_map[x].BaseAddress, e820_map[x].Length, e820_map[x].Type));
}

VOID 
FillE820(
  IN OUT  VOID*           E820Map,
  IN OUT  UINTN*          E820MapSize,
  IN      ADD_E820_ENTRY  AddE820Entry,
  OUT     UINT64*         TotalPages
  )
{
  EFI_STATUS              Status;
  UINTN                   nr_map, i;
  UINT64                  start, end, size;
  EFI_MEMORY_DESCRIPTOR   *md, *p;
  UINTN                   MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR   *MemoryMap;
  UINTN                   MapKey;
  UINTN                   DescriptorSize;
  UINT32                  DescriptorVersion;
  UINTN                   Pages;
//  EFI_PEI_HOB_POINTERS    ResHob;

  MemoryMap = NULL;
  MemoryMapSize = 0;
  //	E820Size = 0;
  //	e820_map = NULL;
  Pages = 0;
  *TotalPages = 0;

  Status = gBS->GetMemoryMap (
        &MemoryMapSize,
        MemoryMap,
        &MapKey,
        &DescriptorSize,
        &DescriptorVersion
        );

  DEBUG((EFI_D_INFO, "MemoryMapSize:%x\n", MemoryMapSize));
  if (Status == EFI_BUFFER_TOO_SMALL) {

    MemoryMapSize += DescriptorSize*5;
    Pages = EFI_SIZE_TO_PAGES (MemoryMapSize) + 1;
    MemoryMap = AllocatePages (Pages);

    //
    // Get System MemoryMap
    //
    Status = gBS->GetMemoryMap (
    &MemoryMapSize,
    MemoryMap,
    &MapKey,
    &DescriptorSize,
    &DescriptorVersion
    );
  }

  ASSERT_EFI_ERROR(Status);

  DEBUG((EFI_D_INFO, "MemoryMapSize:%x\n", MemoryMapSize));

  EFI_ERROR_RET(Status, "");

  nr_map = MemoryMapSize/DescriptorSize;

  DEBUG((EFI_D_INFO, "nr_map:%d e820:%d\n",
  nr_map, *E820MapSize ));

  if ( nr_map > *E820MapSize ) {
    *E820MapSize = nr_map;
    Status = EFI_BUFFER_TOO_SMALL;
    EFI_ERROR_RET(Status, "");
  }

  *E820MapSize = 0;

  for (i = 0, p = MemoryMap; i < nr_map; i++)
  {
    md = p;
    switch (md->Type) {
    case EfiACPIReclaimMemory:
      AddE820Entry(
            E820Map,
            E820MapSize,
            md->PhysicalStart,
            md->NumberOfPages << EFI_PAGE_SHIFT,
            E820_ACPI
            );
      break;
    case EfiRuntimeServicesCode:
      AddE820Entry(
            E820Map,
            E820MapSize,
            md->PhysicalStart,
            md->NumberOfPages << EFI_PAGE_SHIFT,
            E820_RESERVED
            );
      break;
    case EfiRuntimeServicesData:
    case EfiReservedMemoryType:
    case EfiMemoryMappedIO:
    case EfiMemoryMappedIOPortSpace:
    case EfiUnusableMemory:
    case EfiPalCode:
      AddE820Entry(
            E820Map,
            E820MapSize,
            md->PhysicalStart,
            md->NumberOfPages << EFI_PAGE_SHIFT,
            E820_RESERVED
            );
      break;
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiConventionalMemory:
      start = md->PhysicalStart;
      size = md->NumberOfPages << EFI_PAGE_SHIFT;
      end = start + size;
      /* Fix up for BIOS that claims RAM in 640K-1MB region */
      if (start < 0x100000ULL && end > 0xA0000ULL) {
        if (start < 0xA0000ULL) {
          /* start < 640K
          * set memory map from start to 640K
          */
          AddE820Entry(
                E820Map,
                E820MapSize,
                start,
                0xA0000ULL-start,
                E820_RAM
                );
        }
        if (end <= 0x100000ULL)
          continue;
        /* end > 1MB
         * set memory map avoiding 640K to 1MB hole
         */
        start = 0x100000ULL;
        size = end - start;
      }
      AddE820Entry(
            E820Map,
            E820MapSize,
            start, size,
            E820_RAM
            );
      break;
    case EfiACPIMemoryNVS:
      AddE820Entry(
            E820Map,
            E820MapSize,
            md->PhysicalStart,
            md->NumberOfPages << EFI_PAGE_SHIFT,
            E820_NVS
            );
      break;
    default:
    /* We should not hit this case */
      AddE820Entry(
            E820Map,
            E820MapSize,
            md->PhysicalStart,
            md->NumberOfPages << EFI_PAGE_SHIFT,
            E820_RESERVED
            );
      break;
    }
    p = NEXT_MEMORY_DESCRIPTOR(p, DescriptorSize);
    *TotalPages += md->NumberOfPages;
  }

  DEBUG((EFI_D_ERROR, "\n"));
  /* Add bios  */
  AddE820Entry(
      E820Map, 
      E820MapSize,
      0xA0000,
      0x60000,
      E820_RESERVED
      );

OnError:
  if(MemoryMap != NULL) {
    FreePages (MemoryMap, Pages);
  }
  return;
} 

VOID
StartOSMultiboot( 
  MULTIBOOT_ENTRY *Entry
  )
{
  EFI_STATUS Status;
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;
  CHAR8 AsciiStr[MULTIBOOT_MAX_STRING];
  EFI_PHYSICAL_ADDRESS Address;
  UINTN Size;

  UINTN                   MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR   *MemoryMap;
  UINTN                   MapKey;
  UINTN                   DescriptorSize;
  UINT32                  DescriptorVersion;
  UINTN                   Pages;
  MULTIBOOT_HEADER*       Header;
  UINTN                   Index;
  EFI_PHYSICAL_ADDRESS    KernelLowAddress;
  EFI_PHYSICAL_ADDRESS    KernelHighAddress;
  EFI_PHYSICAL_ADDRESS    KernelLoadAddress;
  UINT32                  KernelEntry;
  CHAR8*                  CmdLine; //, *KernelAdditionalArgs;
  UINTN                   CmdLineLength;
  UINTN                   ModulesCount;
  MULTIBOOT_MODULES_LIST  *ModulesList;
  UINTN                   E820MapSize;
  UINT64                  TotalPages;
  MULTIBOOT_E820_ENTRY    *E820Map;


  DEBUG((EFI_D_INFO, "StartMultibootOS\n"));
  Address = 0;
  Size = 0;
  KernelEntry = 0;
  KernelLowAddress = 0;
  KernelLoadAddress = 0;

  ListEntry = Entry->ModuleHead.ForwardLink;

  Header = NULL;
  CmdLine = NULL;

  ModulesCount = 0;

  if(IsListEmpty(&Entry->ModuleHead)) {
    Status = EFI_INVALID_PARAMETER;
    EFI_ERROR_RET(Status, "");
  }

	Status = MbAllocatePool (
			sizeof(MULTIBOOT_MODULES_LIST)*MULTIBOOT_MAX_MODULES,
			&ModulesList
			);

  EFI_ERROR_RET(Status, "");

  ZeroMem(ModulesList, sizeof(MULTIBOOT_MODULES_LIST)*MULTIBOOT_MAX_MODULES);



  while( ListEntry != &Entry->ModuleHead ) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry );

    StrnToAscii( Module->DevPath, AsciiStr, sizeof(AsciiStr) );
    Status = LoadModule( AsciiStr, &Address, &Size, Module->bHashPresent,
      Module->Hash, Module->GuidStr );
    EFI_ERROR_RET(Status, "Load module ERROR\n");

    DEBUG(( EFI_D_INFO, "Loaded module Path:%S Address:%p Size:%x\n Status:%r\n", 
          Module->DevPath, Address, Size, Status ));

    if(Header == NULL) {
      // Load Kernel

      KernelLoadAddress = Address;

      for(Index = 0; Index < MULTIBOOT_SEARCH; Index++) {
        Header = (MULTIBOOT_HEADER*) (UINTN) (Address+Index*4);

        if(Header->magic == MULTIBOOT_MAGIC) {
          break;
        } else {
          Header = NULL;
        }
      }

      if( Header == NULL ) {
        Status = EFI_NOT_FOUND;
        EFI_ERROR_RET(Status, "Multiboot header not found\n");
      }
      
      DEBUG(( EFI_D_INFO, "\nMBH: magic:%x\nflags:%x\nheader_addr:%x\nload_addr:%x\n"
              "load_end_addr:%x\nbss_end_addr:%x\nentry_addr:%x\n", 
              Header->magic,
              Header->flags,
              Header->header_addr,
              Header->load_addr,
              Header->load_end_addr,
              Header->bss_end_addr,
              Header->entry_addr
              ));
 
      Status = ProcessElf32 (
          (Elf32_Ehdr*) (UINTN) Address, 
          &KernelLowAddress, 
          &KernelHighAddress,
          &KernelEntry );

      

      if(EFI_ERROR(Status)) {
        // Try binary load
        if(!(Header->flags & MULTIBOOT_AOUT_KLUDGE)) {
          // unknown adress field 
          Status = EFI_NOT_FOUND;
          EFI_ERROR_RET(Status, "Error !ELF && !MULTIBOOT_AOUT_KLUDGE\n");
        }

        KernelLowAddress = Header->load_addr;
        KernelHighAddress = KernelLowAddress + Size;
        KernelEntry = Header->entry_addr;

        Status = ProcessBinary (
            Address, 
            &KernelLowAddress, 
            &KernelHighAddress,
            &KernelEntry
            );
      }

      EFI_ERROR_RET(Status, "");

      Size = (UINTN) (KernelHighAddress - KernelLowAddress);

      CmdLineLength = StrLen(Module->Args); // + AsciiStrLen(KernelAdditionalArgs);

      if(CmdLineLength) {
        Status = MbAllocatePool(CmdLineLength+1, &CmdLine);
        EFI_ERROR_RET(Status, "");        

        StrnToAscii( Module->Args, CmdLine, CmdLineLength+1 );
      }

    } else {
      UINTN ModuleCmdLineLength;

      ModuleCmdLineLength = StrLen(Module->Args);

      if( ModuleCmdLineLength ) {
				CHAR8* ModuleCmdLine;
        Status = MbAllocatePool(ModuleCmdLineLength+1, &ModuleCmdLine);
        EFI_ERROR_RET(Status, "");
        StrnToAscii( Module->Args, ModuleCmdLine, ModuleCmdLineLength+1 );       
        ModulesList[ModulesCount].cmdline = (UINT32) (UINTN) ModuleCmdLine;
      }
      
      ModulesList[ModulesCount].mod_start = (UINT32) Address;
      ModulesList[ModulesCount].mod_end = (UINT32)  (Address + Size);
      ModulesCount++;

      if(ModulesCount >= MULTIBOOT_MAX_MODULES ) {
        break;
      }
    }

    ListEntry = ListEntry->ForwardLink;
  }

	Status = MbAllocatePool(
			sizeof( MULTIBOOT_INFO ), 
			(VOID**)&gMultibootInfo );

  EFI_ERROR_RET( Status, "" );

  ZeroMem( gMultibootInfo, sizeof(MULTIBOOT_INFO) );

  Status = MbAllocatePool( 
			E820_MAX * sizeof(MULTIBOOT_E820_ENTRY), 
			(VOID**) &E820Map );

  EFI_ERROR_RET( Status, "" );
  ZeroMem(E820Map, E820_MAX * sizeof(MULTIBOOT_E820_ENTRY));

  E820MapSize = E820_MAX;
  TotalPages = 0;

  FillE820( E820Map, &E820MapSize, MultibootAddE820Entry, &TotalPages );

  gMultibootInfo->mem_upper = (UINT32) (TotalPages << EFI_PAGE_SHIFT) - 0x100000;
  gMultibootInfo->mem_lower = 0xA0000;
  gMultibootInfo->mmap_addr = (UINT32) (UINTN) E820Map;
  gMultibootInfo->mmap_length = (UINT32) MultU64x32(
      E820MapSize, 
      sizeof(MULTIBOOT_E820_ENTRY)
      );
  DEBUG((EFI_D_INFO, "Mmap:0x%X Len:%x TotalPages:%llx\n", 
        gMultibootInfo->mmap_addr,
        gMultibootInfo->mmap_length,
        TotalPages
        ));

  gMultibootInfo->flags = (  MB_INFO_BOOT_LOADER_NAME |
      MB_INFO_MEM_MAP | MB_INFO_EFI );

  if(CmdLine != NULL) {
    gMultibootInfo->flags |= MB_INFO_CMDLINE;
    gMultibootInfo->cmdline = (UINT32)(UINTN) CmdLine;
  }

  if(ModulesCount) {
    gMultibootInfo->flags |= MB_INFO_MODS;
    gMultibootInfo->mods_count = (UINT32) ModulesCount;
    gMultibootInfo->mods_addr = (UINT32) (UINTN) ModulesList;
  }

  MemoryMap = NULL;
  MemoryMapSize = 0;
  Pages = 0;
  do {
    Status = gBS->GetMemoryMap (
        &MemoryMapSize,
        MemoryMap,
        &MapKey,
        &DescriptorSize,
        &DescriptorVersion
        );

    if (Status == EFI_BUFFER_TOO_SMALL) {

      Pages = EFI_SIZE_TO_PAGES (MemoryMapSize) + 1;
      MemoryMap = AllocatePages (Pages);

      //
      // Get System MemoryMap
      //
      Status = gBS->GetMemoryMap (
          &MemoryMapSize,
          MemoryMap,
          &MapKey,
          &DescriptorSize,
          &DescriptorVersion
          );
      // Don't do anything between the GetMemoryMap() and ExitBootServices()      
    }
    if (!EFI_ERROR (Status)) {
      Status = gBS->ExitBootServices (gImageHandle, MapKey);
      if (EFI_ERROR (Status) && MemoryMap != NULL) {
        FreePages (MemoryMap, Pages);
        MemoryMap = NULL;
        MemoryMapSize = 0;
        Pages = 0;
      }
    }
  } while (EFI_ERROR (Status));

  gMultibootInfo->efi_systab = (UINT32) (UINTN) gST;
  gMultibootInfo->efi_mmap = (UINT32) (UINTN) MemoryMap;
  gMultibootInfo->efi_mmap_size = (UINT32) (UINTN) MemoryMapSize;
  gMultibootInfo->efi_desc_size = (UINT32) (UINTN) DescriptorSize;

  //Clean and invalidate caches.
  WriteBackInvalidateDataCache();
  InvalidateInstructionCache();
  DEBUG((EFI_D_INFO, "Header:%x StartAddress:%x LoadAddress:%x Size:%x Entry%x\n",
        Header, 
        (UINT32) KernelLowAddress, 
        (UINT32) KernelLoadAddress, 
        (UINT32) Size, 
        (UINT32) KernelEntry
        ));
  BiosStartBeep();
  PrepareToStartOS(
      Header, 
      (UINT32) KernelLowAddress, 
      (UINT32) KernelLoadAddress, 
      (UINT32) Size, 
      (UINT32) KernelEntry
      );

OnError:
  return;  
}



EFI_STATUS
StartOSLinux( 
    MULTIBOOT_ENTRY      *Entry
    )
{
  UINTN                 MemoryMapSize;
  EFI_MEMORY_DESCRIPTOR *MemoryMap;
  UINTN                 MapKey;
  UINTN                 DescriptorSize;
  UINT32                DescriptorVersion;
  UINTN                 Pages;

  LIST_ENTRY           *ListEntry;
  CHAR8                AsciiStr[MULTIBOOT_MAX_STRING];
  EFI_PHYSICAL_ADDRESS Address;
  //MULTIBOOT_ENTRY      *Entry;
  MULTIBOOT_MODULE     *Module;
  MULTIBOOT_MODULE     *RamDisk;
  UINTN                Size;
  EFI_PHYSICAL_ADDRESS RamDiskAddress;
  UINTN                RamDiskSize;
  LINUX_HEADER         *LinuxHeader;
  LINUX_PARAMS         *LinuxParams;
  EFI_PHYSICAL_ADDRESS TmpPtr;
  UINTN                VideoColumns;
  UINTN                VideoRows;
  EFI_STATUS           Status;
  UINTN                SetupSize;
  UINTN                RealModeSize;
  UINTN                E820MapSize;
  UINT64               TotalPages;
  CHAR8*               CmdLine;
  UINTN                CmdLineLength;
  
  CmdLine = 0;
  CmdLineLength = 0;

  if(IsListEmpty(&Entry->ModuleHead)) {
    return EFI_INVALID_PARAMETER;
  }
  // Load Kernel
  ListEntry = Entry->ModuleHead.ForwardLink;
  Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry );

  DEBUG((EFI_D_INFO, "StartOSLinux: Module->DevPath=%s\n", Module->DevPath));

  StrnToAscii( Module->DevPath, AsciiStr, sizeof(AsciiStr) );
  
  Status = LoadModule(AsciiStr, &Address, &Size, Module->bHashPresent,
    Module->Hash, Module->GuidStr);

  if (EFI_ERROR(Status)) {
    return Status;
  }

  LinuxHeader = (LINUX_HEADER* ) (UINTN) Address;
  
  if(LinuxHeader->boot_flag != 0xAA55) {
    return EFI_INVALID_PARAMETER;
  }

  if(LinuxHeader->setup_sects > LINUX_MAX_SETUP_SECTORS) {
    return EFI_INVALID_PARAMETER;
  }

  if(LinuxHeader->header != LINUX_MAGIC_SIGNATURE ||
    LinuxHeader->version < 0x0203) {
    return EFI_INVALID_PARAMETER;
  }

  if(!(LinuxHeader->loadflags & LINUX_FLAG_BIG_KERNEL)) {
    return EFI_INVALID_PARAMETER;
  }

  SetupSize = LinuxHeader->setup_sects * 512;
  if( SetupSize == 0 ) {
    SetupSize = LINUX_DEFAULT_SETUP_SIZE;
  }

  TmpPtr = 0x10000;

  RealModeSize = LINUX_CL_END_OFFSET; 
  Status = gBS->AllocatePages (
        AllocateAddress,
        EfiLoaderData,
        EFI_SIZE_TO_PAGES(LINUX_CL_END_OFFSET),
        &TmpPtr );

	//EFI_ERROR_RET(Status, "");
  if (EFI_ERROR(Status)) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  LinuxParams =  (LINUX_PARAMS*) (UINTN) TmpPtr;
  DEBUG((EFI_D_INFO, "LinuxParams:%p\n", TmpPtr));

  ZeroMem(LinuxParams, LINUX_CL_END_OFFSET);
  CopyMem(
      &LinuxParams->setup_sects, 
      &(LinuxHeader->setup_sects), 
      sizeof (LINUX_HEADER) - 0x1F1
      );

  LinuxParams->ps_mouse = 0;
  LinuxParams->padding10 =  0;
  LinuxParams->type_of_loader = (LINUX_LOADER_ID_ELILO << 4);

  LinuxParams->cl_magic = LINUX_CL_MAGIC;
  LinuxParams->cl_offset = LINUX_CL_OFFSET;
  LinuxParams->cmd_line_ptr = ((UINT32) (UINTN) LinuxParams) + LINUX_CL_OFFSET;
  
  //  Load initrd

  ListEntry = Entry->ModuleHead.ForwardLink;

  if(ListEntry->ForwardLink != &Entry->ModuleHead) {
    ListEntry = ListEntry->ForwardLink; // Next module initrd
    RamDisk = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry );
    StrnToAscii( RamDisk->DevPath, AsciiStr, sizeof(AsciiStr) );
    Status = LoadModule( AsciiStr, &RamDiskAddress, &RamDiskSize,
      RamDisk->bHashPresent, RamDisk->Hash, RamDisk->GuidStr);

/*
    EFI_ERROR_RET(Status, "Load ramdisk ERROR\n");
*/
    if (EFI_ERROR(Status)) {
      return EFI_INVALID_PARAMETER;
    }

    DEBUG(( EFI_D_INFO, "Loaded ramdisk Path:%S Address:%llx Size:%p\n Status:%r\n", 
      RamDisk->DevPath, RamDiskAddress, RamDiskSize, Status ));
    
    LinuxParams->ramdisk_image = (UINT32) (UINTN) RamDiskAddress;
    LinuxParams->ramdisk_size =  (UINT32) RamDiskSize;

  } else {

    LinuxParams->ramdisk_image = 0;
    LinuxParams->ramdisk_size = 0;

  }

  LinuxParams->heap_end_ptr = LINUX_HEAP_END_OFFSET;
  LinuxParams->loadflags |= LINUX_FLAG_CAN_USE_HEAP;

  /* These are not needed to be precise, because Linux uses these values
    only to raise an error when the decompression code cannot find good
    space.  */
  LinuxParams->ext_mem = ((32 * 0x100000) >> 10);
  LinuxParams->alt_mem = ((32 * 0x100000) >> 10);

  LinuxParams->video_cursor_x = (UINT8) gST->ConOut->Mode->CursorColumn;
  LinuxParams->video_cursor_y = (UINT8) gST->ConOut->Mode->CursorRow;
  LinuxParams->video_page = 0; /* ??? */

  gST->ConOut->QueryMode(
      gST->ConOut, 
      gST->ConOut->Mode->Mode, 
      &VideoColumns, 
      &VideoRows
      );

  LinuxParams->video_mode  = (UINT8) gST->ConOut->Mode->Mode;
  LinuxParams->video_width = (UINT8) VideoColumns;
  LinuxParams->video_height = (UINT8) VideoRows;
  LinuxParams->video_ega_bx = 0;
  LinuxParams->have_vga = 0;
  LinuxParams->font_size = 16; /* XXX */

  TmpPtr = 0x100000;
  Size -= (SetupSize + 512);

  Status = gBS->AllocatePages (
        AllocateAddress,
        EfiLoaderData,
        EFI_SIZE_TO_PAGES(Size) + 1,
        &TmpPtr );

  if (EFI_ERROR(Status)) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem( 
      (VOID*) (UINTN) TmpPtr, 
      (VOID*) (UINTN) (Address + (SetupSize + 512)),
      Size
      );

  DEBUG(( EFI_D_INFO , "Linux Setup:%p [%llx, %p] \n", SetupSize + 512, TmpPtr, Size ));

  E820MapSize =  LINUX_E820_MAX_ENTRY;
  TotalPages = 0; 
  FillE820( &LinuxParams->e820_map[0], &E820MapSize, LinuxAddE820Entry, &TotalPages );

  LinuxParams->mmap_size = (UINT8) E820MapSize;
  CmdLineLength = LINUX_CL_END_OFFSET - LINUX_CL_OFFSET;

  if(StrLen(Module->Args)) {
    CmdLine = (CHAR8*) ((UINTN) LinuxParams) + LINUX_CL_OFFSET;
    StrnToAscii( Module->Args, CmdLine, CmdLineLength );
    UpdateKernelCmdLine(CmdLine, CmdLineLength);
    DEBUG((EFI_D_INFO, "CmdLine:%a\n", CmdLine));
  }

  MemoryMap = NULL;
  MemoryMapSize = 0;
  Pages = 0;
  do {
    Status = gBS->GetMemoryMap (
        &MemoryMapSize,
        MemoryMap,
        &MapKey,
        &DescriptorSize,
        &DescriptorVersion
        );

    if (Status == EFI_BUFFER_TOO_SMALL) {

      Pages = EFI_SIZE_TO_PAGES (MemoryMapSize) + 1;
      MemoryMap = AllocatePages (Pages);

      //
      // Get System MemoryMap
      //
      Status = gBS->GetMemoryMap (
          &MemoryMapSize,
          MemoryMap,
          &MapKey,
          &DescriptorSize,
          &DescriptorVersion
          );
      // Don't do anything between the GetMemoryMap() and ExitBootServices()      
    }
    if (!EFI_ERROR (Status)) {
      Status = gBS->ExitBootServices (gImageHandle, MapKey);
      if (EFI_ERROR (Status) && MemoryMap != NULL) {
        FreePages (MemoryMap, Pages);
        MemoryMap = NULL;
        MemoryMapSize = 0;
        Pages = 0;
      }
    }
  } while (EFI_ERROR (Status));

  if(LinuxParams->version >= 0x0206) {
    // It set to default IA32 arch. For X64 it make in StartLinuxKernel. 
    LinuxParams->efi.v0206.signature = LINUX_EFI_SIGNATURE32;
    LinuxParams->efi.v0206.system_table    = (UINT32) (UINTN) gST;
    LinuxParams->efi.v0206.system_table_hi = (UINT32) (((UINT64) (UINTN) gST) >> 32);

    LinuxParams->efi.v0206.mem_desc_size = (UINT32) DescriptorSize;
    LinuxParams->efi.v0206.mem_desc_version  = DescriptorVersion;
    LinuxParams->efi.v0206.mmap = (UINT32) (UINTN) MemoryMap;
    LinuxParams->efi.v0206.mmap_hi = (UINT32) (((UINT64) (UINTN) MemoryMap) >> 32);
    LinuxParams->efi.v0206.mmap_size = (UINT32) (UINTN) MemoryMapSize;
  } else 
    if (LinuxParams->version >= 0x0204) {
      LinuxParams->efi.v0204.signature = LINUX_EFI_SIGNATURE_0204; 
      LinuxParams->efi.v0204.system_table = (UINT32) (UINTN) gST;

      LinuxParams->efi.v0204.mem_desc_size = (UINT32) DescriptorSize;
      LinuxParams->efi.v0204.mem_desc_version  = DescriptorVersion;
      LinuxParams->efi.v0204.mmap = (UINT32) (UINTN) MemoryMap;
      LinuxParams->efi.v0204.mmap_size = (UINT32) (UINTN) MemoryMapSize;
    }

  BiosStartBeep();
  StartLinuxKernel( LinuxParams->code32_start, LinuxParams );
  return EFI_LOAD_ERROR;
}

EFI_STATUS
StartOSEfi( 
  IN MULTIBOOT_ENTRY *Entry
  )
{
  EFI_STATUS Status;
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  UINTN ExitDataSize;
  CHAR16 *ExitData, ShortName[5], *FullName;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if(IsListEmpty(&Entry->ModuleHead)) {
    DEBUG((EFI_D_ERROR, 
      "%a.%d Error! Default option is emty try to load from hdd!!!\n", 
      __FUNCTION__, __LINE__));

	MsgInfo(GetStringErrorOfLoadingOsEmpty());

    return EFI_INVALID_PARAMETER;
  }

  ListEntry = Entry->ModuleHead.ForwardLink;
  Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry );

  DEBUG((EFI_D_INFO, "StartOS EFI: Module->DevPath=%s\n", Module->DevPath));

  CopyMem(ShortName, Module->DevPath, 4 * sizeof(CHAR16));
  ShortName[4] = 0;
  DEBUG((EFI_D_INFO, "%a.%d ShortName=%s\n", __FUNCTION__, __LINE__, ShortName));
  FullName = FsDescTableGetFullName(ShortName);
  if (NULL == FullName) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  DevicePath = StrToDevicePath(FullName);

  if (IsLegacyBootDevPath(DevPathToString(DevicePath, FALSE, TRUE))) {
    SMART_CARD_PROTOCOL *pSmartCardProtocol;
    pSmartCardProtocol = TokenGetSmartCardProtocol();
    if (pSmartCardProtocol != NULL) {
      pSmartCardProtocol->EjectNotify = NULL;
      pSmartCardProtocol->EjectNotifyContext = NULL;
    }
  }
  SetBootEfiArgs (Module->Args);
  Status = BootEfi(MbImageHandle, DevicePath, Module->DevPath, 
    &ExitDataSize, &ExitData, 5);
  DEBUG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
StartOS( 
  IN MULTIBOOT_ENTRY *Entry
  )
{
  EFI_STATUS Status = EFI_LOAD_ERROR;

  //
  // Signal the EVT_SIGNAL_READY_TO_BOOT event
  //

  if (IsNeedAmt ()) {
    /* Reset WDT */
    gBS->SetWatchdogTimer (0, 0x0000, 0x00, NULL);    
    AmtHelper ();
  }

  BmSignalReadyToBoot ();

  if (IsNeedAmt ()) {
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }

  switch (Entry->Format) {
  case ModuleFormatLinux:
    BmCopyAcpi ();
    Status = StartOSLinux(Entry);
    break;

  case ModuleFormatMultibootAuto:
  case ModuleFormatMultibootBin:         // Multiboot kernel Binary
  case ModuleFormatMultibootElf32:
  case ModuleFormatMultibootElf64:
    BmCopyAcpi ();
    StartOSMultiboot(Entry);
    break;

  case ModuleFormatEfi:
    Status = StartOSEfi(Entry);
    break;

  default:
    MsgInfo(GetStringErrUnknownModuleFmt() /*STRING_TOKEN(STR_ERR_UNKNOWN_MODULE_FORMAT)*/);
    return EFI_INVALID_PARAMETER;
  }  

  DEBUG((EFI_D_INFO, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

static MULTIBOOT_DATA * 
InitMultiBootData(
  VOID
  )
{
  MULTIBOOT_DATA *Data;
  
  Data = AllocateZeroPool( sizeof(MULTIBOOT_DATA) );
  if(Data == NULL) {
    return NULL;
  }

  Data->Signature = MULTIBOOT_DATA_SIGNATURE;
  Data->Multiboot.SetModule = MultibootSetModule;
  Data->Multiboot.GetModule = MultibootGetModule;
  Data->Multiboot.RemoveModule = MultibootRemoveModule;
  Data->Multiboot.Start = MultibootStart;
  Data->DriverHandle = NULL;
  Data->Config.State = 0;
  
  InitializeListHead(&Data->Config.FormHead);
  gMultibootData = Data;
	
	if(gST->StdErr != NULL) {
		mOutput = gST->StdErr;
	} else 
		if(gST->ConOut != NULL) {
			mOutput = gST->ConOut;
		} else {
			ASSERT(0);
		} 
 
  return Data;
}

static VOID
FirmwareVersion(
  IN MULTIBOOT_CONFIG *Config
  )
{
  T_FIRMWARE_INFO FwInfo;
  BiosInfoRecord *pBiosInfo;
  EFI_GUID HwPlatformGuid;
  EFI_STATUS Status;

  FwInfo.FwVer = PcdGet32(PcdFwVersion);
  DEBUG((EFI_D_INFO, "%a.%d FwVer=%08X\n", 
    __FUNCTION__, __LINE__, FwInfo.FwVer));  
  if (-1 == FindMainFv(MAIN_FV_GUID_STR, &MainFvInfo)) {
    MsgInternalError(INT_ERR_INVALID_EXT_HEADER);
    return;
  }
  
  pBiosInfo = (BiosInfoRecord*)FindBiosInfoRecord(&MainFvInfo);
  if (NULL == pBiosInfo) {
    MsgInternalError(INT_ERR_BIOS_INFO_NOT_FOUND);
    return;
  }

  Status = StringToGuid_L(Config->PlatformGuidStr, &HwPlatformGuid);
  if (EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_HW_PLATFORM_GUID_NOT_FOUND);
    return;
  }

  if (CompareMem(&HwPlatformGuid, &pBiosInfo->PlatformGuid, sizeof(EFI_GUID))) {
    MsgInternalError(INT_ERR_WRONG_HW_PLATFORM_GUID);
    return;
  }

  CopyMem(&FwInfo.PlatformGuid, &pBiosInfo->PlatformGuid, sizeof(EFI_GUID));
  AsciiStrCpy(FwInfo.FwVerStr, pBiosInfo->BiosVerStr);
  AsciiStrCpy(FwInfo.FwBuildStr, pBiosInfo->BiosBuildStr);

  SetFirmwareInfo(&FwInfo);
}

STATIC
VOID
AddFsItemForXmlCfg(
  IN EFI_HANDLE ImageHandle
  )
{
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *pDp = NULL;
  CHAR16 *PathString = NULL;
  EFI_STATUS Status;

  //find newfv by label file
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  PcdHelperInit();
  if (gPcdHelperProtocol && 
      gPcdHelperProtocol->PcdGet32PcdNewFvSize(gPcdHelperProtocol) != 0) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = FindFileDpInVolume (PcdGetPtr(PcdNewFvLabel), &pDp, &PathString);
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    if (!EFI_ERROR(Status) && PathString != NULL && pDp != NULL) {
      //add newfv to fs mapping table
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      DEBUG(( EFI_D_INFO, "-*-> %S\n", PathString ));
      AddFsDescTableItem(L"newfv", PathString, FALSE);
      FreePool(PathString);
    }
  }

  //add mainfv to fs mapping table
  gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);
  
  pDp = DevicePathFromHandle(ImageInfo->DeviceHandle);
  PathString = DevicePathToStr(pDp);
  DEBUG(( EFI_D_ERROR, "-*-> %S\n", PathString ));
  AddFsDescTableItem(L"fv", PathString, FALSE);
  if (PathString != NULL) {
    FreePool(PathString);
  }
}  

EFI_STATUS
ResetSmartCard (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN                                 HandleCount;
  EFI_HANDLE                            *HandleBuffer;
  UINTN                                 Index;

  HandleBuffer  = NULL;
  HandleCount   = 0;

  Status = gBS->LocateHandleBuffer (
        ByProtocol,
        &gSmartCardReaderProtocolGuid,
        NULL,
        &HandleCount,
        &HandleBuffer
        );
  DEBUG ((EFI_D_INFO, "%a.%d Status = %r\n", 
      __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (HandleCount == 0 || HandleBuffer == NULL) {
    return EFI_ABORTED;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->DisconnectController (HandleBuffer[Index], NULL, NULL);
    DEBUG ((EFI_D_INFO, "%a.%d Status = %r\n", 
      __FUNCTION__, __LINE__, Status));
    Status = gBS->ConnectController (HandleBuffer[Index], NULL, NULL, FALSE);
    DEBUG ((EFI_D_INFO, "%a.%d Status = %r\n", 
      __FUNCTION__, __LINE__, Status));
  }
  
  return EFI_SUCCESS;
}

/**
  An empty function to pass error checking of CreateEventEx ().

  @param  Event                 Event whose notification function is being invoked.
  @param  Context               Pointer to the notification function's context,
                                which is implementation-dependent.

**/
VOID
EFIAPI
CoreEmptyEndOfDxeCallbackFunction (
  IN EFI_EVENT                Event,
  IN VOID                     *Context
  )
{
  return;
}



EFI_STATUS
EFIAPI
MultibootLoaderInit (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  )
{
  EFI_STATUS Status;
  MULTIBOOT_DATA *Data;
  MULTIBOOT_CONFIG *Config;
  MULTIBOOT_ENTRY *MbootDefaultEntry = NULL;
  EFI_GUID HwGuid;
  REMOTE_CFG_TLS_PROTOCOL *RCTP = NULL;

  Status = MultibootInstallFreePoolHook();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d MultibootInstallFreePoolHook(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    MsgInternalError(INT_ERR_CANT_INSTALL_MEMORY_HOOK);
  }
  
  DEBUG ((DEBUG_INFO | DEBUG_LOAD, "%a.%d\n", __FUNCTION__, __LINE__));
  HistorySetAddRecordQuietFlag (TRUE);
  HistoryAddRecord (
    HEVENT_MULTIBOOT_START,
    USER_UNKNOWN_ID, 
    SEVERITY_LVL_NOTICE,
    HISTORY_RECORD_FLAG_RESULT_OK);
  HistorySetAddRecordQuietFlag (FALSE);
  
  MbImageHandle = ImageHandle;
  
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  Data = InitMultiBootData();
  if (NULL == Data) {
    MsgInternalError(INT_ERR_INIT_MULTIBOOT_DATA_ERROR);
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mExitPmAuthProtocolHandle,
                  &gExitPmAuthProtocolGuid,
                  &mExitPmAuthProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Install gEfiDxeSmmReadyToLockProtocolGuid
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mSmmReadyToLockProtocolHandle,
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  &mSmmReadyToLockProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (AllocFsDescTable(10) == -1) {
    MsgInternalError(INT_ERR_ALLOC_FS_DESC_TABLE_ERROR);
  }
  
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
  /* Add item for loading xml config */
  AddFsItemForXmlCfg(ImageHandle);  

  Config = &gMultibootData->Config;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
  Status = LoadConfig(Config);
  if(EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_LOAD_XML_CONFIG);
  }
  
  Status = InitSetupEfiVar(Config->PlatformNameStr);
  if(EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_WHILE_INITIALIZE_SETUP_VAR);
  }
  DEBUG((EFI_D_INFO, "%a.%d Hwplatform: %a\n", __FUNCTION__, __LINE__, 
    Config->PlatformGuidStr));

  Status = StringToGuid_L(Config->PlatformGuidStr, &HwGuid);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    MsgInternalError(INT_ERR_INVALID_PLATFORM_CFG);
  }
  Status = SetSetupPlatformGuid(&HwGuid);
  if(EFI_ERROR(Status)) {
    MsgInternalError(INT_ERR_WHILE_INITIALIZE_SETUP_VAR);
  }

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
  MbootDefaultEntry = FindEntryByIndex(Config, Config->Default);
  InitFsDescTable(Config->DevDescStr);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
  CreateObjectsDescTable(Config->ObjDescStr);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
  CreatePciDaTable(Config->PciDaStr);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  FirmwareVersion(Config);

  GostHelperTest ();

    if (MbootDefaultEntry != NULL) {

        /* Extended timeout value for slow image reading */    
      gBS->SetWatchdogTimer (5 * 60, 0x0000, 0x00, NULL);    

      DEBUG((EFI_D_INFO, "StartOS()\n"));
      HistoryAddRecord(HEVENT_START_TO_LOAD_OS, GetCurrentUserId(),
          SEVERITY_LVL_INFO, HISTORY_RECORD_FLAG_RESULT_OK);

      if (RCTP != NULL) {
        Status = RCTP->Stop(RCTP);
        DEBUG ((EFI_D_INFO, "%a.%d RCTP->Stop: Status = %r\n", __FUNCTION__, __LINE__, Status));
      }

  MsgInternalError(INT_ERR_NO_DATA_FOR_LOAD);
  return EFI_SUCCESS;
}
