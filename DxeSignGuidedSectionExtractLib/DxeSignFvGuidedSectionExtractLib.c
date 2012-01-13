/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/** @file
 
**/

#include <PiPei.h>
#include <Library/GostHashLib.h> 
#include <Library/Md5.h> 
#include <Library/Crc32.h> 
#include <Library/sha.h>
#include <Guid/SignFvGuidedSectionExtraction.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/ExtractGuidedSectionLib.h>


enum CALC_CS_FLAGS {
  CALC_CS_UPDATE,
  CALC_CS_RESET = (1 << 1),
  CALC_CS_FINALIZE = (1 << 2)
};


#define EFI_SECITON_SIZE_MASK 0x00ffffff

///
/// Sign Guided Section header
///
#pragma pack(1)
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
#pragma pack()

typedef struct {
  EFI_GUID_DEFINED_SECTION  GuidedSectionHeader; ///< EFI guided section header
  UINT8                     Type;
  UINT8                     DataLen[3];
  UINT8                     SignData[32];
} SIGN_FV_SECTION_HEADER;



STATIC
VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  )
{
  UINTN i;

  for (i = 0; i < Len; i++) {
    if (i && !(i & 0xF)) {
      //DEBUG(( EFI_D_ERROR, "\n" ));
      //MsgDebugPrint("\n");
      DEBUG(( EFI_D_INFO, "\n"));
    }
    //DEBUG(( EFI_D_ERROR, "%02x ", Bytes[i] ));
    //MsgDebugPrint("%02x ", Bytes[i]);
    DEBUG(( EFI_D_INFO, "%02x ", Bytes[i]));
  }
  //DEBUG(( EFI_D_ERROR, "\n" ));
  //MsgDebugPrint("\n");
  DEBUG(( EFI_D_INFO, "\n"));
}


/**

  GetInfo gets raw data size and attribute of the input guided section.
  It first checks whether the input guid section is supported. 
  If not, EFI_INVALID_PARAMETER will return.

  @param InputSection       Buffer containing the input GUIDed section to be processed.
  @param OutputBufferSize   The size of OutputBuffer.
  @param ScratchBufferSize  The size of ScratchBuffer.
  @param SectionAttribute   The attribute of the input guided section.

  @retval EFI_SUCCESS            The size of destination buffer, the size of scratch buffer and 
                                 the attribute of the input section are successull retrieved.
  @retval EFI_INVALID_PARAMETER  The GUID in InputSection does not match this instance guid.

**/
EFI_STATUS
EFIAPI
SignFvGuidedSectionGetInfo (
  IN  CONST VOID  *InputSection,
  OUT UINT32      *OutputBufferSize,
  OUT UINT32      *ScratchBufferSize,
  OUT UINT16      *SectionAttribute
  )
{
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // Check whether the input guid section is recognized.
  //
  if (!CompareGuid (
        &gEfiSignFvGuidedSectionExtractionGuid, 
        &(((EFI_GUID_DEFINED_SECTION *) InputSection)->SectionDefinitionGuid))) {
    return EFI_INVALID_PARAMETER;
  }
  //
  // Retrieve the size and attribute of the input section data.
  //
  *SectionAttribute  = ((EFI_GUID_DEFINED_SECTION *) InputSection)->Attributes;
  *ScratchBufferSize = 0;
  *OutputBufferSize  = *(UINT32 *) (((EFI_COMMON_SECTION_HEADER *) InputSection)->Size) & EFI_SECITON_SIZE_MASK;
  *OutputBufferSize  -= ((EFI_GUID_DEFINED_SECTION *) InputSection)->DataOffset;

  return EFI_SUCCESS;
}

/**
  @param InputSection    Buffer containing the input GUIDed section to be processed.
  @param OutputBuffer    Buffer to contain the output raw data allocated by the caller.
  @param ScratchBuffer   A pointer to a caller-allocated buffer for function internal use.
  @param AuthenticationStatus A pointer to a caller-allocated UINT32 that indicates the
                              authentication status of the output buffer.

  @retval EFI_SUCCESS            Section Data and Auth Status is extracted successfully.
  @retval EFI_INVALID_PARAMETER  The GUID in InputSection does not match this instance guid.

**/
EFI_STATUS
EFIAPI
SignFvGuidedSectionHandler (
  IN CONST  VOID    *InputSection,
  OUT       VOID    **OutputBuffer,
  IN        VOID    *ScratchBuffer,        OPTIONAL
  OUT       UINT32  *AuthenticationStatus
  )
{
  EFI_STATUS                Status = EFI_SUCCESS;
  SIGN_FV_SECTION_HEADER    SignFvSectionHeader;
  UINT32                    OutputBufferSize;
  UINT8                     TestDigest[256];

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // Check whether the input guid section is recognized.
  //
  if (!CompareGuid (
        &gEfiSignFvGuidedSectionExtractionGuid, 
        &(((EFI_GUID_DEFINED_SECTION *) InputSection)->SectionDefinitionGuid))) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  //
  // Points to the SignFv section header
  //
  //SignFvSectionHeader = (SIGN_FV_SECTION_HEADER *) InputSection;
  CopyMem(&SignFvSectionHeader, InputSection, sizeof(SIGN_FV_SECTION_HEADER));
  DumpBytes((UINT8*)&SignFvSectionHeader, sizeof(SIGN_FV_SECTION_HEADER));
  *OutputBuffer      = (UINT8 *) InputSection + SignFvSectionHeader.GuidedSectionHeader.DataOffset;
  OutputBufferSize   = *(UINT32 *) (((EFI_COMMON_SECTION_HEADER *) InputSection)->Size) & EFI_SECITON_SIZE_MASK; 
  OutputBufferSize   -= SignFvSectionHeader.GuidedSectionHeader.DataOffset;
  //ASSERT (SignFvSectionHeader.GuidedSectionHeader.Attributes & EFI_GUIDED_SECTION_AUTH_STATUS_VALID);
  *AuthenticationStatus = EFI_AUTH_STATUS_IMAGE_SIGNED;

  DEBUG((EFI_D_INFO, "%a.%d Type=0x%X DataLen=%d\n", 
    __FUNCTION__, __LINE__, SignFvSectionHeader.Type, (*(UINT32*)SignFvSectionHeader.DataLen & 0xFFFFFF)));

  DEBUG((EFI_D_INFO, "%a.%d OutputBufferSize=%d\n", 
    __FUNCTION__, __LINE__, OutputBufferSize));
  //DumpBytes(*OutputBuffer, 32);
  //DumpBytes((UINT8*)*OutputBuffer + OutputBufferSize - 33, 32);
  //DumpBytes(*OutputBuffer, OutputBufferSize);
  ZeroMem(TestDigest, sizeof(TestDigest));


  if ((*(UINT32*)SignFvSectionHeader.DataLen & 0xFFFFFF) < 
      sizeof (EFI_COMMON_SECTION_HEADER)) {
    Status = EFI_CRC_ERROR;
  } 
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    *AuthenticationStatus |= EFI_AUTH_STATUS_NOT_TESTED;
  }

#if 0
  //
  // Check whether there exists EFI_SECURITY_POLICY_PROTOCOL_GUID.
  //
  Status = gBS->LocateProtocol (&gEfiSecurityPolicyProtocolGuid, NULL, &DummyInterface);
  if (!EFI_ERROR (Status)) {
    //
    // If SecurityPolicy Protocol exist, AUTH platform override bit is set.
    //
    *AuthenticationStatus |= EFI_AUTH_STATUS_PLATFORM_OVERRIDE;
  } else {
    
  }
#endif

  return EFI_SUCCESS;
}

/**
  Register the handler to extract SignFv guided section.

  @param  ImageHandle  ImageHandle of the loaded driver.
  @param  SystemTable  Pointer to the EFI System Table.

  @retval  EFI_SUCCESS            Register successfully.
  @retval  EFI_OUT_OF_RESOURCES   No enough memory to register this handler.
**/
RETURN_STATUS
EFIAPI
DxeSignFvGuidedSectionExtractLibConstructor (
#if 0
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
#else
  VOID
#endif
  )
{
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return ExtractGuidedSectionRegisterHandlers (
          &gEfiSignFvGuidedSectionExtractionGuid,
          SignFvGuidedSectionGetInfo,
          SignFvGuidedSectionHandler
          );
}

