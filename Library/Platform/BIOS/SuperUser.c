/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/SuperUser.h>
#include <Library/Lib/Users.h>


BOOLEAN
SuCheckName(
  IN CHAR8 *Name
  )
{
  return (AsciiStrCmp(Name, SU_NAME) == 0) ? TRUE : FALSE;
}


BOOLEAN
SuPassVarPresent(
  VOID
  )
{
  UINTN Size;
  EFI_STATUS Status;

  Size = 0;
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, NULL);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  return (Status != EFI_BUFFER_TOO_SMALL) ? FALSE : TRUE;
}

EFI_STATUS
SuGetHash(
  IN OUT UINT8 *Data
  )
{
  UINTN Size;
  EFI_STATUS Status;
  
  if (NULL == Data) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (!SuPassVarPresent()) {
    CopyMem(Data, SuDigest, sizeof(SuDigest));
    return EFI_SUCCESS;
  }
  
  Size = 0;
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, NULL);
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, Data);
  if (EFI_ERROR(Status)) {
    /* Show warning about corrupt password data */
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    CopyMem(Data, SuDigest, sizeof(SuDigest));
    return EFI_SUCCESS;
  }
  return Status;
}

static EFI_STATUS
SuCheckPass(
  IN CHAR8 *InputStr,
  IN UINTN InputStrLen
  )
{
  UINTN Size;
  EFI_STATUS Status;
  UINT8 DigestBuf[MAX_HASH_LEN];

  Size = 0;
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, NULL);
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, DigestBuf);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  Status = CalcHashCs(CS_TYPE_CRC32, InputStr, InputStrLen,
      CALC_CS_RESET | CALC_CS_FINALIZE, DigestBuf);
  if (EFI_SUCCESS != Status) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  return EFI_SUCCESS;
}


EFI_STATUS
SuVerify(
  IN CHAR8 *InputStr,
  IN UINTN InputStrLen
  )
{
  EFI_STATUS Status;
  
  if (!SuPassVarPresent()) {
    Status = CheckDataWithHash(CS_TYPE_CRC32, InputStr, InputStrLen, SuDigest);
  } else {
    Status = SuCheckPass(InputStr, InputStrLen);
  }
  DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
SuPassUpdate(
  IN CHAR8 *PassStr,
  IN UINTN PassStrLen
  )
{
  UINTN Size;
  EFI_STATUS Status;
  UINT8 DigestBuf[MAX_HASH_LEN];

  if (PassStr == NULL || PassStrLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
    
  Size = 0;
  Status = gRT->GetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
      NULL, &Size, NULL);

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }

  Status = CalcHashCs(CS_TYPE_CRC32, PassStr, PassStrLen,
    CALC_CS_RESET | CALC_CS_FINALIZE, DigestBuf);
  if (EFI_SUCCESS != Status) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = gRT->SetVariable(SU_PASS_VAR_NAME, &gSuPassVarGuid,
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS), 
    MAX_HASH_LEN, DigestBuf);

  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
