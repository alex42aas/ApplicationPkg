/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include "RevokeChkConfigInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

extern EFI_GUID gRevokeChkConfVarGuid;

STATIC BOOLEAN readConf = FALSE;

STATIC REVOKE_CHECK_CONFIG currentConfig = {NOT_USE_REVOKE_CHECK, 0, NULL, 0, NULL};

STATIC
UINTN
GetSizeOfRevokeChkConfig (
  IN const REVOKE_CHECK_CONFIG *config
  );

STATIC
VOID
FlushRevokeChkConfig (
  IN REVOKE_CHECK_CONFIG *config
  );

STATIC
EFI_STATUS
SetCrlUsageFlag(
  IN UINT16 usageFlag
  );

STATIC
EFI_STATUS
SetAllCrlUsageFlag(
  IN UINT16 usageFlag
  );

STATIC
UINT16
GetCrlUsageFlag( 
  VOID
);

STATIC
UINT16
GetAllCrlUsageFlag( 
  VOID
);

STATIC
EFI_STATUS
SetTLSCrlUsageFlag(
  IN UINT16 usageFlag
);

STATIC
EFI_STATUS
SetAllTLSCrlUsageFlag(
  IN UINT16 usageFlag
);


VOID
ResetReadRevokeChkConfig (
  VOID
  )
{
  readConf = FALSE;
}

//------------------------------------------------------------------------------
/*! \brief Reset config to default values */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeDefaultConfig (
  IN OUT REVOKE_CHECK_CONFIG *config
  )
{
  FlushRevokeChkConfig(config);

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Store the Revoke Check Config to the buffer */
/*! \param[in] *config Pointer to the config to store to the buffer
    \param[out] *bufferToStore Pointer to the buffer to keep a config */
//------------------------------------------------------------------------------
STATIC
VOID
StoreRevokeChkConfigToBuffer (
  IN const REVOKE_CHECK_CONFIG *config,
  OUT CHAR8 *bufferToStore
  )
{
  if (config == NULL || bufferToStore == NULL)
    return;

  CopyMem(bufferToStore, &(config->usageFlag), sizeof(config->usageFlag));
  bufferToStore += sizeof(config->usageFlag);

  CopyMem(bufferToStore, &(config->urlOcspLen), sizeof(config->urlOcspLen));
  bufferToStore += sizeof(config->urlOcspLen);
  if (config->urlOcspLen > 0) {
    CopyMem(bufferToStore, config->pOcspUrl[0], config->urlOcspLen);
    bufferToStore += config->urlOcspLen;
  }

  CopyMem(bufferToStore, &(config->urlCdpLen), sizeof(config->urlCdpLen));
  bufferToStore += sizeof(config->urlCdpLen);
  if (config->urlCdpLen > 0) {
    CopyMem(bufferToStore, config->pCdpUrl[0], config->urlCdpLen);
    bufferToStore += config->urlCdpLen;
  }

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Retrieve config from buffer */
/*! \param[in] *bufferToStore Pointer to the buffer stores a config data 
    \param[out] *config Pointer to the read config */
/*! \return Code Of Error */
/*! \retval EFI_OUT_OF_RESOURCES
    \retval EFI_SUCCESS */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
RetrieveRevokeChkConfigFromBuffer (
  IN const CHAR8 *buffer,
  OUT REVOKE_CHECK_CONFIG *config
  )
{
  CHAR16 *pBuf;

  CopyMem(&(config->usageFlag), buffer, sizeof(config->usageFlag));
  buffer += sizeof(config->usageFlag);

  CopyMem(&(config->urlOcspLen), buffer, sizeof(config->urlOcspLen));
  buffer += sizeof(config->urlOcspLen);

  if (config->urlOcspLen > 0) {
    pBuf = AllocateZeroPool(config->urlOcspLen);
    if (NULL == pBuf) {
      FlushRevokeChkConfig(config);
      return EFI_OUT_OF_RESOURCES;
    }
    config->pOcspUrl[0] = pBuf;

    CopyMem(config->pOcspUrl[0], buffer, config->urlOcspLen);
    buffer += config->urlOcspLen;
  }

  CopyMem(&(config->urlCdpLen), buffer, sizeof(config->urlCdpLen));
  buffer += sizeof(config->urlCdpLen);

  if (config->urlCdpLen > 0) {
    pBuf = AllocateZeroPool(config->urlCdpLen);
    if (NULL == pBuf) {
      FlushRevokeChkConfig(config);
      return EFI_OUT_OF_RESOURCES;
    }
    config->pCdpUrl[0] = pBuf;

    CopyMem(config->pCdpUrl[0], buffer, config->urlCdpLen);
    buffer += config->urlCdpLen;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush Revoke Check Config */
/*! Free all buffers, set all buffer's sizes to zero */
/*! \param[in] *config Pointer to Revoke check config */
//------------------------------------------------------------------------------
STATIC
VOID
FlushRevokeChkConfig (
  IN REVOKE_CHECK_CONFIG *config
  )
{
  if (config->pOcspUrl[0] != NULL) {
      FreePool(config->pOcspUrl[0]);
      config->pOcspUrl[0] = NULL;
  }
  if (config->pCdpUrl[0] != NULL) {
      FreePool(config->pCdpUrl[0]);
      config->pCdpUrl[0] = NULL;
  }

  config->urlOcspLen = 0;
  config->urlCdpLen  = 0;

  config->usageFlag = NOT_USE_REVOKE_CHECK;

  readConf = FALSE;

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get size of the Revoke Check Config */
/*! \param[in] config A config of Revoke check */
/*! \return A size of the Revoke check config in bytes. */
//------------------------------------------------------------------------------
STATIC
UINTN
GetSizeOfRevokeChkConfig (
  IN const REVOKE_CHECK_CONFIG *config
  )
{
  UINTN     Size = 0;

  Size = sizeof(config->usageFlag) +
         sizeof(config->urlOcspLen) + config->urlOcspLen +
         sizeof(config->urlCdpLen) + config->urlCdpLen;

  return Size;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read Revoke Check Config from the NVRAM */
/*! \return Status of an operaton */
/*! \retval EFI_SUCCESS Config has been read from NVRAM
    \retval EFI_OUT_OF_RESOURCES Can't allocate memory for the config
    \retval EFI_ABORTED Can't read the config form NVRAM. See debug log for details. */
//------------------------------------------------------------------------------
EFI_STATUS
ReadRevokeChkConfig (
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINTN      Size       = 0;
  CHAR8     *varBuffer = NULL;

  LOG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));

  if (TRUE == readConf) {
    LOG((EFI_D_ERROR, "%a.%d: No need to read the config.\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }

  Status = gRT->GetVariable(
                  REVOKE_CHECK_CONFIG_VAR_NAME,
                  &gRevokeChkConfVarGuid,
                  NULL,
                  &Size,
                  NULL
                  );
  if (Status == EFI_NOT_FOUND) {
    MakeDefaultConfig(&currentConfig);
    Size = GetSizeOfRevokeChkConfig((const REVOKE_CHECK_CONFIG*)&currentConfig);
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
        LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
    }
    StoreRevokeChkConfigToBuffer(&currentConfig, varBuffer);

    Status = gRT->SetVariable (
                    REVOKE_CHECK_CONFIG_VAR_NAME,
                    &gRevokeChkConfVarGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                    Size,
                    varBuffer
                    );
    // Fill the config from INI file and save to flash
    // Don't check a result - if error, the config stays empty
    {
      CHAR8 Fname[255];
      AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdRevokeChkConfigFile));
      LOG((EFI_D_ERROR, "PcdRevokeChkConfigFile: %a \n", Fname));
      SetConfigFromINIFile(Fname);
    }

  } else {
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
        LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
    }
    
    Status = gRT->GetVariable(
                    REVOKE_CHECK_CONFIG_VAR_NAME,
                    &gRevokeChkConfVarGuid,
                    NULL,
                    &Size,
                    varBuffer
                    );
                    
    if (Status == EFI_SUCCESS){
      FlushRevokeChkConfig(&currentConfig);
      Status = RetrieveRevokeChkConfigFromBuffer((const CHAR8*)varBuffer, &currentConfig);
    }
  }
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: EFI_STATUS = %d\n", __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  }

  readConf = TRUE;

  LOG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Erase buffers of the Revoke Check Config data */
//------------------------------------------------------------------------------
VOID
DeleteRevokeChkConfig (
  VOID
  )
{
  FlushRevokeChkConfig(&currentConfig);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a OCSP usage status */
/*! \return Value of a OCSP usage setting */
//------------------------------------------------------------------------------
UINT16
GetOcspUsageFlag( 
  VOID
)
{
  UINT16 ocspUsageFlag;

  ReadRevokeChkConfig();

  ocspUsageFlag = (currentConfig.usageFlag & OCSP_USAGE_MASK);

  return ocspUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get OCSP URL */
/*! \return A pointer to the OCSP URL string */
//------------------------------------------------------------------------------
CHAR16*
GetOcspUrl(
  VOID
)
{
  ReadRevokeChkConfig();

  return currentConfig.pOcspUrl[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a lenght of the OCSP Url string */
/*! \retval A lenght oa the OCSP Url string */
//------------------------------------------------------------------------------
UINTN
GetOcspUrlLenght(
  VOID
)
{
  ReadRevokeChkConfig();

  return currentConfig.urlOcspLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a Local CDP usage status */
/*! \return Value of a Local CDP usage setting */
//------------------------------------------------------------------------------
UINT16
GetLocalCdpUsageFlag( 
  VOID
)
{
  UINT16 localCdpUsageFlag;

  ReadRevokeChkConfig();

  localCdpUsageFlag = (currentConfig.usageFlag & LOCAL_CDP_USAGE_MASK) >> USE_LOCAL_CDP_OFFSET;

  return localCdpUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get Local CDP URL */
/*! \return A pointer to the CDP CRL URL string */
//------------------------------------------------------------------------------
CHAR16*
GetLocalCdpUrl(
  VOID
)
{
  ReadRevokeChkConfig();

  return currentConfig.pCdpUrl[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a lenght of the Local CDP Url string */
/*! \retval A lenght oa the Local CDP Url string */
//------------------------------------------------------------------------------
UINTN
GetLocalCdpUrlLenght(
  VOID
)
{
  ReadRevokeChkConfig();

  return currentConfig.urlCdpLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a CRL Check mode */
/*! \return Value of a CRL Check mode */
//------------------------------------------------------------------------------
UINT16
GetCrlCheckMode( 
  VOID
)
{
  UINT16 crlUsageFlag;

  ReadRevokeChkConfig();

  crlUsageFlag = (currentConfig.usageFlag & CRL_ALL_USAGE_MASK) >> USE_CRL_ALL_OFFSET;
  if (crlUsageFlag == USE)
    return ALL_CRL_CHECK;

  crlUsageFlag = (currentConfig.usageFlag & CRL_USAGE_MASK) >> USE_CRL_OFFSET;
  if (crlUsageFlag == USE)
    return CRL_CHECK;

  return DONT_CHECK_CRL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get TLS CRL Check mode */
/*! \return Value of TLS CRL Check mode */
//------------------------------------------------------------------------------
UINT16
GetTLSCrlCheckMode( 
  VOID
)
{
  UINT16 crlUsageFlag;

  ReadRevokeChkConfig();

  crlUsageFlag = (currentConfig.usageFlag & TLS_ALL_CRL_MASK) >> USE_TLS_ALL_CRL_OFFSET;
  if (crlUsageFlag == USE)
    return ALL_CRL_CHECK;

  crlUsageFlag = (currentConfig.usageFlag & TLS_PEER_CRL_MASK) >> USE_TLS_PEER_CRL_OFFSET;
  if (crlUsageFlag == USE)
    return CRL_CHECK;

  return DONT_CHECK_CRL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CDP Cashe usage status */
//------------------------------------------------------------------------------
UINT16
GetCDPCasheUsageFlag(
  VOID
)
{
  UINT16 CDPCasheUsageFlag;

  ReadRevokeChkConfig();

  CDPCasheUsageFlag = (currentConfig.usageFlag & CDP_CASHE_ENABLE_MASK) >> USE_CDP_CASHE_OFFSET;

  return CDPCasheUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get OCSP response verify */
//------------------------------------------------------------------------------
UINT16
GetOCSPResponceVerifyUsageFlag(
  VOID
)
{
  UINT16 OCSPResponceVerifyUsageFlag;

  ReadRevokeChkConfig();

  OCSPResponceVerifyUsageFlag = (currentConfig.usageFlag & OCSP_RSP_VERIFY_MASK) >> USE_OCSP_RSP_VER_OFFSET;

  return OCSPResponceVerifyUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CDP from certificate usage status */
//------------------------------------------------------------------------------
UINT16
GetCDPfromCertUsageFlag(
  VOID
)
{
  UINT16 CDPfromCertUsageFlag;

  ReadRevokeChkConfig();

  CDPfromCertUsageFlag = (currentConfig.usageFlag & CDP_FROM_CERT_MASK) >> USE_CDP_FROM_CERT_OFFSET;

  return CDPfromCertUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the OCSP usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetOcspUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= usageFlag;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~OCSP_USAGE_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the OCSP Url string */
/*! \param[in] *utlStr Pointer to a string, containes OCSP Url */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_OUT_OF_RESOURCES Allocate memory error
    \retval EFI_INVALID_PARAMETER Pass a NULL param */
//------------------------------------------------------------------------------
EFI_STATUS
SetOcspUrl(
  IN CHAR16* utlStr
)
{
  UINTN lenght = 0;

  if (utlStr == NULL)
    return EFI_INVALID_PARAMETER;

  if (currentConfig.pOcspUrl[0] != NULL) {
    currentConfig.urlOcspLen = 0;
    FreePool(currentConfig.pOcspUrl[0]);
    currentConfig.pOcspUrl[0] = NULL;
  }

  // if utlStr = "\0" or equal
  lenght = StrSize(utlStr);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentConfig.urlOcspLen = lenght;

  currentConfig.pOcspUrl[0] = AllocateZeroPool(currentConfig.urlOcspLen);
  if (NULL == currentConfig.pOcspUrl[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentConfig.pOcspUrl[0], utlStr);

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the Local CDP usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetLocalCdpUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= LOCAL_CDP_USAGE_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~LOCAL_CDP_USAGE_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the Local CDP Url string */
/*! \param[in] *utlStr Pointer to a string, containes Url */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_OUT_OF_RESOURCES Allocate memory error
    \retval EFI_INVALID_PARAMETER Pass a NULL param */
//------------------------------------------------------------------------------
EFI_STATUS
SetLocalCdpUrl(
  IN CHAR16* urlStr
)
{
  UINTN lenght = 0;

  if (urlStr == NULL)
    return EFI_INVALID_PARAMETER;

  if (currentConfig.pCdpUrl[0] != NULL) {
    currentConfig.urlCdpLen = 0;
    FreePool(currentConfig.pCdpUrl[0]);
    currentConfig.pCdpUrl[0] = NULL;
  }

  // if urlStr = "\0" or equal
  lenght = StrSize(urlStr);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentConfig.urlCdpLen = lenght;

  currentConfig.pCdpUrl[0] = AllocateZeroPool(currentConfig.urlCdpLen);
  if (NULL == currentConfig.pCdpUrl[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentConfig.pCdpUrl[0], urlStr);

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the CRL Check mode */
/*! \retval EFI_INVALID_PARAMETER Value is unsupported 
    \retval EFI_SUCCESS Mode is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetCrlCheckMode(
  IN UINT16 crlMode
)
{
  if (DONT_CHECK_CRL == crlMode) {
    SetCrlUsageFlag(NOT_USE);
    SetAllCrlUsageFlag(NOT_USE);
  } else if (ALL_CRL_CHECK == crlMode) {
    SetCrlUsageFlag(NOT_USE);
    SetAllCrlUsageFlag(USE);
  } else if (CRL_CHECK == crlMode) {
    SetCrlUsageFlag(USE);
    SetAllCrlUsageFlag(NOT_USE);
  } else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the TLS CRL Check mode */
/*! \retval EFI_INVALID_PARAMETER Value is unsupported 
    \retval EFI_SUCCESS Mode is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetTLSCrlCheckMode(
  IN UINT16 crlMode
)
{
  if (DONT_CHECK_CRL == crlMode) {
    SetTLSCrlUsageFlag(NOT_USE);
    SetAllTLSCrlUsageFlag(NOT_USE);
  } else if (ALL_CRL_CHECK == crlMode) {
    SetTLSCrlUsageFlag(NOT_USE);
    SetAllTLSCrlUsageFlag(USE);
  } else if (CRL_CHECK == crlMode) {
    SetTLSCrlUsageFlag(USE);
    SetAllTLSCrlUsageFlag(NOT_USE);
  } else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the CRL Check usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetCrlUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= CRL_USAGE_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~CRL_USAGE_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the TLS CRL Check usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetTLSCrlUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= TLS_PEER_CRL_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~TLS_PEER_CRL_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the All CRL Check usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetAllCrlUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= CRL_ALL_USAGE_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~CRL_ALL_USAGE_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the All TLS CRL Check usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported 
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetAllTLSCrlUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= TLS_ALL_CRL_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~TLS_ALL_CRL_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the CDP Cashe usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetCDPCasheUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= CDP_CASHE_ENABLE_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~CDP_CASHE_ENABLE_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set OCSP response verify usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetOCSPResponceVerifyUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= OCSP_RSP_VERIFY_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~OCSP_RSP_VERIFY_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set CDP from certificate usage flag */
/*! \retval EFI_INVALID_PARAMETER Value of flag is unsupported
    \retval EFI_SUCCESS Flag is succefully set */
//------------------------------------------------------------------------------
EFI_STATUS
SetCDPfromCertUsageFlag(
  IN UINT16 usageFlag
)
{
  if (USE == usageFlag)
    currentConfig.usageFlag |= CDP_FROM_CERT_MASK;
  else if (NOT_USE == usageFlag)
    currentConfig.usageFlag &= ~CDP_FROM_CERT_MASK;
  else
    return EFI_INVALID_PARAMETER;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free OcspUrl string */
//------------------------------------------------------------------------------
STATIC
VOID
DeleteOcspUrl (
  VOID
)
{
  if (currentConfig.pOcspUrl[0] != NULL) {
      FreePool(currentConfig.pOcspUrl[0]);
      currentConfig.pOcspUrl[0] = NULL;
  }

  currentConfig.urlOcspLen = 0;

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free LocalCdpUrl string */
//------------------------------------------------------------------------------
STATIC
VOID
DeleteLocalCdpUrl (
  VOID
)
{
  if (currentConfig.pCdpUrl[0] != NULL) {
      FreePool(currentConfig.pCdpUrl[0]);
      currentConfig.pCdpUrl[0] = NULL;
  }

  currentConfig.urlCdpLen = 0;

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete a data has been entered and has been unselected and check */
/*! \retval EFI_SUCCESS Success 
    \retval EFI_UNSUPPORTED Unsupported setting: One of url's strings is empty */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
PrepareConfigToSaveAndCheck (
  VOID
  )
{
  if (GetOcspUsageFlag() == USE) {
    if (GetOcspUrl() == NULL)
      return EFI_UNSUPPORTED;
  }
  if (GetLocalCdpUsageFlag() == USE && GetCDPfromCertUsageFlag() == NOT_USE) {
    if (GetLocalCdpUrl() == NULL)
      return EFI_UNSUPPORTED;
  }

  if (GetOcspUsageFlag() == NOT_USE) {
    DeleteOcspUrl();
    SetOCSPResponceVerifyUsageFlag(NOT_USE);
  }
  if (GetLocalCdpUsageFlag() == NOT_USE) {
    DeleteLocalCdpUrl();
    SetCDPCasheUsageFlag(NOT_USE);
    SetCDPfromCertUsageFlag(NOT_USE);
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save ocsp config to the NVRAM */
/*! \return Status of an operation. See debug log for more details */
//------------------------------------------------------------------------------
EFI_STATUS
SaveRevokeChkConfig (
  VOID
  )
{
  EFI_STATUS Status    = EFI_SUCCESS;
  UINTN      Size      = 0;
  CHAR8     *varBuffer;
  
  LOG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  if (GetOcspUsageFlag() == NOT_USE &&
      GetLocalCdpUsageFlag() == NOT_USE &&
      GetCrlCheckMode() == DONT_CHECK_CRL &&
      GetTLSCrlCheckMode() == DONT_CHECK_CRL) {
    DeleteRevokeChkConfig();
  } else {
    Status = PrepareConfigToSaveAndCheck();
    if (Status != EFI_SUCCESS)
      return Status;
  }
  
  Size = GetSizeOfRevokeChkConfig((const REVOKE_CHECK_CONFIG*)&currentConfig);
  
  LOG((EFI_D_ERROR, "%a.%d: Size = %d\n", __FUNCTION__, __LINE__, Size));
  
  varBuffer = AllocateZeroPool(Size);
  if (NULL == varBuffer) {
    LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  StoreRevokeChkConfigToBuffer(&currentConfig, varBuffer);

  Status = gRT->SetVariable(
                  REVOKE_CHECK_CONFIG_VAR_NAME,
                  &gRevokeChkConfVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  Size,
                  varBuffer
                  );
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  LOG((EFI_D_ERROR, "%a.%d: Status = %d\n", __FUNCTION__, __LINE__, Status));
  
  return Status;
}
//------------------------------------------------------------------------------

