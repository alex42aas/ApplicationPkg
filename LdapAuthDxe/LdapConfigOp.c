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
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/LdapInterfaceLib/LdapInterfaceLib.h>
#include <TlsConfigStruct.h>
#include <arpa/inet.h>

#include <Protocol/LdapConfigOp.h>

#include <LdapCommon.h>

#include "LdapConfigInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

extern EFI_GUID gLdapClientConfigVarGuid;

STATIC LDAP_CLIENT_CONFIG currentLdapConfig = {VAR_VERSION, NOT_USE_LDAP_AUTH, L"", 389};

STATIC BOOLEAN readConf = FALSE;

STATIC UINTN GetSizeOfLdapConfig(const LDAP_CLIENT_CONFIG *ldapConfig);
STATIC VOID  FlushLdapConfig(LDAP_CLIENT_CONFIG *ldapConfig);
                                        
//------------------------------------------------------------------------------
/*! \brief Store ldap client config to the buffer */
/*! \param[out] *bufferToStore Pointer to the buffer to keep a config
    \param[in] *ldapConfig Pointer to the config to store to the buffer */
//------------------------------------------------------------------------------
STATIC
VOID
StoreLdapConfigToBuffer (
  OUT CHAR8 *bufferToStore,
  IN const LDAP_CLIENT_CONFIG *ldapConfig
)
{
  if (ldapConfig == NULL || bufferToStore == NULL)
    return;

  CopyMem(bufferToStore, &(ldapConfig->version), sizeof(ldapConfig->version));
  bufferToStore += sizeof(ldapConfig->version);
  
  CopyMem(bufferToStore, &(ldapConfig->usageFlag), sizeof(ldapConfig->usageFlag));
  bufferToStore += sizeof(ldapConfig->usageFlag);

  CopyMem(bufferToStore, ldapConfig->address, sizeof(ldapConfig->address));
  bufferToStore += sizeof(ldapConfig->address);
  
  CopyMem(bufferToStore, &(ldapConfig->port), sizeof(ldapConfig->port));
  bufferToStore += sizeof(ldapConfig->port);
  
  CopyMem(bufferToStore, &(ldapConfig->suffixLen), sizeof(ldapConfig->suffixLen));
  bufferToStore += sizeof(ldapConfig->suffixLen);
  if (ldapConfig->suffixLen > 0) {
    CopyMem(bufferToStore, ldapConfig->pSuffix[0], ldapConfig->suffixLen);
    bufferToStore += ldapConfig->suffixLen;
  }
  
  CopyMem(bufferToStore, &(ldapConfig->rootdnLen), sizeof(ldapConfig->rootdnLen));
  bufferToStore += sizeof(ldapConfig->rootdnLen);
  if (ldapConfig->rootdnLen > 0) {
    CopyMem(bufferToStore, ldapConfig->pRootdn[0], ldapConfig->rootdnLen);
    bufferToStore += ldapConfig->rootdnLen;
  }

  CopyMem(bufferToStore, &(ldapConfig->rootpwLen), sizeof(ldapConfig->rootpwLen));
  bufferToStore += sizeof(ldapConfig->rootpwLen);
  if (ldapConfig->rootpwLen > 0) {
    CopyMem(bufferToStore, ldapConfig->pRootpw[0], ldapConfig->rootpwLen);
    bufferToStore += ldapConfig->rootpwLen;
  }

  CopyMem(bufferToStore, &(ldapConfig->nameLen), sizeof(ldapConfig->nameLen));
  bufferToStore += sizeof(ldapConfig->nameLen);
  if (ldapConfig->nameLen > 0) {
    CopyMem(bufferToStore, ldapConfig->pName[0], ldapConfig->nameLen);
    bufferToStore += ldapConfig->nameLen;
  }

  CopyMem(bufferToStore, &(ldapConfig->pcBaseLen), sizeof(ldapConfig->pcBaseLen));
  bufferToStore += sizeof(ldapConfig->pcBaseLen);
  if (ldapConfig->pcBaseLen > 0)
    CopyMem(bufferToStore, ldapConfig->pcBase[0], ldapConfig->pcBaseLen);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Retrieve Ldap config version 1 */
/*! \param[out] *ldapConfig Pointer to the config V1
    \param[in] *bufferToStore Pointer to the buffer stores a config data */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
RetrieveLdapConfigV1 (
  OUT LDAP_CLIENT_CONFIG *ldapConfig,
  IN const CHAR8 *buffer
)
{
  CHAR16 *pBuf;

  CopyMem(&(ldapConfig->usageFlag), buffer, sizeof(ldapConfig->usageFlag));
  buffer += sizeof(ldapConfig->usageFlag);
  CopyMem(ldapConfig->address, buffer, sizeof(ldapConfig->address));
  buffer += sizeof(ldapConfig->address);
  CopyMem(&(ldapConfig->port), buffer, sizeof(ldapConfig->port));
  buffer += sizeof(ldapConfig->port);
  
  CopyMem(&(ldapConfig->suffixLen), buffer, sizeof(ldapConfig->suffixLen));
  buffer += sizeof(ldapConfig->suffixLen);
  
  if (ldapConfig->suffixLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->suffixLen);
    if (NULL == pBuf) {
      FlushLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pSuffix[0] = pBuf;

    CopyMem(ldapConfig->pSuffix[0], buffer, ldapConfig->suffixLen);
    buffer += ldapConfig->suffixLen;
  }
  
  CopyMem(&(ldapConfig->rootdnLen), buffer, sizeof(ldapConfig->rootdnLen));
  buffer += sizeof(ldapConfig->rootdnLen);
  
  if (ldapConfig->rootdnLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->rootdnLen);
    if (NULL == pBuf) {
      FlushLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pRootdn[0] = pBuf;

    CopyMem(ldapConfig->pRootdn[0], buffer, ldapConfig->rootdnLen);
    buffer += ldapConfig->rootdnLen;
  }
  
  CopyMem(&(ldapConfig->rootpwLen), buffer, sizeof(ldapConfig->rootpwLen));
  buffer += sizeof(ldapConfig->rootpwLen);
  
  if (ldapConfig->rootpwLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->rootpwLen);
    if (NULL == pBuf) {
      FlushLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pRootpw[0] = pBuf;

    CopyMem(ldapConfig->pRootpw[0], buffer, ldapConfig->rootpwLen);
    buffer += ldapConfig->rootpwLen;
  }
  
  CopyMem(&(ldapConfig->nameLen), buffer, sizeof(ldapConfig->nameLen));
  buffer += sizeof(ldapConfig->nameLen);
  
  if (ldapConfig->nameLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->nameLen);
    if (NULL == pBuf) {
      FlushLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pName[0] = pBuf;

    CopyMem(ldapConfig->pName[0], buffer, ldapConfig->nameLen);
    buffer += ldapConfig->nameLen;
  }

  CopyMem(&(ldapConfig->pcBaseLen), buffer, sizeof(ldapConfig->pcBaseLen));
  buffer += sizeof(ldapConfig->pcBaseLen);
  
  if (ldapConfig->pcBaseLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->pcBaseLen);
    if (NULL == pBuf) {
      FlushLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pcBase[0] = pBuf;

    CopyMem(ldapConfig->pcBase[0], buffer, ldapConfig->pcBaseLen);
  }
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Retrieve config from buffer */
/*! \param[out] *ldapConfig Pointer to the read config
    \param[in] *bufferToStore Pointer to the buffer stores a config data */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
RetrieveLdapConfigFromBuffer (
  OUT LDAP_CLIENT_CONFIG *ldapConfig,
  IN const CHAR8 *buffer
)
{
  EFI_STATUS Status;
  if (buffer == NULL || ldapConfig == NULL)
    return EFI_ABORTED;

  CopyMem(&(ldapConfig->version), buffer, sizeof(ldapConfig->version));
  buffer += sizeof(ldapConfig->version);

  switch(ldapConfig->version) {
    case 1:
      Status = RetrieveLdapConfigV1(ldapConfig, buffer);
      break;
    default:
      Status = EFI_UNSUPPORTED;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush ldap client config */
/*! Free all buffers, set all buffer's sizes to zero */
/*! \param[in] *ldapConfig Pointer to ldap client config */
//------------------------------------------------------------------------------
STATIC
VOID
FlushLdapConfig (
  IN LDAP_CLIENT_CONFIG *ldapConfig
)
{
  ldapConfig->version = VAR_VERSION;

  StrCpy(&ldapConfig->address[0], L"");
  
  if (ldapConfig->pSuffix[0] != NULL) {
    FreePool(ldapConfig->pSuffix[0]);
    ldapConfig->pSuffix[0] = NULL;
  }
  if (ldapConfig->pRootdn[0] != NULL) {
    FreePool(ldapConfig->pRootdn[0]);
    ldapConfig->pRootdn[0] = NULL;
  }
  if (ldapConfig->pRootpw[0] != NULL) {
    FreePool(ldapConfig->pRootpw[0]);
    ldapConfig->pRootpw[0] = NULL;
  }
  if (ldapConfig->pName[0] != NULL) {
    FreePool(ldapConfig->pName[0]);
    ldapConfig->pName[0] = NULL;
  }
  if (ldapConfig->pcBase[0] != NULL) {
    FreePool(ldapConfig->pcBase[0]);
    ldapConfig->pcBase[0] = NULL;
  }

  ldapConfig->suffixLen = 0;
  ldapConfig->rootpwLen = 0;
  ldapConfig->rootdnLen = 0;
  ldapConfig->nameLen   = 0;
  ldapConfig->pcBaseLen = 0;
  
  ldapConfig->usageFlag &= ~USE_TLS;
  
  readConf = FALSE;
  
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Erase buffers of a ldap server config data */
//------------------------------------------------------------------------------
VOID
DeleteLdapConfig (
  VOID
)
{
  FlushLdapConfig(&currentLdapConfig);
  
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! Get size of the ldap client config */
/*! \param[in] *ldapConfig A pointer to the config to calculate a length */
/*! \return a size of ldap client config in bytes. */
//------------------------------------------------------------------------------
STATIC
UINTN
GetSizeOfLdapConfig (
  IN const LDAP_CLIENT_CONFIG *ldapConfig
)
{
  UINTN Size = 0;
  
  Size = sizeof(ldapConfig->version) +sizeof(ldapConfig->usageFlag) +
         sizeof(ldapConfig->address) + sizeof(ldapConfig->port) + 
         sizeof(ldapConfig->suffixLen) + ldapConfig->suffixLen + 
         sizeof(ldapConfig->rootdnLen) + ldapConfig->rootdnLen + 
         sizeof(ldapConfig->rootpwLen) + ldapConfig->rootpwLen +
         sizeof(ldapConfig->nameLen) + ldapConfig->nameLen +
         sizeof(ldapConfig->pcBaseLen) + ldapConfig->pcBaseLen;

  return Size;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read ldap client config. If config isn't exist, create default config */
/*! \return Pointer to read data */
//------------------------------------------------------------------------------
LDAP_CLIENT_CONFIG*
ReadLdapClientConfig ( 
  VOID
)
{
  EFI_STATUS Status     = EFI_SUCCESS;
  UINTN      Size       = 0;
  CHAR8     *varBuffer = NULL;
  
  if (TRUE == readConf)
    return &currentLdapConfig;
  
  Status = gRT->GetVariable(
                  LDAP_CLIENT_CONFIG_VAR_NAME,
                  &gLdapClientConfigVarGuid,
                  NULL,
                  &Size,
                  NULL
                  );

  if (Status == EFI_NOT_FOUND) {
    Size = GetSizeOfLdapConfig((const LDAP_CLIENT_CONFIG*)&currentLdapConfig);
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
      LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    
    StoreLdapConfigToBuffer(varBuffer, &currentLdapConfig);

    Status = gRT->SetVariable (
                    LDAP_CLIENT_CONFIG_VAR_NAME,
                    &gLdapClientConfigVarGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                    Size,
                    varBuffer
                   );

    // Fill the config from INI file and save to flash
    // Don't check a result - if error, the config stays empty
    {
      CHAR8 Fname[255];
      AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdLDAPConfigFile));
      LOG((EFI_D_ERROR, "PcdLDAPConfigFile: %a \n", Fname));
      SetConfigFromINIFile(Fname);
    }
  } else {
    // Found config. Need to allocate buffer and read it.
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
      LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    
    Status = gRT->GetVariable(
        LDAP_CLIENT_CONFIG_VAR_NAME,
        &gLdapClientConfigVarGuid,
        NULL,
        &Size,
        varBuffer
        );
    if (Status == EFI_SUCCESS){
      FlushLdapConfig(&currentLdapConfig);
      Status = RetrieveLdapConfigFromBuffer(&currentLdapConfig, (const CHAR8*)varBuffer);
    }
  }
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));
    return NULL;
  }
  
  readConf = TRUE;
  
  return &currentLdapConfig;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Write ldap client config to the gRT variable */
/*! \param[in] *ldapConfig Pointer to the ldap client config to write */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
WriteLdapClientConfig (
  IN const LDAP_CLIENT_CONFIG *ldapConfig
)
{
  EFI_STATUS Status      = EFI_SUCCESS;
  UINTN      Size      = 0;
  CHAR8     *varBuffer;
  
  Size = GetSizeOfLdapConfig(ldapConfig);
  
  LOG((EFI_D_ERROR, "%a.%d: Size = %d\n", __FUNCTION__, __LINE__, Size));
  
  varBuffer = AllocateZeroPool(Size);
  if (NULL == varBuffer) {
    LOG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  StoreLdapConfigToBuffer(varBuffer, ldapConfig);
  
  Status = gRT->SetVariable(
                  LDAP_CLIENT_CONFIG_VAR_NAME,
                  &gLdapClientConfigVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  Size,
                  varBuffer
                  );
  if (Status != EFI_SUCCESS)
    LOG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap auth usage status */
/*! \return Value of a ldap auth usage setting */
//------------------------------------------------------------------------------
CHAR16
GetLdapAuthUsageStatus (
  VOID
)
{
  CHAR16 ldapUsageStatus;
  
  ReadLdapConfig();
  
  ldapUsageStatus = (currentLdapConfig.usageFlag & LDAP_USAGE_MASK);
  
  return ldapUsageStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a TLS usage status */
/*! \retval TRUE if TLS is used 
    \retval FALSE if TLS is not used */
//------------------------------------------------------------------------------
BOOLEAN
IsUseTLS(
  VOID
)
{
  CHAR16 tlsUsageStatus;
  
  ReadLdapConfig();
  
  tlsUsageStatus = (currentLdapConfig.usageFlag & TLS_USAGE_MASK);
  if (tlsUsageStatus == USE_TLS)
    return TRUE;
  else
    return FALSE;
}  
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read ldap server address */
/*! \return Pointer to the ldap server IP address in CHAR16 string */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapServerAddr(
  VOID
)
{
  ReadLdapConfig();
  
  return &currentLdapConfig.address[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length of a string, containes the ldap server IP address */
/*! \return Size of string, contains ldap server IP address */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapServerAddr(
  VOID
)
{
  ReadLdapConfig();
  
  return sizeof(currentLdapConfig.address);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap port value */
/*! \return Value of the ldap server port */
//------------------------------------------------------------------------------
CHAR16
GetLdapServerPort(
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.port;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get suffix (base) */
/*! \return  Pointer to the ldap suffix */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapSuffix(
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.pSuffix[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains suffix */
/*! \return length of a string, contains suffix */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapSuffix(
  VOID
)
{
  return currentLdapConfig.suffixLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get rootdn */
/*! \return  Pointer to the ldap rootdn */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapRootdn(
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.pRootdn[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains ldap rootdn */
/*! \return length of a string, contains ldap rootdn */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapRootdn( 
  VOID
)
{
  return currentLdapConfig.rootdnLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get rootpw */
/*! \return  Pointer to the ldap rootpw */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapRootpw( 
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.pRootpw[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains ldap rootpw */
/*! \return length of a string, contains ldap rootpw */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapRootpw( 
  VOID
)
{
  return currentLdapConfig.rootpwLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains ldap server name */
/*! \return length of a string, contains ldap server name */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapServerName(
  VOID
)
{
  return currentLdapConfig.nameLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ldap server name */
/*! \return  Pointer to the ldap server name */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapServerName(
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.pName[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ldap pc search base length */
/*! \return length of a string, contains ldap pc search base */
//------------------------------------------------------------------------------
UINTN
GetSizeOfLdapPCBase(
  VOID
)
{
  return currentLdapConfig.pcBaseLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ldap pc search base */
/*! \return  Pointer to the ldap pc search base */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapPCBase(
  VOID
)
{
  ReadLdapConfig();
  
  return currentLdapConfig.pcBase[0];
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Check a number of a ldap port */
/*! You can choose a number from registered range and dinamic range only */
/*! \return TRUE if number of a ldap port is valid, otherwise FALSE */
//------------------------------------------------------------------------------
BOOLEAN
IsValidPort(
  IN UINTN portNum
)
{
  /*if (portNum < MIN_PORT || portNum > MAX_PORT)
      return FALSE;
  else*/
  // No need to check, but will be in the future
  return TRUE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a ldap usage setting */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS if success 
    \retval EFI_INVALID_PARAMETER if incorrect setting */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapAuthUsageStatus ( 
  IN CHAR16 usageSetting
)
{
  if (USE_LDAP_AUTH == usageSetting)
    currentLdapConfig.usageFlag |= usageSetting;
  else if (NOT_USE_LDAP_AUTH == usageSetting)
    currentLdapConfig.usageFlag &= ~USE_LDAP_AUTH;
  else
    return EFI_INVALID_PARAMETER;
      
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a tls usage setting */
/*! \param[in] isUseTLS Use TLS or not */
//------------------------------------------------------------------------------
void
SetTLSUsage (
  IN BOOLEAN isUseTLS
)
{
  if (isUseTLS == TRUE)
    currentLdapConfig.usageFlag |= USE_TLS;
  else
    currentLdapConfig.usageFlag &= ~USE_TLS;
      
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a ldap port */
/*! \param[in] portNum number of a ldap port */
/*! \retunr Code Of Error*/
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapPort(
  IN UINTN portNum
)
{
  if (TRUE == IsValidPort(portNum)) {
    currentLdapConfig.port = (CHAR16)portNum;
    return EFI_SUCCESS;
  }
  else
    return EFI_INVALID_PARAMETER;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the rootdn */
/*! \param[in] *rootdn Pointer to a string, containes rootdn */
/*! \return Error Of Code */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapRootdn(
  IN CHAR16 *rootdn
)
{
  UINTN lenght = 0;

  if (currentLdapConfig.pRootdn[0] != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Try to free pRootdn %a\n", __FUNCTION__, __LINE__));
    currentLdapConfig.rootdnLen = 0;
    FreePool(currentLdapConfig.pRootdn[0]);
    currentLdapConfig.pRootdn[0] = NULL;
  }

  // if rootdn = "\0" or equal
  lenght = StrSize(rootdn);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentLdapConfig.rootdnLen = lenght;
  
  currentLdapConfig.pRootdn[0] = AllocateZeroPool(currentLdapConfig.rootdnLen);
  if (NULL == currentLdapConfig.pRootdn[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentLdapConfig.pRootdn[0],rootdn);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the rootpw */
/*! \param[in] *rootpw Pointer to a string, containes rootpw */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_OUT_OF_RESOURCES */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapRootpw(
  IN CHAR16 *rootpw
)
{
  UINTN lenght = 0;

  if (currentLdapConfig.pRootpw[0] != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Try to free pRootpw\n", __FUNCTION__, __LINE__));
    currentLdapConfig.rootpwLen = 0;
    FreePool(currentLdapConfig.pRootpw[0]);
    currentLdapConfig.pRootpw[0] = NULL;
  }

  // if rootpw = "\0" or equal
  lenght = StrSize(rootpw);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentLdapConfig.rootpwLen = lenght;
  
  currentLdapConfig.pRootpw[0] = AllocateZeroPool(currentLdapConfig.rootpwLen);
  if (NULL == currentLdapConfig.pRootpw[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentLdapConfig.pRootpw[0],rootpw);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the suffix */
/*! \param[in] *suffix Pointer to a string, containes suffix */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_OUT_OF_RESOURCES */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapSuffix(
  IN CHAR16 *suffix
)
{
  UINTN lenght = 0;

  if (currentLdapConfig.pSuffix[0] != NULL) {
    currentLdapConfig.suffixLen = 0;
    FreePool(currentLdapConfig.pSuffix[0]);
    currentLdapConfig.pSuffix[0] = NULL;
  }

  // if suffix = "\0" or equal
  lenght = StrSize(suffix);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentLdapConfig.suffixLen = lenght;

  currentLdapConfig.pSuffix[0] = AllocateZeroPool(currentLdapConfig.suffixLen);
  if (NULL == currentLdapConfig.pSuffix[0])
    return EFI_OUT_OF_RESOURCES;
      
  StrCpy(currentLdapConfig.pSuffix[0], suffix);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the ldap server name */
/*! \param[in] *name Pointer to a string, containes ldap server name */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_OUT_OF_RESOURCES */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapServerName(
  IN CHAR16 *name
)
{
  UINTN lenght = 0;

  if (currentLdapConfig.pName[0] != NULL) {
    currentLdapConfig.nameLen = 0;
    FreePool(currentLdapConfig.pName[0]);
    currentLdapConfig.pName[0] = NULL;
  }

  // if name = "\0" or equal
  lenght = StrSize(name);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentLdapConfig.nameLen = lenght;

  currentLdapConfig.pName[0] = AllocateZeroPool(currentLdapConfig.nameLen);
  if (NULL == currentLdapConfig.pName[0])
    return EFI_OUT_OF_RESOURCES;
      
  StrCpy(currentLdapConfig.pName[0], name);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new ldap server IP address */
/*! \param[in] *ipAddr Pointer to a string, containes ldap server IP address */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapServerAddr(
 IN CHAR16 *ipAddr
)
{
  CHAR8 addrC8[STRING_ADDR_LEN], resultAddr[STRING_ADDR_LEN];
  
  // Allow to delete IP and use serverName
  if (StrLen(ipAddr) == 0) {
    StrCpy(currentLdapConfig.address, ipAddr);
    return EFI_SUCCESS;
  }

  if (StrLen(ipAddr) <= STRING_ADDR_LEN) {
    UnicodeStrToAsciiStr(ipAddr, addrC8);
    LOG((EFI_D_ERROR, "%a.%d: addrC8: %a\n", __FUNCTION__, __LINE__, addrC8));
    if (1 == ldap_chk_addr(AF_INET, addrC8, resultAddr)) {
      StrCpy(currentLdapConfig.address, ipAddr);
      return EFI_SUCCESS;
    }
  }

  return EFI_INVALID_PARAMETER;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new ldap pc search base */
/*! \param[in] *ipAddr Pointer to a string, containes ldap pc search base */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapPCBase(
 IN CHAR16 *pcBase
)
{
  UINTN lenght = 0;

  if (currentLdapConfig.pcBase[0] != NULL) {
    currentLdapConfig.pcBaseLen= 0;
    FreePool(currentLdapConfig.pcBase[0]);
    currentLdapConfig.pcBase[0] = NULL;
  }

  // if name = "\0" or equal
  lenght = StrSize(pcBase);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentLdapConfig.pcBaseLen = lenght;

  currentLdapConfig.pcBase[0] = AllocateZeroPool(currentLdapConfig.pcBaseLen);
  if (NULL == currentLdapConfig.pcBase[0])
    return EFI_OUT_OF_RESOURCES;
      
  StrCpy(currentLdapConfig.pcBase[0], pcBase);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a data of openssl.cnf  and crl stack for TLS */
//------------------------------------------------------------------------------
EFI_STATUS
SetOpensslConfig (
  IN tlsConfig_t config
)
{
  if (ldap_set_tls_config(config) == 0)
    return EFI_SUCCESS;
  else
    return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save Ldap client config to the gRT */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
SaveLdapConfig(
  VOID
)
{
  if (NOT_USE_LDAP_AUTH == GetLdapAuthUsageStatus()) {
    // Flush config and than save empty config
    FlushLdapConfig(&currentLdapConfig);
  }
  
  return WriteLdapClientConfig(&currentLdapConfig);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read Ldap config to init internal private data */
/*! If you want to use ldap config data, you have to call this function first */
/*! \return Status of the read operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_LOAD_ERROR Can't read ldap config. See debug log for more details. */
//------------------------------------------------------------------------------
EFI_STATUS
ReadLdapConfig(
  VOID
)
{
  if (NULL == ReadLdapClientConfig())
    return EFI_LOAD_ERROR;
  else
    return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize Ldap Config Op structure */
/*! \param[in] *This Pointer to the operation structure */
//------------------------------------------------------------------------------
VOID
InitLdapConfigOp (
  IN LDAP_CONFIG_OP *This
)
{
  This->GetLdapServerPort       = GetLdapServerPort;
  This->GetLdapServerAddr       = GetLdapServerAddr;
  This->GetLdapServerName       = GetLdapServerName;
  This->GetLdapSuffix           = GetLdapSuffix;
  This->GetLdapRootdn           = GetLdapRootdn;
  This->GetLdapRootpw           = GetLdapRootpw;
  This->GetLdapPCBase           = GetLdapPCBase;

  This->GetSizeOfLdapServerAddr = GetSizeOfLdapServerAddr;
  This->GetSizeOfLdapServerName = GetSizeOfLdapServerName;
  This->GetSizeOfLdapSuffix     = GetSizeOfLdapSuffix;
  This->GetSizeOfLdapRootdn     = GetSizeOfLdapRootdn;
  This->GetSizeOfLdapRootpw     = GetSizeOfLdapRootpw;
  This->GetSizeOfLdapPCBase     = GetSizeOfLdapPCBase;

  This->SetLdapServerAddr       = SetLdapServerAddr;
  This->SetLdapServerName       = SetLdapServerName;
  This->SetLdapPort             = SetLdapPort;
  This->SetLdapSuffix           = SetLdapSuffix;
  This->SetLdapRootdn           = SetLdapRootdn;
  This->SetLdapRootpw           = SetLdapRootpw;
  This->SetLdapPCBase           = SetLdapPCBase;

  This->SaveLdapConfig          = SaveLdapConfig;
  This->ReadLdapConfig          = ReadLdapConfig;
  This->DeleteLdapConfig        = DeleteLdapConfig;
  
  This->GetLdapAuthUsageStatus  = GetLdapAuthUsageStatus;
  This->SetLdapAuthUsageStatus  = SetLdapAuthUsageStatus;
  
  This->IsUseTLS                = IsUseTLS;
  This->SetTLSUsage             = SetTLSUsage;
  
  This->SetOpensslConfig        = SetOpensslConfig;
  This->SetConfigFromINI        = SetConfigFromINIFile;
  This->SetConfigFromData       = SetConfigFromData;
  
  return;
}
//------------------------------------------------------------------------------
