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
#include <LdapCommon.h>
#include <TlsConfigStruct.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PcdLib.h>
#include <Library/LdapInterfaceLib/LdapInterfaceLib.h>

#include <Library/CDPSupportLib/CDPInternal.h>

#include "CDPLdapConfig.h"

extern EFI_GUID gCDPLdapConfigVarGuid;

static BOOLEAN readConf = FALSE;

static CDP_LDAP_CONFIG currentCDPLdapConfig = {VAR_VERSION, L"", 389};

static
VOID
FlushCDPLdapConfig (
  IN CDP_LDAP_CONFIG *ldapConfig
);

//------------------------------------------------------------------------------
/*! \brief Retrieve CDP Ldap config version 1 */
/*! \param[out] *ldapConfig Pointer to the config V1
    \param[in] *bufferToStore Pointer to the buffer stores a config data */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
static
EFI_STATUS
RetrieveCDPLdapConfigV1 (
  OUT CDP_LDAP_CONFIG *ldapConfig,
  IN const CHAR8 *buffer
)
{
  CHAR16 *pBuf;

  CopyMem(ldapConfig->address, buffer, sizeof(ldapConfig->address));
  buffer += sizeof(ldapConfig->address);
  CopyMem(&(ldapConfig->port), buffer, sizeof(ldapConfig->port));
  buffer += sizeof(ldapConfig->port);
  
  CopyMem(&(ldapConfig->suffixLen), buffer, sizeof(ldapConfig->suffixLen));
  buffer += sizeof(ldapConfig->suffixLen);
  
  if (ldapConfig->suffixLen > 0) {
    pBuf = AllocateZeroPool(ldapConfig->suffixLen);
    if (NULL == pBuf) {
      FlushCDPLdapConfig(ldapConfig);
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
      FlushCDPLdapConfig(ldapConfig);
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
      FlushCDPLdapConfig(ldapConfig);
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
      FlushCDPLdapConfig(ldapConfig);
      return EFI_OUT_OF_RESOURCES;
    }
    ldapConfig->pName[0] = pBuf;

    CopyMem(ldapConfig->pName[0], buffer, ldapConfig->nameLen);
    buffer += ldapConfig->nameLen;
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
static
EFI_STATUS
RetrieveCDPLdapConfigFromBuffer (
  OUT CDP_LDAP_CONFIG *ldapConfig,
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
      Status = RetrieveCDPLdapConfigV1(ldapConfig, buffer);
      break;
    default:
      Status = EFI_UNSUPPORTED;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush CDP ldap config */
/*! Free all buffers, set all buffer's sizes to zero */
/*! \param[in] *ldapConfig Pointer to CDP ldap config */
//------------------------------------------------------------------------------
static
VOID
FlushCDPLdapConfig (
  IN CDP_LDAP_CONFIG *ldapConfig
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

  ldapConfig->suffixLen = 0;
  ldapConfig->rootpwLen = 0;
  ldapConfig->rootdnLen = 0;
  ldapConfig->nameLen   = 0;
  
  readConf = FALSE;
  
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Store CDP ldap config to the buffer */
/*! \param[out] *bufferToStore Pointer to the buffer to keep a config
    \param[in] *ldapConfig Pointer to the config to store to the buffer */
//------------------------------------------------------------------------------
static
VOID
StoreCDPLdapConfigToBuffer (
  OUT CHAR8 *bufferToStore,
  IN const CDP_LDAP_CONFIG *ldapConfig
)
{
  if (ldapConfig == NULL || bufferToStore == NULL)
    return;

  CopyMem(bufferToStore, &(ldapConfig->version), sizeof(ldapConfig->version));
  bufferToStore += sizeof(ldapConfig->version);
  
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

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! Get size of the CDP ldap config */
/*! \param[in] *ldapConfig A pointer to the config to calculate a length */
/*! \return a size of CDP ldap config in bytes. */
//------------------------------------------------------------------------------
static
UINTN
GetSizeOfCDPLdapConfig (
  IN const CDP_LDAP_CONFIG *ldapConfig
)
{
  UINTN Size = 0;
  
  Size = sizeof(ldapConfig->version) +
         sizeof(ldapConfig->address) + sizeof(ldapConfig->port) + 
         sizeof(ldapConfig->suffixLen) + ldapConfig->suffixLen + 
         sizeof(ldapConfig->rootdnLen) + ldapConfig->rootdnLen + 
         sizeof(ldapConfig->rootpwLen) + ldapConfig->rootpwLen +
         sizeof(ldapConfig->nameLen) + ldapConfig->nameLen;

  return Size;
}
//------------------------------------------------------------------------------

VOID
ResetCDPLdapConfig (
  VOID
  )
{
  readConf = FALSE;
}

//------------------------------------------------------------------------------
/*! \brief Read CDP ldap config. If config isn't exist, create default config */
/*! \return Pointer to read data */
//------------------------------------------------------------------------------
CDP_LDAP_CONFIG*
ReadCDPLdapConfigFromVariable ( 
  VOID
)
{
  EFI_STATUS Status     = EFI_SUCCESS;
  UINTN      Size       = 0;
  CHAR8     *varBuffer = NULL;
  
  if (TRUE == readConf)
    return &currentCDPLdapConfig;

  Status = gRT->GetVariable(
                CDP_LDAP_CONFIG_VAR_NAME,
                &gCDPLdapConfigVarGuid,
                NULL,
                &Size,
                NULL
                );

  if (Status == EFI_NOT_FOUND) {
    Size = GetSizeOfCDPLdapConfig((const CDP_LDAP_CONFIG*)&currentCDPLdapConfig);
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
      DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
      return NULL;
  }
  
    StoreCDPLdapConfigToBuffer(varBuffer, &currentCDPLdapConfig);

    Status = gRT->SetVariable (
                    CDP_LDAP_CONFIG_VAR_NAME,
                    &gCDPLdapConfigVarGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                    Size,
                    varBuffer
                   );

    // Fill the config from INI file and save to flash
    // Don't check a result - if error, the config stays empty
    {
      CHAR8 Fname[255];
      AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdCDPLdapConfigFile));
      DEBUG((EFI_D_ERROR, "PcdCDPLdapConfigFile: %a \n", Fname));
      SetCDPLdapConfigFromINIFile(Fname);
    }
  } else {
    // Found config. Need to allocate buffer and read it.
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
      DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    
    Status = gRT->GetVariable(
        CDP_LDAP_CONFIG_VAR_NAME,
        &gCDPLdapConfigVarGuid,
        NULL,
        &Size,
        varBuffer
        );
    if (Status == EFI_SUCCESS){
      FlushCDPLdapConfig(&currentCDPLdapConfig);
      Status = RetrieveCDPLdapConfigFromBuffer(&currentCDPLdapConfig, (const CHAR8*)varBuffer);
    }
  }
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  if (Status != EFI_SUCCESS) {
    DEBUG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));
    return NULL;
  }
  
  readConf = TRUE;
  
  return &currentCDPLdapConfig;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Write CDP ldap config to the variable */
/*! \param[in] *ldapConfig Pointer to the CDP ldap config to write */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
WriteCDPLdapConfigToVariable (
  IN const CDP_LDAP_CONFIG *ldapConfig
)
{
  EFI_STATUS Status      = EFI_SUCCESS;
  UINTN      Size      = 0;
  CHAR8     *varBuffer;
  
  Size = GetSizeOfCDPLdapConfig(ldapConfig);
  
  DEBUG((EFI_D_ERROR, "%a.%d: Size = %d\n", __FUNCTION__, __LINE__, Size));
  
  varBuffer = AllocateZeroPool(Size);
  if (NULL == varBuffer) {
    DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  StoreCDPLdapConfigToBuffer(varBuffer, ldapConfig);
  
  Status = gRT->SetVariable(
                  CDP_LDAP_CONFIG_VAR_NAME,
                  &gCDPLdapConfigVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  Size,
                  varBuffer
                  );
  if (Status != EFI_SUCCESS)
    DEBUG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read CDP Ldap config to init internal private data */
/*! If you want to use CDP ldap config data, you have to call this function first */
/*! \return Status of the read operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_LOAD_ERROR Can't read ldap config. See debug log for more details. */
//------------------------------------------------------------------------------
EFI_STATUS
ReadCDPLdapConfig(
  VOID
)
{
  if (NULL == ReadCDPLdapConfigFromVariable())
    return EFI_LOAD_ERROR;
  else
    return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save CDP Ldap config to the variable */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
SaveCDPLdapConfig(
  VOID
)
{
  return WriteCDPLdapConfigToVariable(&currentCDPLdapConfig);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete CDP LDAP config */
/*! Delete temp current config from memory, not from variable */
//------------------------------------------------------------------------------
VOID
DeleteCDPLdapConfig(
  VOID
)
{
  FlushCDPLdapConfig(&currentCDPLdapConfig);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read ldap server address */
/*! \return Pointer to the ldap server IP address in CHAR16 string */
//------------------------------------------------------------------------------
const CHAR16*
GetCDPLdapServerAddr(
  VOID
)
{
  ReadCDPLdapConfig();
  
  return &currentCDPLdapConfig.address[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length of a string, containes the ldap server IP address */
/*! \return Size of string, contains ldap server IP address */
//------------------------------------------------------------------------------
UINTN
GetSizeOfCDPLdapServerAddr(
  VOID
)
{
  ReadCDPLdapConfig();
  
  return sizeof(currentCDPLdapConfig.address);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap port value */
/*! \return Value of the ldap server port */
//------------------------------------------------------------------------------
CHAR16
GetCDPLdapServerPort(
  VOID
)
{
  ReadCDPLdapConfig();
  
  return currentCDPLdapConfig.port;
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
/*! \brief Get rootdn */
/*! \return  Pointer to the CDP ldap rootdn */
//------------------------------------------------------------------------------
const CHAR16*
GetCDPLdapRootdn(
  VOID
)
{
  ReadCDPLdapConfig();
  
  return currentCDPLdapConfig.pRootdn[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains ldap rootdn */
/*! \return length of a string, contains CDP ldap rootdn */
//------------------------------------------------------------------------------
UINTN
GetSizeOfCDPLdapRootdn( 
  VOID
)
{
  return currentCDPLdapConfig.rootdnLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get rootpw */
/*! \return  Pointer to the CDP ldap rootpw */
//------------------------------------------------------------------------------
const CHAR16*
GetCDPLdapRootpw( 
  VOID
)
{
  ReadCDPLdapConfig();
  
  return currentCDPLdapConfig.pRootpw[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains CDP ldap rootpw */
/*! \return length of a string, contains CDP ldap rootpw */
//------------------------------------------------------------------------------
UINTN
GetSizeOfCDPLdapRootpw( 
  VOID
)
{
  return currentCDPLdapConfig.rootpwLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ldap server name */
/*! \return  Pointer to the ldap server name */
//------------------------------------------------------------------------------
const CHAR16*
GetCDPLdapServerName(
  VOID
)
{
  ReadCDPLdapConfig();
  
  return currentCDPLdapConfig.pName[0];
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a length in bytes of a string, contains CDP ldap server name */
/*! \return length of a string, contains CDP ldap server name */
//------------------------------------------------------------------------------
UINTN
GetSizeOfCDPLdapServerName(
  VOID
)
{
  return currentCDPLdapConfig.nameLen;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a ldap port */
/*! \param[in] portNum number of a ldap port */
/*! \retunr Code Of Error*/
//------------------------------------------------------------------------------
EFI_STATUS
SetCDPLdapPort(
  IN UINTN portNum
)
{
  currentCDPLdapConfig.port = (CHAR16)portNum;
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the rootdn */
/*! \param[in] *rootdn Pointer to a string, containes rootdn */
/*! \return Error Of Code */
//------------------------------------------------------------------------------
EFI_STATUS
SetCDPLdapRootdn(
  IN CHAR16 *rootdn
)
{
  UINTN lenght = 0;

  if (currentCDPLdapConfig.pRootdn[0] != NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Try to free pRootdn %a\n", __FUNCTION__, __LINE__));
    currentCDPLdapConfig.rootdnLen = 0;
    FreePool(currentCDPLdapConfig.pRootdn[0]);
    currentCDPLdapConfig.pRootdn[0] = NULL;
  }

  // if rootdn = "\0" or equal
  lenght = StrSize(rootdn);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentCDPLdapConfig.rootdnLen = lenght;
  
  currentCDPLdapConfig.pRootdn[0] = AllocateZeroPool(currentCDPLdapConfig.rootdnLen);
  if (NULL == currentCDPLdapConfig.pRootdn[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentCDPLdapConfig.pRootdn[0],rootdn);
  
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
SetCDPLdapRootpw(
  IN CHAR16 *rootpw
)
{
  UINTN lenght = 0;

  if (currentCDPLdapConfig.pRootpw[0] != NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Try to free pRootpw\n", __FUNCTION__, __LINE__));
    currentCDPLdapConfig.rootpwLen = 0;
    FreePool(currentCDPLdapConfig.pRootpw[0]);
    currentCDPLdapConfig.pRootpw[0] = NULL;
  }

  // if rootpw = "\0" or equal
  lenght = StrSize(rootpw);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentCDPLdapConfig.rootpwLen = lenght;
  
  currentCDPLdapConfig.pRootpw[0] = AllocateZeroPool(currentCDPLdapConfig.rootpwLen);
  if (NULL == currentCDPLdapConfig.pRootpw[0])
    return EFI_OUT_OF_RESOURCES;

  StrCpy(currentCDPLdapConfig.pRootpw[0],rootpw);
  
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
SetCDPLdapServerName(
  IN CHAR16 *name
)
{
  UINTN lenght = 0;

  if (currentCDPLdapConfig.pName[0] != NULL) {
    currentCDPLdapConfig.nameLen = 0;
    FreePool(currentCDPLdapConfig.pName[0]);
    currentCDPLdapConfig.pName[0] = NULL;
  }

  // if name = "\0" or equal
  lenght = StrSize(name);
  if (lenght <= sizeof(CHAR16))
    return EFI_SUCCESS;

  currentCDPLdapConfig.nameLen = lenght;

  currentCDPLdapConfig.pName[0] = AllocateZeroPool(currentCDPLdapConfig.nameLen);
  if (NULL == currentCDPLdapConfig.pName[0])
    return EFI_OUT_OF_RESOURCES;
      
  StrCpy(currentCDPLdapConfig.pName[0], name);
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new ldap server IP address */
/*! \param[in] *ipAddr Pointer to a string, containes ldap server IP address */
/*! \return Code Of Error */
//------------------------------------------------------------------------------
EFI_STATUS
SetCDPLdapServerAddr(
 IN CHAR16 *ipAddr
)
{
  CHAR8 addrC8[STRING_ADDR_LEN], resultAddr[STRING_ADDR_LEN];
  
  // Allow to delete IP and use serverName
  if (StrLen(ipAddr) == 0) {
    StrCpy(currentCDPLdapConfig.address, ipAddr);
    return EFI_SUCCESS;
  }

  if (StrLen(ipAddr) <= STRING_ADDR_LEN) {
    UnicodeStrToAsciiStr(ipAddr, addrC8);
    DEBUG((EFI_D_ERROR, "%a.%d: addrC8: %a\n", __FUNCTION__, __LINE__, addrC8));
    if (1 == ldap_chk_addr(AF_INET, addrC8, resultAddr)) {
      StrCpy(currentCDPLdapConfig.address, ipAddr);
      return EFI_SUCCESS;
    }
  }

  return EFI_INVALID_PARAMETER;
}
//------------------------------------------------------------------------------

