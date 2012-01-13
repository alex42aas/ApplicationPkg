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
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/AuthModeConfig/AuthModeConfigInternal.h>

extern EFI_GUID gAuthModeConfVarGuid;

static BOOLEAN readConf = FALSE;

static AUTH_MODE_CONFIG currentConfig = {DEFAULT_AUTH_MODE, 0, {{CN_CMP,0,{NULL}},{OU_CMP,0,{NULL}},{SUBJECT_CMP,0,{NULL}}}};

static CHAR16   *comparisonDataStr;
static CMP_TYPE arrayOfCmpTypes[CMP_TYPE_NUM] = {{L"CN:", CN_CMP},
                                                 {L"OU:", OU_CMP},
                                                 {L"SUBJECT:", SUBJECT_CMP}};

static
UINTN
GetSizeOfAuthModeConfig (
  IN const AUTH_MODE_CONFIG *config
  );

static
VOID
FlushAuthModeConfig (
  IN AUTH_MODE_CONFIG *config
  );

//------------------------------------------------------------------------------
/*! \brief Store the auth mode config to the buffer */
/*! \param[in] *config Pointer to the config to store to the buffer
    \param[out] *bufferToStore Pointer to the buffer to keep a config */
//------------------------------------------------------------------------------
static
VOID
StoreAuthModeConfigToBuffer (
  IN const AUTH_MODE_CONFIG *config,
  OUT CHAR8 *bufferToStore
  )
{
  UINT8 i = 0;

  CopyMem(bufferToStore, &(config->authMode), sizeof(config->authMode));
  bufferToStore += sizeof(config->authMode);
    
  CopyMem(bufferToStore, &(config->cmpType), sizeof(config->cmpType));
  bufferToStore += sizeof(config->cmpType);
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    CopyMem(bufferToStore, &(config->data[i].type), sizeof(config->data[i].type));
    bufferToStore += sizeof(config->data[i].type);
    CopyMem(bufferToStore, &(config->data[i].dataSize), sizeof(config->data[i].dataSize));
    bufferToStore += sizeof(config->data[i].dataSize);
    if (config->data[i].dataSize > 0) {
      CopyMem(bufferToStore, config->data[i].dataBody[0], config->data[i].dataSize);
      bufferToStore += config->data[i].dataSize;
    }
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
static
EFI_STATUS
RetrieveAuthModeConfigFromBuffer (
  IN const CHAR8 *buffer,
  OUT AUTH_MODE_CONFIG *config
  )
{
  CHAR16 *pBuf;
  UINT8  i = 0;
  
  CopyMem(&(config->authMode), buffer, sizeof(config->authMode));
  buffer += sizeof(config->authMode);
    
  CopyMem(&(config->cmpType), buffer, sizeof(config->cmpType));
  buffer += sizeof(config->cmpType);
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    CopyMem(&(config->data[i].type), buffer, sizeof(config->data[i].type));
    buffer += sizeof(config->data[i].type);
    CopyMem(&(config->data[i].dataSize), buffer, sizeof(config->data[i].dataSize));
    buffer += sizeof(config->data[i].dataSize);
    
    if (config->data[i].dataSize > 0) {
      pBuf = AllocateZeroPool(config->data[i].dataSize);
      if (NULL == pBuf) {
          FlushAuthModeConfig(config);
          return EFI_OUT_OF_RESOURCES;
      }
      config->data[i].dataBody[0] = pBuf;

      CopyMem(config->data[i].dataBody[0], buffer, config->data[i].dataSize);
      buffer += config->data[i].dataSize;
    }
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make a string of a comparison data */
/*! Return a string looks like "CN=tester;OU=guests;SUBJECT=subject;" */
/*! You have to free the retreived data, when you dont need it any more */
/*! \param[in] *config Pointer to the config */
/*! \retval Pointer to the string of a comparison data */
//------------------------------------------------------------------------------
static
CHAR16*
MakeStringOfComparisonDataN (
  IN AUTH_MODE_CONFIG *config
  )
{
  CHAR16  delTmp[]     = L",";
  CHAR16 *dataStr = NULL, *startStr = NULL;
  UINTN   dataSize = 0;
  UINT8 i = 0; 
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));

  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if ((config->data[i].type & currentConfig.cmpType) == config->data[i].type) {
      if (config->data[i].dataSize > 0 && (config->data[i].dataBody[0] != NULL)) {
        dataSize += (config->data[i].dataSize + sizeof(CHAR16) + StrSize(arrayOfCmpTypes[i].cmpTitle));
      }
    }
  }
  
  if (dataSize == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d: Comparison data is empty.\n", __FUNCTION__, __LINE__));
    return NULL; 
  }
  
  dataStr = AllocateZeroPool(dataSize);
  
  startStr = dataStr;
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if ((config->data[i].type & currentConfig.cmpType) == config->data[i].type) {
      if ((config->data[i].dataSize > 0) && (config->data[i].dataBody[0] != NULL)) {
        StrCpy(dataStr, arrayOfCmpTypes[i].cmpTitle);
        dataStr += StrLen(arrayOfCmpTypes[i].cmpTitle);
        StrCpy(dataStr, config->data[i].dataBody[0]);
        dataStr += StrLen(config->data[i].dataBody[0]);
        if (i < CMP_TYPE_NUM - 1) {
          StrCpy(dataStr, delTmp);
          dataStr += StrLen(delTmp);
        }
      }
    }
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d: Comparison Data: %s\n", __FUNCTION__, __LINE__, startStr));
  
  return startStr;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush auth mode config */
/*! Free all buffers, set all buffer's sizes to zero */
/*! \param[in] *config Pointer to auth mode config */
//------------------------------------------------------------------------------
static
VOID
FlushAuthModeConfig (
  IN AUTH_MODE_CONFIG *config
  )
{
  UINT8 i = 0;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  SetLocalUsageStatus(DONT_USE_SETTING);
  SetLdapUsageStatus(DONT_USE_SETTING);
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if (config->data[i].dataBody[0] != NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: i: %d, type: %d\n", 
        __FUNCTION__, __LINE__, i, config->data[i].type));
      FreePool(config->data[i].dataBody[0]);
      config->data[i].dataBody[0] = NULL;
      config->data[i].dataSize = 0;
    }
  }
  
  config->cmpType = 0;
  
  readConf = FALSE;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
    
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Erase buffers of an auth mode config data */
//------------------------------------------------------------------------------
VOID
DeleteAuthModeConfig (
  VOID
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));

  FlushAuthModeConfig(&currentConfig);
  
  if (comparisonDataStr != NULL) {
    FreePool(comparisonDataStr);
    comparisonDataStr = NULL;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
    
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete a data has been entered and has been unselected and check */
/*! \retval EFI_UNSUPPORTED Trying to use a guest auth, but dont select no local no ldap 
    \retval EFI_INVALID_PARAMETER Comparison data has been selected but not entered
    \retval EFI_SUCCESS Success */
//------------------------------------------------------------------------------
static
EFI_STATUS
PrepareConfigToSaveAndCheck (
  VOID
  )
{
  UINT8 i = 0;
  
  if (GetAuthMode() == GUEST_AUTH_MODE) {
    if ((IsUseLocalGuestLogin() == FALSE) && (IsUseLdapGuestLogin() == FALSE)) {
      return EFI_UNSUPPORTED;
    }
  }
  
  if (IsUseLocalGuestLogin() == FALSE) {
    for(i = 0; i < CMP_TYPE_NUM; i++) {
      CleanCmpData(arrayOfCmpTypes[i].cmpMask);
    }
    currentConfig.cmpType = 0;
  } else {
    if (currentConfig.cmpType == 0) 
      return EFI_INVALID_PARAMETER;
      
    for(i = 0; i < CMP_TYPE_NUM; i++) {
      if ((currentConfig.cmpType & arrayOfCmpTypes[i].cmpMask) != arrayOfCmpTypes[i].cmpMask) {
        CleanCmpData(arrayOfCmpTypes[i].cmpMask);
      } else if (currentConfig.data[i].dataSize <= StrSize(L""))
        return EFI_INVALID_PARAMETER;
    }
  }
    
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get size of the auth mode config */
/*! \param[in] config A config of an auth mode */
/*! \return A size of an auth mode config in bytes. */
//------------------------------------------------------------------------------
static
UINTN
GetSizeOfAuthModeConfig (
  IN const AUTH_MODE_CONFIG *config
  )
{
  UINT8     i    = 0;
  UINTN     Size = 0;

  Size = sizeof(config->authMode) +
         sizeof(config->cmpType);
         
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    Size += sizeof(config->data[i].type);
    Size += sizeof(config->data[i].dataSize);
    Size += config->data[i].dataSize;
  }

  return Size;
}
//------------------------------------------------------------------------------

VOID
ResetAuthModeConfig (
  VOID
  )
{
  readConf = FALSE;
}

//------------------------------------------------------------------------------
/*! \brief Read Auth Mode Config from the NVRAM */
/*! \return Status of an operaton */
/*! \retval EFI_SUCCESS Config has been read from NVRAM
    \retval EFI_OUT_OF_RESOURCES Can't allocate memory for the config
    \retval EFI_ABORTED Can't read the config form NVRAM. See debug log for details. */
//------------------------------------------------------------------------------
EFI_STATUS
ReadAuthModeConfig (
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINTN      Size       = 0;
  CHAR8     *varBuffer = NULL;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  if (TRUE == readConf) {
    DEBUG((EFI_D_ERROR, "%a.%d: No need to read the config.\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
    
  Status = gRT->GetVariable(
                  AUTH_MODE_CONFIG_VAR_NAME,
                  &gAuthModeConfVarGuid,
                  NULL,
                  &Size,
                  NULL
                  );
  if (Status == EFI_NOT_FOUND) {
    Size = GetSizeOfAuthModeConfig((const AUTH_MODE_CONFIG*)&currentConfig);
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
        DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
    }
    StoreAuthModeConfigToBuffer(&currentConfig, varBuffer);

    Status = gRT->SetVariable (
                    AUTH_MODE_CONFIG_VAR_NAME,
                    &gAuthModeConfVarGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                    Size,
                    varBuffer
                    );
    // Fill the config from INI file and save to flash
    // Don't check a result - if error, the config stays empty
    {
      CHAR8 Fname[255];
      AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdAuthModeConfigFile));
      DEBUG((EFI_D_ERROR, "PcdAuthModeConfigFile: %a \n", Fname));
      SetAuthConfigFromINIFile(Fname);
    }
  } else {
    varBuffer = AllocateZeroPool(Size);
    if (NULL == varBuffer) {
        DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
    }
    
    Status = gRT->GetVariable(
                    AUTH_MODE_CONFIG_VAR_NAME,
                    &gAuthModeConfVarGuid,
                    NULL,
                    &Size,
                    varBuffer
                    );
                    
    if (Status == EFI_SUCCESS){
      FlushAuthModeConfig(&currentConfig);
      Status = RetrieveAuthModeConfigFromBuffer((const CHAR8*)varBuffer, &currentConfig);
    }
  }
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  if (Status != EFI_SUCCESS) {
    DEBUG((EFI_D_ERROR, "%a.%d: EFI_STATUS = %d\n", __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  }
    
  comparisonDataStr = MakeStringOfComparisonDataN(&currentConfig);
  
  readConf = TRUE;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save auth mode config to the NVRAM */
/*! \return Status of an operation. See debug log for more details */
//------------------------------------------------------------------------------
EFI_STATUS
SaveAuthModeConfig (
  VOID
  )
{
  EFI_STATUS Status    = EFI_SUCCESS;
  UINTN      Size      = 0;
  CHAR8     *varBuffer;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  if (GetAuthMode() == DEFAULT_AUTH_MODE) {
    DeleteAuthModeConfig();
  } else {
    Status = PrepareConfigToSaveAndCheck();
    if (Status != EFI_SUCCESS)
      return Status;
  }
  
  Size = GetSizeOfAuthModeConfig((const AUTH_MODE_CONFIG*)&currentConfig);
  
  DEBUG((EFI_D_ERROR, "%a.%d: Size = %d\n", __FUNCTION__, __LINE__, Size));
  
  varBuffer = AllocateZeroPool(Size);
  if (NULL == varBuffer) {
    DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate varBuffer\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  StoreAuthModeConfigToBuffer(&currentConfig, varBuffer);

  Status = gRT->SetVariable(
                  AUTH_MODE_CONFIG_VAR_NAME,
                  &gAuthModeConfVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  Size,
                  varBuffer
                  );
  
  if (varBuffer != NULL)
    FreePool(varBuffer);
  
  DEBUG((EFI_D_ERROR, "%a.%d: Status = %d\n", __FUNCTION__, __LINE__, Status));
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check use ldap or not */
/*! \retval TRUE Use ldap to auth guest user
    \retval FALSE Dont use ldap to auth guest user.
*/
//------------------------------------------------------------------------------
BOOLEAN
IsUseLdapGuestLogin (
  VOID
  )
{
  UINT8 ldapUsage;
  
  ReadAuthModeConfig();
  
  ldapUsage = (currentConfig.authMode & LDAP_USAGE_MASK) >> LDAP_USAGE_OFFS;
  
  if (USE_SETTING == ldapUsage)
    return TRUE;

  return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check use local guest or not */
/*! \retval TRUE Use local settings to auth guest user
    \retval FALSE Dont use local settings to auth guest user.
*/
//------------------------------------------------------------------------------
BOOLEAN
IsUseLocalGuestLogin (
  VOID
  )
{
  UINT8 localUsage;
  
  ReadAuthModeConfig();
  
  localUsage = (currentConfig.authMode & LOCAL_USAGE_MASK) >> LOCAL_USAGE_OFFS;
  
  if (USE_SETTING == localUsage)
    return TRUE;

  return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get User PC check enable flag */
/*! \retval TRUE User-PC link is enable
    \retval FALSE User-PC link is disable.
*/
//------------------------------------------------------------------------------
BOOLEAN
IsUserPCLinkCheck (
  VOID
  )
{
  UINT8 status;

  ReadAuthModeConfig();

  status = (currentConfig.authMode & USER_PC_LINK_MASK) >> USER_PC_LINK_OFFS;

  if (USE_SETTING == status)
    return TRUE;

  return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get the Auth Mode */
//------------------------------------------------------------------------------
UINT8
GetAuthMode (
  VOID
  )
{
  UINT8 mode;
  
  ReadAuthModeConfig();
  
  mode = currentConfig.authMode & MODE_MASK;
  
  return mode;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a comparison type */
//------------------------------------------------------------------------------
UINT8
GetTypeOfComparison (
  VOID
  )
{
  ReadAuthModeConfig();
  
  return currentConfig.cmpType;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get data of comparison */
/*! \param[in] cmpType Type of a data to get */
/*! \return  Pointer to the data, NULL if a cmpType not presented */
//------------------------------------------------------------------------------
const CHAR16*
GetCmpDataByType( 
  IN UINT8 cmpType
  )
{
  UINT8 i = 0;
  
  ReadAuthModeConfig();
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if ((currentConfig.data[i].type & cmpType) == cmpType) {
       return currentConfig.data[i].dataBody[0];
    }
  }
  
  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a comparison data in a string */
/*! \return  Pointer to the comparison data */
//------------------------------------------------------------------------------
const CHAR16*
GetComparisonDataAsStr (
  VOID
  )
{
  ReadAuthModeConfig();
  
  return comparisonDataStr;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a mode of an authenticate */
/*! \param[in] newAuthMode Mode to set */
/*! \retval EFI_INVALID_PARAMETER Invalid (unsupported) auth mode
    \retval EFI_SUCCESS Success */
//------------------------------------------------------------------------------
EFI_STATUS
SetAuthMode (
  IN UINT8 newAuthMode
  )
{
  UINT8 modeToSet = newAuthMode & MODE_MASK;
  
  if (newAuthMode <= GUEST_AUTH_MODE && newAuthMode >= DEFAULT_AUTH_MODE) {
    currentConfig.authMode &= ~(MODE_MASK);
    currentConfig.authMode |= modeToSet;
  } else
    return EFI_INVALID_PARAMETER;
    
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set ldap usage status */
/*! \param[in] ldapUsageStatus Status to set */
/*! \retval EFI_INVALID_PARAMETER Invalid (unsupported) value
    \retval EFI_SUCCESS Success */
//------------------------------------------------------------------------------
EFI_STATUS
SetLdapUsageStatus (
  IN UINT8 ldapUsageStatus
  )
{
  UINT8 ldapUsageBit = (ldapUsageStatus << LDAP_USAGE_OFFS) & LDAP_USAGE_MASK;
  
  if (ldapUsageStatus <= USE_SETTING && ldapUsageStatus >= DONT_USE_SETTING) {
    currentConfig.authMode &= ~(LDAP_USAGE_MASK);
    currentConfig.authMode |= ldapUsageBit;
  } else
    return EFI_INVALID_PARAMETER;
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set local usage status */
/*! \param[in] localUsageStatus Status to set */
/*! \retval EFI_INVALID_PARAMETER Invalid (unsupported) value
    \retval EFI_SUCCESS Success */
//------------------------------------------------------------------------------
EFI_STATUS
SetLocalUsageStatus (
  IN UINT8 localUsageStatus
  )
{
  UINT8 localUsageBit = (localUsageStatus << LOCAL_USAGE_OFFS) & LOCAL_USAGE_MASK;
  
  if (localUsageStatus <= USE_SETTING && localUsageStatus >= DONT_USE_SETTING) {
    currentConfig.authMode &= ~(LOCAL_USAGE_MASK);
    currentConfig.authMode |= localUsageBit;
  } else
    return EFI_INVALID_PARAMETER;
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set User-PC link check */
/*! \param[in] flag Status to set */
/*! \retval EFI_INVALID_PARAMETER Invalid (unsupported) value
    \retval EFI_SUCCESS Success */
//------------------------------------------------------------------------------
EFI_STATUS
SetUserPCLinkCheckStatus (
  IN UINT8 flag
  )
{
  UINT8 usageBit = (flag << USER_PC_LINK_OFFS) & USER_PC_LINK_MASK;

  if (flag <= USE_SETTING && flag >= DONT_USE_SETTING) {
    currentConfig.authMode &= ~(USER_PC_LINK_MASK);
    currentConfig.authMode |= usageBit;
  } else
    return EFI_INVALID_PARAMETER;
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a comparison type */
/*! \param[in] type A comparison type  */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS if success */
//------------------------------------------------------------------------------
EFI_STATUS
SetTypeOfComparison ( 
  IN UINT8 type
  )
{
  currentConfig.cmpType |= type;
    
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Clear a comparison type */
/*! \param[in] type A comparison type  */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS if success */
//------------------------------------------------------------------------------
EFI_STATUS
ClearTypeOfComparison ( 
  IN UINT8 type 
  )
{
    currentConfig.cmpType &= ~type;
    
    return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check for comparison type */
/*! \param[in] type A comparison type  */
//------------------------------------------------------------------------------
BOOLEAN
IsTypeOfComparison ( 
  IN UINT8 type
  )
{
  if((currentConfig.cmpType & type) == 0) {
    return FALSE;
  } else {
    return TRUE;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a new value of the comparison data */
/*! \param[in]  cmpType Type of a data to set
    \param[in] *newData Pointer to a string, containes the data */
/*! \return Error Of Code */
//------------------------------------------------------------------------------
EFI_STATUS
SetCmpDataByType (
  IN UINT8 cmpType,
  IN const CHAR16 *newData
  )
{
  UINT8 i = 0;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if ((currentConfig.data[i].type & cmpType) == cmpType) {
       if (currentConfig.data[i].dataBody[0] != NULL) {
         DEBUG((EFI_D_ERROR, "%a.%d: Try to free data. Type%d, index: %d\n", __FUNCTION__, __LINE__, cmpType, i));
         currentConfig.data[i].dataSize = 0;
         FreePool(currentConfig.data[i].dataBody[0]);
         currentConfig.data[i].dataBody[0] = NULL;
         break;
       }
    }
  }

  for(i = 0; i < CMP_TYPE_NUM; i++) {
    if ((currentConfig.data[i].type & cmpType) == cmpType) {
      currentConfig.data[i].dataSize = StrSize(newData);
      currentConfig.data[i].dataBody[0] = AllocateZeroPool(currentConfig.data[i].dataSize);
      if (NULL == currentConfig.data[i].dataBody[0]) {
        currentConfig.data[i].dataSize = 0;
        return EFI_OUT_OF_RESOURCES;
      }
      StrCpy(currentConfig.data[i].dataBody[0], newData);
      break;
    }
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Clear comparison data */
/*! \param[in] mask Type of a data to clear */
//------------------------------------------------------------------------------
EFI_STATUS
CleanCmpData (
  IN UINT8 mask
  )
{
  UINT8 i = 0;
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  for(i = 0; i < CMP_TYPE_NUM; i ++) {
    if ((currentConfig.data[i].type & mask) == mask) {
      if (currentConfig.data[i].dataBody[0] != NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d: i: %d, mask: %d, body: %s\n", __FUNCTION__, __LINE__, i, mask, currentConfig.data[i].dataBody[0]));
        FreePool(currentConfig.data[i].dataBody[0]);
        currentConfig.data[i].dataBody[0] = NULL;
        currentConfig.data[i].dataSize = 0;
        break;
      }
    }
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d: \n", __FUNCTION__, __LINE__));
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

