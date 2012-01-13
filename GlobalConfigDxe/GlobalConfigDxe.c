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
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/IniParserDxe.h>
#include <Protocol/GlobalConfigDxe.h>

#include "GlobalConfigDxeInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

extern EFI_GUID gIniParserDxeProtocolGuid;

STATIC GLOBAL_CONFIG_INTERNAL_DATA gGlobalConfigInternalData;

//------------------------------------------------------------------------------
/*! \brief Get a config, which has been registered, by name */
/*! \param[in] *configName A pointer to a name of the config */
/*! \return A pointer to the config if config has been registered, NULL otherwise */
//------------------------------------------------------------------------------
STATIC
CONFIG_ENTRY *
GetConfigByName (
  IN CHAR8 *configName
)
{
  CONFIG_ENTRY *config = NULL;
  LIST_ENTRY *Link;

  if (configName == NULL || &gGlobalConfigInternalData.configEntryHead == NULL)
    return NULL;

  if (IsListEmpty(&gGlobalConfigInternalData.configEntryHead))
    return NULL;

  Link = GetFirstNode(&gGlobalConfigInternalData.configEntryHead);
  while(!IsNull(&gGlobalConfigInternalData.configEntryHead, Link)) {
    config = (CONFIG_ENTRY *)Link;
    if (AsciiStrCmp(config->configName, configName) == 0)
      return config;
    Link = GetNextNode(&gGlobalConfigInternalData.configEntryHead, Link);
  }

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a number of config subsystems in the list */
/*! \return A count of subsystems */
//------------------------------------------------------------------------------
STATIC
UINTN
GetConfigCount (
  IN LIST_ENTRY *configList
)
{
  LIST_ENTRY *Link;
  UINTN count;

  if (configList == NULL)
    return 0;

  if (IsListEmpty(configList))
    return 0;

  count = 0;

  for (Link = GetFirstNode(configList); 
       !IsNull(configList, Link); 
       ) {
    Link = GetNextNode (configList, Link);
    count++;
  }
  return count;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Add config callback function for subsystem */
/*! \param[in] *configName A pointer to a name of the config
    \param[in] *SetConfigFromDictionary A pointer to the subsystem callback config method */
//------------------------------------------------------------------------------
EFI_STATUS
AddConfig (
  IN CHAR8 *configName,
  IN CONFIG_ERROR_T (*SetConfigFromDictionary)(dictionary *dict),
  IN CONFIG_ERROR_T (*DumpConfigToDictionary)(dictionary *dict)
)
{
  CONFIG_ENTRY *config = NULL;

  if (SetConfigFromDictionary == NULL /*|| DumpConfigToDictionary == NULL*/ || configName == NULL)
    return EFI_INVALID_PARAMETER;

  if (GetConfigByName(configName) != NULL) {
    LOG((EFI_D_ERROR, "%a has already been registered\n", configName));
    return EFI_SUCCESS;
  }

  config = AllocateZeroPool(sizeof(CONFIG_ENTRY));
  if (config == NULL)
    return EFI_OUT_OF_RESOURCES;

  config->configName = configName;
  config->SetConfigFromDictionary = SetConfigFromDictionary;
  config->DumpConfigToDictionary = DumpConfigToDictionary;
  
  InitializeListHead( &config->ModuleHead);
  InsertTailList( &gGlobalConfigInternalData.configEntryHead, &config->ListEntry );

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return A result of a config operation with list of subsystems */
//------------------------------------------------------------------------------
STATIC
CONFIG_RESULT_T
DumpAllConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  LIST_ENTRY *Link;
  CONFIG_ENTRY *config;

  UINTN configCount = 0;
  CONFIG_RESULT_T result = {EFI_ABORTED, 0, NULL};

  configCount = GetConfigCount(&gGlobalConfigInternalData.configEntryHead);
  if (configCount > 0) {
    REPORT_LIST_T *report;

    result.reportList = AllocateZeroPool(sizeof(REPORT_LIST_T)*configCount);
    if (result.reportList == NULL) {
      result.globalStatus = EFI_OUT_OF_RESOURCES;
      goto _exit;
    }

    result.numSubsystems = configCount;
    result.globalStatus = EFI_SUCCESS;

    report = result.reportList;

    Link = GetFirstNode(&gGlobalConfigInternalData.configEntryHead);
    while(!IsNull(&gGlobalConfigInternalData.configEntryHead, Link)) {
      config = (CONFIG_ENTRY *)Link;
      report->configName = config->configName;
      LOG((EFI_D_ERROR, "%a.%d Do  %a\n", __FUNCTION__, __LINE__, config->configName));
      if (config->DumpConfigToDictionary != NULL) {
        report->status = config->DumpConfigToDictionary(dict);
        if (report->status != SUCCESS_TO_SET_CONFIG) {
          LOG((EFI_D_ERROR, "%a.%d  Error to dump config %a\n", __FUNCTION__, __LINE__, config->configName));
          result.globalStatus = EFI_LOAD_ERROR;
        }
      } else {
        report->status = SUCCESS_TO_SET_CONFIG;
      }
      report++;
      Link = GetNextNode(&gGlobalConfigInternalData.configEntryHead, Link);
    }
  } else
    result.globalStatus = EFI_ABORTED;

_exit:
  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered */
/*! \param[in] *configData A data from config INI file
    \param[in] dataLen A length of the data */
//------------------------------------------------------------------------------
CONFIG_RESULT_T
DumpAllConfigToData (
  UINT8 **configData,
  UINTN *dataLen
)
{
  EFI_STATUS Status = EFI_ABORTED;
  dictionary *dict;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  CONFIG_RESULT_T result;

  ZeroMem (&result, sizeof(result));

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (configData == NULL || dataLen == NULL) {
    result.globalStatus = EFI_INVALID_PARAMETER;
    return result;
  }

  Status = gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             );
  if (EFI_ERROR(Status)) {
    result.globalStatus = EFI_NOT_FOUND;
    return result;
  }

  dict = iniParserProtocol->NewEmptyIniDictionary();
  if (dict == NULL) {
    result.globalStatus = EFI_OUT_OF_RESOURCES;
    return result;
  }

  result = DumpAllConfigToDictionary(iniParserProtocol, dict);

  if (!EFI_ERROR(result.globalStatus)) {
    result.globalStatus = iniParserProtocol->DumpIniDictionaryToData(dict, configData, dataLen);
  }

  iniParserProtocol->DeleteIniDictionary(dict);

  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return A result of a config operation with list of subsystems */
//------------------------------------------------------------------------------
STATIC
CONFIG_RESULT_T
DoAllConfigWithDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  LIST_ENTRY *Link;
  CONFIG_ENTRY *config;

  UINTN configCount = 0;
  CONFIG_RESULT_T result = {EFI_ABORTED, 0, NULL};

  configCount = GetConfigCount(&gGlobalConfigInternalData.configEntryHead);
  if (configCount > 0) {
    REPORT_LIST_T *report;

    result.reportList = AllocateZeroPool(sizeof(REPORT_LIST_T)*configCount);
    if (result.reportList == NULL) {
      result.globalStatus = EFI_OUT_OF_RESOURCES;
      goto _exit;
    }

    result.numSubsystems = configCount;
    result.globalStatus = EFI_SUCCESS;

    report = result.reportList;

    Link = GetFirstNode(&gGlobalConfigInternalData.configEntryHead);
    while(!IsNull(&gGlobalConfigInternalData.configEntryHead, Link)) {
      config = (CONFIG_ENTRY *)Link;
      report->configName = config->configName;
      LOG((EFI_D_ERROR, "%a.%d Do  %a\n", __FUNCTION__, __LINE__, config->configName));
      report->status = config->SetConfigFromDictionary(dict);
      if (report->status != SUCCESS_TO_SET_CONFIG) {
        LOG((EFI_D_ERROR, "%a.%d  Error to config %a\n", __FUNCTION__, __LINE__, config->configName));
        result.globalStatus = EFI_LOAD_ERROR;
      }
      if (NO_CONFIG_SECTION == report->status) {
        if (result.numSubsystems) {
          result.numSubsystems--;
        }
        goto _no_report;
      }      
      report++;
_no_report:      
      Link = GetNextNode(&gGlobalConfigInternalData.configEntryHead, Link);
    }
  } else
    result.globalStatus = EFI_ABORTED;

_exit:
  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered */
/*! \param[in] *filePath A path the INI file */
//------------------------------------------------------------------------------
CONFIG_RESULT_T
DoAllConfigWithFile (
  IN CHAR8 *filePath
)
{
  EFI_STATUS Status = EFI_ABORTED;
  dictionary *dict;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  CONFIG_RESULT_T result;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             );
  if (EFI_ERROR(Status)) {
    result.globalStatus = EFI_NOT_FOUND;
    return result;
  }

  dict = iniParserProtocol->NewIniDictionary(filePath);
  if (dict == NULL) {
    result.globalStatus = EFI_OUT_OF_RESOURCES;
    return result;
  }

  result = DoAllConfigWithDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered */
/*! \param[in] *configData A data from config INI file
    \param[in] dataLen A length of the data */
//------------------------------------------------------------------------------
CONFIG_RESULT_T
DoAllConfigWithData (
  UINT8 *configData,
  UINTN dataLen
)
{
  EFI_STATUS Status = EFI_ABORTED;
  dictionary *dict;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  CONFIG_RESULT_T result;

  ZeroMem (&result, sizeof(result));

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             );
  if (EFI_ERROR(Status)) {
    result.globalStatus = EFI_NOT_FOUND;
    return result;
  }

  dict = iniParserProtocol->NewIniDictionaryWithData(configData, dataLen);
  if (dict == NULL) {
    result.globalStatus = EFI_OUT_OF_RESOURCES;
    return result;
  }

  result = DoAllConfigWithDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Config all subsystems have been registered with default setting */
//------------------------------------------------------------------------------
CONFIG_RESULT_T
DoAllConfig (
  VOID
)
{
  CHAR8 Fname[255];
  CONFIG_RESULT_T result;

  AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdGlobalConfigFile));
  LOG((EFI_D_ERROR, "PcdGlobalConfigFile: %a \n", Fname));

  result = DoAllConfigWithFile(Fname);

  return result;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Entry point of the global config DXE driver */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
GlobalConfigInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ZeroMem(&gGlobalConfigInternalData, sizeof(gGlobalConfigInternalData));

  InitializeListHead(&gGlobalConfigInternalData.configEntryHead);

  gGlobalConfigInternalData.GlobalConfigProtocol.AddConfig           = AddConfig;
  gGlobalConfigInternalData.GlobalConfigProtocol.DumpAllConfigToData = DumpAllConfigToData;
  gGlobalConfigInternalData.GlobalConfigProtocol.DoAllConfigWithFile = DoAllConfigWithFile;
  gGlobalConfigInternalData.GlobalConfigProtocol.DoAllConfigWithData = DoAllConfigWithData;
  gGlobalConfigInternalData.GlobalConfigProtocol.DoAllConfig         = DoAllConfig;

  Status = gBS->InstallProtocolInterface(
                &gGlobalConfigInternalData.DriverHandle,
                &gGlobalConfigProtocolGuid,
                EFI_NATIVE_INTERFACE,
                &gGlobalConfigInternalData.GlobalConfigProtocol
              );

  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

