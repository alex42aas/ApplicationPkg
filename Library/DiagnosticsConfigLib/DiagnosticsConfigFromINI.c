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
#include <Library/BaseLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DiagnosticsConfigLib/DiagnosticsConfig.h>

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#include "DiagnosticsConfigInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC CHAR8 diagnosticsSectionName[] = "DiagnosticsConfig";

STATIC CHAR8 useDiagnosticsLogKey[] = "UseDiagnosticsLog";
STATIC CHAR8 useComPortKey[]        = "UseComPort";
STATIC CHAR8 useNetLogKey[]         = "UseNetLog";
STATIC CHAR8 useRamLogKey[]         = "UseRamLog";

STATIC CHAR8 removeSettingStr[] = "\"\"";

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseDiagnosticsLogFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;
  BOOLEAN useDiagnosticsLog = FALSE;

  status = iniParserProtocol->GetBoolean(dict, diagnosticsSectionName, useDiagnosticsLogKey, &useDiagnosticsLog);
  if (!EFI_ERROR(status)) {
    if (FALSE == useDiagnosticsLog)
      SetDiagnosticsLogUsageFlag(NOT_USE);
    else
      SetDiagnosticsLogUsageFlag(USE);
  }
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseComPortFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;
  BOOLEAN useComPort = FALSE;

  status = iniParserProtocol->GetBoolean(dict, diagnosticsSectionName, useComPortKey, &useComPort);
  if (!EFI_ERROR(status)) {
    if (FALSE == useComPort)
      SetComPortUsageFlag(NOT_USE);
    else
      SetComPortUsageFlag(USE);
  }
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseNetLogFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;
  BOOLEAN useNetLog = FALSE;

  status = iniParserProtocol->GetBoolean(dict, diagnosticsSectionName, useNetLogKey, &useNetLog);
  if (!EFI_ERROR(status)) {
    if (FALSE == useNetLog)
      SetNetLogUsageFlag(NOT_USE);
    else
      SetNetLogUsageFlag(USE);
  }
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseRamLogFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;
  BOOLEAN useRamLog = FALSE;

  status = iniParserProtocol->GetBoolean(dict, diagnosticsSectionName, useRamLogKey, &useRamLog);
  if (!EFI_ERROR(status)) {
    if (FALSE == useRamLog)
      SetRamLogUsageFlag(NOT_USE);
    else
      SetRamLogUsageFlag(USE);
  }
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
SetDiagnosticsConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = ReadDiagnosticsConfig();
  if (EFI_ERROR(status))
    return CANT_READ_CONFIG_FROM_VARIABLE;

  status = SetUseDiagnosticsLogFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetUseComPortFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetUseNetLogFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetUseRamLogFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseDiagnosticsLogToictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status = EFI_ABORTED;

  UINT16 useDiagnostics = GetDiagnosticsLogUsageFlag();
  switch(useDiagnostics) {
    case USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useDiagnosticsLogKey, TRUE);
      break;
    case NOT_USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useDiagnosticsLogKey, FALSE);
      break;
    default:
      status = EFI_NOT_FOUND;
      break;
  }

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseComPortToDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status = EFI_ABORTED;

  UINT16 useComPort = GetComPortUsageFlag();
  switch(useComPort) {
    case USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useComPortKey, TRUE);
      break;
    case NOT_USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useComPortKey, FALSE);
      break;
    default:
      status = EFI_NOT_FOUND;
      break;
  }

  return status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseNetLogToDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status = EFI_ABORTED;

  UINT16 useNetLog = GetNetLogUsageFlag();
  switch(useNetLog) {
    case USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useNetLogKey, TRUE);
      break;
    case NOT_USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useNetLogKey, FALSE);
      break;
    default:
      status = EFI_NOT_FOUND;
      break;
  }

  return status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseRamLogToDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status = EFI_ABORTED;

  UINT16 useRamLog = GetNetLogUsageFlag();
  switch(useRamLog) {
    case USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useRamLogKey, TRUE);
      break;
    case NOT_USE:
      status = iniParserProtocol->SetBoolean(dict, diagnosticsSectionName, useRamLogKey, FALSE);
      break;
    default:
      status = EFI_NOT_FOUND;
      break;
  }

  return status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
StoreDiagnosticsConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status, retval = EFI_SUCCESS;

  status = ReadDiagnosticsConfig();
  if (EFI_ERROR(status))
    return CANT_READ_CONFIG_FROM_VARIABLE;

  status = SaveUseDiagnosticsLogToictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveUseComPortToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveUseNetLogToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveUseRamLogToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  if (EFI_ERROR(retval))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetDiagnosticsConfigFromINIFile (
  CHAR8 *filePath
)
{
  CONFIG_ERROR_T status;
  dictionary *dict;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  status = gBS->LocateProtocol (
                  &gIniParserDxeProtocolGuid,
                  NULL,
                  (VOID **) &iniParserProtocol
                  );
  if (EFI_ERROR(status))
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  dict = iniParserProtocol->NewIniDictionary(filePath);
  if (dict == NULL)
    return ERROR_OUT_OF_MEMORY;

  status = SetDiagnosticsConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief  */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
DumpDiagnosticsConfigToDictionary (
  IN OUT dictionary *dict
)
{
  CONFIG_ERROR_T status;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  status = StoreDiagnosticsConfigToDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
SetConfigFromDictionary (
  IN dictionary *dict
)
{
  CONFIG_ERROR_T status;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS) {
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  if (!iniParserProtocol->CheckSecPresent(dict, diagnosticsSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetDiagnosticsConfigFromDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
DiagnosticsConfigConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
)
{
  EFI_STATUS status;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  status = gBS->LocateProtocol (
                  &gGlobalConfigProtocolGuid,
                  NULL,
                  (VOID **) &pGlobalConfigProtocol
                  );
  if (EFI_ERROR(status))
    return status;

  status = pGlobalConfigProtocol->AddConfig(diagnosticsSectionName,
                                    SetConfigFromDictionary, DumpDiagnosticsConfigToDictionary);

  return status;
}
//------------------------------------------------------------------------------

