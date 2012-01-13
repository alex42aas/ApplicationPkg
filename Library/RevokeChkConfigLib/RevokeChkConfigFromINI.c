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

#include <Protocol/GlobalConfigDxe.h>

#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>

#include <Protocol/IniParserDxe.h>

#include "RevokeChkConfigInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC CHAR8 revokeChkSectionName[] = "RevokeChkConfig";

STATIC CHAR8 useOCSPKey[]           = "UseOCSP";
STATIC CHAR8 ocspUrlKey[]           = "OCSP_url";
STATIC CHAR8 crlOCSPChkKey[]        = "OCSP_crt_check";
STATIC CHAR8 tlsCRLcheckKey[]       = "TLS_CRL_check";
STATIC CHAR8 userCRLcheckKey[]      = "user_CRL_check";
STATIC CHAR8 useCDPKey[]            = "UseCDP";
STATIC CHAR8 cdpFromCertKey[]       = "CDP_from_cert";
STATIC CHAR8 cdpUrlKey[]            = "CDP_url";
STATIC CHAR8 casheCRLKey[]          = "CasheCRL";

STATIC CHAR8 removeSettingStr[] = "\"\"";

STATIC CHAR8 CRLnoneStr8[]   = "NONE";
STATIC CHAR8 CRLchainStr8[]  = "CHAIN";
STATIC CHAR8 CRLserverStr8[] = "SERVER";
STATIC CHAR8 CRLclientStr8[] = "USER";

//------------------------------------------------------------------------------
/*! \brief Read UseOCSP Status and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseOCSPFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  BOOLEAN useOCSP = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, revokeChkSectionName, useOCSPKey, &useOCSP);
  if (!EFI_ERROR(Status)) {
    if (FALSE == useOCSP)
      SetOcspUsageFlag(NOT_USE);
    else
      SetOcspUsageFlag(USE);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read OCSP URL and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetOCSPUrlFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *oscpUrl8   = NULL;
  CHAR16 *oscpUrl16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  oscpUrl8 = iniParserProtocol->GetString(dict, revokeChkSectionName, ocspUrlKey);
  if (oscpUrl8 != NULL) {
    LOG((EFI_D_ERROR, "oscpUrl8: %a\n", oscpUrl8));
    if (AsciiStrCmp(oscpUrl8, removeSettingStr) == 0) {
      Status = SetOcspUrl(L"");
    } else {
      oscpUrl16 = AllocateZeroPool(AsciiStrLen(oscpUrl8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (oscpUrl16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(oscpUrl8, oscpUrl16);
        Status = SetOcspUrl(oscpUrl16);
        FreePool(oscpUrl16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "oscpUrl8 is NULL\n"));
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read check OCSP certificate status and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetOCSPCertCheckFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN chkOCSPcert = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, revokeChkSectionName, crlOCSPChkKey, &chkOCSPcert);
  if (!EFI_ERROR(Status)) {
    if (FALSE == chkOCSPcert)
      SetOCSPResponceVerifyUsageFlag(NOT_USE);
    else
      SetOCSPResponceVerifyUsageFlag(USE);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read TLS certificate check setting and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetTlsCrlCheckFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  CHAR8 *tlsCertChk8;

  tlsCertChk8 = iniParserProtocol->GetString(dict, revokeChkSectionName, tlsCRLcheckKey);
  if (tlsCertChk8 != NULL) {
    LOG((EFI_D_ERROR, "tlsCertChk8: %a\n", tlsCertChk8));
    Status = EFI_SUCCESS;
    if (AsciiStrCmp(tlsCertChk8, CRLnoneStr8) == 0) {
      SetTLSCrlCheckMode(DONT_CHECK_CRL);
    } else if (AsciiStrCmp(tlsCertChk8, CRLchainStr8) == 0) {
      SetTLSCrlCheckMode(ALL_CRL_CHECK);
    } else if (AsciiStrCmp(tlsCertChk8, CRLserverStr8) == 0) {
      SetTLSCrlCheckMode(CRL_CHECK);
    } else {
      Status = EFI_UNSUPPORTED;
    }
  } else
    Status = EFI_NOT_FOUND;

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read client certificate check setting and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUserCrlCheckFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  CHAR8 *clientCertChk8;

  clientCertChk8 = iniParserProtocol->GetString(dict, revokeChkSectionName, userCRLcheckKey);
  if (clientCertChk8 != NULL) {
    LOG((EFI_D_ERROR, "clientCertChk8: %a\n", clientCertChk8));
    Status = EFI_SUCCESS;
    if (AsciiStrCmp(clientCertChk8, CRLnoneStr8) == 0) {
      SetCrlCheckMode(DONT_CHECK_CRL);
    } else if (AsciiStrCmp(clientCertChk8, CRLchainStr8) == 0) {
      SetCrlCheckMode(ALL_CRL_CHECK);
    } else if (AsciiStrCmp(clientCertChk8, CRLclientStr8) == 0) {
      SetCrlCheckMode(CRL_CHECK);
    } else {
      Status = EFI_UNSUPPORTED;
    }
  } else
    Status = EFI_NOT_FOUND;

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read use CDP status and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetUseCdpFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN useCDP = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, revokeChkSectionName, useCDPKey, &useCDP);
  if (!EFI_ERROR(Status)) {
    if (FALSE == useCDP)
      SetLocalCdpUsageFlag(NOT_USE);
    else
      SetLocalCdpUsageFlag(USE);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read CDP from certificate extension status and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetCdpCertExtFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN cdpFromCert = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, revokeChkSectionName, cdpFromCertKey, &cdpFromCert);
  if (!EFI_ERROR(Status)) {
    if (FALSE == cdpFromCert)
      SetCDPfromCertUsageFlag(NOT_USE);
    else
      SetCDPfromCertUsageFlag(USE);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read CDP cashe setting and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetCasheCrlFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN casheCRL = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, revokeChkSectionName, casheCRLKey, &casheCRL);
  if (!EFI_ERROR(Status)) {
    if (FALSE == casheCRL)
      SetCDPCasheUsageFlag(NOT_USE);
    else
      SetCDPCasheUsageFlag(USE);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read CDP URL and set */
/*! You have to call SaveRevokeChkConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetCdpUrlFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *cdpUrl8   = NULL;
  CHAR16 *cdpUrl16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  cdpUrl8 = iniParserProtocol->GetString(dict, revokeChkSectionName, cdpUrlKey);
  if (cdpUrl8 != NULL) {
    LOG((EFI_D_ERROR, "cdpUrl8: %a\n", cdpUrl8));
    if (AsciiStrCmp(cdpUrl8, removeSettingStr) == 0) {
      Status = SetLocalCdpUrl(L"");
    } else {
      cdpUrl16 = AllocateZeroPool(AsciiStrLen(cdpUrl8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (cdpUrl16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(cdpUrl8, cdpUrl16);
        Status = SetLocalCdpUrl(cdpUrl16);
        FreePool(cdpUrl16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "cdpUrl8 is NULL\n"));
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read config from dictionary and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
SetRevokeChkConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = ReadRevokeChkConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read RevokeChk config\n", __FUNCTION__, __LINE__));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  status = SetUseOCSPFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }
  
  status = SetOCSPUrlFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return ERROR_OUT_OF_MEMORY;
  
  status = SetOCSPCertCheckFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetTlsCrlCheckFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return UNSUPPORTED_KEY_VALUE;
  }

  status = SetUserCrlCheckFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return UNSUPPORTED_KEY_VALUE;
  }

  status = SetUseCdpFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetCdpCertExtFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetCasheCrlFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetCdpUrlFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return ERROR_OUT_OF_MEMORY;

  status = SaveRevokeChkConfig();
  switch(status) {
    case EFI_UNSUPPORTED:
      return UNSUPPORTED_SETTING_COMBINATION;
    case EFI_SUCCESS:
      return SUCCESS_TO_SET_CONFIG;
    default:
      return CANT_SAVE_CONFIG_TO_VARIABLE;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief RevokeChk config with config INI file */
/*! Read RevokeChk config from INI file and save to the variable. Use this function
    to config RevokeChk directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetConfigFromINIFile (
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

  status = SetRevokeChkConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief RevokeChk config with config INI file */
/*! Read RevokeChk config from INI file and save to the variable. Use this function
    to config RevokeChk directly without using GlobalConfigDxe */
/*! \param[in] *configData A data from config INI file
    \param[in] dataLen A length of the data */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetConfigFromData (
  UINT8 *configData,
  UINTN dataLen
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

  dict = iniParserProtocol->NewIniDictionaryWithData(configData, dataLen);
  if (dict == NULL)
    return EFI_OUT_OF_RESOURCES;

  status = SetRevokeChkConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief RevokeChk config with INI dictionary */
/*! Register this function as a callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
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

  if (!iniParserProtocol->CheckSecPresent(dict, revokeChkSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetRevokeChkConfigFromDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseOCSPToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 useOCSP = GetOcspUsageFlag();

  switch(useOCSP) {
    case USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, useOCSPKey, TRUE);
      break;
    case NOT_USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, useOCSPKey, FALSE);
      break;
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveOCSPUrlToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  CHAR8  *oscpUrl8  = NULL;
  CHAR16 *oscpUrl16 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  oscpUrl16 = GetOcspUrl();
  if (oscpUrl16 == NULL) {
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName,
                                  ocspUrlKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(oscpUrl16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, ocspUrlKey, removeSettingStr);
  } else {
    oscpUrl8 = AllocateZeroPool(StrLen(oscpUrl16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (oscpUrl8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (oscpUrl16, oscpUrl8);
      Status = iniParserProtocol->SetString(dict, revokeChkSectionName, ocspUrlKey, oscpUrl8);
      FreePool(oscpUrl8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveOCSPCertCheckToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  UINT16 useOCSPCert = GetOCSPResponceVerifyUsageFlag();

  switch(useOCSPCert) {
    case USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, crlOCSPChkKey, TRUE);
      break;
    case NOT_USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, crlOCSPChkKey, FALSE);
      break;
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveTlsCrlCheckToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 tlsCertChkMode = GetTLSCrlCheckMode();

  switch(tlsCertChkMode) {
  case DONT_CHECK_CRL:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, tlsCRLcheckKey, CRLnoneStr8);
    break;
  case ALL_CRL_CHECK:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, tlsCRLcheckKey, CRLchainStr8);
    break;
  case CRL_CHECK:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, tlsCRLcheckKey, CRLserverStr8);
    break;
  default:
    Status = EFI_UNSUPPORTED;
    break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUserCrlCheckToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 tlsCertChkMode = GetCrlCheckMode();

  switch(tlsCertChkMode) {
  case DONT_CHECK_CRL:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, userCRLcheckKey, CRLnoneStr8);
    break;
  case ALL_CRL_CHECK:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, userCRLcheckKey, CRLchainStr8);
    break;
  case CRL_CHECK:
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, userCRLcheckKey, CRLserverStr8);
    break;
  default:
    Status = EFI_UNSUPPORTED;
    break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseCdpToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 useCDP = GetLocalCdpUsageFlag();

  switch(useCDP) {
    case USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, useCDPKey, TRUE);
      break;
    case NOT_USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, useCDPKey, FALSE);
      break;
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveCdpCertExtToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 cdpFromCert = GetCDPfromCertUsageFlag();

  switch(cdpFromCert) {
    case USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, cdpFromCertKey, TRUE);
      break;
    case NOT_USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, cdpFromCertKey, FALSE);
      break;
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveCasheCrlToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  UINT16 casheCRL = GetCDPCasheUsageFlag();

  switch(casheCRL) {
    case USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, casheCRLKey, TRUE);
      break;
    case NOT_USE:
      Status = iniParserProtocol->SetBoolean(dict, revokeChkSectionName, casheCRLKey, FALSE);
      break;
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveCdpUrlToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  CHAR8  *cdpUrl8  = NULL;
  CHAR16 *cdpUrl16 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  cdpUrl16 = GetLocalCdpUrl();
  if (cdpUrl16 == NULL) {
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName,
                                  cdpUrlKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(cdpUrl16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, revokeChkSectionName, cdpUrlKey, removeSettingStr);
  } else {
    cdpUrl8 = AllocateZeroPool(StrLen(cdpUrl16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (cdpUrl8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (cdpUrl16, cdpUrl8);
      Status = iniParserProtocol->SetString(dict, revokeChkSectionName, cdpUrlKey, cdpUrl8);
      FreePool(cdpUrl8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
StoreRevokeChkConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status, retval = EFI_SUCCESS;

  Status = ReadRevokeChkConfig();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read RevokeChk config\n", __FUNCTION__, __LINE__));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  Status = SaveUseOCSPToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveOCSPUrlToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveOCSPCertCheckToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveTlsCrlCheckToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveUserCrlCheckToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveUseCdpToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveCdpCertExtToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveCasheCrlToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveCdpUrlToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  if (EFI_ERROR(retval))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Store all revocation check settings to the dictionary */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
DumpRevokeChkConfigToDictionary (
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

  status = StoreRevokeChkConfigToDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief RevokeChk Constructor */
/*! The task of this constructor is to register RevokeChkConfig in the
    GlobalConfigDxe */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
RevokeChkConstructor (
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
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d: Error: status = 0x%x\n", __FUNCTION__, __LINE__, status));
    return status;
  }

  status = pGlobalConfigProtocol->AddConfig(revokeChkSectionName,
                                    SetConfigFromDictionary, DumpRevokeChkConfigToDictionary);

  LOG((EFI_D_ERROR, "%a.%d:  status: 0x%x\n", __FUNCTION__, __LINE__, status));

  return status;
}
//------------------------------------------------------------------------------

