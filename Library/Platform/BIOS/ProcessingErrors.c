/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "ProcessingErrors.h"

#include <Library/Lib/History.h>
#include <Library/Lib/OpensslFunctions.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/BiosLogProtocol.h>

STATIC BIOS_LOG_PROTOCOL *pBiosLogProtocol;

//------------------------------------------------------------------------------
/*! \brief Put a message to BIOS LOG message */
//------------------------------------------------------------------------------
VOID
LogBiosMessage (
  IN UINTN logLevel,
  IN const CHAR8 *subsystem,
  IN const CHAR8 *format,
  ...
)
{
  VA_LIST args;
  CHAR8   buffer[MAX_DEBUG_MESSAGE_LENGTH];

  EFI_STATUS status = EFI_ABORTED;

  VA_START (args, format);

  AsciiVSPrint (buffer, sizeof (buffer), format, args);

  VA_END(args);

  status = gBS->LocateProtocol (&gBiosLogProtocolGuid, NULL, (VOID **) &pBiosLogProtocol);
  if (EFI_ERROR(status))
    return;

  pBiosLogProtocol->PutError(subsystem, buffer);

  return;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Save error code to log and, if needed, show error message */
/*! \param[in] CurrentHiiHandle Hii handle contains form
    \param[in] CurrentLanguage Language (ru, eng, etc)
    \param[in] UsrId User ID for the user in the name of save the log record
    \param[in] messageIfError Flag - show error message or not
    \param[in] chkStatus LdapError Status */
//------------------------------------------------------------------------------
VOID
ShowLdapErrorAndSaveHistory(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN UINT8 UsrId,
  IN BOOLEAN messageIfError,
  IN UINTN chkStatus
  )
{
  switch(chkStatus) {
  case LDAP_SEARCH_SUCCESS:
    // No need to do anything
    return;
  case CANT_MAKE_REQUEST:
    HistoryAddRecord(HEVENT_CANT_MAKE_REQUEST, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_MAKE_LDAP_REQUEST_ERROR),
          CurrentLanguage));
    break;
  case CANT_PROC_LDAP_OPT:
    HistoryAddRecord(HEVENT_CANT_PROC_LDAP_OPT, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS),
          CurrentLanguage));
    break;
  case CANT_INIT_LDAP_SESSION:
    HistoryAddRecord(HEVENT_CANT_INIT_LDAP_SESSION, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS),
          CurrentLanguage));
    break;
  case LDAP_ROOT_ERR_CREDENTIALS:
    HistoryAddRecord(HEVENT_LDAP_ROOT_ERR_CREDENTIALS, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS),
          CurrentLanguage));
    break;
  case CANT_CONNECT_TO_LDAP:
    HistoryAddRecord(HEVENT_LDAP_CONNECT_ERROR, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_CONNECT_ERROR),
          CurrentLanguage));
    break;
  case LDAP_SEARCH_ERROR:
    HistoryAddRecord(HEVENT_LDAP_SEARCH_ERROR, UsrId, SEVERITY_LVL_ERROR, 0);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_CANT_FIND_LDAP_USER), NULL));
    break;
  case LDAP_SERVER_DENY:
    HistoryAddRecord(HEVENT_LDAP_SERVER_DENY , UsrId, SEVERITY_LVL_ERROR, 0);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS), NULL));
    break;
  case LDAP_TOO_MANY_ENTRIES:
    HistoryAddRecord(HEVENT_LDAP_TOO_MANY_USERS , UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TOO_MANY_ENTRIES),
          CurrentLanguage));
    break;
  case LDAP_TLS_CACERTFILE_EMPTY:
    HistoryAddRecord(HEVENT_LDAP_TLS_CACERTFILE_EMPTY , UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TLS_CACERTFILE_EMPTY),
        CurrentLanguage));
    break;
  case LDAP_TLS_CACERTFILE_FAIL:
    HistoryAddRecord(HEVENT_LDAP_TLS_CACERTFILE_FAIL , UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TLS_CACERTFILE_FAIL),
        CurrentLanguage));
    break;
  case LDAP_ERROR_TO_START_TLS:
    HistoryAddRecord(HEVENT_LDAP_START_TLS , UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_TLS_START_ERROR),
        CurrentLanguage));
    break;
  case LDAP_ERROR_TO_GET_PERMIT:
    HistoryAddRecord(HEVENT_LDAP_ERROR_TO_GET_PERMIT , UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(MSG_ERROR_TO_GET_PERMIT),
        CurrentLanguage));
    break;

  case OSSL_ERR_VERIFY_WITH_USER_PKEY:
    HistoryAddRecord(HEVENT_CANT_VERIFY_USER_WITH_PKEY, UsrId, 
        SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError) {
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_VERIFY_USER_WITH_PKEY),NULL));
    }
    break;
  case OSSL_ERR_RUTOKEN_SUPPORT_ERR:
    HistoryAddRecord(HEVENT_ERR_RUTOKEN_SUPPORT_ERR, UsrId, 
        SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError) {
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_RUTOKEN_SUPPORT_ERR),NULL));
    }
    break;
  case LDAP_INTERNAL_ERROR:
  case LDAP_OUT_OF_MEMORY:
  default:
    DEBUG((EFI_D_ERROR, "%a.%d chkStatus: %d\n", __FUNCTION__, __LINE__, chkStatus));
    HistoryAddRecord(HEVENT_LDAP_INTERNAL_ERROR, UsrId, SEVERITY_LVL_ERROR, 1);
    if (TRUE == messageIfError)
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_UNKNOWN_ERROR),
          CurrentLanguage));
    break;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save error code to log and, if needed, show error message */
/*! \param[in] CurrentHiiHandle Hii handle contains form
    \param[in] CurrentLanguage Language (ru, eng, etc)
    \param[in] UsrId User ID for the user in the name of save the log record
    \param[in] messageIfError Flag - show error message or not
    \param[in] verifyStatus LdapError Status */
//------------------------------------------------------------------------------
VOID
ShowVerifyErrorAndSaveHistory(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN UINT8 UsrId,
  IN BOOLEAN messageIfError,
  IN OSSL_STATUS verifyStatus
  )
{
  SaveErrorToHistory(CurrentHiiHandle, CurrentLanguage, UsrId, verifyStatus);
  if (messageIfError == TRUE)
    ShowVerifyError(CurrentHiiHandle, CurrentLanguage, verifyStatus);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a error string by error code */
//------------------------------------------------------------------------------
const CHAR16*
GetLdapErrorStr(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN UINTN chkStatus
  )
{
  switch(chkStatus) {
  case LDAP_SEARCH_SUCCESS:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), "en-US");
  case CANT_MAKE_REQUEST:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_MAKE_LDAP_REQUEST_ERROR), "en-US");
  case CANT_PROC_LDAP_OPT:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS), "en-US");
  case CANT_INIT_LDAP_SESSION:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS), "en-US");
  case LDAP_ROOT_ERR_CREDENTIALS:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS), "en-US");
  case CANT_CONNECT_TO_LDAP:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_CONNECT_ERROR), "en-US");
  case LDAP_SEARCH_ERROR:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CANT_FIND_LDAP_USER), "en-US");
  case LDAP_SERVER_DENY:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS), "en-US");
  case LDAP_TOO_MANY_ENTRIES:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TOO_MANY_ENTRIES), "en-US");
  case LDAP_TLS_CACERTFILE_EMPTY:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TLS_CACERTFILE_EMPTY), "en-US");
  case LDAP_TLS_CACERTFILE_FAIL:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_TLS_CACERTFILE_FAIL), "en-US");
  case LDAP_ERROR_TO_START_TLS:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_TLS_START_ERROR), "en-US");
  case LDAP_ERROR_TO_GET_PERMIT:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(MSG_ERROR_TO_GET_PERMIT), "en-US");
  case LDAP_INTERNAL_ERROR:
  case LDAP_OUT_OF_MEMORY:
  default:
    return HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_UNKNOWN_ERROR), "en-US");
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Show an error message */
//------------------------------------------------------------------------------
VOID
ShowVerifyError(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN OSSL_STATUS verifyStatus
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d OSSL Error: %d\n", __FUNCTION__, __LINE__, verifyStatus));
  switch(verifyStatus) {
    case OSSL_VERIFY_SUCCESS:
      return;
    case OSSL_UNKNOWN_CRL_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_CRL),NULL));
      break;
    case OSSL_UNKNOWN_CERT_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_UNKNOWN_FORMAT_OF_CERTIFICATE),NULL));
      break;
    case OSSL_UNKNOWN_KEY_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_KEY),NULL));
      break;
    case OSSL_UNKNOWN_PKCS7_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_CHAIN),NULL));
      break;
    case OSSL_INVALID_SIGNATURE:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_ERR_CA_SIGN),NULL));
      break;
    case OSSL_CERT_REVOKED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_CERT_REVOKED),NULL));
      break;
    case OSSL_CANT_GET_PKEY_FROM_CERT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_GET_CA_PUBKEY),NULL));
      break;
    case OSSL_INVALID_CRL_SIGNATURE:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_CRL_VERIFY),NULL));
      break;
    case OSSL_PKCS7_NOT_SIGNED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_PKCS7_NOT_SIGNED),NULL));
      break;
    case OSSL_VERIFY_ERROR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_VERIFY_ERROR),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_CRL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_CRL),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_ISSUER_CERT),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY),NULL));
      break;
    case OSSL_CANT_GET_TRUSTED_CERTS:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_GET_TRUSTED_CERTS),NULL));
      break;
    case OSSL_CERT_NOT_YET_VALID:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CERT_NOT_YET_VALID),NULL));
      break;
    case OSSL_CERT_HAS_EXPIRED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CERT_HAS_EXPIRED),NULL));
      break;
    case OSSL_CRL_HAS_EXPIRED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CRL_HAS_EXPIRED),NULL));
      break;
    case OSSL_ERR_UNABLE_TO_GET_CRL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_UNABLE_TO_GET_CRL),NULL));
      break;
    case OSSL_OCSP_URL_ERROR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCPS_URL_ERROR),NULL));
      break;
    case OSSL_OCSP_RESPONSE_VERIFICATION:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_RESPONSE_VERIFICATION),NULL));
      break;
    case OSSL_OCSP_RESPONDER_QUERY_FAILED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_RESPONDER_QUERY_FAILED),NULL));
      break;
    case OSSL_OCSP_CERT_UNKNOWN:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_CERT_UNKNOWN),NULL));
      break;
    case OSSL_ERROR_TO_SAVE_CRL_TO_LOCAL_STACK:
    case OSSL_ERROR_TO_SAVE_BIO:
    case OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CDP_ERROR),NULL));
      break;
    case OSSL_ERR_CANT_GET_SUBJECT_NAME:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_GET_SUBJECT_NAME),NULL));
      break;
    case OSSL_NO_ERROR:
      // No error
      break;
    case OSSL_ERR_VERIFY_WITH_USER_PKEY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_VERIFY_USER_WITH_PKEY),NULL));
      break;
	case OSSL_ERR_RUTOKEN_SUPPORT_ERR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_RUTOKEN_SUPPORT_ERR),NULL));
      break;
    default:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_ERR_INTERNAL),NULL));
      break;
  }

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
VOID
SaveErrorToHistory(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN UINT8 UsrId,
  IN OSSL_STATUS verifyStatus
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d OSSL Error: %d\n", __FUNCTION__, __LINE__, verifyStatus));
  switch(verifyStatus) {
    case OSSL_VERIFY_SUCCESS:
      return;
    case OSSL_UNKNOWN_CRL_FORMAT:
      HistoryAddRecord(HEVENT_UNKNOWN_FORMAT_OF_CRL, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_UNKNOWN_CERT_FORMAT:
      HistoryAddRecord(HEVENT_UNKNOWN_FORMAT_OF_CERT, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_UNKNOWN_KEY_FORMAT:
      HistoryAddRecord(HEVENT_UNKNOWN_KEY_FORMAT, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_UNKNOWN_PKCS7_FORMAT:
      HistoryAddRecord(HEVENT_UNKNOWN_FORMAT_OF_CHAIN, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_INVALID_SIGNATURE:
      HistoryAddRecord(HEVENT_ERR_CA_SIGN, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CERT_REVOKED:
      HistoryAddRecord(HEVENT_ERR_CERT_REVOKED, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CANT_GET_PKEY_FROM_CERT:
      HistoryAddRecord(HEVENT_ERR_GET_CA_PUBKEY, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_INVALID_CRL_SIGNATURE:
      HistoryAddRecord(HEVENT_ERR_CRL_VERIFY, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_PKCS7_NOT_SIGNED:
      HistoryAddRecord(HEVENT_PKCS7_NOT_SIGNED, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_VERIFY_ERROR:
      HistoryAddRecord(HEVENT_VERIFY_ERROR, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERROR_TO_LOAD_CRL:
      HistoryAddRecord(HEVENT_ERROR_TO_LOAD_CRL, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT:
      HistoryAddRecord(HEVENT_ERROR_TO_LOAD_ISSUER_CERT, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY:
      HistoryAddRecord(HEVENT_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CANT_GET_TRUSTED_CERTS:
      HistoryAddRecord(HEVENT_CANT_GET_TRUSTED_CERTS, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CERT_NOT_YET_VALID:
      HistoryAddRecord(HEVENT_CERT_NOT_YET_VALID, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CERT_HAS_EXPIRED:
      HistoryAddRecord(HEVENT_CERT_HAS_EXPIRED, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_CRL_HAS_EXPIRED:
      HistoryAddRecord(HEVENT_CRL_HAS_EXPIRED, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERR_UNABLE_TO_GET_CRL:
      HistoryAddRecord(HEVENT_UNABLE_TO_GET_CRL, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_OCSP_URL_ERROR:
      HistoryAddRecord(HEVENT_OCPS_URL_ERROR, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_OCSP_RESPONSE_VERIFICATION:
      HistoryAddRecord(HEVENT_OCSP_RESPONSE_VERIFICATION, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_OCSP_RESPONDER_QUERY_FAILED:
      HistoryAddRecord(HEVENT_OCSP_RESPONDER_QUERY_FAILED, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_OCSP_CERT_UNKNOWN:
      HistoryAddRecord(HEVENT_OCSP_CERT_UNKNOWN, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERROR_TO_SAVE_CRL_TO_LOCAL_STACK:
    case OSSL_ERROR_TO_SAVE_BIO:
    case OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN:
      HistoryAddRecord(HEVENT_CDP_ERROR, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERR_CANT_GET_SUBJECT_NAME:
      HistoryAddRecord(HEVENT_ERR_INTERNAL, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_ERR_VERIFY_WITH_USER_PKEY:
      HistoryAddRecord(HEVENT_CANT_VERIFY_USER_WITH_PKEY, UsrId, 
        SEVERITY_LVL_ERROR, 1);
      break;
	case OSSL_ERR_RUTOKEN_SUPPORT_ERR:
      HistoryAddRecord(HEVENT_ERR_RUTOKEN_SUPPORT_ERR, UsrId, 
        SEVERITY_LVL_ERROR, 1);
      break;
    case OSSL_NO_ERROR:
      // No error
      break;
    default:
      HistoryAddRecord(HEVENT_ERR_INTERNAL, UsrId, SEVERITY_LVL_ERROR, 1);
      break;
  }

  return;
}
//------------------------------------------------------------------------------

