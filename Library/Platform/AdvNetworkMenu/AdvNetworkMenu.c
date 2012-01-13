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
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/NetSetupLib/DnsSetup.h>

#include <Library/AdvNetworkMenu/AdvNetworkMenu.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Library/BIOSLib/History.h>

//------------------------------------------------------------------------------
/*! \brief Read DNS adresses from the variable for a specified element */
/*! Use this function to initialize DNS addresses */
/*! \param[in] QuestionId ID of the element that keeps DNS address */
/*! \return Code of Error */
//------------------------------------------------------------------------------
EFI_STATUS
ReadResolvConf( 
  IN EFI_QUESTION_ID QuestionId
)
{
  switch(QuestionId) {
  case ENTER_DNS_SERVER_1:
    ReadDnsAddrFromVar(PRIMARY_DNS);
    break;
  case ENTER_DNS_SERVER_2:
    ReadDnsAddrFromVar(SECONDARY_DNS);
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete DNS address */
/*! Each DNS address in the temp variable is associated with a form element */
/*! \param[in] QuestionId ID of element, which DNS address we want to delete */
//------------------------------------------------------------------------------
VOID
FlushDnsAddr(
  IN EFI_QUESTION_ID QuestionId
)
{
  switch(QuestionId) {
  case ENTER_DNS_SERVER_1:
    FlushDnsAddrFromVar(PRIMARY_DNS);
    break;
  case ENTER_DNS_SERVER_2:
    FlushDnsAddrFromVar(SECONDARY_DNS);
    break;
  }

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a data to the Value of the element */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which Value we want to set
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return EFI_SUCCESS if success, code of the error otherwise */
//------------------------------------------------------------------------------
EFI_STATUS
FillAdvNetworkFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  CHAR16  *recvString16 = (CHAR16*)Value;
  CHAR16  *dnsServer = NULL;

  if (recvString16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  switch(QuestionId) {
  case ENTER_DNS_SERVER_1:
    dnsServer = GetDnsAddr(PRIMARY_DNS);
    if (dnsServer != NULL) {
      StrnCpy(recvString16, dnsServer, MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_DNS_SERVER_2:
    dnsServer = GetDnsAddr(SECONDARY_DNS);
    if (dnsServer != NULL) {
      StrnCpy(recvString16, dnsServer, MAX_INPUT_AREA_SIZE);
    }
    break;

  default:
    // NOP. Unknown QuestionId.
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from Advanced Network Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest An action request to the top level of the AdvMenu */
/*! \return Code of error */
/*! \retval EFI_SUCCESS Success of the operation */
/*! \retval EFI_INVALID_PARAMETER */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessAdvNetworkFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  EFI_STRING_ID StrId = Value->string;
  CHAR16 *recvString16 = NULL;
  EFI_STATUS Status;

  if (QuestionId != SAVE_CONFIG) {
    if (StrId == (EFI_STRING_ID)0) {
      DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }

    recvString16 = HiiGetString(This->GetHiiHandle(This), StrId, NULL);
    if (recvString16 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
  }

  switch(QuestionId){
  case ENTER_DNS_SERVER_1:
    SetDnsAddr(recvString16, PRIMARY_DNS);
    break;
  case ENTER_DNS_SERVER_2:
    SetDnsAddr(recvString16, SECONDARY_DNS);
    break;
  case SAVE_CONFIG:
    Status = SaveResolvConf();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_EXT_NETWORK_CFG_CHANGED, 
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    if (EFI_SUCCESS == Status) {
      ShowSuccessPopup(This->GetHiiHandle(This),
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_SUCCESS),
        NULL));
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    } else {
      ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_ERROR),
        NULL));
    }
    break;
  default:
    // NOP. Unknown QuestionId.
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

