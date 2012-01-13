/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/DebugLib.h>
#include <Library/MultibootDescUtils.h>
#include <Library/AdvMenu/AdvMenu.h>
#include <Library/BIOSLib/vfrdata.h>
#include <Library/TokenViewerLib/AdvTokenViewerMenu.h>

#include <Protocol/AdvMenuHandlerProto.h>

#include "TokenViewerInternals.h"

extern EFI_STRING_ID AdvMenuStrings[];

extern EFI_GUID gTokenSelectCertVarGuid;

static ADV_MENU_HANDLER_PROTOCOL *pAdvMenuHandlerProto;

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)  DEBUG(MSG)
#endif

//------------------------------------------------------------------------------
/*! \brief Make subject menu entry for the given certificate */
/*! \param[in] *title A title of parameter
    \param[in] *certificateInfo A pointer on the certificate
    \param[in] entryIndex
    \param[out] **entry Menu entry */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeActionEntryForCertSubject(
  IN CHAR16 *title,
  IN CERT_T *certificateInfo,
  IN UINTN   entryIndex,
  OUT MULTIBOOT_ENTRY **entry
)
{
  UINTN offset;

  if (entry == NULL || *entry != NULL ||
    certificateInfo == NULL || certificateInfo->certInfo == NULL)
    return EFI_INVALID_PARAMETER;

  *entry = AllocateZeroPool(sizeof(MULTIBOOT_ENTRY));
  if (*entry == NULL)
    return EFI_OUT_OF_RESOURCES;

  StrCpy((*entry)->Name, title);

  offset = StrLen(title);

  if (StrLen(certificateInfo->certInfo->certCN) > MULTIBOOT_MAX_STRING - offset)
    StrnCpy((*entry)->Name + offset, certificateInfo->certInfo->certCN, MULTIBOOT_MAX_STRING - offset);
  else
    StrCpy((*entry)->Name + offset, certificateInfo->certInfo->certCN);

  (*entry)->MenuItemType = MenuItemAction;

  (*entry)->Index = entryIndex;
  certificateInfo->menuCertId = entryIndex;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make issuer menu entry for the given certificate */
/*! \param[in] *title
    \param[in] *param A pointer to the parameter string
    \param[in] entryIndex An index of the new entry
/*! \param[out] **entry Menu entry */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeEntryForAdditionalParam(
  IN CHAR16 *title,
  IN CHAR16 *param,
  IN UINTN entryIndex,
  OUT MULTIBOOT_ENTRY **entry
)
{
  CHAR16 tmpStr[] = L" -- ";

  UINTN offset, tmpLen;

  if (entry == NULL || *entry != NULL)
    return EFI_INVALID_PARAMETER;

  *entry = AllocateZeroPool(sizeof(MULTIBOOT_ENTRY));
  if (*entry == NULL)
    return EFI_OUT_OF_RESOURCES;

  StrCpy((*entry)->Name, title);

  offset = StrLen(title);

  if (param != NULL) {
    if (StrLen(param) > MULTIBOOT_MAX_STRING - offset)
      StrnCpy((*entry)->Name + offset, param, MULTIBOOT_MAX_STRING - offset);
    else
      StrCpy((*entry)->Name + offset, param);
  } else {
    tmpLen = StrLen(tmpStr);

    if (tmpLen > MULTIBOOT_MAX_STRING - offset)
      StrnCpy((*entry)->Name + offset, tmpStr, MULTIBOOT_MAX_STRING - offset);
    else
      StrCpy((*entry)->Name + offset, tmpStr);
  }

  (*entry)->MenuItemType = MenuItemEmptyAction;
  (*entry)->Index        = entryIndex;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make TokenViewer menu */
/*! \param[in] HiiHandle A handle with resources
    \param[in] *config A pointer to multiboot config
    \param[in] stringIDs[5] An array of menu strings IDs
    \param[in] *certList A list of certificates
    \param[in] certCount A count of certificates in the list */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeTokenViewerMenu (
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  IN CERT_T *certList,
  IN UINTN   certCount
)
{
  UINTN count, entryIndex = ADVANCED_MODE_START_QID;

  EFI_STATUS Status = EFI_ABORTED;
  MULTIBOOT_FORM *Form;
  EFI_GUID formGuid = ADV_TOKEN_VIEWER_FORM_GUID;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Form = GetFormByGuid(config, &formGuid);
  if (NULL == Form) {
    LOG((EFI_D_ERROR, "%a.%d Can't find TokenViewer form\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  ClearForm(Form);  // We want to remake form, so clear it first

  for(count = 0; count < certCount; count++) {
    MULTIBOOT_ENTRY *EntryCN = NULL;
    MULTIBOOT_ENTRY *EntryIssuer = NULL;
    MULTIBOOT_ENTRY *EntryNotBefore = NULL;
    MULTIBOOT_ENTRY *EntryNotAfter = NULL;
    MULTIBOOT_ENTRY *EntrySerial = NULL;

    if (certList == NULL || certList->certInfo == NULL)
      break;

    Status = MakeActionEntryForCertSubject(HiiGetString(HiiHandle,AdvMenuStrings[CERT_SUBJECT], NULL),
                                           certList,
                                           entryIndex,
                                           &EntryCN);
    if (EFI_ERROR(Status))
      goto _exit;

    InitializeListHead( &EntryCN->ModuleHead );
    InsertTailList( &Form->EntryHead, &EntryCN->ListEntry );
    entryIndex++;

    Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_ISSUER], NULL),
                                         certList->certInfo->certIssuer,
                                         entryIndex,
                                         &EntryIssuer);

    InitializeListHead( &EntryIssuer->ModuleHead );
    InsertTailList( &Form->EntryHead, &EntryIssuer->ListEntry );
    entryIndex++;

    Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_NOT_BEFORE], NULL),
                                         certList->certInfo->notBefore,
                                         entryIndex,
                                         &EntryNotBefore);

    InitializeListHead( &EntryNotBefore->ModuleHead );
    InsertTailList( &Form->EntryHead, &EntryNotBefore->ListEntry );
    entryIndex++;

    Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_NOT_AFTER], NULL),
                                         certList->certInfo->notAfter,
                                         entryIndex,
                                         &EntryNotAfter);

    InitializeListHead( &EntryNotAfter->ModuleHead );
    InsertTailList( &Form->EntryHead, &EntryNotAfter->ListEntry );
    entryIndex++;

    Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_SERIAL], NULL),
                                         certList->certInfo->serial,
                                         entryIndex,
                                         &EntrySerial);

    InitializeListHead( &EntrySerial->ModuleHead );
    InsertTailList( &Form->EntryHead, &EntrySerial->ListEntry );
    entryIndex++;

    certList++;

  }

_exit:
  if (EFI_ERROR(Status))
    ClearForm(Form);

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ID of a certificate on token by menu item ID */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
GetTokenCertIdByMenuCertId(
  OUT    UINT8  *selectedId,
  IN OUT UINTN  *lengthOfId,
  IN     CERT_T *certList,
  IN     UINTN   certCount,
  IN     UINTN   selectMenuCertId
)
{
  UINTN i = 0;
  BOOLEAN isFound = FALSE;
  EFI_STATUS Status = EFI_ABORTED;

  if (selectedId == NULL || certList == NULL || certCount == 0 || *lengthOfId == 0)
    return EFI_INVALID_PARAMETER;

  for(i = 0; i < certCount; i++) {
    LOG((EFI_D_ERROR, "menuCertId: 0x%X, selectMenuCertId: 0x%X\n", certList->menuCertId, selectMenuCertId));
    if (certList->menuCertId == selectMenuCertId) {
      if (certList->lenId <= *lengthOfId) {
        CopyMem(selectedId, certList->certId, certList->lenId);
        *lengthOfId = certList->lenId;
      } else
        CopyMem(selectedId, certList->certId, *lengthOfId);

      LOG((EFI_D_ERROR, "%a.%d CertId:\n", __FUNCTION__, __LINE__));
      DumpBytes(selectedId, certList->lenId);
      LOG((EFI_D_ERROR, "\n"));

      isFound = TRUE;
      break;
    }
    certList++;
    
  }

  if (isFound == FALSE)
    Status = EFI_ABORTED;
  else
    Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Main TokenViewer procedure */
/*! \param[in] HiiHandle A handle with resources
    \param[in] *config Multiboot config
    \param[out] *selectedId An ID of the selected certificate
    \param[out] *lengthOfId A length of ID */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessTokenViewer (
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  OUT UINT8 *selectedId,
  OUT UINTN *lengthOfId
)
{
  EFI_STATUS Status;

  CERT_T *certList  = NULL;
  UINTN   certCount = 0, size = 0;
  UINTN   selectMenuCertId = 0;

  STATIC UINT16 dumpVar = 0;

  EFI_GUID formGuid = ADV_TOKEN_VIEWER_FORM_GUID;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = GetCertListFromToken(&certList, &certCount);
  if (EFI_ERROR(Status) || (certList == NULL) || (certCount == 0)) {
    LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = RegisterAdvMenu(&AdvMenuStrings[0]);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  Status = gBS->LocateProtocol ( &gAdvMenuHandlerProtocolGuid, NULL, (VOID**)&pAdvMenuHandlerProto);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  Status = MakeTokenViewerMenu(HiiHandle, config, certList, certCount);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  // Clear variable before start token viewer menu
  Status = gRT->SetVariable(
                TOKEN_SELECT_CERT_VAR_NAME,
                &gTokenSelectCertVarGuid,
                EFI_VARIABLE_BOOTSERVICE_ACCESS,
                sizeof(dumpVar),
                &dumpVar
                );

  pAdvMenuHandlerProto->SetupCfgData(pAdvMenuHandlerProto, config, HiiHandle);
  Status = pAdvMenuHandlerProto->ShowMenu(pAdvMenuHandlerProto, &formGuid);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  size = sizeof(selectMenuCertId);

  // get variable with selected certificate ID
  gRT->GetVariable(TOKEN_SELECT_CERT_VAR_NAME,
                   &gTokenSelectCertVarGuid,
                   NULL,
                   &size,
                   &selectMenuCertId);

  Status = GetTokenCertIdByMenuCertId(selectedId,
                                      lengthOfId,
                                      certList,
                                      certCount,
                                      selectMenuCertId);
_exit:

  if (certList != NULL)
    FreeCertList(certList, certCount);

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

