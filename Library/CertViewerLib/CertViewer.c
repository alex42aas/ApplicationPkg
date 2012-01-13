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
#include <Library/Lib/OpensslFunctions.h>
#include <Library/Lib/Vfrdata.h>
#include <Library/AdvMenu/AdvMenu.h>
#include <Library/CertViewerLib/CertViewer.h>
#include <Library/CertViewerLib/AdvCertViewerMenu.h>

#include <Protocol/AdvMenuHandlerProto.h>

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)  DEBUG(MSG)
#endif

extern EFI_STRING_ID AdvMenuStrings[];

STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;
STATIC ADV_MENU_HANDLER_PROTOCOL *pAdvMenuHandlerProto;

//------------------------------------------------------------------------------
/*! \brief Make subject menu entry for the given certificate */
/*! \param[in] *title A title of parameter
    \param[in] *certificateInfo A pointer on the certificate
    \param[in] entryIndex
    \param[out] **entry Menu entry */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeActionEntryForSubject(
  IN CHAR16 *title,
  IN OSSL_CERT_INFO_T *certificateInfo,
  IN INT32 entryIndex,
  OUT MULTIBOOT_ENTRY **entry
)
{
  UINTN offset;

  if (entry == NULL || *entry != NULL || certificateInfo == NULL)
    return EFI_INVALID_PARAMETER;

  *entry = AllocateZeroPool(sizeof(MULTIBOOT_ENTRY));
  if (*entry == NULL)
    return EFI_OUT_OF_RESOURCES;

  StrCpy((*entry)->Name, title);

  offset = StrLen(title);

  if (StrLen(certificateInfo->certCN) > MULTIBOOT_MAX_STRING - offset)
    StrnCpy((*entry)->Name + offset, certificateInfo->certCN, MULTIBOOT_MAX_STRING - offset);
  else
    StrCpy((*entry)->Name + offset, certificateInfo->certCN);

  (*entry)->MenuItemType = MenuItemAction;
  (*entry)->Index        = entryIndex;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make parameter menu entry for the given certificate */
/*! \param[in] *title A title of the parameter
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
/*! \brief make a set of menu entries */
/*! \param[in] HiiHandle A handle with recources
    \param[in] *Form A multiboot form
    \param[in] certInfo A certificate info
    \param[in] *entryIndex  Menu entry index */
//------------------------------------------------------------------------------
EFI_STATUS
MakeEntrySetForCertificate(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_FORM *Form,
  IN OSSL_CERT_INFO_T *certInfo,
  IN INT32 *entryIndex
)
{
  EFI_STATUS Status = EFI_ABORTED;

  MULTIBOOT_ENTRY *EntryCN = NULL;
  MULTIBOOT_ENTRY *EntryIssuer = NULL;
  MULTIBOOT_ENTRY *EntryNotBefore = NULL;
  MULTIBOOT_ENTRY *EntryNotAfter = NULL;
  MULTIBOOT_ENTRY *EntrySerial = NULL;

  Status = MakeActionEntryForSubject(HiiGetString(HiiHandle,AdvMenuStrings[CERT_SUBJECT], NULL),
                                     certInfo,
                                     *entryIndex,
                                     &EntryCN);
  if (EFI_ERROR(Status))
    return Status;

  InitializeListHead( &EntryCN->ModuleHead );
  InsertTailList( &Form->EntryHead, &EntryCN->ListEntry );
  (*entryIndex)++;

  Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_ISSUER], NULL),
                                       certInfo->certIssuer,
                                       *entryIndex,
                                       &EntryIssuer);

  InitializeListHead( &EntryIssuer->ModuleHead );
  InsertTailList( &Form->EntryHead, &EntryIssuer->ListEntry );
  (*entryIndex)++;

  Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_NOT_BEFORE], NULL),
                                       certInfo->notBefore,
                                       *entryIndex,
                                       &EntryNotBefore);

  InitializeListHead( &EntryNotBefore->ModuleHead );
  InsertTailList( &Form->EntryHead, &EntryNotBefore->ListEntry );
  (*entryIndex)++;

  Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_NOT_AFTER], NULL),
                                       certInfo->notAfter,
                                       *entryIndex,
                                       &EntryNotAfter);

  InitializeListHead( &EntryNotAfter->ModuleHead );
  InsertTailList( &Form->EntryHead, &EntryNotAfter->ListEntry );
  (*entryIndex)++;

  Status = MakeEntryForAdditionalParam(HiiGetString(HiiHandle,AdvMenuStrings[CERT_SERIAL], NULL),
                                       certInfo->serial,
                                       *entryIndex,
                                       &EntrySerial);

  InitializeListHead( &EntrySerial->ModuleHead );
  InsertTailList( &Form->EntryHead, &EntrySerial->ListEntry );
  (*entryIndex)++;

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create CertViewer menu in the config */
/*! Try to find form in the config by GUID and add GUI entries in it */
/*! \param[in] HiiHandle A handle with recources
    \param[in] config MULTIBOOT_CONFIG contains CertViewer form
    \param[in] chainData Chain binary data
    \param[in] chainDataLen Chain binary data length */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeChainViewerMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
  )
{
  INT32 certCount = 0, i;
  INT32 entryIndex = ADVANCED_MODE_START_QID;

  EFI_STATUS Status = EFI_ABORTED;
  MULTIBOOT_FORM *Form;
  EFI_GUID formGuid = ADV_CERT_VIEWER_FORM_GUID;

  if (pOpenSSLProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gOpenSSLProtocolGuid,
                    NULL,
                    (VOID **) &pOpenSSLProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }

  certCount = pOpenSSLProtocol->GetCertificateCountFromChain(chainData, chainDataLen);
  if (certCount == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG ((EFI_D_ERROR, "%a.%d certCount: %d\n", __FUNCTION__, __LINE__, certCount));

  Form = GetFormByGuid(config, &formGuid);
  if (NULL == Form) {
    LOG((EFI_D_ERROR, "%a.%d Can't find CerViewer form\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
    }

  ClearForm(Form);  // We want to remake form, so clear it first

  for(i = 0; i < certCount; i++) {
    OSSL_CERT_INFO_T *certInfo = NULL;

    Status = pOpenSSLProtocol->GetCertificateInfoFromChain(chainData, chainDataLen, i, &certInfo);
    if (certInfo == NULL || EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      goto _exit;
    }

    Status = MakeEntrySetForCertificate(HiiHandle, Form, certInfo, &entryIndex);

    pOpenSSLProtocol->FreeCertInfo(certInfo);

    if (EFI_ERROR(Status)) {
      ClearForm(Form);
      break;
    }
  }

_exit:

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeCertViewerMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  IN CHAR8 *certData,
  IN UINTN certDataLen
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  MULTIBOOT_FORM *Form;
  EFI_GUID formGuid = ADV_CERT_VIEWER_FORM_GUID;

  OSSL_CERT_INFO_T *certInfo = NULL;

  INT32 entryIndex = ADVANCED_MODE_START_QID;

  if (pOpenSSLProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gOpenSSLProtocolGuid,
                    NULL,
                    (VOID **) &pOpenSSLProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }

  Form = GetFormByGuid(config, &formGuid);
  if (NULL == Form) {
    LOG((EFI_D_ERROR, "%a.%d Can't find CerViewer form\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
    }

  ClearForm(Form);  // We want to remake form, so clear it first

  Status = pOpenSSLProtocol->GetCertificateInfoFromCertBinary(certData, certDataLen, &certInfo);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  }

  Status = MakeEntrySetForCertificate(HiiHandle, Form, certInfo, &entryIndex);

  pOpenSSLProtocol->FreeCertInfo(certInfo);
  
  LOG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Main certificate viewer procedure */
/*! \param[in] HiiHandle A handle with recources
    \param[in] *config A multiboot config
    \param[in] type A type of object (chain/certificate)
    \param[in] *objectData An object binary
    \param[in] objectDataLen A length of the binary */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessCertViewer(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  IN OBJECT_T type,
  IN CHAR8 *objectData,
  IN UINTN objectDataLen
  )
{
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  EFI_GUID formGuid = ADV_CERT_VIEWER_FORM_GUID;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = RegisterAdvMenu(&AdvMenuStrings[0]);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = gBS->LocateProtocol ( &gAdvMenuHandlerProtocolGuid, NULL, (VOID**)&pAdvMenuHandlerProto);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  switch(type) {
  case P7B_CHAIN:
    Status = MakeChainViewerMenu(HiiHandle, config, objectData, objectDataLen);
    break;

  case CERT_OBJ:
    Status = MakeCertViewerMenu(HiiHandle, config, objectData, objectDataLen);
    break;

  case CRL_OBJ:
  default:
    return EFI_UNSUPPORTED;
    break;
  }

  if (!EFI_ERROR(Status)) {
    pAdvMenuHandlerProto->SetupCfgData(pAdvMenuHandlerProto, config, HiiHandle);
    Status = pAdvMenuHandlerProto->ShowMenu(pAdvMenuHandlerProto, &formGuid);
  }

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

