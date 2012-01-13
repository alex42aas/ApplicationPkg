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
#include <Library/MemoryAllocationLib.h>
#include <Library/FsUtils.h>

#include <InternalErrDesc.h>

#include <Protocol/IniParserDxe.h>
#include <Protocol/LoadedImage.h>

#include "IniParserDxeInternal.h"

#include "src/iniparser.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

#define DEFAULT_INI_FILE_LEN   512
#define DEFAULT_DICT_SIZE      64

STATIC CHAR8 delimiter[] = ":";
STATIC CHAR8 notFoundStr[] = "NOT_FOUND";

STATIC int notFoundValue = -1; // int and boolean values

STATIC INI_PARSER_INTERNAL_DATA gIniParserInternalData;

//------------------------------------------------------------------------------
/*! \brief Make Sector:Key string for the parser */
/*! This is STATIC function, so we don't check *section and *key for NULL */
//------------------------------------------------------------------------------
STATIC
CHAR8*
MakeKeyString (
  IN CHAR8 *section,
  IN CHAR8 *key
)
{
  CHAR8 *keyStr = NULL, *StartStr = NULL;

  keyStr = AllocateZeroPool(AsciiStrLen(section) + AsciiStrLen(delimiter)
             + AsciiStrLen(key) + sizeof(CHAR8));
  if (key == NULL)
    return NULL;

  StartStr = keyStr;

  AsciiStrCpy(keyStr, section);
  keyStr += AsciiStrLen(section);
  AsciiStrCpy(keyStr, delimiter);
  keyStr += AsciiStrLen(delimiter);
  AsciiStrCpy(keyStr, key);

  return StartStr;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create empty dictionary without data */
/*! \return New dictionary, has been created */
//------------------------------------------------------------------------------
dictionary*
NewEmptyIniDictionary (
  VOID
)
{
  dictionary *newDict = dictionary_new(DEFAULT_DICT_SIZE);

  return newDict;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create new dictionary with data */
/*! \param[in] *data A pointer to the data
    \param[in] sizeOfData Size of data */
/*! \return New dictionary, has been created with data */
//------------------------------------------------------------------------------
dictionary*
NewIniDictionaryWithData (
  IN UINT8 *data,
  IN UINTN sizeOfData
)
{
  dictionary *newDict = iniparser_load_from_data(data, sizeOfData);

  return newDict;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Dump ini dictionary to allocated buffer */
/*! \param[out] *data A pointer to the data
    \param[out] sizeOfData Size of data */
/*! \return EFI_STATUS of operation */
//------------------------------------------------------------------------------
EFI_STATUS
DumpIniDictionaryToData (
  IN dictionary *iniDict,
  IN UINT8 **data,
  IN UINTN *sizeOfData
)
{
  VOID *DataBuf = NULL;
  UINTN DataBufLen = DEFAULT_INI_FILE_LEN;
  int UsedDataBufLen = 0;
  int Ret;

  do {
    DataBuf = AllocateZeroPool(DataBufLen);
    if (DataBuf == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    UsedDataBufLen = (int)DataBufLen;
    Ret = iniparser_dump_ini_to_data(iniDict, DataBuf, &UsedDataBufLen);
    if (Ret == -1) {
      FreePool(DataBuf);
      return EFI_ABORTED;
    } else if (Ret == 0) {
      FreePool(DataBuf);
      DataBufLen += DEFAULT_INI_FILE_LEN;
      continue;
    } else {
      break;
    }
  } while(TRUE);

  *data = (UINT8 *)DataBuf;
  *sizeOfData = (UINTN)UsedDataBufLen;
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create new dictionary from INI file */
/*! \param[in] *filePath path to INI file */
/*! \return New dictionary, has been created with data from INI file */
//------------------------------------------------------------------------------
dictionary*
NewIniDictionary (
  IN CHAR8 *filePath
)
{
  dictionary *newDict = iniparser_load(filePath);

  return newDict;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete dictionary */
/*! \param[in] *dictToDel Dictionary to delete */
//------------------------------------------------------------------------------
VOID
DeleteIniDictionary (
  dictionary *dictToDel
)
{
  iniparser_freedict(dictToDel);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get boolean value for specified key from section */
/*! If EFI_ERROR(Status) result is not specified */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[out] *result Result value */
/*! \retval Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
GetBoolean (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  OUT BOOLEAN *result
)
{
  CHAR8 *keyStr = NULL;
  EFI_STATUS status = EFI_INVALID_PARAMETER;
  int keyValue;

  if (iniDict == NULL || section == NULL ||
      key == NULL || result == NULL)
    return EFI_INVALID_PARAMETER;

  keyStr = MakeKeyString(section, key);
  if (keyStr == NULL)
    return EFI_OUT_OF_RESOURCES;

  keyValue = iniparser_getboolean(iniDict, keyStr, notFoundValue);
  if (keyValue == notFoundValue)
    status = EFI_NOT_FOUND;
  else if (keyValue == 0) {
    status = EFI_SUCCESS;
    *result = FALSE;
  } else {
    status = EFI_SUCCESS;
    *result = TRUE;
  }

  if (keyStr != NULL)
    FreePool(keyStr);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get string value for specified key from section */
/*! This string is just a pointer from the dictionary. Don't free this pointer! */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name */
//------------------------------------------------------------------------------
CHAR8*
GetString (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key
)
{
  CHAR8 *keyStr = NULL, *resultStr = NULL;

  if (iniDict == NULL || section == NULL || key == NULL)
    return NULL;

  keyStr = MakeKeyString(section, key);
  if (keyStr == NULL)
    return NULL;

  resultStr = iniparser_getstr(iniDict, keyStr);

  if (keyStr != NULL)
    FreePool(keyStr);

  return resultStr;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get integer value for specified key from section */
/*! value -1 is reserved */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[out] *Status Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
GetInteger (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  OUT INT32 *resultInt
)
{
  CHAR8 *keyStr = NULL;
  EFI_STATUS status = EFI_INVALID_PARAMETER;

  if (iniDict == NULL || section == NULL || key == NULL || resultInt == NULL)
    return EFI_INVALID_PARAMETER;

  keyStr = MakeKeyString(section, key);

  *resultInt = iniparser_getint(iniDict, keyStr, notFoundValue);
  if (*resultInt == notFoundValue)
    status = EFI_NOT_FOUND;
  else
    status = EFI_SUCCESS;

  if (keyStr != NULL)
    FreePool(keyStr);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get double value for specified key from section */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[out] *Status Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
GetDouble (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  OUT double *resultDouble
)
{
  return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set boolean value for specified key from section */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[in] value to set */
/*! \retval Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
SetBoolean (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN BOOLEAN valBool
)
{
  CHAR8 *keyStr = NULL;

  if (iniDict == NULL || section == NULL ||
      key == NULL)
    return EFI_INVALID_PARAMETER;

  keyStr = MakeKeyString(section, key);
  if (keyStr == NULL)
    return EFI_OUT_OF_RESOURCES;

  if (valBool) {
    iniparser_setint(iniDict, keyStr, 1);
  } else {
    iniparser_setint(iniDict, keyStr, 0);
  }

  if (keyStr != NULL)
    FreePool(keyStr);

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set string value for specified key from section */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name */
//------------------------------------------------------------------------------
EFI_STATUS
SetString (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN CHAR8* valStr
)
{
  int result;
  CHAR8 *keyStr = NULL;
  UINTN valLen;
  CHAR8 *valQuotesStr = NULL;

  if (iniDict == NULL || section == NULL || key == NULL || valStr == NULL)
    return EFI_INVALID_PARAMETER;

  keyStr = MakeKeyString(section, key);
  if (keyStr == NULL)
    return EFI_OUT_OF_RESOURCES;

  valLen = AsciiStrLen(valStr);
  if (valStr[0] == '\"' || valStr[valLen-1] == '\"') {
    valQuotesStr = valStr;
  } else {
    valQuotesStr = AllocatePool(valLen + 3);
    if (valQuotesStr == NULL) {
      if (keyStr != NULL)
        FreePool(keyStr);
      return EFI_OUT_OF_RESOURCES;
    }
    AsciiSPrint(valQuotesStr, valLen + 3, "\"%a\"", valStr);
  }

  result = iniparser_setstr(iniDict, keyStr, valQuotesStr);

  if (keyStr != NULL) {
    FreePool(keyStr);
  }
  if (valQuotesStr != valStr) {
    FreePool(valQuotesStr);
  }

  if (result == 0) {
    return EFI_SUCCESS;
  } else {
    return EFI_ABORTED;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set integer value for specified key from section */
/*! value -1 is reserved */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[out] *Status Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
SetInteger (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN INT32 valInt
)
{
  CHAR8 *keyStr = NULL;

  if (iniDict == NULL || section == NULL || key == NULL)
    return EFI_INVALID_PARAMETER;

  keyStr = MakeKeyString(section, key);
  if (keyStr == NULL)
    return EFI_OUT_OF_RESOURCES;


  iniparser_setint(iniDict, keyStr, valInt);

  if (keyStr != NULL)
    FreePool(keyStr);

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set double value for specified key from section */
/*! \param[in] *iniDict A pointer to the dictionary
    \param[in] *section Section name
    \param[in] *key Key name
    \param[out] *Status Status of operation */
//------------------------------------------------------------------------------
EFI_STATUS
SetDouble (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN double valDouble
)
{
  return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Init FsUtils for StdLib is used by IniParserDxe */
//------------------------------------------------------------------------------
STATIC VOID
InitFsUtilsForStdLib(
  IN EFI_HANDLE ImageHandle
  )
{
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *pDp;
  CHAR16 *PathString;

  if (AllocFsDescTable(10) == -1) {
    MsgInternalError(INT_ERR_ALLOC_FS_DESC_TABLE_ERROR);
  }

  gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);

  pDp = DevicePathFromHandle(ImageInfo->DeviceHandle);
  PathString = DevPathToString(pDp, FALSE, TRUE);
  LOG(( EFI_D_ERROR, "-*-> %S\n", PathString ));
  AddFsDescTableItem(L"fv", PathString, FALSE);

  return;
}
//------------------------------------------------------------------------------


char * strlwc(const char * s);

BOOLEAN
EFIAPI
CheckSecPresent (
  IN dictionary *IniDict,
  IN CHAR8 *Section
  )
{
  int nsec, Idx;
  char *secname;

  if (IniDict == NULL || Section == NULL) {
    return FALSE;
  }
  
  nsec = iniparser_getnsec(IniDict);
  if (nsec == 0) {
    return FALSE;
  }

  for (Idx = 0; Idx < nsec; Idx++) {
    secname = iniparser_getsecname(IniDict, Idx);
    if (secname == NULL) {
      continue;
    }
    if (AsciiStrCmp((CHAR8*)strlwc(Section),(CHAR8*)secname) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}


//------------------------------------------------------------------------------
/*! \brief Entry point of the INI parser DXE driver */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
IniParserDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitFsUtilsForStdLib(ImageHandle);

  ZeroMem(&gIniParserInternalData, sizeof(gIniParserInternalData));

  gIniParserInternalData.IniParserPtotocol.NewEmptyIniDictionary = NewEmptyIniDictionary;
  gIniParserInternalData.IniParserPtotocol.NewIniDictionaryWithData = NewIniDictionaryWithData;
  gIniParserInternalData.IniParserPtotocol.DumpIniDictionaryToData = DumpIniDictionaryToData;

  gIniParserInternalData.IniParserPtotocol.NewIniDictionary    = NewIniDictionary;
  gIniParserInternalData.IniParserPtotocol.DeleteIniDictionary = DeleteIniDictionary;

  gIniParserInternalData.IniParserPtotocol.GetBoolean       = GetBoolean;
  gIniParserInternalData.IniParserPtotocol.GetString        = GetString;
  gIniParserInternalData.IniParserPtotocol.GetInteger       = GetInteger;
  gIniParserInternalData.IniParserPtotocol.GetDouble        = GetDouble;

  gIniParserInternalData.IniParserPtotocol.SetBoolean       = SetBoolean;
  gIniParserInternalData.IniParserPtotocol.SetString        = SetString;
  gIniParserInternalData.IniParserPtotocol.SetInteger       = SetInteger;
  gIniParserInternalData.IniParserPtotocol.SetDouble        = SetDouble;
  gIniParserInternalData.IniParserPtotocol.CheckSecPresent  = CheckSecPresent;

  Status  = gBS->InstallProtocolInterface(
              &gIniParserInternalData.DriverHandle,
              &gIniParserDxeProtocolGuid,
              EFI_NATIVE_INTERFACE,
              &gIniParserInternalData.IniParserPtotocol
              );

  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

