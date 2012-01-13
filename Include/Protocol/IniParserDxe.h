/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef INI_PARSER_DXE_H
#define INI_PARSER_DXE_H

#include <Uefi/UefiBaseType.h>

/*-------------------------------------------------------------------------*/
/**
  @brief Dictionary object

  This object contains a list of string/string associations. Each
  association is identified by a unique string key. Looking up values
  in the dictionary is speeded up by the use of a (hopefully collision-free)
  hash function.
 */
/*-------------------------------------------------------------------------*/
typedef struct _dictionary_ {
	int            n ;  /** Number of entries in dictionary */
	int         size ;  /** Storage size */
	char       **val ;  /** List of string values */
	char       **key ;  /** List of string keys */
	unsigned   *hash ;  /** List of hash values for keys */
} dictionary ;

typedef struct _INI_PARSER_PROTOCOL INI_PARSER_PROTOCOL;

typedef
dictionary*
(EFIAPI *INI_GET_DICTIONARY_WITH_DATA) (
  IN UINT8 *data,
  IN UINTN sizeOfData
  );

typedef
EFI_STATUS
(EFIAPI *DUMP_INI_DICTIONARY_TO_DATA) (
  IN dictionary *iniDict,
  IN UINT8 **data,
  IN UINTN *sizeOfData
  );

typedef
dictionary*
(EFIAPI *INI_NEW_EMPTY_DICTIONARY) (
  VOID
  );

typedef
dictionary*
(EFIAPI *INI_NEW_DICTIONARY) (
  IN CHAR8 *filePath
  );

typedef
VOID
(EFIAPI *INI_DELETE_DICTIONARY) (
  IN dictionary *iniDict
  );

typedef
EFI_STATUS
(EFIAPI *INI_GET_BOOLEAN) (
    IN dictionary *iniDict,
    IN CHAR8 *section,
    IN CHAR8 *key,
    OUT BOOLEAN *result
  );


typedef
CHAR8*
(EFIAPI *INI_GET_STRING) (
    IN dictionary *iniDict,
    IN CHAR8 *section,
    IN CHAR8 *key
  );


typedef
EFI_STATUS
(EFIAPI *INI_GET_INTEGER) (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  OUT INT32 *resultInt
  );

typedef
EFI_STATUS
(EFIAPI *INI_GET_DOUBLE) (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  OUT double *resultDouble
  );

typedef
EFI_STATUS
(EFIAPI *INI_SET_BOOLEAN) (
    IN dictionary *iniDict,
    IN CHAR8 *section,
    IN CHAR8 *key,
    IN BOOLEAN valBool
  );


typedef
EFI_STATUS
(EFIAPI *INI_SET_STRING) (
    IN dictionary *iniDict,
    IN CHAR8 *section,
    IN CHAR8 *key,
    IN CHAR8* valStr
  );


typedef
EFI_STATUS
(EFIAPI *INI_SET_INTEGER) (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN INT32 valInt
  );

typedef
EFI_STATUS
(EFIAPI *INI_SET_DOUBLE) (
  IN dictionary *iniDict,
  IN CHAR8 *section,
  IN CHAR8 *key,
  IN double valDouble
  );

typedef
BOOLEAN
(EFIAPI *INI_CHECK_SEC_PRESENT) (
  IN dictionary *IniDict,
  IN CHAR8 *Section
  );

/*! Sruct of the INI parser protocol */
struct _INI_PARSER_PROTOCOL {
  INI_GET_DICTIONARY_WITH_DATA NewIniDictionaryWithData;
  DUMP_INI_DICTIONARY_TO_DATA  DumpIniDictionaryToData;

  INI_NEW_EMPTY_DICTIONARY NewEmptyIniDictionary;      //!< Create empty dictionary
  INI_NEW_DICTIONARY     NewIniDictionary;      //!< Get dictionary for the specified INI file
  INI_DELETE_DICTIONARY  DeleteIniDictionary;   //!< Delete dictionary

  INI_GET_BOOLEAN        GetBoolean;            //!< Get bool value for specified key in section
  INI_GET_STRING         GetString;             //!< Get string value for specified key in section
  INI_GET_INTEGER        GetInteger;            //!< Get integer value for specified key in section
  INI_GET_DOUBLE         GetDouble;             //!< Get double value for specified key in section

  INI_SET_BOOLEAN        SetBoolean;            //!< Set bool value for specified key in section
  INI_SET_STRING         SetString;             //!< Set string value for specified key in section
  INI_SET_INTEGER        SetInteger;            //!< Set integer value for specified key in section
  INI_SET_DOUBLE         SetDouble;             //!< Set double value for specified key in section
  INI_CHECK_SEC_PRESENT  CheckSecPresent;
};

extern EFI_GUID gIniParserDxeProtocolGuid;

#endif
