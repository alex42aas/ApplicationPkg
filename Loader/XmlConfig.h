/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __XML__CONFIG__H
#define __XML__CONFIG__H


#include <Guid/GlobalVariable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/UnicodeCollation.h>
#include <Library/FsUtils.h>
#include <Library/XmlParser.h>
#include <MultibootDesc.h>

/* Card part type */
enum {
  TYPE_ERROR = 0,
  TYPE_QUESTION,
  TYPE_ANSWER
};

/* The maximum size of an element that is to be returned through the
   feed callback fn */
#define DEF_XMLBUFSZ 1024
//#define DEF_LOAD_MAX 128
//#define BSIZE 1024 /* txt buffer size */

enum {
  ST_BASE = 0,       
  ST_GLOBAL,
  ST_TIMEOUT,    
  ST_DEFAULT,    
  ST_INTERACTIVE,
  ST_LANGUAGE,
  ST_ENTRY,
  ST_FSDEV,
  ST_PCIDA,
  ST_OBJDESC,
  ST_NAME,       
  ST_ID,
  ST_FORM_ID,
  ST_TYPE,
  ST_MNITEM,
  ST_MODULE,     
  ST_BASEADDRESS,
  ST_UNCOMPRESS,
  ST_KERNEL,
  ST_KBASEADDRESS,
  ST_KENTRYPOINT,
  ST_KUNCOMPRESS,
  ST_KHASH,
  ST_DEVPATH,
  ST_PARAMS,
  ST_HASH,
  ST_GUID,
  ST_EGUID,
  ST_KDEVPATH,
  ST_KPARAMS,
  ST_KGUID,
  ST_FORM,
  ST_FGUID,
  ST_PLATFORM_GUID,
  ST_PLATFORM_NAME,
  ST_TITLE,
  ST_TOKENDEVPATH,
  ST_MN_LIST,
  ST_HELP,
  ST_SECURE_GRAY,
  ST_DEF_USER,
  ST_USR_NAME,
  ST_USR_FIO,
  ST_USR_INFO,
  ST_PASSHASH,
  ST_DGST,
  ST_WORK_MODE,
  ST_FILTER_STR,
  ST_ERROR_TAG
};


typedef struct _CONFIG_STATE_TABLE{
  UINT32 State;
  CHAR8* Name; /* tag or attr name; may be null */
  UINT32 Length;
  UINT32 Event;
  UINT32 Next;
  UINT32 Emit; /* true if we must emit element */
} CONFIG_STATE_TABLE;


INTN
EFIAPI
StringNoCaseCompare (
  IN  CHAR16             *Buffer1,
  IN  CHAR16             *Buffer2
  );

EFI_STATUS 
ParseConfig( 
  CHAR8            *Text8, 
  UINT32           Length,
  UINT32           State,
  UINT32           NextState, 
  UINT32           Emit,
  MULTIBOOT_CONFIG *Config
  );

/* simpler than dealing with strcasecmp and more efficient as we only
   need to fold the incoming text */
#define FOLD(c) ((c < 'A' || c > 'Z') ? c : (c + 'a' - 'A'))

static int ConfigCallback(
  int event,
  const char* txt, 
  int len,
  void* user);


/**
  Read the EFI variable (VendorGuid/Name) and return a dynamically allocated
  buffer, and the size of the buffer. If failure return NULL.

  @param  Name                  String part of EFI variable name
  @param  VendorGuid            GUID part of EFI variable name
  @param  VariableSize          Returns the size of the EFI variable that was read

  @return                       Dynamically allocated memory that contains a copy of the EFI variable
  Caller is responsible freeing the buffer.
  @retval NULL                  Variable was not read

 **/
VOID *
EFIAPI
MultibootGetVariableAndSize (
  IN  CHAR16              *Name,
  IN  EFI_GUID            *VendorGuid,
  OUT UINTN               *VariableSize
  );

EFI_STATUS
XmlConfigRead(
  IN OUT MULTIBOOT_CONFIG *Config,
  IN CHAR8 *ConfigTest,
  IN UINTN Size
  );

#endif	/* #ifndef __XML__CONFIG__H */
