/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __BOOT__XML__CFG__H
#define __BOOT__XML__CFG__H

#include <Protocol/UnicodeCollation.h>
#include <Library/XmlParser.h>
#include <Library/BootMngrLib.h>
#include "BootManager.h"


enum {
  ST_BASE = 0,
  ST_BOOT_CONF,
  ST_CONF_GUID,
  ST_CONF_TYPE,
  ST_BOOT_TYPE,
  ST_MODULE,
  ST_DEVPATH,
  ST_PARAMS,
  ST_MOD_HASH,
  ST_ICFL,
  ST_ENTRY,
  ST_FILE,
  ST_HASH,
  ST_ERROR_TAG
};


typedef struct _CONFIG_STATE_TABLE{
  UINT32 State;
  CHAR16 *Name; /* tag or attr name; may be null */
  UINT32 Length;
  UINT32 Event;
  UINT32 Next;
  UINT32 Emit; /* true if we must emit element */
} CONFIG_STATE_TABLE;


EFI_STATUS 
ParseConfig16( 
  IN CHAR16 *Text16, 
  IN UINT32 Length,
  IN UINT32 State,
  IN UINT32 NextState, 
  IN UINT32 Emit,
  IN LIST_ENTRY *IcflList,
  IN CBCFG_DATA_SET *DataSet
  );

/* simpler than dealing with strcasecmp and more efficient as we only
   need to fold the incoming text */
#define FOLD(c) ((c < 'A' || c > 'Z') ? c : (c + 'a' - 'A'))


EFI_STATUS
Xml16ConfigRead(
  IN CHAR16 *ConfigTest,
  IN UINTN Size
  );

#endif /* #ifndef __BOOT__XML__CFG__H */

