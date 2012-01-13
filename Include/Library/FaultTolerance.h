/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __FAULT__TOLERANCE__H
#define __FAULT__TOLERANCE__H

#include <Library/CommonUtils.h>


#define FT_INTEGRITY_ERR              0x01
#define FT_SERVICE_CONF_ERR           0x02
#define FT_BIOS_INTEGRITY_ERR         0x03
#define FT_CTRL_APP_RUN_ERR           0xFE
#define FT_OS_RUN_ERR                 0xFF

#define FT_MAX_LOAD_COUNTER           65535


EFI_STATUS
FtUpdateLoadCounter(
  VOID
  );
  
EFI_STATUS
FtGetLoadCounter(
  IN OUT UINT8 *LoadCounter
  );

EFI_STATUS
FtGetStatus(
  IN OUT UINT8 *VarStatus
  );
  
EFI_STATUS
FtSetStatus(
  IN UINT8 VarStatus
  );  


#endif	/* #ifndef __FAULT__TOLERANCE__H */
