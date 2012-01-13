/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _CONFIG_FROM_GRT_H
#define _CONFIG_FROM_GRT_H

extern EFI_GUID gResolvConfVarGuid;

extern const BOOLEAN ResolvConfFromGRT;

#define RESOLV_CONF_VAR_LEN    100 //!< Max lenght of the ResolvConf variable

#define RESOLV_CONF_VAR_NAME L"ResolvConf"

#define DEFAULTRESOLV_CONF "nameserver \nnameserver "

#endif