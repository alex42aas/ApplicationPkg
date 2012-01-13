/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef AUTH_MODE_CONFIG_INTERNAL_H_
#define AUTH_MODE_CONFIG_INTERNAL_H_

#define CMP_TYPE_NUM   3      //!< Max number of types
#define CMP_TITLE_LEN 10      //!< Lenght of a type's name (title)

/** \name Masks in the authMode field*/
#define MODE_MASK         0x01  //!< First bit
#define LDAP_USAGE_MASK   0x02  //!< Second bit
#define LOCAL_USAGE_MASK  0x04  //!< Third bit
#define USER_PC_LINK_MASK 0x08  //!< Fourth bit

#define AUTH_MODE_OFFS    0x00  //!< No need to shift
#define LDAP_USAGE_OFFS   0x01  //!< Shift to one position (bit)
#define LOCAL_USAGE_OFFS  0x02  //!< Shift to two positions (bits)
#define USER_PC_LINK_OFFS 0x03  //!< Shift to three positions (bits)

/*! \brief Type of a comparison */
typedef struct {
  CHAR16 cmpTitle[CMP_TITLE_LEN];   //!< Title, e.x. "CN="
  UINT8  cmpMask;                   //!< A type of a comparison
  } CMP_TYPE;

/** \name A blob of a comparison data */
typedef struct {
  UINT8   type;              //!< A type of a comparison
  UINTN   dataSize;          //!< A size of a data
  CHAR16 *dataBody[1];       //!< A body of a data
} CMP_DATA;

/** \name A config of a auth mode */
typedef struct AUTH_MODE_CONFIG_T{
  UINT8    authMode;            //!< Auth mode (e.x. Default or Guest), ldap usage status
  UINT8    cmpType;             //!< A type of comparison data
  CMP_DATA data[CMP_TYPE_NUM];
} AUTH_MODE_CONFIG;

extern EFI_GUID gIniParserDxeProtocolGuid;

#endif // AUTH_MODE_CONFIG_INTERNAL_H_
