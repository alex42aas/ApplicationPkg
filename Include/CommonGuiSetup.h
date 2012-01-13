/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef COMMON_GUI_SETUP_H_
#define COMMON_GUI_SETUP_H_

/*! Min and max size of an input size of a string */
#define MIN_INPUT_AREA_SIZE 0                 //!< Min size of an input area of a string element
#define MAX_INPUT_AREA_SIZE 255               //!< Max size of an input area of a string element

/*! Min and max size of an input size of a password */
#define PASSWORD_MIN_LEN    0                 //!< Min size of an input area of a password element
#define PASSWORD_MAX_LEN    20                //!< Max size of an input area of a password element

/*! Flags for a string OpCode */
#define EFI_IFR_STRING_NUMERIC         0x02   //!< Flag: Allow to input numeric characters only
#define EFI_IFR_STRING_NUMERIC_DOT     0x04   //!< Flag: Allow to input numeric characters and dot character only

#define EFI_BROWSER_ACTION_HIDE        0x05   //!< Hide an element of a form

#endif