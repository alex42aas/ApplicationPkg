/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __SOME__COMPILER__FIXES__H
#define __SOME__COMPILER__FIXES__H

// Some tweaks for the Microsoft compiler
//
#if defined _MSC_VER
#if !defined inline
#define inline __inline
#endif
#endif

/**
  Defines alignment attribute specification

  @param   align      The value to round up.

  @return  Not applicable
  
**/
#if defined(__GNUC__)
#  define ALIGN(Align) __attribute__((aligned(Align)))
#elif defined _MSC_VER
#  define ALIGN(Align) __declspec(align(Align))
#else
#  error "Alignment attribute specification is not defined for this compiler/architecture"
#endif


#endif	/* #ifndef __SOME__COMPILER__FIXES__H */
