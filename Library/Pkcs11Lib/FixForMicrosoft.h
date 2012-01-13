/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __FIX_FOR_MICROSOFT__
#define __FIX_FOR_MICROSOFT__

/* Getting the code Microsoft-compatible macros are provided below */

/* Set the base for the initialization finction name */
#define FFM_INIT_FUN_NAME_BASE init

/* Initializers */

/* The main initialization macro that is invoked for initialization
   of a non-array automatic structure variable as follows:

  FFM_INITIALIZE_AUTO (
    ASN1_TAG_INFO, // Typename (storage class is always auto)
    TI,            // Variable name
    4,             // The number of fields to be initialized
    (              // Initialization of fields in C99 manner
      .SucNum.Suc = CK_FALSE,
      .Tag        = ASN1_NO_TAG,
      .Pld        = P,
      .Len        = L // <-- No comma here!
    ) // <-- No comma here!
  ); // <-- Here must be a semicolon!

*/

#if defined _MSC_VER

/* Hacking C89-style-emulating-C99-one initialization for Microsoft */
#define FFM_INITIALIZE_AUTO(typename_, varname_, initnum_, initers_) \
  auto typename_ \
  varname_ = ( \
    FFM_ROW_2 ( \
      FFM_HACKING_LIST##initnum_, ( \
        varname_, FFM_SIMPLE_LIST_##initnum_ initers_ \
      ) \
    ) \
  )

#else /* _MSC_VER */

/* Normal C99-style initialization */
#define FFM_INITIALIZE_AUTO(typename_, varname_, initnum_, initers_) \
  auto typename_ \
  varname_ = { \
    FFM_SIMPLE_LIST_##initnum_ initers_ \
  }

#endif /* _MSC_VER */

/* The main initialization macro that is invoked for initialization
   of a non-array global structure variable, which type may be qualified by
   the simple (non-function) CONST macro at the time of invocation, as follows:

FFM_INITIALIZE (
  static ASN1_PRIM_TYPE_DEF, // Storage class/typename
  ASN1_BooleanPrim,          // Variable name
  4,                         // The number of fields to be initialized
  (                          // Initialization of fields in C99 manner
    .Type                = ASN1_BOOLEAN_PRIM_TYPE,
    .Tag                 = ASN1_BOOLEAN_TAG,
    .Constraints.Len.Min = 0,
    .Constraints.Len.Max = 0 // <-- No comma here!
  )
) // <-- No semicolon here!

*/

#define FFM_INITIALIZE(type_, name_, parn_, init_) \
  type_ CONST name_ FFM_PRECODE \
  FFM_ROW_2 (FFM_PARAM_##parn_, (name_, , FFM_SIMPLE_LIST_##parn_ init_)) \
  FFM_POSTCODE

/* The main initialization macro that is invoked for initialization
   of as an array global structure variable, which type may be qualified by
   the simple (non-function) CONST macro at the time of invocation, as follows:

FFM_INITIALIZE_ARRAY (
  static ASN1_PRIM_TYPE_DEF,   // Storage class/typename
  ASN1_BooleanArrPrim,         // Variable name
  2,                           // The number of array elements
  4,                           // The number of element fields to be initialized
  (                            // Initialization of fields written in C99 manner
    (                          // The first array element:
      .Type                = ASN1_BOOLEAN_PRIM_TYPE,
      .Tag                 = ASN1_BOOLEAN_TAG,
      .Constraints.Len.Min = 0,
      .Constraints.Len.Max = 0 // <-- No comma here!
    ), // <-------------------------- Here must be a comma!
    (                          // The second array element:
      .Type                = ASN1_BOOLEAN_PRIM_TYPE,
      .Tag                 = ASN1_BOOLEAN_TAG,
      .Constraints.Len.Min = 0,
      .Constraints.Len.Max = 0 // <-- No comma here!
    ) // <--------------------------- No comma here too!
  )
) // <-- No semicolon here!

*/

#define FFM_INITIALIZE_ARRAY(type_, name_, arrn_, parn_, init_) \
  type_ CONST name_ [arrn_] FFM_PRECODE \
  FFM_ROW_2 (FFM_ARRAY_##arrn_, (name_, parn_, FFM_SIMPLE_LIST_##arrn_ init_)) \
  FFM_POSTCODE

/* Subsidiary macros providing difference between compiler flavors */
#if defined _MSC_VER
#define FFM_PRECODE  ; static VOID INIT_FUN_NAME(VOID) {
#define FFM_POSTCODE ; }
#define FFM_FIELD(name_, p_) name_ p_
#else
#define FFM_PRECODE  = {
#define FFM_POSTCODE } ;
#define FFM_FIELD(name_, p_) p_
#endif

/* Macros for concatenation of parameters */
#define FFM_ROW_2(x_, y_) \
  x_ y_

/* Definitely needed once CPP has no recursion */
#define FFM_ARR_ROW_2(x_, y_) \
  x_ y_

/* Simple listers */
#define FFM_SIMPLE_LIST_0()

#define FFM_SIMPLE_LIST_1(p1_) \
  p1_

#define FFM_SIMPLE_LIST_2(p1_, p2_) \
  p1_, p2_

#define FFM_SIMPLE_LIST_3(p1_, p2_, p3_) \
  p1_, p2_, p3_

#define FFM_SIMPLE_LIST_4(p1_, p2_, p3_, p4_) \
  p1_, p2_, p3_, p4_

#define FFM_SIMPLE_LIST_5(p1_, p2_, p3_, p4_, p5_) \
  p1_, p2_, p3_, p4_, p5_

#define FFM_SIMPLE_LIST_6(p1_, p2_, p3_, p4_, p5_, p6_) \
  p1_, p2_, p3_, p4_, p5_, p6_

#define FFM_SIMPLE_LIST_7(p1_, p2_, p3_, p4_, p5_, p6_, p7_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_

#define FFM_SIMPLE_LIST_8(p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_

#define FFM_SIMPLE_LIST_9(p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_

#define FFM_SIMPLE_LIST_10(p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_

#define FFM_SIMPLE_LIST_11(p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_

#define FFM_SIMPLE_LIST_12(p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_, p12_) \
  p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_, p12_

/* Hacking listers */
#define FFM_HACKING_LIST0(v_) \
, v_

#define FFM_HACKING_LIST1(v_, p0_) \
v_ p0_, v_

#define FFM_HACKING_LIST2(v_, p0_, p1_) \
v_ p0_, v_ p1_, v_

#define FFM_HACKING_LIST3(v_, p0_, p1_, p2_) \
v_ p0_, v_ p1_, v_ p2_, v_

#define FFM_HACKING_LIST4(v_, p0_, p1_, p2_, p3_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_

#define FFM_HACKING_LIST5(v_, p0_, p1_, p2_, p3_, p4_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_

#define FFM_HACKING_LIST6(v_, p0_, p1_, p2_, p3_, p4_, p5_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_

#define FFM_HACKING_LIST7(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_

#define FFM_HACKING_LIST8(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_, p7_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_ p7_, v_

#define FFM_HACKING_LIST9(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_ p7_, v_ p8_, v_

#define FFM_HACKING_LIST10(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_ p7_, v_ p8_, v_ p9_, v_

#define FFM_HACKING_LIST11(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_ p7_, v_ p8_, v_ p9_, v_ p10_, v_

#define FFM_HACKING_LIST12(v_, p0_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_) \
v_ p0_, v_ p1_, v_ p2_, v_ p3_, v_ p4_, v_ p5_, v_ p6_, v_ p7_, v_ p8_, v_ p9_, v_ p10_, v_ p11_, v_

/* Initialization/assignment listers */
#define FFM_PARAM_0(name_, arr_, p1_)

#define FFM_PARAM_1(name_, arr_, p1_) \
  FFM_FIELD (name_, arr_ p1_)

#define FFM_PARAM_2(name_, arr_, p1_, p2_) \
  FFM_PARAM_1 (name_, arr_, p1_), \
  FFM_PARAM_1 (name_, arr_, p2_)

#define FFM_PARAM_3(name_, arr_, p1_, p2_, p3_) \
  FFM_PARAM_2 (name_, arr_, p1_, p2_), \
  FFM_PARAM_1 (name_, arr_, p3_)

#define FFM_PARAM_4(name_, arr_, p1_, p2_, p3_, p4_) \
  FFM_PARAM_3 (name_, arr_, p1_, p2_, p3_), \
  FFM_PARAM_1 (name_, arr_, p4_)

#define FFM_PARAM_5(name_, arr_, p1_, p2_, p3_, p4_, p5_) \
  FFM_PARAM_4 (name_, arr_, p1_, p2_, p3_, p4_), \
  FFM_PARAM_1 (name_, arr_, p5_)

#define FFM_PARAM_6(name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_) \
  FFM_PARAM_5 (name_, arr_, p1_, p2_, p3_, p4_, p5_), \
  FFM_PARAM_1 (name_, arr_, p6_)

#define FFM_PARAM_7(name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_, p7_) \
  FFM_PARAM_6 (name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_), \
  FFM_PARAM_1 (name_, arr_, p7_)

#define FFM_PARAM_8(name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_) \
  FFM_PARAM_7 (name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_, p7_), \
  FFM_PARAM_1 (name_, arr_, p8_)

#define FFM_PARAM_9(name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_) \
  FFM_PARAM_8 (name_, arr_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_), \
  FFM_PARAM_1 (name_, arr_, p9_)

/* Initialization/assignment array listers */
#define FFM_ARRAY_1(name_, parn_, p1_) \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [0], FFM_SIMPLE_LIST_##parn_ p1_))

#define FFM_ARRAY_2(name_, parn_, p1_, p2_) \
  FFM_ARRAY_1 (name_, parn_, p1_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [1], FFM_SIMPLE_LIST_##parn_ p2_))

#define FFM_ARRAY_3(name_, parn_, p1_, p2_, p3_) \
  FFM_ARRAY_2 (name_, parn_, p1_, p2_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [2], FFM_SIMPLE_LIST_##parn_ p3_))

#define FFM_ARRAY_4(name_, parn_, p1_, p2_, p3_, p4_) \
  FFM_ARRAY_3 (name_, parn_, p1_, p2_, p3_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [3], FFM_SIMPLE_LIST_##parn_ p4_))

#define FFM_ARRAY_5(name_, parn_, p1_, p2_, p3_, p4_, p5_) \
  FFM_ARRAY_4 (name_, parn_, p1_, p2_, p3_, p4_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [4], FFM_SIMPLE_LIST_##parn_ p5_))

#define FFM_ARRAY_6(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_) \
  FFM_ARRAY_5 (name_, parn_, p1_, p2_, p3_, p4_, p5_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [5], FFM_SIMPLE_LIST_##parn_ p6_))

#define FFM_ARRAY_7(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_) \
  FFM_ARRAY_6 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [6], FFM_SIMPLE_LIST_##parn_ p7_))

#define FFM_ARRAY_8(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_) \
  FFM_ARRAY_7 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [7], FFM_SIMPLE_LIST_##parn_ p8_))

#define FFM_ARRAY_9(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_) \
  FFM_ARRAY_8 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [8], FFM_SIMPLE_LIST_##parn_ p9_))

#define FFM_ARRAY_10(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_) \
  FFM_ARRAY_9 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [9], FFM_SIMPLE_LIST_##parn_ p10_))

#define FFM_ARRAY_11(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_) \
  FFM_ARRAY_10 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [10], FFM_SIMPLE_LIST_##parn_ p11_))

#define FFM_ARRAY_12(name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_, p12_) \
  FFM_ARRAY_11 (name_, parn_, p1_, p2_, p3_, p4_, p5_, p6_, p7_, p8_, p9_, p10_, p11_), \
  FFM_ARR_ROW_2 (FFM_PARAM_##parn_, (name_, [11], FFM_SIMPLE_LIST_##parn_ p12_))

/* Auxiliary glue macros */
#define _GLUE(x_, y_, z_) x_ ## y_ ## z_
#define GLUE(x_, y_, z_)  _GLUE (x_, y_, z_)

#else /* __FIX_FOR_MICROSOFT__ */

/* Multiple inclusion section starts here */

/* There are two commands to process: 'next fun name' and 'invoke funs' */
#if defined FFM_CMD_NEXT_FUN_NAME || defined FFM_CMD_INVOKE_FUNS

#ifndef FIX_FOR_MICROSOFT

#error The FIX_FOR_MICROSOFT macro MUST be defined before
#error including "FixForMicrosoft.h" as follows:
#error #define FIX_FOR_MICROSOFT "FixForMicrosoft.h"
#error and later "FixForMicrosoft.h" should be included as follows:
#error #include FIX_FOR_MICROSOFT

#else /* FIX_FOR_MICROSOFT */

/* Generate the next function name command */
#if defined FFM_CMD_NEXT_FUN_NAME

/* Check overflow */
#if defined FFM_CMD_NEXT_FUN_NAME_DIGIT_2 && \
            FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 999
#error Internal error: Too many initialization functions (> 999)
#else

#if ! defined FFM_CMD_NEXT_FUN_NAME_ACTION
#define FFM_CMD_NEXT_FUN_NAME_ACTION 0
#endif

#if FFM_CMD_NEXT_FUN_NAME_ACTION == 0 /* Increment the digit 0 */

#if ! defined FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 0

#else /* FFM_CMD_NEXT_FUN_NAME_DIGIT_0 */

#if FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 0
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 1
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 1
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 2
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 2
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 3
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 3
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 4
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 4
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 5
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 5
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 6
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 6
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 7
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 7
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 8
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 8
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 9
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == 9
#undef FFM_CMD_NEXT_FUN_NAME_ACTION
#define FFM_CMD_NEXT_FUN_NAME_ACTION 1
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_NEXT_FUN_NAME_ACTION
#else
#error Internal error: FFM_CMD_NEXT_FUN_NAME_DIGIT_0 has wrong value (0 through 9 are valid)
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_0 == N */

#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_0 */

/* Define INIT_FUN_NAME with the next initialization function name */
#undef INIT_FUN_NAME
#define INIT_FUN_NAME GLUE ( \
                        FFM_INIT_FUN_NAME_BASE,           \
                        _,                                \
                        GLUE (                            \
                          FFM_CMD_NEXT_FUN_NAME_DIGIT_2, \
                          FFM_CMD_NEXT_FUN_NAME_DIGIT_1, \
                          FFM_CMD_NEXT_FUN_NAME_DIGIT_0  \
                          )                               \
                        )

#elif FFM_CMD_NEXT_FUN_NAME_ACTION == 1 /* Increment the digit 1 */

#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 0

#if ! defined FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 0
#else
#if FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 0
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 1
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 1
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 2
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 2
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 3
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 3
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 4
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 4
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 5
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 5
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 6
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 6
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 7
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 7
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 8
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 8
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 9
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == 9
#undef FFM_CMD_NEXT_FUN_NAME_ACTION
#define FFM_CMD_NEXT_FUN_NAME_ACTION 2
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_NEXT_FUN_NAME_ACTION
#else
#error Internal error: FFM_CMD_NEXT_FUN_NAME_DIGIT_1 has wrong value (0 through 9 are valid)
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_1 == N */
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_1 */

#elif FFM_CMD_NEXT_FUN_NAME_ACTION == 2 /* Incrementing the digit 2 */

#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_0
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_0 0
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_1
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_1 0

#if ! defined FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 0
#else
#if FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 0
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 1
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 1
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 2
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 2
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 3
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 3
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 4
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 4
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 5
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 5
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 6
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 6
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 7
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 7
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 8
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 8
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 9
#elif FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 9
#undef FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#define FFM_CMD_NEXT_FUN_NAME_DIGIT_2 999 /* The next attempt would lead to overflow */
#else
#error Internal error: FFM_CMD_NEXT_FUN_NAME_DIGIT_2 has wrong value (0 through 9 are valid)
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == N */
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_2 */

#else
#error Internal error: invalid FFM_CMD_NEXT_FUN_NAME_ACTION value
#endif /* FFM_CMD_NEXT_FUN_NAME_ACTION == N */

#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_2 && FFM_CMD_NEXT_FUN_NAME_DIGIT_2 == 999 */

#undef FFM_CMD_NEXT_FUN_NAME_ACTION

#elif defined FFM_CMD_INVOKE_FUNS /* FFM_CMD_INVOKE_FUNS */

/* Invoke all the functions the names are generated for */

#if defined FFM_CMD_NEXT_FUN_NAME_DIGIT_0 /* There are generations */

#if ! defined FFM_CMD_NEXT_FUN_NAME_DIGIT_1 || \
    ! defined FFM_CMD_NEXT_FUN_NAME_DIGIT_2
#error Internal error: FFM_CMD_NEXT_FUN_NAME_DIGIT_1 and/or FFM_CMD_NEXT_FUN_NAME_DIGIT_2 are undefined
#endif

#if ! defined FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 0
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 0
#endif

#if ! defined FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 2
#endif

#if FFM_CMD_INVOKE_FUNS_DIGIT_2 < FFM_CMD_NEXT_FUN_NAME_DIGIT_2 || \
    (FFM_CMD_INVOKE_FUNS_DIGIT_2 == FFM_CMD_NEXT_FUN_NAME_DIGIT_2 && \
     (FFM_CMD_INVOKE_FUNS_DIGIT_1 < FFM_CMD_NEXT_FUN_NAME_DIGIT_1 || \
      (FFM_CMD_INVOKE_FUNS_DIGIT_1 == FFM_CMD_NEXT_FUN_NAME_DIGIT_1 && \
       FFM_CMD_INVOKE_FUNS_DIGIT_0 <= FFM_CMD_NEXT_FUN_NAME_DIGIT_0)))

#if FFM_CMD_INVOKE_FUNS_ACTION == 3 /* Action == 3 */

/* Form invocation of the next initialization function */
GLUE (FFM_INIT_FUN_NAME_BASE, _, GLUE (
                                   FFM_CMD_INVOKE_FUNS_DIGIT_2,
                                   FFM_CMD_INVOKE_FUNS_DIGIT_1,
                                   FFM_CMD_INVOKE_FUNS_DIGIT_0
                                   ))();

#elif FFM_CMD_INVOKE_FUNS_ACTION == 2 /* Action == 2 */

#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 0
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 1
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 2
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 3
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 4
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 5
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 6
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 7
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 8
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#define FFM_CMD_INVOKE_FUNS_DIGIT_2 9
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 1
#undef FFM_CMD_INVOKE_FUNS_DIGIT_2
#undef FFM_CMD_INVOKE_FUNS_ACTION

#elif FFM_CMD_INVOKE_FUNS_ACTION == 1 /* Action == 1 */

#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 0
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 1
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 2
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 3
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 4
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 5
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 6
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 7
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 8
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 0
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 9
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_DIGIT_1
#define FFM_CMD_INVOKE_FUNS_DIGIT_1 0

#elif FFM_CMD_INVOKE_FUNS_ACTION == 0 /* Action == 2 */

#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 0
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 1
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 2
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 3
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 4
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 5
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 6
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 7
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 8
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_ACTION
#define FFM_CMD_INVOKE_FUNS_ACTION 3
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 9
#include FIX_FOR_MICROSOFT
#undef FFM_CMD_INVOKE_FUNS_DIGIT_0
#define FFM_CMD_INVOKE_FUNS_DIGIT_0 0

#else
#error Internal error: invalid FFM_CMD_INVOKE_FUNS_ACTION value
#endif /* FFM_CMD_INVOKE_FUNS_ACTION == N */
#endif /* FFM_CMD_INVOKE_FUNS_DIGIT_210 <= FFM_CMD_NEXT_FUN_NAME_DIGIT_210 */
#endif /* FFM_CMD_NEXT_FUN_NAME_DIGIT_0 */

#endif /* FFM_CMD_NEXT_FUN_NAME_ACTION == 0 */

#endif /* FFM_CMD_NEXT_FUN_NAME */

#endif /* FIX_FOR_MICROSOFT */

#endif /* FFM_CMD_NEXT_FUN_NAME || defined FFM_CMD_INVOKE_FUNS */
