/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ETOKEN__JAVA__H
#define __ETOKEN__JAVA__H

EFI_STATUS
eTokenJavaEncryptPin (
  IN UINT8 *Pin,
  IN UINTN PinSize,
  IN UINT8 *Salt,
  IN UINTN SaltSize,
  IN UINT8 *Challendge,
  IN OUT UINT8 *Response
  );


UINTN
eTokenJavaCountCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen
  );

EFI_STATUS
eTokenJavaFindCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenJavaDirectory (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenJavaGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenJavaGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenJavaChallendge (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8 *Challendge
  );

EFI_STATUS
eTokenJavaVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  );


EFI_STATUS
eTokenJavaLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  );

EFI_STATUS
eTokenJavaSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  );

EFI_STATUS
eTokenJavaReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  );

EFI_STATUS
eTokenJavaGetSN (
  IN SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenJavaEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenJavaEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  );


#endif /* #ifndef __ETOKEN__JAVA__H */

