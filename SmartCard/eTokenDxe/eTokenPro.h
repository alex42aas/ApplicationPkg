/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ETOKEN__PRO__H
#define __ETOKEN__PRO__H

UINTN
eTokenPro42bCountCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen
  );

EFI_STATUS
eTokenPro42bFindCertsInDirData (
  IN UINT8 *DirData,
  IN UINTN DirDataLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenPro42bDirectory (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenPro42bGetObjectsList (
  IN SMART_CARD_PROTOCOL *This,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenPro42bGetObjectValById(
  IN SMART_CARD_PROTOCOL *This,
  IN UINT8 *Id,
  IN UINTN IdLen,
  OUT UINT8 **ObjData,
  OUT UINTN *ObjDataLen
  );

EFI_STATUS
eTokenPro42bChallendge (
  IN SMART_CARD_PROTOCOL *This,
  IN OUT UINT8 *Challendge
  );

EFI_STATUS
eTokenPro42bVerify (
  IN     SMART_CARD_PROTOCOL *This,
  IN     PIN_USER            UserId,
  IN     LOCAL_RIGHTS        Rights,
  IN     UINT8               *PinCode,
  IN     UINTN               PinCodeLen,
  OUT    UINTN               *TriesLeft
  );


EFI_STATUS
eTokenPro42bLogin (
  IN     SMART_CARD_PROTOCOL *This,
  IN     BOOLEAN             Admin,
  IN     UINT8               *Pin,
  IN     UINT8               PinLen
  );

EFI_STATUS
eTokenPro42bSelectFileByPath (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Path,
  IN     UINTN               PathLen,
  IN     BOOLEAN             AbsPath,
  IN OUT UINT8               *Data,
  IN OUT UINTN               *Len
  );

EFI_STATUS
eTokenPro42bReadBinary (
  IN     SMART_CARD_PROTOCOL *This,
  IN OUT UINT8               *Data,
  IN     UINTN               Off,
  IN     UINTN               Len
  );

EFI_STATUS
eTokenPro42bGetSN (
  IN SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenPro42bEcpInit (
  IN     SMART_CARD_PROTOCOL *This
  );

EFI_STATUS
eTokenPro42bEcp (
  IN     SMART_CARD_PROTOCOL *This,
  IN     UINT8               *Data,
  IN     UINTN               DataLen,
  IN OUT UINT8               **Ecp,
  IN OUT UINTN               *EcpLen
  );



#endif /* #ifndef __ETOKEN__PRO__H */

