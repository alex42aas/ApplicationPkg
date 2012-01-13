/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "SmartCardCredentialProviderDxe.h"
#include "vfrdata.h"

#define CONTROLER_TYPE_EHCI 0
#define CONTROLER_TYPE_OHCI 1
#define CONTROLER_TYPE_UHCI 2


SMART_CARD_PROTOCOL *gSmartCardProtocol;

EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *gDevicePathToTextProtocol;
EFI_GUID gEfiProviderGuid = EFI_USER_CREDENTIAL_PROTOCOL_GUID;
EFI_GUID gEfiUserCredentialClassSecureCardGuid = EFI_USER_CREDENTIAL_CLASS_SECURE_CARD;

EFI_HANDLE gCredentialProviderHandle = NULL;

EFI_GUID   mFormSetGuid = FORMSET_GUID;
EFI_GUID   mInventoryGuid = INVENTORY_GUID;
EFI_SCREEN_DESCRIPTOR   gScreenDimensions;
CHAR16  *gPressEnter;
CHAR16  *gEmptyString;
CHAR16  *gResetString;
CHAR16  *gMiniString;
CHAR16  *gPasswordPopupHelp;
CHAR16  *gAuthFailed;
CHAR16  *gAuthSuccess;
CHAR16  *gNoKey;

USB_DEVICE_PATH	gUsbDevicePath1 = {{3, 5, {6, 0}}, 1, 0};
USB_DEVICE_PATH	gUsbDevicePath2 = {{3, 5, {6, 0}}, 3, 0};

#define ONE_SECOND  10000000
#define POPUP_TEXT                    EFI_LIGHTGRAY
#define POPUP_BACKGROUND              EFI_BLUE
#define POPUP_INVERSE_TEXT            EFI_LIGHTGRAY
#define POPUP_INVERSE_BACKGROUND      EFI_BLACK

VOID
SetUnicodeMem (
  IN VOID   *Buffer,
  IN UINTN  Size,
  IN CHAR16 Value
  );

typedef struct _CREDENTIAL_PRIVATE_DATA {
	EFI_HANDLE                      DriverHandle;
	EFI_HII_HANDLE                  HiiHandle;
	EFI_USER_CREDENTIAL_PROTOCOL    CredentialProviderProtocol;
	EFI_FORM_BROWSER2_PROTOCOL      *FormBrowser2;
	EFI_HII_DATABASE_PROTOCOL       *HiiDatabase;
	EFI_HII_STRING_PROTOCOL         *HiiString;
	EFI_HII_CONFIG_ACCESS_PROTOCOL  ConfigAccess;
} CREDENTIAL_PRIVATE_DATA;



CREDENTIAL_PRIVATE_DATA       gPrivateData = {0};	

typedef struct _USBKEY_INFO {
	UINT16                           QuestionId;
	USB_DEVICE_PATH                  UsbDevicePath;
	EFI_DEVICE_PATH_PROTOCOL         *DevicePathProtocol;
	EFI_FILE_HANDLE                  FileHandle;
	CHAR16                           FilePath[256];
	EFI_USER_INFO_IDENTIFIER         Ident;
	UINT8                            Hash[32];
	BOOLEAN                          Authentificated;
	UINTN                            AtemptCount;
	EFI_USER_PROFILE_HANDLE          UserProfile;
} USBKEY_INFO;


#define MAX_USB_KEYS 2

USBKEY_INFO gUserInfo[MAX_USB_KEYS];
USBKEY_INFO *gCurrentUserInfo = NULL;

EFI_STATUS
CredentialEnroll(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_PROFILE_HANDLE User
		);

EFI_STATUS
CredentialForm(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_GUID *FormSetId,
		OUT EFI_FORM_ID *FormId
		);

EFI_STATUS
CredentialTile(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN OUT UINTN *Width,
		IN OUT UINTN *Height,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_IMAGE_ID *Image
		);

EFI_STATUS
CredentialTitle(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_STRING_ID *String
		);

EFI_STATUS
CredentialUser(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_PROFILE_HANDLE User,
		OUT EFI_USER_INFO_IDENTIFIER *Identifier
		);

EFI_STATUS
CredentialSelect(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
		);

EFI_STATUS
CredentialDeselect(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This
		);

EFI_STATUS
CredentialDefault(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
		);

EFI_STATUS
CredentialGetInfo(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_INFO_HANDLE UserInfo,
		OUT EFI_USER_INFO *Info,
		IN OUT UINTN *InfoSize
		);

EFI_STATUS
CredentialGetNextInfo(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN OUT EFI_USER_INFO_HANDLE *UserInfo
		);



EFI_STATUS
CredentialEnroll(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_PROFILE_HANDLE User
		)
{
  	if (gCurrentUserInfo == NULL) {
	  return EFI_ACCESS_DENIED;
	}

//	if(gCurrentUserInfo->UserProfile != User) {
//	  gCurrentUserInfo->UserProfile = User;
//	  gCurrentUserInfo->Authentificated = FALSE;
//	}

	if (!gCurrentUserInfo->Authentificated) {
	  return EFI_ACCESS_DENIED;
	}


	return EFI_SUCCESS;
}

VOID
SetUnicodeMem (
  IN VOID   *Buffer,
  IN UINTN  Size,
  IN CHAR16 Value
  )
{
  CHAR16  *Ptr;

  Ptr = Buffer;
  while ((Size--)  != 0) {
    *(Ptr++) = Value;
  }
}

UINTN
PrintInternal (
  IN UINTN                            Column,
  IN UINTN                            Row,
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Out,
  IN CHAR16                           *Fmt,
  IN VA_LIST                          Args
  )
{
  CHAR16  *Buffer;
  CHAR16  *BackupBuffer;
  UINTN   Index;
  UINTN   PreviousIndex;
  UINTN   Count;

  //
  // For now, allocate an arbitrarily long buffer
  //
  Buffer        = AllocateZeroPool (0x10000);
  BackupBuffer  = AllocateZeroPool (0x10000);
  ASSERT (Buffer);
  ASSERT (BackupBuffer);

  if (Column != (UINTN) -1) {
    Out->SetCursorPosition (Out, Column, Row);
  }

  UnicodeVSPrint (Buffer, 0x10000, Fmt, Args);

  Out->Mode->Attribute = Out->Mode->Attribute & 0x3f;

  Out->SetAttribute (Out, Out->Mode->Attribute);

  Index         = 0;
  PreviousIndex = 0;
  Count         = 0;

  do {
    for (; (Buffer[Index] != NARROW_CHAR) && (Buffer[Index] != WIDE_CHAR) && (Buffer[Index] != 0); Index++) {
      BackupBuffer[Index] = Buffer[Index];
    }

    if (Buffer[Index] == 0) {
      break;
    }
    //
    // Null-terminate the temporary string
    //
    BackupBuffer[Index] = 0;

    //
    // Print this out, we are about to switch widths
    //
    Out->OutputString (Out, &BackupBuffer[PreviousIndex]);
    Count += StrLen (&BackupBuffer[PreviousIndex]);

    //
    // Preserve the current index + 1, since this is where we will start printing from next
    //
    PreviousIndex = Index + 1;

    //
    // We are at a narrow or wide character directive.  Set attributes and strip it and print it
    //
#if 1
      Out->SetAttribute (Out, Out->Mode->Attribute & 0x7f);
#else
    if (Buffer[Index] == NARROW_CHAR) {
      //
      // Preserve bits 0 - 6 and zero out the rest
      //
      Out->Mode->Attribute = Out->Mode->Attribute & 0x3f;
      Out->SetAttribute (Out, Out->Mode->Attribute);
    } else {
      //
      // Must be wide, set bit 7 ON
      //
      Out->Mode->Attribute = Out->Mode->Attribute & 0x3f;//| EFI_WIDE_ATTRIBUTE;
      Out->SetAttribute (Out, Out->Mode->Attribute);
    }
#endif
    Index++;

  } while (Buffer[Index] != 0);

  //
  // We hit the end of the string - print it
  //
  Out->OutputString (Out, &BackupBuffer[PreviousIndex]);
  Count += StrLen (&BackupBuffer[PreviousIndex]);

  FreePool (Buffer);
  FreePool (BackupBuffer);
  return Count;
}

UINTN
PrintAt (
  IN UINTN     Column,
  IN UINTN     Row,
  IN CHAR16    *Fmt,
  ...
  )
{
  VA_LIST Args;

  VA_START (Args, Fmt);
  return PrintInternal (Column, Row, gST->ConOut, Fmt, Args);
}

UINTN
PrintCharAt (
  IN UINTN     Column,
  IN UINTN     Row,
  CHAR16       Character
  )
{
  return PrintAt (Column, Row, L"%c", Character);
}

UINTN
PrintStringAt (
  IN UINTN     Column,
  IN UINTN     Row,
  IN CHAR16    *String
  )
{
  return PrintAt (Column, Row, L"%s", String);
}

UINTN
ConsolePrint (
  IN CHAR16   *Fmt,
  ...
  )
{
  VA_LIST Args;

  VA_START (Args, Fmt);
  return PrintInternal ((UINTN) -1, (UINTN) -1, gST->ConOut, Fmt, Args);
}

UINTN
PrintChar (
  CHAR16       Character
  )
{
  return ConsolePrint (L"%c", Character);
}

VOID
ClearLines (
  UINTN                                       LeftColumn,
  UINTN                                       RightColumn,
  UINTN                                       TopRow,
  UINTN                                       BottomRow,
  UINTN                                       TextAttribute
  )
{
  CHAR16  *Buffer;
  UINTN   Row;

  //
  // For now, allocate an arbitrarily long buffer
  //
  Buffer = AllocateZeroPool (0x10000);
  ASSERT (Buffer != NULL);

  //
  // Set foreground and background as defined
  //
  gST->ConOut->SetAttribute (gST->ConOut, TextAttribute);

  //
  // Much faster to buffer the long string instead of print it a character at a time
  //
  SetUnicodeMem (Buffer, RightColumn - LeftColumn, L' ');

  //
  // Clear the desired area with the appropriate foreground/background
  //
  for (Row = TopRow; Row <= BottomRow; Row++) {
    PrintStringAt (LeftColumn, Row, Buffer);
  }

  gST->ConOut->SetCursorPosition (gST->ConOut, LeftColumn, TopRow);

  FreePool (Buffer);
  return ;
}


EFI_STATUS
CredentialForm(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_GUID *FormSetId,
		OUT EFI_FORM_ID *FormId
		)
{
	if( (Hii == NULL) ||
		(FormSetId == NULL) ||
		(FormId == NULL) ) {
		return EFI_INVALID_PARAMETER;
	}

	*Hii = gPrivateData.HiiHandle;
	CopyGuid( FormSetId, &mFormSetGuid );
        *FormId = USBKEY_MANAGER_FORM_ID;

	return EFI_SUCCESS;
}


EFI_STATUS
CredentialTile(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN OUT UINTN *Width,
		IN OUT UINTN *Height,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_IMAGE_ID *Image
		)
{
	return EFI_UNSUPPORTED;
}


EFI_STATUS
CredentialTitle(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_HII_HANDLE *Hii,
		OUT EFI_STRING_ID *String
		)
{
	return EFI_UNSUPPORTED;
}


EFI_STATUS
CredentialUser(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_PROFILE_HANDLE User,
		OUT EFI_USER_INFO_IDENTIFIER *Identifier
		)
{
  	if((gCurrentUserInfo == NULL) ||
	    (!gCurrentUserInfo->Authentificated)) {
	  return EFI_ACCESS_DENIED;
	}

	CopyMem(
	    Identifier,
	    gCurrentUserInfo->Ident,
	    sizeof(EFI_USER_INFO_IDENTIFIER)
	    );

	return EFI_SUCCESS;
}


EFI_STATUS
CredentialSelect(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
		)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS
CredentialDeselect(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This
		)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS
CredentialDefault(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		OUT EFI_CREDENTIAL_LOGON_FLAGS *AutoLogon
		)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS
CredentialGetInfo(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN EFI_USER_INFO_HANDLE UserInfo,
		OUT EFI_USER_INFO *Info,
		IN OUT UINTN *InfoSize
		)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS
CredentialGetNextInfo(
		IN CONST EFI_USER_CREDENTIAL_PROTOCOL *This,
		IN OUT EFI_USER_INFO_HANDLE *UserInfo
		)
{
	return EFI_UNSUPPORTED;
}

EFI_STATUS
CreateDialog (
  IN  UINTN                       NumberOfLines,
  IN  BOOLEAN                     HotKey,
  IN  UINTN                       MaximumStringSize,
  OUT CHAR16                      *StringBuffer,
  OUT EFI_INPUT_KEY               *KeyValue,
  ...
  );

VOID
CreatePopUp2 (
  IN  UINTN                       RequestedWidth,
  IN  UINTN                       NumberOfLines,
  ...
  );
#if 1

UINTN
GetStringWidth (
  CHAR16                                      *String
  )
{
  UINTN Index;
  UINTN Count;
  UINTN IncrementValue;

  Index           = 0;
  Count           = 0;
  IncrementValue  = 1;

  do {
    //
    // Advance to the null-terminator or to the first width directive
    //
    for (;
         (String[Index] != NARROW_CHAR) && (String[Index] != WIDE_CHAR) && (String[Index] != 0);
         Index++, Count = Count + IncrementValue
        )
      ;

    //
    // We hit the null-terminator, we now have a count
    //
    if (String[Index] == 0) {
      break;
    }
    //
    // We encountered a narrow directive - strip it from the size calculation since it doesn't get printed
    // and also set the flag that determines what we increment by.(if narrow, increment by 1, if wide increment by 2)
    //
    if (String[Index] == NARROW_CHAR) {
      //
      // Skip to the next character
      //
      Index++;
      IncrementValue = 1;
    } else {
      //
      // Skip to the next character
      //
      Index++;
      IncrementValue = 2;
    }
  } while (String[Index] != 0);

  //
  // Increment by one to include the null-terminator in the size
  //
  Count++;

  return Count * sizeof (CHAR16);
}

#endif


EFI_STATUS
WaitForKeyStroke(
  OUT EFI_INPUT_KEY *Key
  )
{
  UINTN                         Index;
  EFI_STATUS                    Status;
  EFI_EVENT                     TimerEvent;
  EFI_EVENT                     WaitList[2];

  do {
    Status = gBS->CreateEvent (EVT_TIMER, 0, NULL, NULL, &TimerEvent);

    //
    // Set a timer event of 1 second expiration
    //
    gBS->SetTimer (
          TimerEvent,
          TimerRelative,
          10000000
          );

    //
    // Wait for the keystroke event or the timer
    //
    WaitList[0] = gST->ConIn->WaitForKey;
    WaitList[1] = TimerEvent;
    Status      = gBS->WaitForEvent (2, WaitList, &Index);

    //
    // Check for the timer expiration
    //

    if (!EFI_ERROR (Status) && Index == 1) {
      Status = EFI_TIMEOUT;
    }

    gBS->CloseEvent (TimerEvent);
  } while (Status == EFI_TIMEOUT);

  Status = gST->ConIn->ReadKeyStroke (gST->ConIn, Key);
  return Status;
}


EFI_STATUS
ReadString (
  IN  CHAR16                      *Prompt,
  IN  UINTN                       MinLen,
  IN  UINTN                       MaxLen,
  IN  BOOLEAN                     IsPassword,
  OUT CHAR16                      *StringPtr
  )
{
  EFI_STATUS              Status;
  EFI_INPUT_KEY           Key;
  CHAR16                  NullCharacter;
  UINTN                   ScreenSize;
  CHAR16                  Space[2];
  CHAR16                  KeyPad[2];
  CHAR16                  *TempString;
  CHAR16                  *BufferedString;
  UINTN                   Index;
  UINTN                   Count;
  UINTN                   Start;
  UINTN                   Top;
  UINTN                   DimensionsWidth;
  UINTN                   DimensionsHeight;
  BOOLEAN                 CursorVisible;
//  UINTN                   Minimum;
  UINTN                   Maximum;

  DimensionsWidth  = gScreenDimensions.RightColumn - gScreenDimensions.LeftColumn;
  DimensionsHeight = gScreenDimensions.BottomRow - gScreenDimensions.TopRow;

  NullCharacter    = CHAR_NULL;
  ScreenSize       = GetStringWidth (Prompt) / sizeof (CHAR16);
  Space[0]         = L' ';
  Space[1]         = CHAR_NULL;

//  Minimum          = MinLen;
  Maximum          = MaxLen;

  TempString = AllocateZeroPool ((Maximum + 1)* sizeof (CHAR16));
  ASSERT (TempString);

  if (ScreenSize < (Maximum + 1)) {
    ScreenSize = Maximum + 1;
  }

  if ((ScreenSize + 2) > DimensionsWidth) {
    ScreenSize = DimensionsWidth - 2;
  }

  BufferedString = AllocateZeroPool (ScreenSize * 2);
  ASSERT (BufferedString);

  Start = (DimensionsWidth - ScreenSize - 2) / 2 + gScreenDimensions.LeftColumn + 1;
  Top   = ((DimensionsHeight - 6) / 2) + gScreenDimensions.TopRow - 1;

  //
  // Display prompt for string
  //
  CreatePopUp2 (ScreenSize, 4, &NullCharacter, Prompt, Space, &NullCharacter);

  gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_BLACK, EFI_LIGHTGRAY));

  CursorVisible = gST->ConOut->Mode->CursorVisible;
  gST->ConOut->EnableCursor (gST->ConOut, TRUE);

  do {
    Status = WaitForKeyStroke (&Key);
    ASSERT_EFI_ERROR (Status);

    gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_BLACK, EFI_LIGHTGRAY));
    switch (Key.UnicodeChar) {
    case CHAR_NULL:
      switch (Key.ScanCode) {
      case SCAN_LEFT:
        break;

      case SCAN_RIGHT:
        break;

      case SCAN_ESC:
        FreePool (TempString);
        FreePool (BufferedString);
        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
        gST->ConOut->EnableCursor (gST->ConOut, CursorVisible);
        return EFI_DEVICE_ERROR;

      default:
        break;
      }

      break;

    case CHAR_CARRIAGE_RETURN:
#if 1
        FreePool (TempString);
        FreePool (BufferedString);
        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
        gST->ConOut->EnableCursor (gST->ConOut, CursorVisible);
        return EFI_SUCCESS;

#else
      if (GetStringWidth (StringPtr) >= ((Minimum + 1) * sizeof (CHAR16))) {

        FreePool (TempString);
        FreePool (BufferedString);
        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
        gST->ConOut->EnableCursor (gST->ConOut, CursorVisible);
        return EFI_SUCCESS;
      } else {
        //
        // Simply create a popup to tell the user that they had typed in too few characters.
        // To save code space, we can then treat this as an error and return back to the menu.
        //
        do {
          CreateDialog (4, TRUE, 0, NULL, &Key, &NullCharacter, gMiniString, gPressEnter, &NullCharacter);
        } while (Key.UnicodeChar != CHAR_CARRIAGE_RETURN);

	FreePool (TempString);
        FreePool (BufferedString);

	ClearLines(0, 80, 8, 20, EFI_TEXT_ATTR (EFI_BLACK, EFI_LIGHTGRAY));
//        gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
        gST->ConOut->EnableCursor (gST->ConOut, CursorVisible);
        return EFI_DEVICE_ERROR;
      }
#endif
      break;

    case CHAR_BACKSPACE:
      if (StringPtr[0] != CHAR_NULL) {
        for (Index = 0; StringPtr[Index] != CHAR_NULL; Index++) {
          TempString[Index] = StringPtr[Index];
        }
        //
        // Effectively truncate string by 1 character
        //
        TempString[Index - 1] = CHAR_NULL;
        StrCpy (StringPtr, TempString);
      }

    default:
      //
      // If it is the beginning of the string, don't worry about checking maximum limits
      //
      if ((StringPtr[0] == CHAR_NULL) && (Key.UnicodeChar != CHAR_BACKSPACE)) {
        StrnCpy (StringPtr, &Key.UnicodeChar, 1);
        StrnCpy (TempString, &Key.UnicodeChar, 1);
      } else if ((GetStringWidth (StringPtr) < ((Maximum + 1) * sizeof (CHAR16))) && (Key.UnicodeChar != CHAR_BACKSPACE)) {
        KeyPad[0] = Key.UnicodeChar;
        KeyPad[1] = CHAR_NULL;
        StrCat (StringPtr, KeyPad);
        StrCat (TempString, KeyPad);
      }

      //
      // If the width of the input string is now larger than the screen, we nee to
      // adjust the index to start printing portions of the string
      //
      SetUnicodeMem (BufferedString, ScreenSize - 1, L' ');
      PrintStringAt (Start + 1, Top + 3, BufferedString);

      if ((GetStringWidth (StringPtr) / 2) > (DimensionsWidth - 2)) {
        Index = (GetStringWidth (StringPtr) / 2) - DimensionsWidth + 2;
      } else {
        Index = 0;
      }

      if (IsPassword) {
        gST->ConOut->SetCursorPosition (gST->ConOut, Start + 1, Top + 3);
      }

      for (Count = 0; Index + 1 < GetStringWidth (StringPtr) / 2; Index++, Count++) {
        BufferedString[Count] = StringPtr[Index];

        if (IsPassword) {
          PrintChar (L'*');
        }
      }

      if (!IsPassword) {
        PrintStringAt (Start + 1, Top + 3, BufferedString);
      }
      break;
    }

    gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLACK));
    gST->ConOut->SetCursorPosition (gST->ConOut, Start + GetStringWidth (StringPtr) / 2, Top + 3);
  } while (TRUE);

}

VOID
CreateSharedPopUp (
  IN  UINTN                       RequestedWidth,
  IN  UINTN                       NumberOfLines,
  IN  VA_LIST                     Marker
  )
{
  UINTN   Index;
  UINTN   Count;
  CHAR16  Character;
  UINTN   Start;
  UINTN   End;
  UINTN   Top;
  UINTN   Bottom;
  CHAR16  *String;
  UINTN   DimensionsWidth;
  UINTN   DimensionsHeight;

  DimensionsWidth   = gScreenDimensions.RightColumn - gScreenDimensions.LeftColumn;
  DimensionsHeight  = gScreenDimensions.BottomRow - gScreenDimensions.TopRow;

  gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR(POPUP_TEXT, POPUP_BACKGROUND));

  if ((RequestedWidth + 2) > DimensionsWidth) {
    RequestedWidth = DimensionsWidth - 2;
  }

  //
  // Subtract the PopUp width from total Columns, allow for one space extra on
  // each end plus a border.
  //
  Start     = (DimensionsWidth - RequestedWidth - 2) / 2 + gScreenDimensions.LeftColumn + 1;
  End       = Start + RequestedWidth + 1;

  Top       = ((DimensionsHeight - NumberOfLines - 2) / 2) + gScreenDimensions.TopRow - 1;
  Bottom    = Top + NumberOfLines + 2;

  Character = BOXDRAW_DOWN_RIGHT;
  PrintCharAt (Start, Top, Character);
  Character = BOXDRAW_HORIZONTAL;
  for (Index = Start; Index + 2 < End; Index++) {
    PrintChar (Character);
  }

  Character = BOXDRAW_DOWN_LEFT;
  PrintChar (Character);
  Character = BOXDRAW_VERTICAL;

  Count = 0;
  for (Index = Top; Index + 2 < Bottom; Index++, Count++) {
    String = VA_ARG (Marker, CHAR16*);

    //
    // This will clear the background of the line - we never know who might have been
    // here before us.  This differs from the next clear in that it used the non-reverse
    // video for normal printing.
    //
    if (GetStringWidth (String) / 2 > 1) {
      ClearLines (Start, End, Index + 1, Index + 1, EFI_TEXT_ATTR(POPUP_TEXT, POPUP_BACKGROUND));
    }

    //
    // Passing in a space results in the assumption that this is where typing will occur
    //
    if (String[0] == L' ') {
      ClearLines (Start + 1, End - 1, Index + 1, Index + 1, POPUP_INVERSE_TEXT | POPUP_INVERSE_BACKGROUND);
    }

    //
    // Passing in a NULL results in a blank space
    //
    if (String[0] == CHAR_NULL) {
      ClearLines (Start, End, Index + 1, Index + 1, EFI_TEXT_ATTR(POPUP_TEXT, POPUP_BACKGROUND));
    }

    PrintStringAt (
      ((DimensionsWidth - GetStringWidth (String) / 2) / 2) + gScreenDimensions.LeftColumn + 1,
      Index + 1,
      String
      );
    gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR(POPUP_TEXT, POPUP_BACKGROUND));
    PrintCharAt (Start, Index + 1, Character);
    PrintCharAt (End - 1, Index + 1, Character);
  }

  Character = BOXDRAW_UP_RIGHT;
  PrintCharAt (Start, Bottom - 1, Character);
  Character = BOXDRAW_HORIZONTAL;
  for (Index = Start; Index + 2 < End; Index++) {
    PrintChar (Character);
  }

  Character = BOXDRAW_UP_LEFT;
  PrintChar (Character);
}

EFI_STATUS
CreateDialog (
  IN  UINTN                       NumberOfLines,
  IN  BOOLEAN                     HotKey,
  IN  UINTN                       MaximumStringSize,
  OUT CHAR16                      *StringBuffer,
  OUT EFI_INPUT_KEY               *KeyValue,
  ...
  )
{
  VA_LIST       Marker;
  VA_LIST       MarkerBackup;
  UINTN         Count;
  EFI_INPUT_KEY Key;
  UINTN         LargestString;
  CHAR16        *TempString;
  CHAR16        *BufferedString;
  CHAR16        *StackString;
  CHAR16        KeyPad[2];
  UINTN         Start;
  UINTN         Top;
  UINTN         Index;
  EFI_STATUS    Status;
  BOOLEAN       SelectionComplete;
  UINTN         InputOffset;
  UINTN         CurrentAttribute;
  UINTN         DimensionsWidth;
  UINTN         DimensionsHeight;

  DimensionsWidth   = gScreenDimensions.RightColumn - gScreenDimensions.LeftColumn;
  DimensionsHeight  = gScreenDimensions.BottomRow - gScreenDimensions.TopRow;

  SelectionComplete = FALSE;
  InputOffset       = 0;
  TempString        = AllocateZeroPool (MaximumStringSize * 2);
  BufferedString    = AllocateZeroPool (MaximumStringSize * 2);
  CurrentAttribute  = gST->ConOut->Mode->Attribute;

  ASSERT (TempString);
  ASSERT (BufferedString);

  VA_START (Marker, KeyValue);
  MarkerBackup = Marker;

  //
  // Zero the outgoing buffer
  //
  ZeroMem (StringBuffer, MaximumStringSize);

  if (HotKey) {
    if (KeyValue == NULL) {
      return EFI_INVALID_PARAMETER;
    }
  } else {
    if (StringBuffer == NULL) {
      return EFI_INVALID_PARAMETER;
    }
  }
  //
  // Disable cursor
  //
  gST->ConOut->EnableCursor (gST->ConOut, FALSE);

  LargestString = 0;

  //
  // Determine the largest string in the dialog box
  // Notice we are starting with 1 since String is the first string
  //
  for (Count = 0; Count < NumberOfLines; Count++) {
    StackString = VA_ARG (Marker, CHAR16 *);

    if (StackString[0] == L' ') {
      InputOffset = Count + 1;
    }

    if ((GetStringWidth (StackString) / 2) > LargestString) {
      //
      // Size of the string visually and subtract the width by one for the null-terminator
      //
      LargestString = (GetStringWidth (StackString) / 2);
    }
  }

  Start = (DimensionsWidth - LargestString - 2) / 2 + gScreenDimensions.LeftColumn + 1;
  Top   = ((DimensionsHeight - NumberOfLines - 2) / 2) + gScreenDimensions.TopRow - 1;

  Count = 0;

  //
  // Display the Popup
  //
  CreateSharedPopUp (LargestString, NumberOfLines, MarkerBackup);

  //
  // Take the first key typed and report it back?
  //
  if (HotKey) {
    Status = WaitForKeyStroke (&Key);
    ASSERT_EFI_ERROR (Status);
    CopyMem (KeyValue, &Key, sizeof (EFI_INPUT_KEY));

  } else {
    do {
      Status = WaitForKeyStroke (&Key);

      switch (Key.UnicodeChar) {
      case CHAR_NULL:
        switch (Key.ScanCode) {
        case SCAN_ESC:
          FreePool (TempString);
          FreePool (BufferedString);
          gST->ConOut->SetAttribute (gST->ConOut, CurrentAttribute);
          gST->ConOut->EnableCursor (gST->ConOut, TRUE);
          return EFI_DEVICE_ERROR;

        default:
          break;
        }

        break;

      case CHAR_CARRIAGE_RETURN:
        SelectionComplete = TRUE;
        FreePool (TempString);
        FreePool (BufferedString);
        gST->ConOut->SetAttribute (gST->ConOut, CurrentAttribute);
        gST->ConOut->EnableCursor (gST->ConOut, TRUE);
        return EFI_SUCCESS;
        break;

      case CHAR_BACKSPACE:
        if (StringBuffer[0] != CHAR_NULL) {
          for (Index = 0; StringBuffer[Index] != CHAR_NULL; Index++) {
            TempString[Index] = StringBuffer[Index];
          }
          //
          // Effectively truncate string by 1 character
          //
          TempString[Index - 1] = CHAR_NULL;
          StrCpy (StringBuffer, TempString);
        }

      default:
        //
        // If it is the beginning of the string, don't worry about checking maximum limits
        //
        if ((StringBuffer[0] == CHAR_NULL) && (Key.UnicodeChar != CHAR_BACKSPACE)) {
          StrnCpy (StringBuffer, &Key.UnicodeChar, 1);
          StrnCpy (TempString, &Key.UnicodeChar, 1);
        } else if ((GetStringWidth (StringBuffer) < MaximumStringSize) && (Key.UnicodeChar != CHAR_BACKSPACE)) {
          KeyPad[0] = Key.UnicodeChar;
          KeyPad[1] = CHAR_NULL;
          StrCat (StringBuffer, KeyPad);
          StrCat (TempString, KeyPad);
        }
        //
        // If the width of the input string is now larger than the screen, we nee to
        // adjust the index to start printing portions of the string
        //
        SetUnicodeMem (BufferedString, LargestString, L' ');

        PrintStringAt (Start + 1, Top + InputOffset, BufferedString);

        if ((GetStringWidth (StringBuffer) / 2) > (DimensionsWidth - 2)) {
          Index = (GetStringWidth (StringBuffer) / 2) - DimensionsWidth + 2;
        } else {
          Index = 0;
        }

        for (Count = 0; Index + 1 < GetStringWidth (StringBuffer) / 2; Index++, Count++) {
          BufferedString[Count] = StringBuffer[Index];
        }

        PrintStringAt (Start + 1, Top + InputOffset, BufferedString);
        break;
      }
    } while (!SelectionComplete);
  }

  gST->ConOut->SetAttribute (gST->ConOut, CurrentAttribute);
  gST->ConOut->EnableCursor (gST->ConOut, TRUE);
  return EFI_SUCCESS;
}


VOID
CreatePopUp2 (
  IN  UINTN                       RequestedWidth,
  IN  UINTN                       NumberOfLines,
  ...
  )
{
  VA_LIST Marker;

  VA_START (Marker, NumberOfLines);

  CreateSharedPopUp (RequestedWidth, NumberOfLines, Marker);

  VA_END (Marker);
}

CHAR16 *
GetToken (
  IN  EFI_STRING_ID                Token,
  IN  EFI_HII_HANDLE               HiiHandle
  )
{
  EFI_STRING  String;
  CHAR16      *mUnknownString = L"!";

  String = HiiGetString (HiiHandle, Token, NULL);
  if (String == NULL) {
    String = AllocateCopyPool (sizeof (mUnknownString), mUnknownString);
    ASSERT (String != NULL);
  }
  return (CHAR16 *) String;
}


EFI_STATUS
EFIAPI
FakeExtractConfig (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Request,
  OUT EFI_STRING                             *Progress,
  OUT EFI_STRING                             *Results
  )
{
  return EFI_NOT_FOUND;
}


EFI_STATUS
EFIAPI
FakeRouteConfig (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Configuration,
  OUT EFI_STRING                             *Progress
  )
{
  return EFI_SUCCESS;
}


BOOLEAN
EFIAPI
MatchPartitionUSBDevice (
  IN  EFI_DEVICE_PATH_PROTOCOL   *BlockIoDevicePath,
  IN  USB_DEVICE_PATH            *UsbDevicePath,
  IN  UINTN                        PartitionNumber
  )
{
  HARDDRIVE_DEVICE_PATH     *TmpHdPath;
  USB_DEVICE_PATH           *TmpUsbDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *UsbDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL  *BlockIoHdDevicePathNode;

  if ((BlockIoDevicePath == NULL) || (UsbDevicePath == NULL)) {
    return FALSE;
  }

  //
  // Make PreviousDevicePath == the device path node before the end node
  //
  DevicePath        = BlockIoDevicePath;
  UsbDevicePathNode = NULL;

  //
  // find the partition device path node
  //
  while (!IsDevicePathEnd (DevicePath)) {
    if ((DevicePathType (DevicePath) == MESSAGING_DEVICE_PATH) &&
        (DevicePathSubType (DevicePath) == MSG_USB_DP)
        ) {
      UsbDevicePathNode = DevicePath;
      break;
    }

    DevicePath = NextDevicePathNode (DevicePath);
  }

  if (UsbDevicePathNode == NULL) {
    return FALSE;
  }

  TmpUsbDevicePathNode = (USB_DEVICE_PATH*) UsbDevicePathNode;

  //
  // Compare USB paths
  //

  if( (UsbDevicePath->ParentPortNumber != TmpUsbDevicePathNode->ParentPortNumber)
      || (UsbDevicePath->InterfaceNumber != TmpUsbDevicePathNode->InterfaceNumber)) {

    return FALSE;
  }



  DevicePath              = BlockIoDevicePath;
  BlockIoHdDevicePathNode = NULL;

  //
  // find the partition device path node
  //

  while (!IsDevicePathEnd (DevicePath)) {
    if ((DevicePathType (DevicePath) == MEDIA_DEVICE_PATH) &&
        (DevicePathSubType (DevicePath) == MEDIA_HARDDRIVE_DP)
        ) {
      BlockIoHdDevicePathNode = DevicePath;
      break;
    }

    DevicePath = NextDevicePathNode (DevicePath);
  }

  if (BlockIoHdDevicePathNode == NULL) {
    return FALSE;
  }

  TmpHdPath = (HARDDRIVE_DEVICE_PATH *) BlockIoHdDevicePathNode;

  if (TmpHdPath->PartitionNumber != PartitionNumber) {
    return FALSE;
  }

  return TRUE;
}

VOID
AsciiSkipSpace(CHAR8 **Data)
{
  CHAR8 *Ptr;
  if (Data == NULL) {
  	return;
  }

  Ptr = *Data;
  while (*Ptr == ' ') {
    Ptr++;
  }

  *Data = Ptr;
}

EFI_STATUS
ReadHash(USBKEY_INFO *UserInfo)
{
  EFI_STATUS Status;
  EFI_FILE_HANDLE Root;
  EFI_FILE_HANDLE File;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Volume;
  EFI_HANDLE Handle;
  UINTN BufferSize;
  CHAR8 *Buffer;
  CHAR8 *Ptr;
  EFI_HANDLE *BlockIoBuffer;
  EFI_DEVICE_PATH_PROTOCOL *BlockIoDevicePath;
  UINTN BlockIoHandleCount;
  UINTN Index;
  UINTN Count;
  UINT8 byte;

  if(UserInfo == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto exit;
  }

  if(!UserInfo->FileHandle) {

    // Expand partial device path

    Status = gBS->LocateHandleBuffer (
	ByProtocol,
    &gEfiSimpleFileSystemProtocolGuid,
//	&gEfiBlockIoProtocolGuid,
	NULL,
	&BlockIoHandleCount,
	&BlockIoBuffer
	);

    if(EFI_ERROR(Status) || BlockIoHandleCount == 0 || BlockIoBuffer == NULL) {

      DEBUG((EFI_D_ERROR, "!!LocateHandleBuffer Status:%llx BlockIoHandleCount:%lld\n",
	    Status,
	    BlockIoHandleCount)
	  );

      Status = EFI_INVALID_PARAMETER;
      goto exit;
    }

    Handle = NULL;
    for(Index = 0; Index < BlockIoHandleCount; Index++) {
      CHAR16 *PathString;

      Status = gBS->HandleProtocol (
	  BlockIoBuffer[Index],
	  &gEfiDevicePathProtocolGuid,
	  (VOID *) &BlockIoDevicePath
	  );

      PathString = gDevicePathToTextProtocol->ConvertDevicePathToText(
	  BlockIoDevicePath,
	  FALSE,
	  TRUE);

      DEBUG((EFI_D_ERROR, "PATH:%S\n", PathString ));

	if(MatchPartitionUSBDevice( BlockIoDevicePath, &UserInfo->UsbDevicePath, 1)) {
	  Handle = BlockIoBuffer[Index];
	  UserInfo->DevicePathProtocol = BlockIoDevicePath;
	  break;
	}
    }

    if(Handle == NULL) {
      Status = EFI_NOT_FOUND;
      goto exit;
    }

    Status = gBS->HandleProtocol (
	Handle,
	&gEfiSimpleFileSystemProtocolGuid,
	(VOID **) &Volume
	);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "1:0x%x\n", Status));
      goto exit;
    }

    //
    // Open the root directory of the volume
    //
    Root = NULL;

    Status = Volume->OpenVolume (
	Volume,
	&Root
	);

    ASSERT_EFI_ERROR (Status);
    ASSERT (Root != NULL);

    //
    // Open file
    //
    Status = Root->Open (
	Root,
	&UserInfo->FileHandle,
	UserInfo->FilePath,
	EFI_FILE_MODE_READ,
	0
	);

    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "passwd not found\n"));
      UserInfo->FileHandle = NULL;
      Root->Close (Root);
      goto exit;
    }

    //
    // Close the Root directory
    //

    Root->Close (Root);

  }

  File = UserInfo->FileHandle;

  Status = File->SetPosition(File, 0);

  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "2:0x%x\n", Status));
    File->Close(File);
    UserInfo->FileHandle = NULL;
    goto exit;
  }

  BufferSize = 1024;
  Buffer = AllocateZeroPool(BufferSize);

  Status = File->Read(File, &BufferSize, Buffer);
  Ptr = Buffer;
  AsciiSkipSpace(&Ptr);

  // Read Hash
  Index = 0;
  Count = 0;
  while(Index < 32*2) {
    byte = ((Ptr[Index] >= '0') && (Ptr[Index] <= '9')) ?  Ptr[Index] - '0' :
     ((Ptr[Index] >= 'a') && (Ptr[Index] <= 'f')) ? Ptr[Index] - 'a' + 10:
     ((Ptr[Index] >= 'A') && (Ptr[Index] <= 'F')) ? Ptr[Index] - 'A' + 10:
     0;
    Index++;
    byte <<= 4;
    byte |= ((Ptr[Index] >= '0') && (Ptr[Index] <= '9')) ?  Ptr[Index] - '0' :
     ((Ptr[Index] >= 'a') && (Ptr[Index] <= 'f')) ? Ptr[Index] - 'a' + 10:
     ((Ptr[Index] >= 'A') && (Ptr[Index] <= 'F')) ? Ptr[Index] - 'A' + 10:
     0;
    Index++;
    UserInfo->Hash[Count++] = byte;
  }


  DEBUG((EFI_D_ERROR, "HASH:"));

  for(Index = 0; Index < 32; Index++) {
    DEBUG((EFI_D_ERROR, "%02x", UserInfo->Hash[Index]));
  }

  DEBUG((EFI_D_ERROR, "\n"));

  if (EFI_ERROR(Status)) {
    File->Close(File);
    UserInfo->FileHandle = NULL;
    goto exit;
  }

exit:

  return Status;
}

#define QID_TO_INDEX(X) (X-0x2000)

extern int test_cryptoki(void);

EFI_STATUS
EFIAPI
FormCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
//	EFI_STATUS Status;
//  DEVICE_MANAGER_CALLBACK_DATA *PrivateData;
    EFI_STATUS Status;
	CHAR16 NullCharacter;
	CHAR16 Passwd[21];
	CHAR8 APasswd[21];
//	GHOST_DIGEST Hash;
//	GostHashCtx ctx;
	UINTN Index;
	EFI_INPUT_KEY Key;
	CHAR16 TmpBuf[80];
	INTN Times = 10;
	//CHAR16 NullCharacter    = CHAR_NULL;
//	CHAR16 Space[2];
	INTN ScreenSize;
	UINTN Tmr;
	UINTN Tryes;
	EFI_EVENT TimerEvent;
	UINT8 AtrString[40];

#if 0
        if (test_cryptoki() == 0) {
          DEBUG((EFI_D_ERROR, "Cryptoki testing: OK\n"));
        } else {
          DEBUG((EFI_D_ERROR, "Cryptoki testing: FAILED\n"));
        }
#endif

	Status = gBS->LocateProtocol(
	    &gSmartCardProtocolGuid,
	    NULL,
	    (VOID**) &gSmartCardProtocol );

	if (EFI_ERROR (Status)) {
		DEBUG((EFI_D_ERROR, "Can't Locate SmartCardProtocol\n"));
		return Status;
	}


	ScreenSize = GetStringWidth( gAuthFailed ) / sizeof(CHAR16);
//	Space[0] = L' ';
//	Space[1] = CHAR_NULL;

	NullCharacter = CHAR_NULL;

	if( (Value == NULL) || (ActionRequest == NULL) ) {
		return EFI_INVALID_PARAMETER;
	}

	Status = EFI_SUCCESS;

	ZeroMem( &gScreenDimensions, sizeof(EFI_SCREEN_DESCRIPTOR) );

	gST->ConOut->QueryMode( gST->ConOut,
							gST->ConOut->Mode->Mode,
							&gScreenDimensions.RightColumn,
							&gScreenDimensions.BottomRow );

	switch( QuestionId ) {
	case 0x2000:
	case 0x2001:
		Index = QID_TO_INDEX(QuestionId);

//		Status = ReadHash( &gUserInfo[Index] );

		Status = gSmartCardProtocol->Reset(
		                            gSmartCardProtocol,
		                            AtrString,
		                            sizeof(AtrString)
		                            );

		if( EFI_ERROR(Status) ) {
			do {

				CreateDialog(	4,
								TRUE,
								0,
								NULL,
								&Key,
								&NullCharacter,
								gNoKey,
								gPressEnter,
								&NullCharacter );

			} while( Key.UnicodeChar != CHAR_CARRIAGE_RETURN );

			break;
		}

		ZeroMem( Passwd, sizeof(Passwd) );

		do {
			Status = ReadString( gPasswordPopupHelp, 6, 20, TRUE, Passwd );
		} while( EFI_ERROR(Status) );

		UnicodeStrToAsciiStr( Passwd, APasswd );

DEBUG((EFI_D_ERROR, "%a.%d pass=%a\n", __FUNCTION__, __LINE__, APasswd));

		Status = gBS->LocateProtocol(
		    &gSmartCardProtocolGuid,
		    NULL,
		    (VOID**) &gSmartCardProtocol );

		if (!EFI_ERROR (Status)) {

			Status = gSmartCardProtocol->Verify(
		                            gSmartCardProtocol,
		                            ScCredentialAdministrator,
		                            LocalRightsNone,
		                            (UINT8*) APasswd,
		                            AsciiStrLen( APasswd ),
		                            &Tryes
		                            );
		}

//		gosthash_reset( &ctx );
//		gosthash_update( &ctx, APasswd, AsciiStrLen( APasswd ) );
//		gosthash_final( &ctx, Hash );

		ZeroMem( Passwd, sizeof(Passwd) );
		ZeroMem( APasswd, sizeof(APasswd) );

		if( !EFI_ERROR(Status) ) {

		  Status = gSmartCardProtocol->Lock(
		      gSmartCardProtocol
		      );
		}

		if( !EFI_ERROR(Status) ) {




		  do {
				CreateDialog(	4,
								TRUE,
								0,
								NULL,
								&Key,
								&NullCharacter,
								gAuthSuccess,
								gPressEnter,
								&NullCharacter );

			} while( Key.UnicodeChar != CHAR_CARRIAGE_RETURN );
			gCurrentUserInfo = &gUserInfo[Index];
			gUserInfo[Index].Authentificated = TRUE;
			*ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;

			// XXX check type of USB controller, now it's locked to OHCI
			//  EHCI
#if 0
			*gsmi_nsd_flags = gUserInfo[Index].UsbDevicePath.ParentPortNumber
					| (1 << 31);
#endif
			Status = EFI_SUCCESS;
		} else {

			do {
				Status = gBS->CreateEvent( 	EVT_TIMER,
											0,
											NULL,
											NULL,
											&TimerEvent );

				UnicodeSPrint( TmpBuf, sizeof(TmpBuf), gResetString, Times );

				CreatePopUp2( 	ScreenSize,
								5,
								&NullCharacter,
								gAuthFailed,
								&NullCharacter,
								TmpBuf,
								&NullCharacter,
								&NullCharacter );

				//
				// Set a timer event of 1 second expiration
				//
				gBS->SetTimer( TimerEvent, TimerRelative, 10000000 );

				Status = gBS->WaitForEvent( 1, &TimerEvent, &Tmr );
				gBS->CloseEvent( TimerEvent );
				Times--;

			} while( Times );

			gUserInfo[Index].AtemptCount++;
			gUserInfo[Index].Authentificated = FALSE;
			Status = EFI_ACCESS_DENIED;
			gRT->ResetSystem( EfiResetCold, EFI_SUCCESS, 0, NULL );
		}

		break;

	default:
		break;
	}

	return Status;

}

EFI_STATUS
EFIAPI
SmartCardCPDriverInit (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  )
{
	EFI_STATUS Status;
	EFI_USER_CREDENTIAL_PROTOCOL *CredentialProviderProtocol;

DEBUG ((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));


	CredentialProviderProtocol = &gPrivateData.CredentialProviderProtocol;


	CopyGuid(&CredentialProviderProtocol->Identifier, &gEfiProviderGuid);
	CopyGuid(&CredentialProviderProtocol->Type, &gEfiUserCredentialClassSecureCardGuid);
	CredentialProviderProtocol->Enroll = CredentialEnroll;
	CredentialProviderProtocol->Form = CredentialForm;
	CredentialProviderProtocol->Tile = CredentialTile;
	CredentialProviderProtocol->Title = CredentialTitle;
	CredentialProviderProtocol->User = CredentialUser;
	CredentialProviderProtocol->Select = CredentialSelect;
	CredentialProviderProtocol->Deselect = CredentialDeselect;
	CredentialProviderProtocol->Default = CredentialDefault;
	CredentialProviderProtocol->GetInfo = CredentialGetInfo;
	CredentialProviderProtocol->GetNextInfo = CredentialGetNextInfo;


	Status = gBS->InstallProtocolInterface(
		&gPrivateData.DriverHandle,
		&gEfiUserCredentialProtocolGuid,
		EFI_NATIVE_INTERFACE,
		&gPrivateData.CredentialProviderProtocol
		);
	
		
	if( EFI_ERROR(Status) ) {
DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
		return Status;
	}

	//
	// Locate Hii Database protocol
	//
	Status = gBS->LocateProtocol (
			&gEfiHiiDatabaseProtocolGuid,
			NULL,
			(VOID **) &gPrivateData.HiiDatabase
			);


	if (EFI_ERROR (Status)) {
DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
		return Status;
	}


	//
	// Locate HiiString protocol
	//
	Status = gBS->LocateProtocol (
			&gEfiHiiStringProtocolGuid,
			NULL,
			(VOID **) &gPrivateData.HiiString
			);

	if (EFI_ERROR (Status)) {
DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
		return Status;
	}

	//
	// Locate Formbrowser2 protocol
	//

	gPrivateData.ConfigAccess.ExtractConfig = FakeExtractConfig;
	gPrivateData.ConfigAccess.RouteConfig = FakeRouteConfig;
	gPrivateData.ConfigAccess.Callback = FormCallback;

	Status = gBS->InstallProtocolInterface (
                  &gPrivateData.DriverHandle,
                  &gEfiHiiConfigAccessProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &gPrivateData.ConfigAccess
                  );

	 ASSERT_EFI_ERROR (Status);


	//
	// Publish our HII data
	//

	gPrivateData.HiiHandle = HiiAddPackages (
			&mFormSetGuid,
			gPrivateData.DriverHandle,
			SmartCardVfrBin,
			SmartCardProviderStrings,
	     		NULL
	);
	
	if (gPrivateData.HiiHandle == NULL) {
DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
		return EFI_OUT_OF_RESOURCES;
	}
	gPressEnter = GetToken (STRING_TOKEN (PRESS_ENTER), gPrivateData.HiiHandle);
	gEmptyString = GetToken (STRING_TOKEN (EMPTY_STRING), gPrivateData.HiiHandle);
	gMiniString = GetToken (STRING_TOKEN (MINI_STRING), gPrivateData.HiiHandle);
	gPasswordPopupHelp = GetToken (STRING_TOKEN (STR_POPUP_PASSWORD_HELP), gPrivateData.HiiHandle);
	gAuthSuccess = GetToken (STRING_TOKEN (STR_AUTH_SUCCESS), gPrivateData.HiiHandle);
	gAuthFailed = GetToken (STRING_TOKEN (STR_AUTH_FAILED), gPrivateData.HiiHandle);
	gNoKey = GetToken (STRING_TOKEN (STR_NO_KEY), gPrivateData.HiiHandle);
	gResetString = GetToken (STRING_TOKEN (STR_RESET_WAIT), gPrivateData.HiiHandle);

//	L"PciRoot(0x0)/Pci(0x13,0x5)/USB(0x1,0x0)/HD(1,MBR,0x54455544,0x3F,0x3C0E76)"
//	L"PciRoot(0x0)/Pci(0x13,0x5)/USB(0x3,0x0)/HD(1,MBR,0x54455544,0x3F,0x3C0E76)"
//      L"VenHw(58C518B1-76F3-11D4-BCEA-0080C73C8881)/VenHw(0C95A935-A006-11D4-BCFA-0080C73C8881,00000000)"
//      L"VenHw(58C518B1-76F3-11D4-BCEA-0080C73C8881)/VenHw(0C95A935-A006-11D4-BCFA-0080C73C8881,01000000)"

	Status = gBS->LocateProtocol (
			&gEfiDevicePathToTextProtocolGuid,
			NULL,
			(VOID **) &gDevicePathToTextProtocol
			);


	if(EFI_ERROR(Status)) {
DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
	  ASSERT_EFI_ERROR(Status);
	  return Status;
	}


	ZeroMem(&gUserInfo, sizeof(USBKEY_INFO));
	CopyMem(&gUserInfo[0].UsbDevicePath, &gUsbDevicePath1, sizeof(USB_DEVICE_PATH));
	StrCpy(gUserInfo[0].FilePath, L"\\passwd");
	CopyMem(&gUserInfo[1].UsbDevicePath, &gUsbDevicePath2, sizeof(USB_DEVICE_PATH));
	StrCpy(gUserInfo[1].FilePath, L"\\passwd");

	// gsmi_nsd_flags = (UINT32*) (UINTN) (0xD0000 + 0x400 * 2);
	return EFI_SUCCESS;
}

