/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DiagnosticsConfigLib/DiagnosticsConfig.h>

#include <Protocol/DiagnosticsConfigDxe.h>

#include "DiagnosticsConfigInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC DIAGNOSTIC_CONFIG_PROTOCOL *pDiagnosticsConfigProtocol;

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
EFI_STATUS
SetDiagnosticsLogUsageFlag (
  IN UINT16 usageFlag
)
{
  EFI_STATUS  Status;

  Status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (Status != EFI_SUCCESS)
    return Status;

  Status = pDiagnosticsConfigProtocol->SetDiagnosticsLogUsageFlag(usageFlag);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
EFI_STATUS
SetComPortUsageFlag (
  IN UINT16 usageFlag
)
{
  EFI_STATUS  Status;

  Status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (Status != EFI_SUCCESS)
    return Status;

  Status = pDiagnosticsConfigProtocol->SetComPortUsageFlag(usageFlag);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
EFI_STATUS
SetNetLogUsageFlag (
  IN UINT16 usageFlag
)
{
  EFI_STATUS  status;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return status;

  status = pDiagnosticsConfigProtocol->SetNetLogUsageFlag(usageFlag);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
EFI_STATUS
SetRamLogUsageFlag (
  IN UINT16 usageFlag
)
{
  EFI_STATUS  status;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return status;

  status = pDiagnosticsConfigProtocol->SetRamLogUsageFlag(usageFlag);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get diagnostics usage flag */
//------------------------------------------------------------------------------
UINT16
GetDiagnosticsLogUsageFlag (
  VOID
)
{
  EFI_STATUS  status;
  UINT16      diagnosticsFlag;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return NOT_USE;

  diagnosticsFlag = pDiagnosticsConfigProtocol->GetDiagnosticsLogUsageFlag();

  return diagnosticsFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief  */
//------------------------------------------------------------------------------
UINT16
GetComPortUsageFlag (
  VOID
)
{
  EFI_STATUS  status;
  UINT16      comPortUsageFlag;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return NOT_USE;

  comPortUsageFlag = pDiagnosticsConfigProtocol->GetComPortUsageFlag();

  return comPortUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief  */
//------------------------------------------------------------------------------
UINT16
GetNetLogUsageFlag (
  VOID
)
{
  EFI_STATUS  status;
  UINT16      netLogUsageFlag;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return NOT_USE;

  netLogUsageFlag = pDiagnosticsConfigProtocol->GetNetLogUsageFlag();

  return netLogUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief  */
//------------------------------------------------------------------------------
UINT16
GetRamLogUsageFlag (
  VOID
)
{
  EFI_STATUS  status;
  UINT16      ramLogUsageFlag;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return NOT_USE;

  ramLogUsageFlag = pDiagnosticsConfigProtocol->GetRamLogUsageFlag();

  return ramLogUsageFlag;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Erase buffers of the Diagnostics Config data */
//------------------------------------------------------------------------------
VOID
DeleteDiagnosticsConfig (
  VOID
)
{
  EFI_STATUS  status;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return;

  pDiagnosticsConfigProtocol->DeleteDiagnosticsConfig();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save diagnostics config to varable */
//------------------------------------------------------------------------------
EFI_STATUS
SaveDiagnosticsConfig (
  VOID
)
{
  EFI_STATUS status;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return status;

  status = pDiagnosticsConfigProtocol->SaveDiagnosticsConfig();

  return status;
}
//------------------------------------------------------------------------------

VOID
ResetDiagnosticsConfig (
  VOID
  )
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  pDiagnosticsConfigProtocol->DeleteDiagnosticsConfig ();
}

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
EFI_STATUS
ReadDiagnosticsConfig (
  VOID
)
{
  EFI_STATUS status;

  status = gBS->LocateProtocol (
                  &gDiagnosticsConfigProtocolGuid,
                  NULL,
                  (VOID **) &pDiagnosticsConfigProtocol
                  );
  if (status != EFI_SUCCESS)
    return status;

  status = pDiagnosticsConfigProtocol->ReadDiagnosticsConfig();

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

