/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "PciDesc.h"

extern EFI_GUID gEfiAcpiSdtProtocolGuid;
extern EFI_GUID gEfiPciRootBridgeIoProtocolGuid;

PCI_CLASS_ENTRY PCI_BlankEntry[];
PCI_CLASS_ENTRY PCI_SubClass_00[];
PCI_CLASS_ENTRY PCI_SubClass_01[];
PCI_CLASS_ENTRY PCI_SubClass_02[];
PCI_CLASS_ENTRY PCI_SubClass_03[];
PCI_CLASS_ENTRY PCI_SubClass_04[];
PCI_CLASS_ENTRY PCI_SubClass_05[];
PCI_CLASS_ENTRY PCI_SubClass_06[];
PCI_CLASS_ENTRY PCI_SubClass_07[];
PCI_CLASS_ENTRY PCI_SubClass_08[];
PCI_CLASS_ENTRY PCI_SubClass_09[];
PCI_CLASS_ENTRY PCI_SubClass_0a[];
PCI_CLASS_ENTRY PCI_SubClass_0b[];
PCI_CLASS_ENTRY PCI_SubClass_0c[];
PCI_CLASS_ENTRY PCI_SubClass_0d[];
PCI_CLASS_ENTRY PCI_SubClass_0e[];
PCI_CLASS_ENTRY PCI_SubClass_0f[];
PCI_CLASS_ENTRY PCI_SubClass_10[];
PCI_CLASS_ENTRY PCI_SubClass_11[];
PCI_CLASS_ENTRY PCI_PIFClass_0101[];
PCI_CLASS_ENTRY PCI_PIFClass_0300[];
PCI_CLASS_ENTRY PCI_PIFClass_0604[];
PCI_CLASS_ENTRY PCI_PIFClass_0700[];
PCI_CLASS_ENTRY PCI_PIFClass_0701[];
PCI_CLASS_ENTRY PCI_PIFClass_0703[];
PCI_CLASS_ENTRY PCI_PIFClass_0800[];
PCI_CLASS_ENTRY PCI_PIFClass_0801[];
PCI_CLASS_ENTRY PCI_PIFClass_0802[];
PCI_CLASS_ENTRY PCI_PIFClass_0803[];
PCI_CLASS_ENTRY PCI_PIFClass_0904[];
PCI_CLASS_ENTRY PCI_PIFClass_0c00[];
PCI_CLASS_ENTRY PCI_PIFClass_0c03[];
PCI_CLASS_ENTRY PCI_PIFClass_0e00[];

//
// Subclass strings entries
//
PCI_CLASS_ENTRY PCI_BlankEntry[] = {
  {
    0x00,
    L"",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_00[] = {
  {
    0x00,
    L"All devices other than VGA",
    PCI_BlankEntry
  },
  {
    0x01,
    L"VGA-compatible devices",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_01[] = {
  {
    0x00,
    L"SCSI controller",
    PCI_BlankEntry
  },
  {
    0x01,
    L"IDE controller",
    PCI_PIFClass_0101
  },
  {
    0x02,
    L"Floppy disk controller",
    PCI_BlankEntry
  },
  {
    0x03,
    L"IPI controller",
    PCI_BlankEntry
  },
  {
    0x04,
    L"RAID controller",
    PCI_BlankEntry
  },
  {
    0x05,
    L"ATA controller",
    PCI_BlankEntry
  },
  {
    0x06,
    L"SATA controller",
    PCI_BlankEntry
  },

  {
    0x80,
    L"Other mass storage controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_02[] = {
  {
    0x00,
    L"Ethernet controller",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Token ring controller",
    PCI_BlankEntry
  },
  {
    0x02,
    L"FDDI controller",
    PCI_BlankEntry
  },
  {
    0x03,
    L"ATM controller",
    PCI_BlankEntry
  },
  {
    0x04,
    L"ISDN controller",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other network controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_03[] = {
  {
    0x00,
    L"VGA/8514 controller",
    PCI_PIFClass_0300
  },
  {
    0x01,
    L"XGA controller",
    PCI_BlankEntry
  },
  {
    0x02,
    L"3D controller",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other display controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */PCI_BlankEntry
  }
};

PCI_CLASS_ENTRY PCI_SubClass_04[] = {
  {
    0x00,
    L"Video device",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Multimedia audio controller",
    PCI_BlankEntry
  },
  {
    0x02,
    L"Computer Telephony device",
    PCI_BlankEntry
  },
  {
    0x03,
    L"Audio device",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other multimedia device",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_05[] = {
  {
    0x00,
    L"RAM memory controller",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Flash memory controller",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other memory controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_06[] = {
  {
    0x00,
    L"Host/PCI bridge",
    PCI_BlankEntry
  },
  {
    0x01,
    L"PCI/ISA bridge",
    PCI_BlankEntry
  },
  {
    0x02,
    L"PCI/EISA bridge",
    PCI_BlankEntry
  },
  {
    0x03,
    L"PCI/Micro Channel bridge",
    PCI_BlankEntry
  },
  {
    0x04,
    L"PCI/PCI bridge",
    PCI_PIFClass_0604
  },
  {
    0x05,
    L"PCI/PCMCIA bridge",
    PCI_BlankEntry
  },
  {
    0x06,
    L"NuBus bridge",
    PCI_BlankEntry
  },
  {
    0x07,
    L"CardBus bridge",
    PCI_BlankEntry
  },
  {
    0x08,
    L"RACEway bridge",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other bridge type",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_07[] = {
  {
    0x00,
    L"Serial controller",
    PCI_PIFClass_0700
  },
  {
    0x01,
    L"Parallel port",
    PCI_PIFClass_0701
  },
  {
    0x02,
    L"Multiport serial controller",
    PCI_BlankEntry
  },
  {
    0x03,
    L"Modem",
    PCI_PIFClass_0703
  },
  {
    0x80,
    L"Other communication device",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_08[] = {
  {
    0x00,
    L"PIC",
    PCI_PIFClass_0800
  },
  {
    0x01,
    L"DMA controller",
    PCI_PIFClass_0801
  },
  {
    0x02,
    L"System timer",
    PCI_PIFClass_0802
  },
  {
    0x03,
    L"RTC controller",
    PCI_PIFClass_0803
  },
  {
    0x04,
    L"Generic PCI Hot-Plug controller",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other system peripheral",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_09[] = {
  {
    0x00,
    L"Keyboard controller",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Digitizer (pen)",
    PCI_BlankEntry
  },
  {
    0x02,
    L"Mouse controller",
    PCI_BlankEntry
  },
  {
    0x03,
    L"Scanner controller",
    PCI_BlankEntry
  },
  {
    0x04,
    L"Gameport controller",
    PCI_PIFClass_0904
  },
  {
    0x80,
    L"Other input controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0a[] = {
  {
    0x00,
    L"Generic docking station",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other type of docking station",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0b[] = {
  {
    0x00,
    L"386",
    PCI_BlankEntry
  },
  {
    0x01,
    L"486",
    PCI_BlankEntry
  },
  {
    0x02,
    L"Pentium",
    PCI_BlankEntry
  },
  {
    0x10,
    L"Alpha",
    PCI_BlankEntry
  },
  {
    0x20,
    L"PowerPC",
    PCI_BlankEntry
  },
  {
    0x30,
    L"MIPS",
    PCI_BlankEntry
  },
  {
    0x40,
    L"Co-processor",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other processor",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0c[] = {
  {
    0x00,
    L"Firewire(IEEE 1394)",
    PCI_PIFClass_0c03
  },
  {
    0x01,
    L"ACCESS.bus",
    PCI_BlankEntry
  },
  {
    0x02,
    L"SSA",
    PCI_BlankEntry
  },
  {
    0x03,
    L"USB",
    PCI_PIFClass_0c00
  },
  {
    0x04,
    L"Fibre Channel",
    PCI_BlankEntry
  },
  {
    0x05,
    L"System Management Bus",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other bus type",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0d[] = {
  {
    0x00,
    L"iRDA compatible controller",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Consumer IR controller",
    PCI_BlankEntry
  },
  {
    0x10,
    L"RF controller",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other type of wireless controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0e[] = {
  {
    0x00,
    L"I2O Architecture",
    PCI_PIFClass_0e00
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_0f[] = {
  {
    0x00,
    L"TV",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Audio",
    PCI_BlankEntry
  },
  {
    0x02,
    L"Voice",
    PCI_BlankEntry
  },
  {
    0x03,
    L"Data",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_10[] = {
  {
    0x00,
    L"Network & computing Encrypt/Decrypt",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Entertainment Encrypt/Decrypt",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other Encrypt/Decrypt",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_SubClass_11[] = {
  {
    0x00,
    L"DPIO modules",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Other DAQ & SP controllers",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

//
// Programming Interface entries
//
PCI_CLASS_ENTRY PCI_PIFClass_0101[] = {
  {
    0x00,
    L"",
    PCI_BlankEntry
  },
  {
    0x01,
    L"OM-primary",
    PCI_BlankEntry
  },
  {
    0x02,
    L"PI-primary",
    PCI_BlankEntry
  },
  {
    0x03,
    L"OM/PI-primary",
    PCI_BlankEntry
  },
  {
    0x04,
    L"OM-secondary",
    PCI_BlankEntry
  },
  {
    0x05,
    L"OM-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x06,
    L"PI-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x07,
    L"OM/PI-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x08,
    L"OM-secondary",
    PCI_BlankEntry
  },
  {
    0x09,
    L"OM-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x0a,
    L"PI-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x0b,
    L"OM/PI-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x0c,
    L"OM-secondary",
    PCI_BlankEntry
  },
  {
    0x0d,
    L"OM-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x0e,
    L"PI-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x0f,
    L"OM/PI-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x80,
    L"Master",
    PCI_BlankEntry
  },
  {
    0x81,
    L"Master, OM-primary",
    PCI_BlankEntry
  },
  {
    0x82,
    L"Master, PI-primary",
    PCI_BlankEntry
  },
  {
    0x83,
    L"Master, OM/PI-primary",
    PCI_BlankEntry
  },
  {
    0x84,
    L"Master, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x85,
    L"Master, OM-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x86,
    L"Master, PI-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x87,
    L"Master, OM/PI-primary, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x88,
    L"Master, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x89,
    L"Master, OM-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x8a,
    L"Master, PI-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x8b,
    L"Master, OM/PI-primary, PI-secondary",
    PCI_BlankEntry
  },
  {
    0x8c,
    L"Master, OM-secondary",
    PCI_BlankEntry
  },
  {
    0x8d,
    L"Master, OM-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x8e,
    L"Master, PI-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x8f,
    L"Master, OM/PI-primary, OM/PI-secondary",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0300[] = {
  {
    0x00,
    L"VGA compatible",
    PCI_BlankEntry
  },
  {
    0x01,
    L"8514 compatible",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0604[] = {
  {
    0x00,
    L"",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Subtractive decode",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0700[] = {
  {
    0x00,
    L"Generic XT-compatible",
    PCI_BlankEntry
  },
  {
    0x01,
    L"16450-compatible",
    PCI_BlankEntry
  },
  {
    0x02,
    L"16550-compatible",
    PCI_BlankEntry
  },
  {
    0x03,
    L"16650-compatible",
    PCI_BlankEntry
  },
  {
    0x04,
    L"16750-compatible",
    PCI_BlankEntry
  },
  {
    0x05,
    L"16850-compatible",
    PCI_BlankEntry
  },
  {
    0x06,
    L"16950-compatible",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0701[] = {
  {
    0x00,
    L"",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Bi-directional",
    PCI_BlankEntry
  },
  {
    0x02,
    L"ECP 1.X-compliant",
    PCI_BlankEntry
  },
  {
    0x03,
    L"IEEE 1284",
    PCI_BlankEntry
  },
  {
    0xfe,
    L"IEEE 1284 target (not a controller)",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0703[] = {
  {
    0x00,
    L"Generic",
    PCI_BlankEntry
  },
  {
    0x01,
    L"Hayes-compatible 16450",
    PCI_BlankEntry
  },
  {
    0x02,
    L"Hayes-compatible 16550",
    PCI_BlankEntry
  },
  {
    0x03,
    L"Hayes-compatible 16650",
    PCI_BlankEntry
  },
  {
    0x04,
    L"Hayes-compatible 16750",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0800[] = {
  {
    0x00,
    L"Generic 8259",
    PCI_BlankEntry
  },
  {
    0x01,
    L"ISA",
    PCI_BlankEntry
  },
  {
    0x02,
    L"EISA",
    PCI_BlankEntry
  },
  {
    0x10,
    L"IO APIC",
    PCI_BlankEntry
  },
  {
    0x20,
    L"IO(x) APIC interrupt controller",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0801[] = {
  {
    0x00,
    L"Generic 8237",
    PCI_BlankEntry
  },
  {
    0x01,
    L"ISA",
    PCI_BlankEntry
  },
  {
    0x02,
    L"EISA",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0802[] = {
  {
    0x00,
    L"Generic 8254",
    PCI_BlankEntry
  },
  {
    0x01,
    L"ISA",
    PCI_BlankEntry
  },
  {
    0x02,
    L"EISA",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0803[] = {
  {
    0x00,
    L"Generic",
    PCI_BlankEntry
  },
  {
    0x01,
    L"ISA",
    PCI_BlankEntry
  },
  {
    0x02,
    L"EISA",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0904[] = {
  {
    0x00,
    L"Generic",
    PCI_BlankEntry
  },
  {
    0x10,
    L"",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0c00[] = {
  {
    0x00,
    L"Universal Host Controller spec",
    PCI_BlankEntry
  },
  {
    0x10,
    L"Open Host Controller spec",
    PCI_BlankEntry
  },
  {
    0x20,
    L"Enhanced Host Controller spec",
    PCI_BlankEntry
  },
  {
    0x30,
    L"eXtensible Host Controller spec",
    PCI_BlankEntry
  },
  {
    0x80,
    L"No specific programming interface",
    PCI_BlankEntry
  },
  {
    0xfe,
    L"(Not Host Controller)",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0c03[] = {
  {
    0x00,
    L"",
    PCI_BlankEntry
  },
  {
    0x10,
    L"Using 1394 OpenHCI spec",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY PCI_PIFClass_0e00[] = {
  {
    0x00,
    L"Message FIFO at offset 40h",
    PCI_BlankEntry
  },
  {
    0x01,
    L"",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};



PCI_CLASS_ENTRY ClassStringListDefs[] = {
  {
    0x00,
    L"Pre 2.0 device",
    PCI_SubClass_00
  },
  {
    0x01,
    L"Mass Storage Controller",
    PCI_SubClass_01
  },
  {
    0x02,
    L"Network Controller",
    PCI_SubClass_02
  },
  {
    0x03,
    L"Display Controller",
    PCI_SubClass_03
  },
  {
    0x04,
    L"Multimedia Device",
    PCI_SubClass_04
  },
  {
    0x05,
    L"Memory Controller",
    PCI_SubClass_05
  },
  {
    0x06,
    L"Bridge Device",
    PCI_SubClass_06
  },
  {
    0x07,
    L"Simple Communications Controllers",
    PCI_SubClass_07
  },
  {
    0x08,
    L"Base System Peripherals",
    PCI_SubClass_08
  },
  {
    0x09,
    L"Input Devices",
    PCI_SubClass_09
  },
  {
    0x0a,
    L"Docking Stations",
    PCI_SubClass_0a
  },
  {
    0x0b,
    L"Processors",
    PCI_SubClass_0b
  },
  {
    0x0c,
    L"Serial Bus Controllers",
    PCI_SubClass_0c
  },
  {
    0x0d,
    L"Wireless Controllers",
    PCI_SubClass_0d
  },
  {
    0x0e,
    L"Intelligent IO Controllers",
    PCI_SubClass_0e
  },
  {
    0x0f,
    L"Satellite Communications Controllers",
    PCI_SubClass_0f
  },
  {
    0x10,
    L"Encryption/Decryption Controllers",
    PCI_SubClass_10
  },
  {
    0x11,
    L"Data Acquisition & Signal Processing Controllers",
    PCI_SubClass_11
  },
  {
    0xff,
    L"Device does not fit in any defined classes",
    PCI_BlankEntry
  },
  {
    0x00,
    NULL,
    /* null string ends the list */NULL
  }
};

PCI_CLASS_ENTRY *
GetClassStringListDefs (
  VOID
  )
{
  return ClassStringListDefs;
}

