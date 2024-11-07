/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_KMDFDriverHelloWorld,
    0xa55d0f86,0x8134,0x4296,0xb4,0x7a,0x69,0x53,0x8f,0x70,0xa1,0xe9);
// {a55d0f86-8134-4296-b47a-69538f70a1e9}
