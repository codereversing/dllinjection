#include <Windows.h>

extern "C" {

__declspec(dllexport) void DisplayHelloWorld() {
    MessageBoxA(nullptr, "Hello World!", nullptr, 0);
}

}
// hinstDLL will contain the address that the
// DLL was loaded at.
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
    LPVOID lpvReserved) {

    switch (fdwReason) {

    // DLL is being mapped into another processes address space.
    case DLL_PROCESS_ATTACH:
        MessageBoxA(nullptr, "DLL Injected!", nullptr, 0);
        break;

    // A thread in the process is being created
    case DLL_THREAD_ATTACH:
        break;

    // A thread in the process is terminating
    case DLL_THREAD_DETACH:
        break;

    // DLL is being unmapped from the process address space.
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
