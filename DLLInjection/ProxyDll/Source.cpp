#pragma comment(linker, "/export:DisplayHelloWorld=GenericDll2.DisplayHelloWorld")

#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
    LPVOID lpvReserved) {

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(nullptr, "Proxy DLL Loaded!", nullptr, 0);
    }

    return TRUE;
}
