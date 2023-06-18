#include <Windows.h>

extern "C" {

__declspec(dllexport) LRESULT CALLBACK KeyboardProc(
    int nCode, WPARAM wParam, LPARAM lParam) {

    if (nCode != HC_ACTION) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }

    // Key is up
    if ((lParam & 0x80000000) || (lParam & 0x40000000)) {
        MessageBoxA(nullptr, "Hello World!",
            nullptr, 0);
    }

    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
    LPVOID lpvReserved) {

    return TRUE;
}
