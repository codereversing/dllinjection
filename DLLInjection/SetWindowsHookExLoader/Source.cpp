#include <Windows.h>

#include <format>
#include <iostream>
#include <utility>

#define PrintErrorAndExit(functionName) \
    PrintErrorWithLineAndExit(functionName, __LINE__)

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, GetLastError()) << std::endl;

    std::exit(-1);
}

std::pair<DWORD, DWORD> GetTargetProcessAndThreadId(const std::string& windowTitle) {

    DWORD processId{};
    const auto threadId{ GetWindowThreadProcessId(
        FindWindowA(nullptr, windowTitle.c_str()),
        &processId) };
    if (threadId == 0 || processId == 0) {
        PrintErrorAndExit("GetWindowThreadProcessId");
    }

    return std::make_pair(processId, threadId);
}

int main(int argc, char* argv[]) {

    const auto injectingLibrary{ LoadLibraryA("SetWindowsHookExDll.dll") };
    if (injectingLibrary == nullptr) {
        PrintErrorAndExit("LoadLibraryA");
    }

    const auto hookFunctionAddress{ reinterpret_cast<HOOKPROC>(
        GetProcAddress(injectingLibrary, "KeyboardProc")) };

    if (hookFunctionAddress == nullptr) {
        std::cerr << "Could not find hook function" << std::endl;
        return -1;
    }
    
    const auto threadId{ GetTargetProcessAndThreadId(
        "Untitled - Notepad").second};

    const auto hook{ SetWindowsHookEx(WH_KEYBOARD,
        hookFunctionAddress, injectingLibrary, threadId) };
    if (hook == nullptr) {
        PrintErrorAndExit("SetWindowsHookEx");
    }

    std::cout << "Hook installed. Press enter to remove hook and exit."
        << std::endl;

    std::cin.get();

    UnhookWindowsHookEx(hook);

    return 0;
}
