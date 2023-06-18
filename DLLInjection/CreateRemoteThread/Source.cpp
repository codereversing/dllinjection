#ifdef _UNICODE
#undef UNICODE
#endif

#include <Windows.h>

#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <format>
#include <iostream>
#include <span>
#include <string>
#include <utility>

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {

    return reinterpret_cast<DWORD_PTR>(baseAddress) -
        reinterpret_cast<DWORD_PTR>(offset);
}

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

HANDLE GetTargetProcessHandle(const DWORD processId) {

    const auto processHandle{ OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        false, processId) };
    if (processHandle == nullptr) {
        PrintErrorAndExit("OpenProcess");
    }

    return processHandle;
}

template <typename T>
void* WriteBytesToTargetProcess(const HANDLE processHandle,
    const std::span<T> bytes, bool makeExecutable = false) {

    static_assert(sizeof(T) == sizeof(uint8_t), "Only bytes can be written.");

    const auto remoteBytesAddress{ VirtualAllocEx(processHandle, nullptr,
    bytes.size(), MEM_RESERVE | MEM_COMMIT,
        makeExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) };
    if (remoteBytesAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    size_t bytesWritten{};
    const auto result{ WriteProcessMemory(processHandle, remoteBytesAddress,
        bytes.data(), bytes.size(), &bytesWritten) };
    if (!result) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    return remoteBytesAddress;
}

void* GetRemoteModuleFunctionAddress(const std::string moduleName,
    const std::string functionName, const DWORD processId) {

    void* localModuleBaseAddress{ GetModuleHandleA(moduleName.c_str()) };
    if (localModuleBaseAddress == nullptr) {
        localModuleBaseAddress = LoadLibraryA(moduleName.c_str());
        if (localModuleBaseAddress == nullptr) {
            PrintErrorAndExit("LoadLibraryA");
        }
    }

    const void* const localFunctionAddress{
        GetProcAddress(static_cast<HMODULE>(localModuleBaseAddress), functionName.c_str()) };

    if (localFunctionAddress == nullptr) {
        PrintErrorAndExit("GetProcAddress");
    }

    const auto functionOffset{ PointerToRva(
        localFunctionAddress, localModuleBaseAddress) };

    const auto snapshotHandle{ CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE, processId) };
    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        PrintErrorAndExit("CreateToolhelp32Snapshot");
    }

    MODULEENTRY32 module {
        .dwSize = sizeof(MODULEENTRY32)
    };

    if (!Module32First(snapshotHandle, &module)) {
        PrintErrorAndExit("Module32First");
    }

    do {
        auto currentModuleName{ std::string{module.szModule} };

        std::transform(currentModuleName.begin(), currentModuleName.end(), currentModuleName.begin(),
            [](unsigned char letter) { return std::tolower(letter); });
        if (currentModuleName == moduleName) {
            return reinterpret_cast<void*>(module.modBaseAddr + functionOffset);
        }

    } while (Module32Next(snapshotHandle, &module));

    return nullptr;
}

std::string GetInjectedDllPath(const std::string& moduleName) {

    char imageName[MAX_PATH]{};
    DWORD bytesWritten{ MAX_PATH };
    auto result{ QueryFullProcessImageNameA(GetCurrentProcess(),
        0, imageName, &bytesWritten) };
    if (!result) {
        PrintErrorAndExit("QueryFullProcessImageNameA");
    }

    const std::string currentDirectoryPath{ imageName, bytesWritten };
    const auto fullModulePath{ currentDirectoryPath.substr(
        0, currentDirectoryPath.find_last_of('\\') + 1)
        + moduleName };

    return fullModulePath;
}

void InjectWithRemoteThread(const DWORD processId, std::string& fullModulePath) {

    const auto processHandle{ GetTargetProcessHandle(processId) };

    const auto remoteStringAddress{ WriteBytesToTargetProcess<char>(
        processHandle, fullModulePath) };

    const auto* const loadLibraryAddress{ GetRemoteModuleFunctionAddress(
        "kernel32.dll", "LoadLibraryA", processId) };

    const auto threadHandle{ CreateRemoteThreadEx(processHandle, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress),
        remoteStringAddress, 0, nullptr, nullptr) };
    if (threadHandle == nullptr) {
        PrintErrorAndExit("CreateRemoteThread");
    }

    CloseHandle(processHandle);
}

int main(int argc, char* argv[]) {

    auto fullModulePath{ GetInjectedDllPath("GenericDll.dll") };

    const auto processId{ GetTargetProcessAndThreadId(
        "Untitled - Notepad").first };

    InjectWithRemoteThread(processId, fullModulePath);

    return 0;
}
