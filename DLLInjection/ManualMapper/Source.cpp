#ifdef _UNICODE
#undef UNICODE
#endif

#pragma comment(lib, "Dbghelp.lib")

#include <Windows.h>

#include <DbgHelp.h>
#include <TlHelp32.h>

#include <algorithm>
#include <format>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

constexpr size_t REMOTE_PE_HEADER_ALLOC_SIZE = 4096;
constexpr size_t REMOTE_RELOC_STUB_ALLOC_SIZE = 4096;

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

typedef struct {
    void* const remoteDllBaseAddress;
    LoadLibraryAPtr remoteLoadLibraryAAddress;
    GetProcAddressPtr remoteGetProcAddressAddress;
} RelocationStubParameters;

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {

    return reinterpret_cast<DWORD_PTR>(baseAddress) -
        reinterpret_cast<DWORD_PTR>(offset);
}

#define RvaToPointer(type, baseAddress, offset) \
    reinterpret_cast<type>( \
        reinterpret_cast<DWORD_PTR>(baseAddress) + offset)


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

HANDLE GetTargetProcessHandle(const DWORD processId) {

    const auto processHandle{ OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE, false, processId) };
    if (processHandle == nullptr) {
        PrintErrorAndExit("OpenProcess");
    }

    return processHandle;
}

void* WriteDllFileBytesToProcess(const HANDLE processHandle, const std::vector<char>& fileBytes) {

    const auto dosHeader{ reinterpret_cast<const IMAGE_DOS_HEADER*>(
        fileBytes.data()) };
    const auto ntHeader{ reinterpret_cast<const IMAGE_NT_HEADERS*>(
        fileBytes.data() + dosHeader->e_lfanew) };

    const auto remoteBaseAddress{ VirtualAllocEx(processHandle, nullptr,
        ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE) };
    if (remoteBaseAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    const auto* currentSection{ IMAGE_FIRST_SECTION(ntHeader) };
    for (size_t i{}; i < ntHeader->FileHeader.NumberOfSections; i++) {

        SIZE_T bytesWritten{};
        const auto result{ WriteProcessMemory(processHandle,
            static_cast<char*>(remoteBaseAddress) + currentSection->VirtualAddress,
            fileBytes.data() + currentSection->PointerToRawData,
            currentSection->SizeOfRawData, &bytesWritten) };
        if (!result || bytesWritten == 0) {
            PrintErrorAndExit("WriteProcessMemory");
        }

        currentSection++;
    }

    SIZE_T bytesWritten{};
    const auto result{ WriteProcessMemory(processHandle, remoteBaseAddress,
        fileBytes.data(), REMOTE_PE_HEADER_ALLOC_SIZE, &bytesWritten) };
    if (!result || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    return remoteBaseAddress;
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

    MODULEENTRY32 module{
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

void RelocationStub(RelocationStubParameters* parameters) {

    const auto dosHeader{ reinterpret_cast<IMAGE_DOS_HEADER*>(
        parameters->remoteDllBaseAddress) };
    const auto ntHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<DWORD_PTR>(
            parameters->remoteDllBaseAddress) + dosHeader->e_lfanew) };

    const auto relocationOffset{ reinterpret_cast<DWORD_PTR>(
        parameters->remoteDllBaseAddress) - ntHeader->OptionalHeader.ImageBase };

    typedef struct {
        WORD offset : 12;
        WORD type : 4;
    } RELOCATION_INFO;

    const auto* baseRelocationDirectoryEntry{
        reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) };

    while (baseRelocationDirectoryEntry->VirtualAddress != 0) {

        const auto relocationCount{ 
            (baseRelocationDirectoryEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(RELOCATION_INFO) };

        const auto* baseRelocationInfo{ reinterpret_cast<RELOCATION_INFO*>(
            reinterpret_cast<DWORD_PTR>(baseRelocationDirectoryEntry) + sizeof(RELOCATION_INFO)) };

        for (size_t i{}; i < relocationCount; i++, baseRelocationInfo++) {
            if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64) {
                const auto relocFixAddress{ reinterpret_cast<DWORD*>(
                    reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
                    baseRelocationDirectoryEntry->VirtualAddress + baseRelocationInfo->offset) };
                *relocFixAddress += static_cast<DWORD>(relocationOffset);
            }
        }

        baseRelocationDirectoryEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<DWORD_PTR>(baseRelocationDirectoryEntry) +
            baseRelocationDirectoryEntry->SizeOfBlock);
    }

    const auto* const baseImportsDirectory{
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
            ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) };

    for (size_t index{}; baseImportsDirectory[index].Characteristics != 0; index++) {

        const auto* const moduleName{ RvaToPointer(char*, parameters->remoteDllBaseAddress,
            baseImportsDirectory[index].Name) };
        const auto loadedModuleHandle{ parameters->remoteLoadLibraryAAddress(moduleName) };

        auto* addressTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
            parameters->remoteDllBaseAddress, baseImportsDirectory[index].FirstThunk) };
        const auto* nameTableEntry{ RvaToPointer(IMAGE_THUNK_DATA*,
            parameters->remoteDllBaseAddress, baseImportsDirectory[index].OriginalFirstThunk) };

        if (nameTableEntry == nullptr) {
            nameTableEntry = addressTableEntry;
        }

        for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {

            const auto* const importedFunction{ RvaToPointer(IMAGE_IMPORT_BY_NAME*,
                parameters->remoteDllBaseAddress, nameTableEntry->u1.AddressOfData) };

            if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

                addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
                    parameters->remoteGetProcAddressAddress(loadedModuleHandle,
                    MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
            }
            else {
                addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
                    parameters->remoteGetProcAddressAddress(loadedModuleHandle,
                    importedFunction->Name));
            }   
        }
    }

    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) {
        const auto* const baseTlsEntries{
            reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
                reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
                ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };

        const auto* tlsCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(
            baseTlsEntries->AddressOfCallBacks) };
        while (tlsCallback != nullptr) {
            (*tlsCallback)(parameters->remoteDllBaseAddress, DLL_PROCESS_ATTACH,
                nullptr);
            tlsCallback++;
        }
    }

    using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

    const auto DllMain{ reinterpret_cast<DllMainPtr>(
        reinterpret_cast<DWORD_PTR>(parameters->remoteDllBaseAddress) +
        ntHeader->OptionalHeader.AddressOfEntryPoint) };

    DllMain(reinterpret_cast<HINSTANCE>(parameters->remoteDllBaseAddress),
        DLL_PROCESS_ATTACH, nullptr);
}

std::pair<void*, void*> WriteRelocationStubToTargetProcess(const HANDLE processHandle,
    const RelocationStubParameters& parameters) {

    auto* const remoteParametersAddress{ VirtualAllocEx(processHandle, nullptr,
        REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
    if (remoteParametersAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    SIZE_T bytesWritten{};
    auto result{ WriteProcessMemory(processHandle, remoteParametersAddress,
        &parameters, sizeof(RelocationStubParameters),
        &bytesWritten) };
    if (!result || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    auto* const remoteRelocationStubAddress{ VirtualAllocEx(processHandle, nullptr,
        REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
    if (remoteRelocationStubAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    result = WriteProcessMemory(processHandle, remoteRelocationStubAddress, RelocationStub,
        REMOTE_RELOC_STUB_ALLOC_SIZE, &bytesWritten);
    if (!result || bytesWritten == 0) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    return std::make_pair(remoteRelocationStubAddress, remoteParametersAddress);
}

std::vector<char> GetDllFileBytes(const std::string& fullModulePath) {

    std::ifstream fileStream(fullModulePath.c_str(),
        std::ios::in | std::ios::binary | std::ios::ate);

    const auto fileSize{ fileStream.tellg() };
    fileStream.seekg(0, std::ios::beg);

    std::vector<char> fileBytes(fileSize);
    fileStream.read(fileBytes.data(), fileSize);

    return fileBytes;
}

void InjectByManualMapping(const DWORD processId, const std::string& fullModulePath) {

    const auto processHandle{ GetTargetProcessHandle(processId) };
    const auto fileBytes{ GetDllFileBytes(fullModulePath) };

    auto* const remoteDllBaseAddress{ WriteDllFileBytesToProcess(processHandle, fileBytes) };
    auto* const remoteLoadLibraryAddress{ GetRemoteModuleFunctionAddress(
        "kernel32.dll", "LoadLibraryA", processId) };
    auto* const remoteGetProcAddressAddress{ GetRemoteModuleFunctionAddress(
        "kernel32.dll", "GetProcAddress", processId) };

    const RelocationStubParameters parameters{
        .remoteDllBaseAddress = remoteDllBaseAddress,
        .remoteLoadLibraryAAddress = reinterpret_cast<LoadLibraryAPtr>(
            remoteLoadLibraryAddress),
        .remoteGetProcAddressAddress = reinterpret_cast<GetProcAddressPtr>(
            remoteGetProcAddressAddress)
    };

    const auto relocationInfo{
        WriteRelocationStubToTargetProcess(processHandle, parameters) };

    std::cout << std::format("Start address: {}\n"
        "Parameters address: {}\n",
        relocationInfo.first, relocationInfo.second);

    const auto remoteThread{ CreateRemoteThreadEx(processHandle, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(relocationInfo.first),
        relocationInfo.second, 0, nullptr, 0) };
    if (remoteThread == nullptr) {
        PrintErrorAndExit("CreateRemoteThreadEx");
    }
}

int main(int argc, char* argv[]) {

    const auto fullModulePath{ GetInjectedDllPath("GenericDll.dll") };

    const auto processId{ GetTargetProcessAndThreadId(
        "Untitled - Notepad").first };

    InjectByManualMapping(processId, fullModulePath);

    return 0;
}
