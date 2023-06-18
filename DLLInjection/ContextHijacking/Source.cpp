#ifdef _UNICODE
#undef UNICODE
#endif

#include <Windows.h>

#include <ProcessSnapshot.h>
#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <format>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#define OVERLOADED_MACRO(M, ...) _OVR(M, _COUNT_ARGS(__VA_ARGS__)) (__VA_ARGS__)
#define _OVR(macroName, number_of_args)   _OVR_EXPAND(macroName, number_of_args)
#define _OVR_EXPAND(macroName, number_of_args)    macroName##number_of_args

#define _COUNT_ARGS(...)  _ARG_PATTERN_MATCH(__VA_ARGS__,2,1)
#define _ARG_PATTERN_MATCH(_1,_2,N, ...)   N

#define PrintErrorAndExit(...)     OVERLOADED_MACRO(PrintErrorAndExit, __VA_ARGS__)

#define PrintErrorAndExit2( X, Y ) PrintErrorWithLineAndExit(X, __LINE__, Y)
#define PrintErrorAndExit1( X ) PrintErrorWithLineAndExit(X, __LINE__, GetLastError())

void PrintErrorWithLineAndExit(const std::string& functionName, const size_t line, const size_t errorCode) {

    std::cerr << std::format("{}@{} failed with {:X}",
        functionName, line, errorCode) << std::endl;

    std::exit(-1);
}

using NtSuspendProcessPtr = int(__stdcall*)(HANDLE processHandle);
using NtResumeProcessPtr = int(__stdcall*)(HANDLE processHandle);

// Courtesy of https://stackoverflow.com/a/42774523
template <typename Type, std::size_t... sizes>
auto concatenate(const std::array<Type, sizes>&... arrays)
{
    std::array<Type, (sizes + ...)> result;
    std::size_t index{};

    ((std::copy_n(arrays.begin(), sizes, result.begin() + index), index += sizes), ...);

    return result;
}

DWORD_PTR PointerToRva(const void* const baseAddress, const void* const offset) {

    return reinterpret_cast<DWORD_PTR>(baseAddress) -
        reinterpret_cast<DWORD_PTR>(offset);
}

void SetTargetThreadContext(const DWORD threadId, const void* const newRip, CONTEXT& context) {

    const auto threadHandle{ OpenThread(THREAD_SET_CONTEXT,
        false, threadId) };
    if (threadHandle == nullptr) {
        PrintErrorAndExit("OpenThread");
    }

    context.Rip = reinterpret_cast<DWORD_PTR>(newRip);

    const auto result{ SetThreadContext(threadHandle, &context) };
    if (!result) {
        PrintErrorAndExit("SetThreadContext");
    }

    CloseHandle(threadHandle);
}

auto GenerateHijackStub(
    const void* const targetStackFrameAddress,
    const void* const targetLoadLibraryAddress,
    const std::string& fullModulePath,
    const DWORD_PTR originalRipAddress,
    const DWORD_PTR originalStackPointer) {

    std::array<unsigned char, 22> hijackStubPrologue{
        /* mov rsp, [target stack pointer address] */
        0x48, 0xBC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

        /* push rax */
        0x50,

        /* push rcx */
        0x51,

        /* push rdx */
        0x52,

        /* push r8*/
        0x41, 0x50,

        /* push r9 */
        0x41, 0x51,

        /* push r10 */
        0x41, 0x52,

        /* push r11 */
        0x41, 0x53,

        /* pushfq */
        0x9C
    };

    std::array<unsigned char, 27> hijackStubLoadLibrary{
        /* lea rcx, [rip + module path offset] */
        0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC,

        /* mov rdx, LoadLibraryA address*/
        0x48, 0xBA, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        
        /* sub rsp, 40h */
        0x48, 0x83, 0xEC, 0x40,

        /* call rdx */
        0xFF, 0xD2,

        /* add rsp, 40h */
        0x48, 0x83, 0xC4, 0x40
    };

    std::array<unsigned char, 36 + MAX_PATH + 1> hijackStubEpilogue{

        /* popfq */
        0x9D,

        /* pop r11 */
        0x41, 0x5B,

        /* pop r10 */
        0x41, 0x5A,

        /* pop r9 */
        0x41, 0x59,

        /* pop r8 */
        0x41, 0x58,

        /* pop rdx */
        0x5A,

        /* pop rcx */
        0x59,

        /* pop rax */
        0x58,

        /* mov rsp, [original stack pointer address] */
        0x48, 0xBC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

        /* push low word of original address*/
        0x68, 0xCC, 0xCC, 0xCC, 0xCC,

        /* mov [rsp+4], high word of original address*/
        0xC7, 0x44, 0x24, 0x04, 0xCC, 0xCC, 0xCC, 0xCC,

        /* ret */
        0xC3,

        /* null-terminated space for module path */
        0x00
    };

    const auto stackFrameAddress{ reinterpret_cast<DWORD_PTR>(targetStackFrameAddress) + 0x40000 };
    std::memcpy(&hijackStubPrologue[2], &stackFrameAddress, sizeof(DWORD_PTR));

    const auto loadLibraryAddress{ reinterpret_cast<DWORD_PTR>(targetLoadLibraryAddress) };
    const auto offsetToModuleName{ 56 };
    const auto lowAddress{ static_cast<DWORD>(originalRipAddress) & 0xFFFFFFFF };
    const auto highAddress{ static_cast<DWORD>((originalRipAddress >> 32)) & 0xFFFFFFFF };

    std::memcpy(&hijackStubLoadLibrary[3], &offsetToModuleName, sizeof(DWORD));
    std::memcpy(&hijackStubLoadLibrary[9], &loadLibraryAddress, sizeof(DWORD_PTR));

    std::memcpy(&hijackStubEpilogue[14], &originalStackPointer, sizeof(DWORD_PTR));
    std::memcpy(&hijackStubEpilogue[23], &lowAddress, sizeof(DWORD));
    std::memcpy(&hijackStubEpilogue[31], &highAddress, sizeof(DWORD));
    std::memcpy(&hijackStubEpilogue[36], fullModulePath.c_str(), fullModulePath.length());

    return concatenate(hijackStubPrologue, hijackStubLoadLibrary, hijackStubEpilogue);
}

template <typename T>
void* WriteBytesToTargetProcess(const HANDLE processHandle,
    const std::span<T> bytes, bool makeExecutable = false) {

    static_assert(sizeof(T) == sizeof(uint8_t), "Only byte types can be written.");

    const auto targetBytesAddress{ VirtualAllocEx(processHandle, nullptr,
    bytes.size(), MEM_RESERVE | MEM_COMMIT,
        makeExecutable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) };
    if (targetBytesAddress == nullptr) {
        PrintErrorAndExit("VirtualAllocEx");
    }

    size_t bytesWritten{};
    const auto result{ WriteProcessMemory(processHandle, targetBytesAddress,
        bytes.data(), bytes.size(), &bytesWritten) };
    if (!result) {
        PrintErrorAndExit("WriteProcessMemory");
    }

    return targetBytesAddress;
}

void* GetTargetModuleFunctionAddress(const std::string moduleName,
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

std::vector<std::pair<DWORD, CONTEXT>> GetTargetProcessThreadContexts(const HANDLE processHandle) {

    const std::shared_ptr<HPSS> snapshot(new HPSS{}, [&](HPSS* snapshotPtr) {
        PssFreeSnapshot(processHandle, *snapshotPtr);
        });

    auto result{ PssCaptureSnapshot(processHandle,
        PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
        CONTEXT_ALL, snapshot.get()) };
    if (result != ERROR_SUCCESS) {
        PrintErrorAndExit("PssCaptureSnapshot", result);
    }

    const std::shared_ptr<HPSSWALK> walker(new HPSSWALK{}, [&](HPSSWALK* walkerPtr) {
        PssWalkMarkerFree(*walkerPtr);
        });

    result = PssWalkMarkerCreate(nullptr, walker.get());
    if (result != ERROR_SUCCESS) {
        PrintErrorAndExit("PssWalkMarkerCreate", result);
    }

    std::vector<std::pair<DWORD, CONTEXT>> threadIdWithContext{};
    PSS_THREAD_ENTRY thread{};

    while (PssWalkSnapshot(*snapshot, PSS_WALK_THREADS,
        *walker, &thread, sizeof(thread)) == ERROR_SUCCESS) {
        threadIdWithContext.push_back(std::make_pair(
            thread.ThreadId, *thread.ContextRecord));
    }

    return threadIdWithContext;
}

template <typename NativeFunction>
NativeFunction GetNativeFunctionPtr(const std::string& functionName) {

    const auto ntdllHandle{ GetModuleHandleA("ntdll.dll") };
    if (ntdllHandle == nullptr) {
        PrintErrorAndExit("GetModuleHandleA");
    }

    return reinterpret_cast<NativeFunction>(
        GetProcAddress(ntdllHandle, functionName.c_str()));
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
        PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, false, processId) };
    if (processHandle == nullptr) {
        PrintErrorAndExit("OpenProcess");
    }

    return processHandle;
}

void InjectWithHijackedThreadContext(const DWORD processId, std::string& fullModulePath) {

    const auto processHandle{ GetTargetProcessHandle(processId) };

    const auto NtSuspendProcess{
        GetNativeFunctionPtr<NtSuspendProcessPtr>("NtSuspendProcess") };
    NtSuspendProcess(processHandle);

    const auto threadContexts{
        GetTargetProcessThreadContexts(processHandle) };

    auto hijackThread{ threadContexts[0] };

    const auto* targetLoadLibraryAddress{ GetTargetModuleFunctionAddress(
        "kernel32.dll", "LoadLibraryA", 
        processId)};

    std::array<unsigned char, 1024 * 512> targetStackFrame{ 0xCC };
    const auto* targetStackFrameAddress{ WriteBytesToTargetProcess<unsigned char>(
        processHandle, targetStackFrame) };

    auto hijackStub{ GenerateHijackStub(
        targetStackFrameAddress, targetLoadLibraryAddress, fullModulePath,
        hijackThread.second.Rip, hijackThread.second.Rsp) };

    const auto* targetHijackStub{ WriteBytesToTargetProcess<unsigned char>(
        processHandle, hijackStub, true) };

    SetTargetThreadContext(hijackThread.first, targetHijackStub, hijackThread.second);

    const auto NtResumeProcess{
        GetNativeFunctionPtr<NtResumeProcessPtr>("NtResumeProcess") };
    NtResumeProcess(processHandle);
}

int main(int argc, char* argv[]) {

    auto fullModulePath{ GetInjectedDllPath("GenericDll.dll") };

    const auto processId{ GetTargetProcessAndThreadId(
        "Untitled - Notepad").first };

    InjectWithHijackedThreadContext(processId, fullModulePath);

    return 0;
}