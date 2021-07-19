#include "pch.h"

using PCreateFileW = decltype(&CreateFileW);
PCreateFileW originalCreateFileW;

auto WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) -> HANDLE
{
    MessageBoxA(NULL, "CreateFileW has been hooked!", "RESULT", MB_OK);
    return originalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

auto WINAPI HookThread(LPVOID hModule) -> DWORD
{
    auto pBase = (size_t)GetModuleHandle(nullptr);
    auto pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    auto pNtHeader = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    auto pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImportDesc->Characteristics)
    {
        auto moduleName = (const char *)(pBase + pImportDesc->Name);
        if (!_stricmp(moduleName, "kernel32.dll"))
        {
            auto pNameTable = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->OriginalFirstThunk);
            auto pAddressTable = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->FirstThunk);
            while (pNameTable->u1.AddressOfData && pAddressTable->u1.Function)
            {
                auto pImport = (PIMAGE_IMPORT_BY_NAME)(pBase + pNameTable->u1.AddressOfData);
                auto functionName = pImport->Name;
                if (!strcmp(functionName, "CreateFileW"))
                {
                    originalCreateFileW = (PCreateFileW)pAddressTable->u1.Function; // note: 相対アドレスではないのでpBaseと足す必要なし
                    DWORD oldProtect;
                    VirtualProtect(pAddressTable, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &oldProtect);
                    pAddressTable->u1.Function = (uintptr_t)HookedCreateFileW;
                    VirtualProtect(pAddressTable, sizeof(IMAGE_THUNK_DATA), oldProtect, &oldProtect);
                }
                ++pNameTable;
                ++pAddressTable;
            }
        }
        ++pImportDesc;
    }
    return TRUE;
}

auto APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) -> BOOL
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        if (auto hThread = CreateThread(nullptr, 0, HookThread, hModule, 0, nullptr); hThread)
        {
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
