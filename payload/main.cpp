#include <windows.h>
#include <stdio.h>
#include <detours.h>
#include <psapi.h>
#include <Lmcons.h>

const uint64_t kServerDoElevationRequestOffset = 0x8e840;
struct rpc_internal_struct {
    unsigned int length;
    unsigned int reserved;
    BYTE* data;
};

typedef void(__fastcall* fnServerDoElevationRequest_t)(RPC_BINDING_HANDLE, HANDLE, HANDLE,
    HANDLE, int, rpc_internal_struct, rpc_internal_struct, rpc_internal_struct,
    rpc_internal_struct, GUID*, HANDLE);

fnServerDoElevationRequest_t OriginalServerDoElevationRequest = NULL;

void __fastcall HookedServerDoElevationRequest(RPC_BINDING_HANDLE rpcHandle,
    HANDLE input_process_handle, HANDLE pipe_handle, HANDLE file_handle, int run_mode,
    rpc_internal_struct cmd, rpc_internal_struct param_7, rpc_internal_struct param_8,
    rpc_internal_struct param_9, GUID* input_guid, HANDLE output_process) {
    OutputDebugStringA("Impersonation attempt.\n");
    RPC_STATUS result = RpcImpersonateClient(rpcHandle);
    if (result != RPC_S_OK) {
        char debugString[100];
        snprintf(debugString, 100, "Impersonation failed: %i\n", result);
        OutputDebugStringA(debugString);
    }
    else {
        OutputDebugStringA("Impersonation successful.\n");
    }
    OutputDebugStringA("Impersonation happened?.\n");
    return;
    return OriginalServerDoElevationRequest(rpcHandle, input_process_handle, pipe_handle, file_handle, run_mode, cmd, param_7, param_8, param_9, input_guid, output_process);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    HMODULE target_process_handle = GetModuleHandle(NULL);
    OriginalServerDoElevationRequest = (fnServerDoElevationRequest_t)((uint64_t)target_process_handle + kServerDoElevationRequestOffset);

    if (dwReason == DLL_PROCESS_ATTACH) {
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
