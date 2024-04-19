#include <windows.h>
#include <detours.h>

struct rust_str {
    unsigned int length;
    BYTE data[];
};

// Forward declaration of the original function
int(__stdcall* OriginalDoElevationRequest)(
    handle_t _hProcHandle,
    HANDLE p0,
    HANDLE p1,
    HANDLE p2,
    int run_mode,
    rust_str* cmd,
    rust_str* args,
    rust_str* cwd,
    rust_str* environment,
    GUID* p8,
    HANDLE* p9);

// Hooked function that will be called instead of the original
int __stdcall HookedDoElevationRequest(
    handle_t _hProcHandle,
    HANDLE p0,
    HANDLE p1,
    HANDLE p2,
    int run_mode,
    rust_str* cmd,
    rust_str* args,
    rust_str* cwd,
    rust_str* environment,
    GUID* p8,
    HANDLE* p9) {

    // Perform your custom logic before calling the original function
    // You can access the original function using OriginalDoElevationRequest

    // Call the original function
    int result = OriginalDoElevationRequest(
        _hProcHandle, p0, p1, p2, run_mode, cmd, args, cwd, environment, p8, p9);

    // Perform your custom logic after calling the original function

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Install the hook on server_DoElevationRequest
        if (!DetourFunction((PBYTE*)&OriginalDoElevationRequest, (PBYTE)HookedDoElevationRequest)) {
            return FALSE;
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        // Remove the hook on server_DoElevationRequest
        DetourRemoveFunction((PBYTE*)&OriginalDoElevationRequest, (PBYTE)HookedDoElevationRequest);
    }
    return TRUE;
}
