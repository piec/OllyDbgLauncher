#include <windows.h>
#include <tchar.h>

//#include "plugin.h"
#include "launcher.h"

void read(HANDLE hProcess)
{
#define SIZE 4096
	char buffer[SIZE];
	SIZE_T read = 0;

	ZeroMemory(buffer, SIZE);
	ReadProcessMemory(hProcess, (LPVOID)0x4E5617, buffer, SIZE, &read);
#undef SIZE
}

#pragma pack(1)

typedef struct {
	int exe_name_len;
	int npatches;
	char sig[sizeof(SIG) - 1];
} footer_t;

typedef struct {
	void *address;
	int size;
} patch_footer_t;

char *g_exe_name = NULL;
PROCESS_INFORMATION g_process_info;
STARTUPINFOA g_startup_info;

int process()
{
	SIZE_T written = 0;

	ZeroMemory(&g_startup_info, sizeof(g_startup_info));
	g_startup_info.cb = sizeof(g_startup_info);
	g_startup_info.lpReserved = NULL;
	g_startup_info.lpDesktop = NULL;
	g_startup_info.lpTitle = NULL;

	return CreateProcessA(
		g_exe_name,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		".",
		&g_startup_info,
		&g_process_info
	) != 0;
}

int patch(void *address, void *ori, void *mod, int size)
{
	int written;
	return WriteProcessMemory(g_process_info.hProcess, address, mod, size, &written) != 0;
}

int go()
{
	TCHAR filename[MAX_PATH + 1];
	HANDLE file;

	GetModuleFileName(NULL, filename, MAX_PATH);
	file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if(file != INVALID_HANDLE_VALUE)
	{
		footer_t footer;
		DWORD read;
		int offset = -sizeof(footer_t);

		SetFilePointer(file, offset, NULL, FILE_END);
		ReadFile(file, &footer, sizeof(footer_t), &read, NULL);
		
		if(memcmp(footer.sig, SIG, sizeof(SIG) - 1) == 0)
		{ // sig ok
			int i;
			char *buffer;
			int buffer_size = 1;
			patch_footer_t patch_footer;
			g_exe_name = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, footer.exe_name_len + 1);

			// get exe name
			offset -= footer.exe_name_len;
			SetFilePointer(file, offset, NULL, FILE_END);
			ReadFile(file, g_exe_name, footer.exe_name_len, &read, NULL);

			// create process
			if(! process())
				return 0;

			// read patch information
			buffer = HeapAlloc(GetProcessHeap(), 0, buffer_size);

			for(i = 0; i < footer.npatches; i++)
			{
				offset -= sizeof(patch_footer_t);
				SetFilePointer(file, offset, NULL, FILE_END);
				ReadFile(file, &patch_footer, sizeof(patch_footer_t), &read, NULL);

				if(patch_footer.size * 2 > buffer_size)
				{
					buffer = HeapReAlloc(GetProcessHeap(), 0, buffer, patch_footer.size * 2);
					buffer_size = patch_footer.size * 2;
				}

				offset -= patch_footer.size * 2;
				SetFilePointer(file, offset, NULL, FILE_END);
				ReadFile(file, buffer, patch_footer.size * 2, &read, NULL);

				if(! patch(patch_footer.address, buffer, buffer + patch_footer.size, patch_footer.size))
					return 0;
			}

			HeapFree(GetProcessHeap(), 0, g_exe_name);
			HeapFree(GetProcessHeap(), 0, buffer);
		}

		CloseHandle(file);
	}
	return 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//base_address = GetModuleHandle("TOTALCMD.EXE");

	go();
	ResumeThread(g_process_info.hThread);

	////read(processInfo.hProcess);


	////read(processInfo.hProcess);
	////assert(written == 2);

	return 0;
}
