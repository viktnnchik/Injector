#include <iostream>
#include <windows.h>

using namespace std;

int InjectDLL(DWORD, char*);
int getDLLpath(char*);
int getPID(int*);
int getProc(HANDLE*, DWORD);

int getDLLpath(char* dll)
{
	std::cout << "Path to dll file\n";
	cin >> dll;
	return 1;
}

int getPID(int* PID)
{
	cout << "Enter PID\n";
	cin >> *PID;
	return 1;
}


int getProc(HANDLE* handleToProc, DWORD pid)
{
	*handleToProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	DWORD dwLastError = GetLastError();

	if (*handleToProc == NULL)
	{
		std::cout << "Cant open \n";
		return -1;
	}
	else
	{
		std::cout << "Proccess opend\n";
		return 1;
	}
}


int InjectDLL(DWORD PID, char* dll)
{
	HANDLE handleToProc;
	LPVOID LoadLibAddr;
	LPVOID baseAddr;
	HANDLE remThread;

	int dllLenght = strlen(dll) + 1;

	if (getProc(&handleToProc, PID) < 0)
		return 1;

	LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	if (!LoadLibAddr)
		return -1;

	baseAddr = VirtualAllocEx(handleToProc, NULL, dllLenght, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!baseAddr) {
		return -1;
	}

	if (!WriteProcessMemory(handleToProc, baseAddr, dll, dllLenght, NULL))
		return -1;

	remThread = CreateRemoteThread(handleToProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, baseAddr, 0, NULL);

	if (!remThread)
		return -1;

	WaitForSingleObject(remThread, INFINITE);

	VirtualFreeEx(handleToProc, baseAddr, dllLenght, MEM_RELEASE);

	if (CloseHandle == 0)
	{
		std::cout << "Fail close handle remote thread";
		return -1;
	}

	if (CloseHandle(handleToProc) == 0)
	{
		std::cout << "Fail close handle to target process";
		return -1;
	}

}


int main()
{
	SetConsoleTitle("NI Injector");

	int PID = -1;
	char* dll = new char[255];

	getDLLpath(dll);
	getPID(&PID);

	InjectDLL(PID, dll);
	system("pause");

	return 0;
}