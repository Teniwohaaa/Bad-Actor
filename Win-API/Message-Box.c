#include <windows.h>

int main(void) {
  MessageBoxW(NULL, L"Ceci est un message", L"Message",
              MB_OK | MB_ICONASTERISK);
  return EXIT_SUCCESS;
  // Exit_success is the same as 0 but we use it for the sake of clarity
}