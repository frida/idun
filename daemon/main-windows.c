#include <windows.h>

int main (int argc, char * argv[]);

int WINAPI
WinMain (HINSTANCE instance, HINSTANCE previous_instance, LPSTR command_line, int show_command)
{
  return main (__argc, __argv);
}
