#include "idun.h"

#include <winsock2.h>
#include <windows.h>
#include <gio/gwin32inputstream.h>

gchar *
_idun_daemon_query_library_path (void)
{
  HMODULE module;
  WCHAR path[MAX_PATH];
  DWORD length;

  GetModuleHandleExW (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
      (LPCWSTR) _idun_daemon_query_library_path, &module);
  length = GetModuleFileNameW (module, path, MAX_PATH);

  return g_utf16_to_utf8 ((gunichar2 *) path, length, NULL, NULL, NULL);
}

guint8 *
_idun_daemon_duplicate_socket (GSocket * socket, guint process_id, gint * result_length, GError ** error)
{
  WSAPROTOCOL_INFOW info;

  if (WSADuplicateSocketW (g_socket_get_fd (socket), process_id, &info) != 0)
  {
    g_set_error (error, EFNI_ERROR, EFNI_ERROR_NOT_SUPPORTED, "Unable to duplicate socket: error %d", WSAGetLastError ());
    *result_length = 0;
    return NULL;
  }

  *result_length = sizeof (info);
  return g_memdup2 (&info, sizeof (info));
}

GSocket *
_idun_daemon_socket_from_duplicate (guint8 * info, gint info_length, GError ** error)
{
  SOCKET handle;
  GSocket * socket;
  GError * io_error = NULL;

  if (info_length != sizeof (WSAPROTOCOL_INFOW))
  {
    g_set_error (error, EFNI_ERROR, EFNI_ERROR_PROTOCOL, "Malformed socket handover");
    return NULL;
  }

  handle = WSASocketW (FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, (WSAPROTOCOL_INFOW *) info, 0,
      WSA_FLAG_OVERLAPPED);
  if (handle == INVALID_SOCKET)
  {
    g_set_error (error, EFNI_ERROR, EFNI_ERROR_NOT_SUPPORTED, "Unable to adopt socket: error %d", WSAGetLastError ());
    return NULL;
  }

  socket = g_socket_new_from_fd ((gint) handle, &io_error);
  if (socket == NULL)
  {
    g_set_error (error, EFNI_ERROR, EFNI_ERROR_NOT_SUPPORTED, "Unable to adopt socket: %s", io_error->message);
    g_error_free (io_error);
    closesocket (handle);
    return NULL;
  }

  return socket;
}

guint
_idun_daemon_query_process_id (void)
{
  return GetCurrentProcessId ();
}

GInputStream *
_idun_daemon_spawn (const gchar * path, GError ** error)
{
  SECURITY_ATTRIBUTES attributes = { sizeof (attributes), NULL, TRUE };
  HANDLE read_end, write_end;
  STARTUPINFOW startup_info = { 0, };
  PROCESS_INFORMATION process_info;
  gchar * command_line;
  gunichar2 * command_line_utf16;
  BOOL success;

  CreatePipe (&read_end, &write_end, &attributes, 0);
  SetHandleInformation (read_end, HANDLE_FLAG_INHERIT, 0);

  startup_info.cb = sizeof (startup_info);
  startup_info.dwFlags = STARTF_USESTDHANDLES;
  startup_info.hStdOutput = write_end;

  command_line = g_strdup_printf ("\"%s\" --background", path);
  command_line_utf16 = g_utf8_to_utf16 (command_line, -1, NULL, NULL, NULL);
  success = CreateProcessW (NULL, command_line_utf16, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, NULL,
      &startup_info, &process_info);
  g_free (command_line_utf16);
  g_free (command_line);

  CloseHandle (write_end);

  if (!success)
  {
    g_set_error (error, EFNI_ERROR, EFNI_ERROR_NOT_SUPPORTED, "Unable to start idund: error %lu", GetLastError ());
    CloseHandle (read_end);
    return NULL;
  }

  CloseHandle (process_info.hThread);
  CloseHandle (process_info.hProcess);

  return g_win32_input_stream_new (read_end, TRUE);
}
