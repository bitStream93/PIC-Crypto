#ifndef RESOLVE_H
#define RESOLVE_H

#include <macros.h>

#define RESOLVE_TYPE(s) \
  .s = reinterpret_cast<decltype(s) *>(expr::hash_string(#s))

#define RESOLVE_API(m, s) resolve::api<decltype(s)>(m, expr::hash_string(#s))

namespace resolve {
	auto declfn get_apiset_physical_name(_In_ const char* api_set_name) -> const wchar_t*;

	auto declfn module(_In_ uint32_t library_hash) -> uintptr_t;

	auto declfn module_ansi(_In_ uint32_t library_ansi_hash) -> uintptr_t;

	auto declfn api_ordinal(_In_ const uintptr_t module_base,
	                                  _In_ const uint16_t  ordinal) -> uintptr_t;

	auto declfn _api(_In_ uintptr_t module_base, _In_ uint32_t symbol_hash) -> uintptr_t;

	template<typename T> inline auto declfn api(_In_ const uintptr_t module_base,
	                                                      _In_ const uint32_t  symbol_hash) -> T* {
		return reinterpret_cast<T *> (_api (module_base, symbol_hash));
	}
}

#endif
