#ifndef CONSTEXPR_H
#define CONSTEXPR_H
#include <cstdint>

namespace expr {
	template<typename T> constexpr size_t struct_count() {
		static_assert (sizeof (T) % sizeof (uintptr_t) == 0,
		               "Struct must be composed of pointer-sized members only.");

		return sizeof (T) / sizeof (uintptr_t);
	}

	template<typename T> constexpr auto
	hash_string(const T* string, size_t len = static_cast<size_t> (-1)) -> uint32_t {
		uint32_t hash = 0x811c9dc5;
		for (size_t i = 0; (len == static_cast<size_t> (-1) ? string[i] != 0 : i < len); ++i) {
			uint32_t c = static_cast<uint32_t> (string[i]);

			if (c >= 'a' && c <= 'z') { c -= 0x20; }

			hash ^= (c & 0xFF);
			hash *= 0x01000193;
		}
		return hash;
	}
}

#endif
