#ifndef MEMORY_H
#define MEMORY_H
#include <native.h>

#include <cstdint>

namespace memory {
#define MAX_KEY_HEX_STRING_LENGTH (32 * 3 + 1)

	__attribute__ ((noinline))
	inline void secure_erase(void* ptr, size_t len) {
		if (!ptr || len == 0) return;

		volatile unsigned char* p = (volatile unsigned char *)ptr;

		for (size_t i = 0; i < len; i++) { p[i] = 0; }

		asm volatile("" : : "r"(ptr) : "memory");
		asm volatile("mfence" ::: "memory");

		for (size_t i = 0; i < len; i++) { p[i] = 0; }

		asm volatile("" : : "r"(ptr) : "memory");
	}

	__attribute__ ((noinline))
	inline void copy(void*       destination,
	                 const void* source, size_t len) {
		if (!destination || !source || len == 0) return;

		unsigned char*       dst = static_cast<unsigned char *> (destination);
		const unsigned char* src = static_cast<const unsigned char *> (source);

		if (src < dst && dst < src + len) {
			dst += len;
			src += len;
			while (len--) { *(--dst) = *(--src); }
		} else { while (len--) { *dst++ = *src++; } }

		asm volatile("" ::: "memory");
	}

	__attribute__ ((noinline))
	inline void set(void*         destination,
	                unsigned char value, size_t len) {
		if (!destination || len == 0) return;

		volatile unsigned char* volatile dst =
				static_cast<volatile unsigned char *volatile> (destination);
		while (len--) { *dst++ = value; }

		asm volatile("" ::: "memory");
	}

	__attribute__ ((noinline))
	inline int compare(const void* source1,
	                   const void* source2, size_t len) {
		if (source1 == source2 || len == 0) return 0;
		if (!source1) return -1;
		if (!source2) return 1;

		const unsigned char* s1 = static_cast<const unsigned char *> (source1);
		const unsigned char* s2 = static_cast<const unsigned char *> (source2);

		for (size_t i = 0; i < len; ++i) { if (s1[i] != s2[i]) return (s1[i] < s2[i]) ? -1 : 1; }

		asm volatile("" ::: "memory");

		return 0;
	}
	__attribute__ ((noinline))
	inline auto strncat(char* destination, const char* source, size_t num) -> char* {
		char* ptr = destination;

		while (*ptr != '\0') { ptr++; }

		size_t i = 0;
		while (i < num && source[i] != '\0') {
			ptr[i] = source[i];
			i++;
		}

		ptr[i] = '\0';

		return destination;
	}
	__attribute__ ((noinline
			,
			pure
		)
	)
	inline size_t strlen(const char* str) {
		if (!str) return 0;

		const char* p = str;

		while (*p) { ++p; }

		return (size_t)(p - str);
	}
	__attribute__ ((noinline))
	inline auto wcslen(_In_ const wchar_t* str) -> size_t {
		if (!str) return 0;

		size_t length = 0;
		while (str[length] != L'\0') { length++; }
		return length;
	}
	__attribute__ ((noinline))
	inline int strncmp(const char* s1, const char* s2, size_t n) {
		if (n == 0) return 0;
		if (!s1 || !s2) return (s1 == s2) ? 0 : (s1 ? 1 : -1);

		while (n-- > 0) {
			if (*s1 != *s2) { return (static_cast<unsigned char> (*s1) < static_cast<unsigned char> (*s2)) ? -1 : 1; }
			if (*s1 == '\0') break;
			++s1;
			++s2;
		}

		asm volatile("" ::: "memory");

		return 0;
	}
	__attribute__ ((noinline))
	inline int wcsncmp(const wchar_t* s1, const wchar_t* s2, size_t n) {
		if (n == 0) return 0;
		if (!s1 || !s2) return (s1 == s2) ? 0 : (s1 ? 1 : -1);

		while (n-- > 0) {
			if (*s1 != *s2) { return (*s1 < *s2) ? -1 : 1; }
			if (*s1 == L'\0') break;
			++s1;
			++s2;
		}

		asm volatile("" ::: "memory");

		return 0;
	}

	__attribute__ ((noinline))
	inline auto to_wide_char(
		_In_ const char* src,
		_Out_ wchar_t*   dest,
		_In_ size_t      dest_size) -> size_t {
		if (!src || !dest || dest_size == 0) return 0;

		size_t i = 0;
		while (src[i] != '\0' && i < (dest_size - 1)) {
			dest[i] = static_cast<wchar_t> (src[i]);
			i++;
		}
		dest[i] = L'\0';
		return i;
	}

	__attribute__ ((noinline))
	inline char* itoa(int value, char* buffer, int base) {
		char* ptr = buffer;
		char* start = buffer;
		bool  negative = false;

		if (base == 10 && value < 0) {
			negative = true;
			value = -value;
			*ptr++ = '-';
			start++;
		}

		char* p = ptr;
		int   n = value;
		do {
			int digit = n % base;
			*p++ = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
			n /= base;
		} while (n > 0);

		char* q = p - 1;
		while (start < q) {
			char tmp = *start;
			*start++ = *q;
			*q-- = tmp;
		}
		*p = '\0';
		return buffer;
	}

	__attribute__ ((noinline))
	inline int strcmp(const char* s1, const char* s2) {
		if (!s1 || !s2) return (s1 == s2) ? 0 : (s1 ? 1 : -1);

		const auto* p1 = reinterpret_cast<const unsigned char *> (s1);
		const auto* p2 = reinterpret_cast<const unsigned char *> (s2);

		while (*p1 && (*p1 == *p2)) {
			p1++;
			p2++;
		}

		asm volatile("" ::: "memory");

		return (*p1 < *p2) ? -1 : (*p1 > *p2);
	}
	__attribute__ ((noinline))
	inline char* strncpy(char* dest, const char* src, size_t n) {
		char* d = dest;
		while (n-- > 0) {
			if (!(*d++ = *src++)) {
				while (n-- > 0) *d++ = '\0';
				break;
			}
		}
		return dest;
	}

	__attribute__ ((noinline))
	inline char* strchr(const char* s, int c) {
		do { if (*s == (char)c) return (char *)s; } while (*s++);
		return nullptr;
	}

	__attribute__ ((noinline))
	inline int atoi(const char* s) {
		int res = 0;
		while (*s >= '0' && *s <= '9') {
			res = (res * 10) + (*s - '0');
			s++;
		}
		return res;
	}

	__attribute__ ((noinline))
	inline DWORD atoui(const char* str) {
		if (!str || *str == '\0') { return 0; }

		DWORD result = 0;

		for (const char* p = str; *p != '\0'; ++p) {
			char c = *p;

			if (c >= '0' && c <= '9') {
				DWORD digit = c - '0';

				result = result * 10 + digit;
			} else { break; }
		}

		return result;
	}

	__attribute__ ((noinline))
	inline char* uitoa(unsigned int value, char* buffer, int base) {
		char* ptr = buffer;
		char* start = buffer;

		char*        p = ptr;
		unsigned int n = value;

		do {
			unsigned int digit = n % base;

			*p++ = (digit < 10) ? ('0' + digit) : ('a' + (digit - 10));
			n /= base;
		} while (n > 0);

		char* q = p - 1;
		while (start < q) {
			char tmp = *start;
			*start++ = *q;
			*q-- = tmp;
		}

		*p = '\0';
		return buffer;
	}

	__attribute__ ((noinline))
	inline char* uitoa64(unsigned __int64 value, char* buffer, int base) {
		if (!buffer) return nullptr;

		char*            p = buffer;
		unsigned __int64 n = value;

		do {
			unsigned __int64 digit = n % base;
			*p++ = (digit < 10) ? ('0' + (char)digit) : ('a' + (char)(digit - 10));
			n /= base;
		} while (n > 0);

		*p = '\0';

		char* left = buffer;
		char* right = p - 1;
		while (left < right) {
			char tmp = *left;
			*left = *right;
			*right = tmp;
			left++;
			right--;
		}

		return buffer;
	}

	struct FormatState {
		int  width = 0;
		char pad_char = ' ';
		bool left_justify = false;
		bool zero_pad = false;
		bool pointer = false;
		bool long_long = false;
		bool long_ = false;
		char specifier = '\0';
	};

	inline void put_char(char* buf, size_t size, size_t & written, char c) {
		if (written < size - 1) { buf[written] = c; }
		written++;
	}

	static size_t print_padded(char*       buffer, size_t bufsize, size_t current_written,
	                           const char* str, int       width, int      left_justify, char pad_char) {
		size_t str_len = 0;
		while (str[str_len] != '\0') str_len++;

		size_t total_written = 0;
		int    padding_needed = width - (int)str_len;
		if (padding_needed < 0) padding_needed = 0;

		if (!left_justify) {
			for (int i = 0; i < padding_needed && current_written + total_written + 1 < bufsize; ++i) {
				buffer[current_written + total_written++] = pad_char;
			}
		}

		for (size_t i = 0; i < str_len && current_written + total_written + 1 < bufsize; ++i) {
			buffer[current_written + total_written++] = str[i];
		}

		if (left_justify) {
			for (int i = 0; i < padding_needed && current_written + total_written + 1 < bufsize; ++i) {
				buffer[current_written + total_written++] = pad_char;
			}
		}

		return total_written;
	}

	__attribute__ ((noinline
			,
			force_align_arg_pointer
		)
	)
	inline int vsnprintf(char* buffer, size_t bufsize, const char* format, va_list args) {
		if (!buffer || bufsize == 0 || !format) return 0;

		size_t written = 0;

		size_t limit = bufsize - 1;

		for (const char* f = format; *f; ++f) {
			if (*f != '%') {
				if (written < limit) buffer[written] = *f;
				written++;
				continue;
			}

			f++;
			FormatState state = { 0 };
			state.pad_char = ' ';

			while (*f == '-' || *f == '0') {
				if (*f == '-') state.left_justify = true;
				if (*f == '0') state.zero_pad = true;
				f++;
			}
			if (state.zero_pad && !state.left_justify) state.pad_char = '0';

			while (*f >= '0' && *f <= '9') {
				state.width = state.width * 10 + (*f - '0');
				f++;
			}

			if (*f == 'l') {
				f++;
				if (*f == 'l') {
					state.long_long = true;
					f++;
				} else { state.long_ = true; }
			} else if (*f == 'p') { state.long_long = true; }

			state.specifier = *f;

			char        numbuf[70];
			const char* content_ptr = nullptr;
			size_t      print_len = 0;

			switch (state.specifier) {
			case 's': {
				content_ptr = va_arg (args, const char*);

				if ((uintptr_t)content_ptr < 0x1000) content_ptr = "(null)";
				print_len = memory::strlen (content_ptr);
				break;
			}
			case 'd':
			case 'i': {
				long long val = (state.long_long) ? va_arg (args, long long) : va_arg (args, int);
				if (val < 0) {
					if (written < limit) buffer[written] = '-';
					written++;
					val = -val;
					if (state.width > 0) state.width--;
				}
				memory::uitoa64 ((unsigned __int64)val, numbuf, 10);
				content_ptr = numbuf;
				print_len = memory::strlen (content_ptr);
				break;
			}
			case 'u':
			case 'x':
			case 'p': {
				unsigned __int64 val;
				if (state.specifier == 'p') {
					val = (unsigned __int64)va_arg (args, void*);

					if (val == 0) {
						content_ptr = "0x0";
						print_len = 3;
						break;
					}
				} else { val = (state.long_long) ? va_arg (args, unsigned long long) : va_arg (args, unsigned int); }
				memory::uitoa64 (val, numbuf, (state.specifier == 'u' ? 10 : 16));
				content_ptr = numbuf;
				print_len = memory::strlen (content_ptr);
				break;
			}
			default: if (written < limit) buffer[written] = *f;
				written++;
				continue;
			}

			int padding = (int)state.width - (int)print_len;
			if (padding < 0) padding = 0;

			if (!state.left_justify) {
				while (padding--) {
					if (written < limit) buffer[written] = state.pad_char;
					written++;
				}
			}

			for (size_t i = 0; i < print_len; i++) {
				if (written < limit) buffer[written] = content_ptr[i];
				written++;
			}

			if (state.left_justify) {
				while (padding--) {
					if (written < limit) buffer[written] = ' ';
					written++;
				}
			}
		}

		if (bufsize > 0) { buffer[written < bufsize ? written : bufsize - 1] = '\0'; }

		return (int)written;
	}

	__attribute__ ((noinline
			,
			force_align_arg_pointer
		)
	)
	inline int snprintf(char* buffer, size_t bufsize, const char* format, ...) {
		if (!buffer || bufsize == 0 || !format) return 0;

		va_list args;
		va_start (args, format);

		int result = vsnprintf (buffer, bufsize, format, args);

		va_end (args);
		return result;
	}
	template<typename T>
	concept Comparable = requires(T a, T b) {
		{ a < b };
	};

	template<Comparable T> T min(T a, T b) { return (a < b) ? a : b; }

	template<Comparable T, Comparable... Rest> T min(T first, T second, Rest... rest) {
		return min (min (first, second), rest...);
	}

	__attribute__ ((noinline))
	inline uint32_t hash_fnv1a(const char* str) {
		uint32_t       hash = 0x811c9dc5;
		const uint32_t fnv_prime = 0x01000193;

		if (!str) return hash;

		while (*str) {
			hash ^= (uint32_t)(unsigned char)*str;
			hash *= fnv_prime;
			str++;
		}

		return hash;
	}

	__attribute__ ((noinline))
	inline uint32_t hash_fnv1a_w(const wchar_t* str) {
		uint32_t       hash = 0x811c9dc5;
		const uint32_t fnv_prime = 0x01000193;

		if (!str) return hash;

		while (*str) {
			hash ^= (uint32_t)(unsigned char)*str;
			hash *= fnv_prime;
			str++;
		}

		return hash;
	}
}

#endif
