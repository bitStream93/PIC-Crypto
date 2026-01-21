#include <../../include/misc/common.h>
#include <../../include/misc/native.h>
#include <../../include/misc/memory.h>

namespace resolve {
	auto declfn get_apiset_physical_name(_In_ const char* api_set_name) -> const wchar_t* {
		auto* peb = NtCurrentPeb();
		if (!peb || !peb->ApiSetMap) return nullptr;

		auto* api_set_namespace = static_cast<PAPI_SET_NAMESPACE> (peb->ApiSetMap);
		auto  base_addr = reinterpret_cast<uintptr_t> (api_set_namespace);
		auto* entries = reinterpret_cast<PAPI_SET_NAMESPACE_ENTRY> (base_addr + api_set_namespace->EntryOffset);

		uint32_t target_hash = expr::hash_string (api_set_name);

		for (uint32_t i = 0; i < api_set_namespace->Count; i++) {
			auto* entry = &entries[i];
			auto* name_ptr = reinterpret_cast<wchar_t *> (base_addr + entry->NameOffset);

			if (expr::hash_string (name_ptr, entry->HashedLength / sizeof (wchar_t)) == target_hash) {
				auto* values = reinterpret_cast<PAPI_SET_VALUE_ENTRY> (base_addr + entry->ValueOffset);
				if (entry->ValueCount > 0) { return reinterpret_cast<wchar_t *> (base_addr + values[0].ValueOffset); }
			}
		}
		return nullptr;
	}

	auto declfn module(_In_ const uint32_t library_hash) -> uintptr_t {
		auto* peb = NtCurrentPeb();
		if (!peb || !peb->Ldr) return 0;

		auto* head = &peb->Ldr->InLoadOrderModuleList;
		auto* current = head->Flink;

		while (current != head) {
			auto* entry = CONTAINING_RECORD (current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (!library_hash || (entry->BaseDllName.Buffer && expr::hash_string (entry->BaseDllName.Buffer) ==
				library_hash)) { return reinterpret_cast<uintptr_t> (entry->DllBase); }
			current = current->Flink;
		}
		return 0;
	}

	auto declfn api_ordinal(_In_ const uintptr_t module_base, _In_ const uint16_t ordinal) -> uintptr_t {
		if (!module_base || !ordinal) return 0;

		auto*  dos = reinterpret_cast<PIMAGE_DOS_HEADER> (module_base);
		auto*  nt = reinterpret_cast<PIMAGE_NT_HEADERS> (module_base + dos->e_lfanew);
		auto & exports_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		auto*    exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY> (module_base + exports_dir.VirtualAddress);
		uint16_t idx = ordinal - static_cast<uint16_t> (exports->Base);

		if (idx >= exports->NumberOfFunctions) return 0;

		uint32_t rva = reinterpret_cast<uint32_t *> (module_base + exports->AddressOfFunctions)[idx];
		return rva ? (module_base + rva) : 0;
	}

	auto declfn _api(_In_ const uintptr_t module_base, _In_ const uint32_t symbol_hash) -> uintptr_t {
		if (!module_base || !symbol_hash) return 0;

		auto*  dos = reinterpret_cast<PIMAGE_DOS_HEADER> (module_base);
		auto*  nt = reinterpret_cast<PIMAGE_NT_HEADERS> (module_base + dos->e_lfanew);
		auto & data_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (!data_dir.VirtualAddress) return 0;

		auto* exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY> (module_base + data_dir.VirtualAddress);
		auto* names = reinterpret_cast<uint32_t *> (module_base + exports->AddressOfNames);
		auto* funcs = reinterpret_cast<uint32_t *> (module_base + exports->AddressOfFunctions);
		auto* ords = reinterpret_cast<uint16_t *> (module_base + exports->AddressOfNameOrdinals);

		for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
			const char* name = reinterpret_cast<const char *> (module_base + names[i]);

			if (expr::hash_string (name) == symbol_hash) {
				uint32_t  rva = funcs[ords[i]];
				uintptr_t addr = module_base + rva;

				if (rva >= data_dir.VirtualAddress && rva < (data_dir.VirtualAddress + data_dir.Size)) {
					char buffer[256];
					memory::strncpy (buffer, reinterpret_cast<const char *> (addr), sizeof(buffer) - 1);

					char* dot = memory::strchr (buffer, '.');
					if (!dot) return 0;
					*dot = '\0';

					char f_mod[256];
					memory::strncpy (f_mod, buffer, sizeof(f_mod) - 5);

					if (memory::strchr (f_mod, '.') == nullptr) { memory::strncat (f_mod, ".dll", 4); }

					const char* f_api = dot + 1;
					uintptr_t   target_module = 0;

					if (memory::strncmp (f_mod, "api-", 4) == 0 || memory::strncmp (f_mod, "ext-", 4) == 0) {
						const wchar_t* phys_name = get_apiset_physical_name (buffer);

						if (phys_name) target_module = resolve::module (expr::hash_string (phys_name));
					}

					if (!target_module) target_module = resolve::module (expr::hash_string (f_mod));

					if (!target_module) return 0;

					if (*f_api == '#') {
						return resolve::api_ordinal (target_module, static_cast<uint16_t> (memory::atoi (f_api + 1)));
					}
					return resolve::_api (target_module, expr::hash_string (f_api));
				}
				return addr;
			}
		}
		return 0;
	}
}
