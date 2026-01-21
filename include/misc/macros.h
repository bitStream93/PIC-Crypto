#ifndef MACROS_H
#define MACROS_H
#define DECLARE_API(x) decltype(x) *x;
#define GET_SYM_ADDR(s) \
  (uintptr_t)((uintptr_t)s + (RipData() - (uintptr_t)&RipData))
#define declfn __attribute__((section(".text$B")))
#define RESOLVE_IMPORT(m)                                                     \
do {                                                                        \
constexpr size_t total_fields = expr::struct_count<decltype(m)>();        \
uintptr_t* fields = reinterpret_cast<uintptr_t*>(&m);                     \
\
for (size_t i = 1; i < total_fields; i++) {                               \
uint32_t hash = static_cast<uint32_t>(fields[i]);                       \
if (hash == 0) continue;                                \
\
fields[i] = (uintptr_t)resolve::api<void>(m.handle, hash);              \
}                                                                         \
} while (0)
#define RangeHeadList(HEAD_LIST, TYPE, SCOPE) \
  {                                           \
    PLIST_ENTRY __Head = (&HEAD_LIST);        \
    PLIST_ENTRY __Next = {0};                 \
    TYPE Entry = (TYPE)__Head->Flink;         \
    for (; __Head != (PLIST_ENTRY)Entry;) {   \
      __Next = ((PLIST_ENTRY)Entry)->Flink;   \
      SCOPE                                   \
      Entry = (TYPE)(__Next);                 \
    }                                         \
  }
#endif
