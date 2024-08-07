#define extism_wamr_VERSION_MAJOR 0
#define extism_wamr_VERSION_MINOR 1

#define EXPAND_AND_STRINGIFY(s) STRINGIFY(s)
#define STRINGIFY(s) #s

#define extism_wamr_VERSION_MAJOR_STR EXPAND_AND_STRINGIFY(extism_wamr_VERSION_MAJOR)
#define extism_wamr_VERSION_MINOR_STR EXPAND_AND_STRINGIFY(extism_wamr_VERSION_MINOR)

#define extism_wamr_VERSION extism_wamr_VERSION_MAJOR_STR "." extism_wamr_VERSION_MINOR_STR
