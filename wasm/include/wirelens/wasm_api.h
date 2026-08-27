#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#define WIRELENS_WASM_NOEXCEPT noexcept
#else
#define WIRELENS_WASM_NOEXCEPT
#endif

/* Allocate a buffer that can be filled from the host and passed to the parser. */
uintptr_t wirelens_alloc(size_t size) WIRELENS_WASM_NOEXCEPT;

/* Transfer ownership of data to the parser. The pointer is consumed on every outcome. */
uint32_t wirelens_parse_owned(uintptr_t data, size_t size) WIRELENS_WASM_NOEXCEPT;

/* Return non-zero only when handle identifies a successful parse result. */
int wirelens_result_ok(uint32_t handle) WIRELENS_WASM_NOEXCEPT;

/* Return normalized JSON bytes for a successful result, or NULL for an invalid/failed result. */
const char* wirelens_result_data(uint32_t handle) WIRELENS_WASM_NOEXCEPT;
size_t wirelens_result_size(uint32_t handle) WIRELENS_WASM_NOEXCEPT;

/* Return a stable error code for a failed result, or NULL when there is no error. */
const char* wirelens_result_error_code(uint32_t handle) WIRELENS_WASM_NOEXCEPT;
uint64_t wirelens_result_error_offset(uint32_t handle) WIRELENS_WASM_NOEXCEPT;

/* Packet indexes are zero-based. Pointers are valid until release or another ABI call mutates it.
 */
const uint8_t* wirelens_packet_data(uint32_t handle, size_t packet_index) WIRELENS_WASM_NOEXCEPT;
size_t wirelens_packet_size(uint32_t handle, size_t packet_index) WIRELENS_WASM_NOEXCEPT;

/* Release a result. Releasing an invalid or already released handle is safe. */
void wirelens_release(uint32_t handle) WIRELENS_WASM_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#undef WIRELENS_WASM_NOEXCEPT
