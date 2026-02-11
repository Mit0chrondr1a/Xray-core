#ifndef XRAY_ZIG_H
#define XRAY_ZIG_H

#include <stddef.h>

typedef struct RingBuffer RingBuffer;
typedef struct Arena Arena;

/* Ring buffer */
RingBuffer* xray_ring_create(size_t capacity);
void xray_ring_destroy(RingBuffer* rb);
size_t xray_ring_write(RingBuffer* rb, const unsigned char* data, size_t len);
size_t xray_ring_read(RingBuffer* rb, unsigned char* buf, size_t len);
size_t xray_ring_available_read(RingBuffer* rb);
size_t xray_ring_available_write(RingBuffer* rb);

/* Arena allocator */
Arena* xray_arena_create(size_t size);
void xray_arena_destroy(Arena* a);
unsigned char* xray_arena_alloc(Arena* a, size_t size);
void xray_arena_reset(Arena* a);
size_t xray_arena_bytes_used(Arena* a);

#endif /* XRAY_ZIG_H */
