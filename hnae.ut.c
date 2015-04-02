#define UT_DUMPSTACK
#include "comm.h"

#include <string.h>

//stub--------------------------------------
static void dma_unmap_single(struct device *dev, dma_addr_t dma_addr,
                 size_t size, int dir)
{
}

#define MAPPED_DMA 0x8989
#define UNMAPPED_DMA 0x7f7f
static dma_addr_t dma_map_single(struct device *dev, void *cpu_addr, size_t size,
               int dir) {
	return MAPPED_DMA;
}

static int dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
        return 0;
}

static void *kzalloc(size_t size, int flags) {
	return NULL;
}
void kfree(const void *objp){}
struct class *class_create(void *mod, const char *name) {
	return NULL;
}

void class_destroy(struct class *cls) {}
#define spin_lock_irqsave(v1, v2)
#define spin_unlock_irqrestore(v1, v2)
#define list_add_tail_rcu(v1, v2)
#define list_for_each_entry_rcu(v1, v2, v3)
#define list_del_rcu(v1)

#define IS_ERR(ptr) 1
static inline long PTR_ERR(const void *ptr)
{
	        return (long) ptr;
}


#include "hnae.c"

//testcase----------------------------------
void testcase1(void)
{
	testcase = 101;
	ut_assert(0);
}

//------------------------------------------
int main(void) {
	testcase1();
	return 0;
}

