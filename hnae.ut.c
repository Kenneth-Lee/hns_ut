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
	return malloc(size);
}
void kfree(void *objp){
	free(objp);
}

struct class *class_create(void *mod, const char *name) {
	return NULL;
}

void class_destroy(struct class *cls) {}
#define spin_lock_irqsave(v1, v2)
#define spin_unlock_irqrestore(v1, v2)

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}
static inline bool IS_ERR(const void *ptr)
{
	return 0;
}

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

#include "hnae.c"

struct hnae_ae_dev ae_dev;
struct hnae_handle1 {
	struct hnae_handle head;
	struct hnae_queue qs[10];
} _handle1 = {
	.head.q_num = 10,
};

#define list_del_rcu(v1)


struct hnae_handle *_get_handle(struct hnae_ae_dev *dev, const char *opts,
			                struct hnae_rb_buf_ops *ops) {
	return (struct hnae_handle *)&_handle1;
}

void _put_handle(struct hnae_handle *handle) {
}

struct hnae_ae_ops ops = {
	.get_handle = _get_handle,
	.put_handle = _put_handle,
};
struct hnae_ae_dev ae_dev =
{
	.dev = NULL,
	.ops = &ops,
	.name = "ae_id",
	.use_count = 0,
};

static int _alloc_buffer(struct hnae_handle *handle,
	struct hnae_ring *ring, struct hnae_rb_desc_cb *cb)
{
	return 0;
}

void _free_buffer(struct hnae_handle *handle,
	struct hnae_ring *ring, struct hnae_rb_desc_cb *cb)
{
}
struct hnae_rb_buf_ops _bops = {
	.alloc_buffer = _alloc_buffer,
	.free_buffer = _free_buffer,
};

//testcase----------------------------------
void test_get_put_handle(void)
{
	struct hnae_handle *h;
	int ret;

	testcase = 101;

	ret = hnae_ae_register(&ae_dev);
	ut_assert(!ret);
	h = hnae_get_handle(NULL, "ae_id", "ad_opts", &_bops);
	ut_assert(h);
	hnae_put_handle(h);
	hnae_ae_unregister(&ae_dev);
}

//------------------------------------------
int main(void) {
	test_get_put_handle();
	return 0;
}

