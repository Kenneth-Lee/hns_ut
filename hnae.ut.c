//#define UT_DUMPSTACK
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
	ut_assert(cpu_addr);
	return MAPPED_DMA;
}

int tc111_dma_mapping = 0;
static int dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	ut_assert(dma_addr);
	switch(testcase) {
		case 111:
			tc111_dma_mapping++;
			if(tc111_dma_mapping==3)
				return 1;
	}
        return 0;
}

int tc110_mem_c = 0;
int tc111_mem_c = 0;
static void *kzalloc(size_t size, int flags) {
	void *p;
	switch(testcase) {
		case 110:
			tc110_mem_c++;
			break;
		case 111:
			tc111_mem_c++;
			break;
	}
	p = malloc(size);
	bzero(p, size);
	return p;
}

void kfree(void *objp){
	switch(testcase) {
		case 110:
			tc110_mem_c--;
			break;
		case 111:
			tc111_mem_c--;
			break;
	}
	free(objp);
}

struct class *class_create(void *mod, const char *name) {
	return NULL;
}

void class_destroy(struct class *cls) {}
#define spin_lock_irqsave(v1, v2)
#define spin_unlock_irqrestore(v1, v2)

void BUG_ON(cond) {
	ut_assert(!cond);
}

#include "hnae.c"

#define Q_NUM 4
struct hnae_ae_dev ae_dev;
struct hnae_queue qs[Q_NUM];
struct hnae_handle _handle = {
	.q_num = Q_NUM,
	.qs = qs,
};

#define list_del_rcu(v1)


struct hnae_handle *_get_handle(struct hnae_ae_dev *dev, const char *opts,
			                struct hnae_rb_buf_ops *ops) {
	return (struct hnae_handle *)&_handle;
}

void _put_handle(struct hnae_handle *handle) {
}

void _toggle_ring_irq(struct hnae_ring *ring, u32 val){}
void _toggle_queue_status(struct hnae_queue *queue, u32 val){}

struct hnae_ae_ops ops = {
	.get_handle = _get_handle,
	.put_handle = _put_handle,
	.toggle_ring_irq = _toggle_ring_irq,
	.toggle_queue_status = _toggle_queue_status,
};
struct device dev;
struct hnae_ae_dev ae_dev =
{
	.dev = &dev,
	.ops = &ops,
	.name = "ae_id",
};

#define BUF_SIZE 1024
#define DESC_NUM 5
static int _alloc_buffer(struct hnae_handle *handle,
	struct hnae_ring *ring, struct hnae_rb_desc_cb *cb)
{
	cb->buf = cb->priv = malloc(ring->buf_size);
	cb->length = ring->buf_size;
	ut_assert(cb->buf);
	return 0;
}

void _free_buffer(struct hnae_handle *handle,
	struct hnae_ring *ring, struct hnae_rb_desc_cb *cb)
{
	ut_assert(cb->buf);
	free(cb->buf);
}
struct hnae_rb_buf_ops _bops = {
	.alloc_buffer = _alloc_buffer,
	.free_buffer = _free_buffer,
};

//testcase----------------------------------
void case_register_ae(void)
{
	int ret;
	
	struct hnae_ae_dev ae1=
	{
		.dev = &dev,
		.name = "ae1",
		.ops = &ops,
	};
	struct hnae_ae_dev ae2=
	{
		.dev = &dev,
		.name = "ae2",
		.ops = &ops,
	};
	struct hnae_ae_dev ae3=
	{
		.dev = &dev,
		.name = "ae3",
		.ops = &ops,
	};
	struct hnae_ae_dev *ae;

	ae = find_ae("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
	ut_assert(!ae);

	ret = hnae_ae_register(&ae1);
	ut_assert(!ret);

	ae = find_ae("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
	ut_assert(!ae);

	ae = find_ae("");
	ut_assert(!ae);

	ae = find_ae("ae1");
	ut_assert(ae);

	ret = hnae_ae_register(&ae2);
	ut_assert(!ret);
	ret = hnae_ae_register(&ae3);
	ut_assert(!ret);

	ae = find_ae("ae1");
	ut_assert(ae);

	ae = find_ae("ae11");
	ut_assert(!ae);

	ae = find_ae("ae2");
	ut_assert(ae);

	ae = find_ae("ae3");
	ut_assert(ae);

	hnae_ae_unregister(&ae1);
	hnae_ae_unregister(&ae2);
	hnae_ae_unregister(&ae3);
}

void case_get_put_handle(void)
{
	struct hnae_handle *h;
	int ret, i;

	for(i=0; i<Q_NUM; i++) {
		qs[i].tx_ring.buf_size = BUF_SIZE;
		qs[i].tx_ring.desc_num = DESC_NUM;
		qs[i].rx_ring.buf_size = BUF_SIZE;
		qs[i].rx_ring.desc_num = DESC_NUM;
	}

	ret = hnae_ae_register(&ae_dev);
	ut_assert(!ret);

	h = hnae_get_handle(NULL, "ae_idddd", "ae_opts", &_bops);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);

	//test to pass
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", &_bops);
	ut_assert(!IS_ERR(h));
	ut_assert_str(ae_dev.use_count == 1, "use_count=%d, should be 1\n", ae_dev.use_count);

	hnae_put_handle(h);

	ut_assert(!ae_dev.use_count);

	ut_assert(tc110_mem_c==0);


	//test to fail: dma_map fail in the middle
	testcase = 111;
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", &_bops);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);
	ut_assert_str(tc111_mem_c==0, "tc111_mem_c=%d\n", tc111_mem_c);

	hnae_ae_unregister(&ae_dev);
}

//------------------------------------------
int main(void) {
	test(100, case_register_ae);
	test(110, case_get_put_handle);
	return 0;
}
