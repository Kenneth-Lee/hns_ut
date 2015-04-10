//#define UT_DUMPSTACK
#include "comm.h"

#include <string.h>

//stub--------------------------------------
ut_cnt_def_range(111, 119, dma_map);
static void dma_unmap_single(struct device *dev, dma_addr_t dma_addr,
                 size_t size, int dir)
{
	ut_cnt_sub_range(111, 119, dma_map);
}

#define MAPPED_DMA 0x8989
#define UNMAPPED_DMA 0x7f7f
static dma_addr_t dma_map_single(struct device *dev, void *cpu_addr, size_t size,
               int dir) {
	ut_assert(cpu_addr);
	ut_cnt_add_range(111, 119, dma_map);
	return MAPPED_DMA;
}

int tc111_dma_cnt = 0;
static int dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	ut_assert(dma_addr);

	if(testcase==111) 
		if(tc111_dma_cnt++==4) {
			ut_cnt_sub_range(111, 119, dma_map);
			return -1;
		}

	if(testcase==113) {
		ut_cnt_sub_range(111, 119, dma_map);
		return -1;
	}


        return 0;
}

static inline dma_addr_t dma_map_page(struct device *dev, struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction dir) {
	ut_cnt_add_range(111, 119, dma_map);
	return MAPPED_DMA;
}

static inline void dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
	size_t size, enum dma_data_direction dir)
{
	ut_cnt_sub_range(111, 119, dma_map);
}

ut_cnt_def(110, alloc);
ut_cnt_def(111, alloc);
ut_cnt_def(112, alloc);
static void *kzalloc(size_t size, int flags) {
	void *p;

	ut_cnt_add(110, alloc);
	ut_cnt_add(111, alloc);
	ut_cnt_add(112, alloc);

	p = malloc(size);
	bzero(p, size);
	return p;
}

void kfree(void *objp){
	ut_cnt_sub(110, alloc);
	ut_cnt_sub(111, alloc);
	ut_cnt_sub(112, alloc);
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

ut_cnt_def(110, page);
ut_cnt_def(111, page);
ut_cnt_def(112, page);
static int tc112_alloc_page_cnt = 0;
static inline struct page *dev_alloc_pages(unsigned int order)
{
	ut_cnt_add(110, page);
	ut_cnt_add(111, page);
	ut_cnt_add(112, page);
	if(testcase==112) {
		if(tc112_alloc_page_cnt++==3) {
			ut_cnt_sub(112, page);
			return 0;
		}
	}
	return (struct page *)malloc(10);
}

void put_page(struct page *page)
{
	ut_cnt_sub(110, page);
	free(page);
}

static inline void *page_address(const struct page *page)
{
	return (void *)page;
}

static inline int get_order(unsigned long size) {
	return 0;
}

#include "hnae.c"

#define Q_NUM 4
struct hnae_ae_dev ae_dev;
struct hnae_queue qs[Q_NUM];
struct hnae_handle _handle = {
	.q_num = Q_NUM,
	.qs = qs,
};

struct hnae_handle *_get_handle(struct hnae_ae_dev *dev, const char *opts)
{
	return (struct hnae_handle *)&_handle;
}

void _put_handle(struct hnae_handle *handle) {
}

int _set_opts(struct hnae_handle *handle, int type, void *opts) {
	return 0;
}
int _get_opts(struct hnae_handle *handle, int type, void **opts) {
	return 0;
}

void _toggle_ring_irq(struct hnae_ring *ring, u32 val){}
void _toggle_queue_status(struct hnae_queue *queue, u32 val){}

struct hnae_ae_ops ops = {
	.get_handle = _get_handle,
	.put_handle = _put_handle,
	.get_opts = _get_opts,
	.set_opts = _set_opts,
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

	h = hnae_get_handle(NULL, "ae_idddd", "ae_opts", NULL);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);

	//test to pass
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", NULL);
	ut_assert(!IS_ERR(h));
	ut_assert_str(ae_dev.use_count == 1, "use_count=%d, should be 1\n", ae_dev.use_count);

	hnae_ae_unregister(&ae_dev); //should not unregister when using
	ut_assert(find_ae("ae_id"));

	hnae_put_handle(h);

	ut_assert(!ae_dev.use_count);

	ut_check_cnt(110, alloc);


	//test to fail: dma_map fail in the middle
	testcase = 111;
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", NULL);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);
	ut_check_cnt(111, alloc);
	ut_check_cnt_range(111, 119, dma_map);

	//test to fail: alloc_buffer fail in the middle
	testcase = 112;
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", NULL);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);
	ut_check_cnt(112, alloc);
	ut_check_cnt_range(111, 119, dma_map);

	//test to fail: dma map fail for desc
	testcase = 113;
	h = hnae_get_handle(NULL, "ae_id", "ae_opts", NULL);
	ut_assert(IS_ERR(h));
	ut_assert(ae_dev.use_count == 0);
	ut_check_cnt(112, alloc);
	ut_check_cnt_range(111, 119, dma_map);

	hnae_ae_unregister(&ae_dev);
	ut_assert(!find_ae("ae_id"));
}

//------------------------------------------
int main(void) {
	test(100, case_register_ae);
	test(110, case_get_put_handle);
	return 0;
}
