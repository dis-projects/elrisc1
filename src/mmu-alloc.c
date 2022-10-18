// SPDX-License-Identifier: GPL-2.0
/*
 * This is a stripped-to-bits version of lib/genalloc.c
 * Copyright 2005 (C) Jes Sorensen <jes@trained-monkey.org>
 * Copyright 2018-2022 RnD Center "ELVEES", JSC
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/bitmap.h>
#include <linux/rculist.h>
#include <linux/interrupt.h>
#include <linux/module.h>

#include "mmu-alloc.h"

static inline size_t chunk_size(const struct mmu_pool_chunk *chunk)
{
	return chunk->end_addr - chunk->start_addr + 1;
}

static int set_bits_ll(unsigned long *addr, unsigned long mask_to_set)
{
	unsigned long val, nval;

	nval = *addr;
	do {
		val = nval;
		if (val & mask_to_set)
			return -EBUSY;
		cpu_relax();
	} while ((nval = cmpxchg(addr, val, val | mask_to_set)) != val);

	return 0;
}

static int clear_bits_ll(unsigned long *addr, unsigned long mask_to_clear)
{
	unsigned long val, nval;

	nval = *addr;
	do {
		val = nval;
		if ((val & mask_to_clear) != mask_to_clear)
			return -EBUSY;
		cpu_relax();
	} while ((nval = cmpxchg(addr, val, val & ~mask_to_clear)) != val);

	return 0;
}

/*
 * bitmap_set_ll - set the specified number of bits at the specified position
 * @map: pointer to a bitmap
 * @start: a bit position in @map
 * @nr: number of bits to set
 *
 * Set @nr bits start from @start in @map lock-lessly. Several users
 * can set/clear the same bitmap simultaneously without lock. If two
 * users set the same bit, one user will return remain bits, otherwise
 * return 0.
 */
static int bitmap_set_ll(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_set >= 0) {
		if (set_bits_ll(p, mask_to_set))
			return nr;
		nr -= bits_to_set;
		bits_to_set = BITS_PER_LONG;
		mask_to_set = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		if (set_bits_ll(p, mask_to_set))
			return nr;
	}

	return 0;
}

/*
 * bitmap_clear_ll - clear specified number of bits at the specified position
 * @map: pointer to a bitmap
 * @start: a bit position in @map
 * @nr: number of bits to set
 *
 * Clear @nr bits start from @start in @map lock-lessly. Several users
 * can set/clear the same bitmap simultaneously without lock. If two
 * users clear the same bit, one user will return remain bits,
 * otherwise return 0.
 */
static int bitmap_clear_ll(unsigned long *map, int start, int nr)
{
	unsigned long *p = map + BIT_WORD(start);
	const int size = start + nr;
	int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

	while (nr - bits_to_clear >= 0) {
		if (clear_bits_ll(p, mask_to_clear))
			return nr;
		nr -= bits_to_clear;
		bits_to_clear = BITS_PER_LONG;
		mask_to_clear = ~0UL;
		p++;
	}
	if (nr) {
		mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
		if (clear_bits_ll(p, mask_to_clear))
			return nr;
	}

	return 0;
}

/**
 * mmu_pool_create - create a new special memory pool
 * @min_alloc_order: log base 2 of number of bytes each bitmap bit represents
 * @nid: node id of the node the pool structure should be allocated on, or -1
 *
 * Create a new special memory pool that can be used to manage special purpose
 * memory not managed by the regular kmalloc/kfree interface.
 */
struct mmu_pool *mmu_pool_create(int min_alloc_order, int nid)
{
	struct mmu_pool *pool;

	pool = kmalloc_node(sizeof(struct mmu_pool), GFP_KERNEL, nid);
	if (pool != NULL) {
		spin_lock_init(&pool->lock);
		INIT_LIST_HEAD(&pool->chunks);
		pool->min_alloc_order = min_alloc_order;
		pool->algo = mmu_pool_first_fit;
		pool->data = NULL;
		pool->name = NULL;
	}
	return pool;
}
//EXPORT_SYMBOL(mmu_pool_create);

/**
 * mmu_pool_add - add a new chunk of special memory to the pool
 * @pool: pool to add new memory chunk to
 * @addr: starting address of memory chunk to add to pool
 * @size: size in bytes of the memory chunk to add to pool
 * @nid: node id of the node the chunk structure and bitmap should be
 *       allocated on, or -1
 *
 * Add a new chunk of special memory to the specified pool.
 *
 * Returns 0 on success or a -ve errno on failure.
 */
int mmu_pool_add(struct mmu_pool *pool, unsigned long addr,
		 size_t size, int nid)
{
	struct mmu_pool_chunk *chunk;
	int nbits = size >> pool->min_alloc_order;
	int nbytes = sizeof(struct mmu_pool_chunk) +
				BITS_TO_LONGS(nbits) * sizeof(long);

	chunk = kzalloc_node(nbytes, GFP_KERNEL, nid);
	if (unlikely(chunk == NULL))
		return -ENOMEM;

	chunk->start_addr = addr;
	chunk->end_addr = addr + size - 1;
	atomic64_set(&chunk->avail, size);

	spin_lock(&pool->lock);
	list_add_rcu(&chunk->next_chunk, &pool->chunks);
	spin_unlock(&pool->lock);

	return 0;
}
//EXPORT_SYMBOL(mmu_pool_add);


/**
 * mmu_pool_destroy - destroy a special memory pool
 * @pool: pool to destroy
 *
 * Destroy the specified special memory pool. Verifies that there are no
 * outstanding allocations.
 */
void mmu_pool_destroy(struct mmu_pool *pool)
{
	struct list_head *_chunk, *_next_chunk;
	struct mmu_pool_chunk *chunk;
	int order = pool->min_alloc_order;
	int bit, end_bit;

	list_for_each_safe(_chunk, _next_chunk, &pool->chunks) {
		chunk = list_entry(_chunk, struct mmu_pool_chunk, next_chunk);
		list_del(&chunk->next_chunk);

		end_bit = chunk_size(chunk) >> order;
		bit = find_next_bit(chunk->bits, end_bit, 0);
		WARN_ON_ONCE(bit < end_bit);

		kfree(chunk);
	}
	kfree_const(pool->name);
	kfree(pool);
}
//EXPORT_SYMBOL(mmu_pool_destroy);

/**
 * mmu_pool_alloc - allocate special memory from the pool
 * @pool: pool to allocate from
 * @size: number of bytes to allocate from the pool
 *
 * Allocate the requested number of bytes from the specified pool.
 * Uses the pool allocation function (with first-fit algorithm by default).
 * Can not be used in NMI handler on architectures without
 * NMI-safe cmpxchg implementation.
 */
unsigned long mmu_pool_alloc(struct mmu_pool *pool, size_t size)
{
	return mmu_pool_alloc_algo(pool, size, pool->algo, pool->data);
}
//EXPORT_SYMBOL(mmu_pool_alloc);

/**
 * mmu_pool_alloc_algo - allocate special memory from the pool
 * @pool: pool to allocate from
 * @size: number of bytes to allocate from the pool
 * @algo: algorithm passed from caller
 * @data: data passed to algorithm
 *
 * Allocate the requested number of bytes from the specified pool.
 * Uses the pool allocation function (with first-fit algorithm by default).
 * Can not be used in NMI handler on architectures without
 * NMI-safe cmpxchg implementation.
 */
unsigned long mmu_pool_alloc_algo(struct mmu_pool *pool, size_t size,
		mmupool_algo_t algo, void *data)
{
	struct mmu_pool_chunk *chunk;
	unsigned long addr = 0;
	int order = pool->min_alloc_order;
	int nbits, start_bit, end_bit, remain;

#ifndef CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG
	BUG_ON(in_nmi());
#endif

	if (size == 0)
		return 0;

	nbits = (size + (1UL << order) - 1) >> order;
	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &pool->chunks, next_chunk) {
		if (size > atomic64_read(&chunk->avail))
			continue;

		start_bit = 0;
		end_bit = chunk_size(chunk) >> order;
retry:
		start_bit = algo(chunk->bits, end_bit, start_bit,
				 nbits, data, pool);
		if (start_bit >= end_bit)
			continue;
		remain = bitmap_set_ll(chunk->bits, start_bit, nbits);
		if (remain) {
			remain = bitmap_clear_ll(chunk->bits, start_bit,
						 nbits - remain);
			BUG_ON(remain);
			goto retry;
		}

		addr = chunk->start_addr + ((unsigned long)start_bit << order);
		size = nbits << order;
		atomic64_sub(size, &chunk->avail);
		break;
	}
	rcu_read_unlock();
	return addr;
}
//EXPORT_SYMBOL(mmu_pool_alloc_algo);

/**
 * mmu_pool_free - free allocated special memory back to the pool
 * @pool: pool to free to
 * @addr: starting address of memory to free back to pool
 * @size: size in bytes of memory to free
 *
 * Free previously allocated special memory back to the specified
 * pool.  Can not be used in NMI handler on architectures without
 * NMI-safe cmpxchg implementation.
 */
void mmu_pool_free(struct mmu_pool *pool, unsigned long addr, size_t size)
{
	struct mmu_pool_chunk *chunk;
	int order = pool->min_alloc_order;
	int start_bit, nbits, remain;

#ifndef CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG
	BUG_ON(in_nmi());
#endif

	nbits = (size + (1UL << order) - 1) >> order;
	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &pool->chunks, next_chunk) {
		if (addr >= chunk->start_addr && addr <= chunk->end_addr) {
			BUG_ON(addr + size - 1 > chunk->end_addr);
			start_bit = (addr - chunk->start_addr) >> order;
			remain = bitmap_clear_ll(chunk->bits, start_bit, nbits);
			BUG_ON(remain);
			size = nbits << order;
			atomic64_add(size, &chunk->avail);
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();
	BUG();
}
//EXPORT_SYMBOL(mmu_pool_free);

/**
 * mmu_pool_for_each_chunk - call func for every chunk of generic memory pool
 * @pool:	the generic memory pool
 * @func:	func to call
 * @data:	additional data used by @func
 *
 * Call @func for every chunk of generic memory pool.  The @func is
 * called with rcu_read_lock held.
 */
void mmu_pool_for_each_chunk(struct mmu_pool *pool,
	void (*func)(struct mmu_pool *pool,
		     struct mmu_pool_chunk *chunk, void *data),
	void *data)
{
	struct mmu_pool_chunk *chunk;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &(pool)->chunks, next_chunk)
		func(pool, chunk, data);
	rcu_read_unlock();
}
//EXPORT_SYMBOL(mmu_pool_for_each_chunk);

/**
 * addr_in_mmu_pool - checks if an address falls within the range of a pool
 * @pool:	the generic memory pool
 * @start:	start address
 * @size:	size of the region
 *
 * Check if the range of addresses falls within the specified pool. Returns
 * true if the entire range is contained in the pool and false otherwise.
 */
bool addr_in_mmu_pool(struct mmu_pool *pool, unsigned long start,
			size_t size)
{
	bool found = false;
	unsigned long end = start + size - 1;
	struct mmu_pool_chunk *chunk;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &(pool)->chunks, next_chunk) {
		if (start >= chunk->start_addr && start <= chunk->end_addr) {
			if (end <= chunk->end_addr) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

/**
 * mmu_pool_avail - get available free space of the pool
 * @pool: pool to get available free space
 *
 * Return available free space of the specified pool.
 */
size_t mmu_pool_avail(struct mmu_pool *pool)
{
	struct mmu_pool_chunk *chunk;
	size_t avail = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &pool->chunks, next_chunk)
		avail += atomic64_read(&chunk->avail);
	rcu_read_unlock();
	return avail;
}
//EXPORT_SYMBOL_GPL(mmu_pool_avail);

/**
 * mmu_pool_size - get size in bytes of memory managed by the pool
 * @pool: pool to get size
 *
 * Return size in bytes of memory managed by the pool.
 */
size_t mmu_pool_size(struct mmu_pool *pool)
{
	struct mmu_pool_chunk *chunk;
	size_t size = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(chunk, &pool->chunks, next_chunk)
		size += chunk_size(chunk);
	rcu_read_unlock();
	return size;
}
//EXPORT_SYMBOL_GPL(mmu_pool_size);

/**
 * mmu_pool_set_algo - set the allocation algorithm
 * @pool: pool to change allocation algorithm
 * @algo: custom algorithm function
 * @data: additional data used by @algo
 *
 * Call @algo for each memory allocation in the pool.
 * If @algo is NULL use mmu_pool_first_fit as default
 * memory allocation function.
 */
void mmu_pool_set_algo(struct mmu_pool *pool, mmupool_algo_t algo, void *data)
{
	rcu_read_lock();

	pool->algo = algo;
	if (!pool->algo)
		pool->algo = mmu_pool_first_fit;

	pool->data = data;

	rcu_read_unlock();
}
//EXPORT_SYMBOL(mmu_pool_set_algo);

/**
 * mmu_pool_first_fit - find the first available region
 * of memory matching the size requirement (no alignment constraint)
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: additional data - unused
 * @pool: pool to find the fit region memory from
 */
unsigned long mmu_pool_first_fit(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct mmu_pool *pool)
{
	return bitmap_find_next_zero_area(map, size, start, nr, 0);
}
//EXPORT_SYMBOL(mmu_pool_first_fit);

/**
 * mmu_pool_first_fit_align - find the first available region
 * of memory matching the size requirement (alignment constraint)
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: data for alignment
 * @pool: pool to get order from
 */
unsigned long mmu_pool_first_fit_align(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct mmu_pool *pool)
{
	struct mmupool_data_align *alignment;
	unsigned long align_mask;
	int order;

	alignment = data;
	order = pool->min_alloc_order;
	align_mask = ((alignment->align + (1UL << order) - 1) >> order) - 1;
	return bitmap_find_next_zero_area(map, size, start, nr, align_mask);
}
//EXPORT_SYMBOL(mmu_pool_first_fit_align);

/**
 * mmu_pool_fixed_alloc - reserve a specific region
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: data for alignment
 * @pool: pool to get order from
 */
unsigned long mmu_pool_fixed_alloc(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct mmu_pool *pool)
{
	struct mmupool_data_fixed *fixed_data;
	int order;
	unsigned long offset_bit;
	unsigned long start_bit;

	fixed_data = data;
	order = pool->min_alloc_order;
	offset_bit = fixed_data->offset >> order;
	if (WARN_ON(fixed_data->offset & ((1UL << order) - 1)))
		return size;

	start_bit = bitmap_find_next_zero_area(map, size,
			start + offset_bit, nr, 0);
	if (start_bit != offset_bit)
		start_bit = size;
	return start_bit;
}
//EXPORT_SYMBOL(mmu_pool_fixed_alloc);

/**
 * mmu_pool_first_fit_order_align - find the first available region
 * of memory matching the size requirement. The region will be aligned
 * to the order of the size specified.
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: additional data - unused
 * @pool: pool to find the fit region memory from
 */
unsigned long mmu_pool_first_fit_order_align(unsigned long *map,
		unsigned long size, unsigned long start,
		unsigned int nr, void *data, struct mmu_pool *pool)
{
	unsigned long align_mask = roundup_pow_of_two(nr) - 1;

	return bitmap_find_next_zero_area(map, size, start, nr, align_mask);
}
//EXPORT_SYMBOL(mmu_pool_first_fit_order_align);

/**
 * mmu_pool_best_fit - find the best fitting region of memory
 * macthing the size requirement (no alignment constraint)
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: additional data - unused
 * @pool: pool to find the fit region memory from
 *
 * Iterate over the bitmap to find the smallest free region
 * which we can allocate the memory.
 */
unsigned long mmu_pool_best_fit(unsigned long *map, unsigned long size,
		unsigned long start, unsigned int nr, void *data,
		struct mmu_pool *pool)
{
	unsigned long start_bit = size;
	unsigned long len = size + 1;
	unsigned long index;

	index = bitmap_find_next_zero_area(map, size, start, nr, 0);

	while (index < size) {
		int next_bit = find_next_bit(map, size, index + nr);

		if ((next_bit - index) < len) {
			len = next_bit - index;
			start_bit = index;
			if (len == nr)
				return start_bit;
		}
		index = bitmap_find_next_zero_area(map, size,
						   next_bit + 1, nr, 0);
	}

	return start_bit;
}
//EXPORT_SYMBOL(mmu_pool_best_fit);

static void devm_mmu_pool_release(struct device *dev, void *res)
{
	mmu_pool_destroy(*(struct mmu_pool **)res);
}

static int devm_mmu_pool_match(struct device *dev, void *res, void *data)
{
	struct mmu_pool **p = res;

	/* NULL data matches only a pool without an assigned name */
	if (!data && !(*p)->name)
		return 1;

	if (!data || !(*p)->name)
		return 0;

	return !strcmp((*p)->name, data);
}

/**
 * mmu_pool_get - Obtain the mmu_pool (if any) for a device
 * @dev: device to retrieve the mmu_pool from
 * @name: name of a mmu_pool or NULL, identifies a particular mmu_pool on device
 *
 * Returns the mmu_pool for the device if one is present, or NULL.
 */
struct mmu_pool *mmu_pool_get(struct device *dev, const char *name)
{
	struct mmu_pool **p;

	p = devres_find(dev, devm_mmu_pool_release, devm_mmu_pool_match,
			(void *)name);
	if (!p)
		return NULL;
	return *p;
}
//EXPORT_SYMBOL_GPL(mmu_pool_get);

#if 0
/**
 * devm_mmu_pool_create - managed mmu_pool_create
 * @dev: device that provides the mmu_pool
 * @min_alloc_order: log base 2 of number of bytes each bitmap bit represents
 * @nid: node selector for allocated mmu_pool, %NUMA_NO_NODE for all nodes
 * @name: name of a mmu_pool or NULL, identifies a particular mmu_pool on device
 *
 * Create a new special memory pool that can be used to manage special purpose
 * memory not managed by the regular kmalloc/kfree interface. The pool will be
 * automatically destroyed by the device management code.
 */
struct mmu_pool *devm_mmu_pool_create(struct device *dev, int min_alloc_order,
				      int nid, const char *name)
{
	struct mmu_pool **ptr, *pool;
	const char *pool_name = NULL;

	/* Check that mmupool to be created is uniquely addressed on device */
	if (mmu_pool_get(dev, name))
		return ERR_PTR(-EINVAL);

	if (name) {
		pool_name = kstrdup_const(name, GFP_KERNEL);
		if (!pool_name)
			return ERR_PTR(-ENOMEM);
	}

	ptr = devres_alloc(devm_mmu_pool_release, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		goto free_pool_name;

	pool = mmu_pool_create(min_alloc_order, nid);
	if (!pool)
		goto free_devres;

	*ptr = pool;
	pool->name = pool_name;
	devres_add(dev, ptr);

	return pool;

free_devres:
	devres_free(ptr);
free_pool_name:
	kfree_const(pool_name);

	return ERR_PTR(-ENOMEM);
}
//EXPORT_SYMBOL(devm_mmu_pool_create);
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memalloc library for VMMU");
