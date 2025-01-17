/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 */


#include "spdk/bdev.h"
#include "spdk/bdev_module.h"
#include "spdk/ftl.h"
#include "spdk/string.h"

#include "ftl_nv_cache.h"
#include "ftl_nv_cache_io.h"
#include "ftl_core.h"
#include "ftl_band.h"
#include "utils/ftl_addr_utils.h"
#include "mngt/ftl_mngt.h"

static inline uint64_t nvc_data_blocks(struct ftl_nv_cache *nv_cache) __attribute__((unused));
static struct ftl_nv_cache_compactor *compactor_alloc(struct spdk_ftl_dev *dev);
static void compactor_free(struct spdk_ftl_dev *dev, struct ftl_nv_cache_compactor *compactor);
static void compaction_process_ftl_done(struct ftl_rq *rq);

static inline const struct ftl_layout_region *
nvc_data_region(struct ftl_nv_cache *nv_cache)
{
	struct spdk_ftl_dev *dev;

	dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	return &dev->layout.region[FTL_LAYOUT_REGION_TYPE_DATA_NVC];
}

static inline void
nvc_validate_md(struct ftl_nv_cache *nv_cache,
		struct ftl_nv_cache_chunk_md *chunk_md)
{
	struct ftl_md *md = nv_cache->md;
	void *buffer = ftl_md_get_buffer(md);
	uint64_t size = ftl_md_get_buffer_size(md);
	void *ptr = chunk_md;

	if (ptr < buffer) {
		ftl_abort();
	}

	ptr += sizeof(*chunk_md);
	if (ptr > buffer + size) {
		ftl_abort();
	}
}

static inline uint64_t
nvc_data_offset(struct ftl_nv_cache *nv_cache)
{
	return nvc_data_region(nv_cache)->current.offset;
}

static inline uint64_t
nvc_data_blocks(struct ftl_nv_cache *nv_cache)
{
	return nvc_data_region(nv_cache)->current.blocks;
}

size_t
ftl_nv_cache_chunk_tail_md_num_blocks(const struct ftl_nv_cache *nv_cache)
{
	struct spdk_ftl_dev *dev =  SPDK_CONTAINEROF(nv_cache,
				    struct spdk_ftl_dev, nv_cache);
	return spdk_divide_round_up(dev->layout.nvc.chunk_data_blocks * dev->layout.l2p.addr_size,
				    FTL_BLOCK_SIZE);
}

static size_t
nv_cache_p2l_map_pool_elem_size(const struct ftl_nv_cache *nv_cache)
{
	/* Map pool element holds the whole tail md */
	return nv_cache->tail_md_chunk_blocks * FTL_BLOCK_SIZE;
}

static uint64_t
get_chunk_idx(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache_chunk *first_chunk = chunk->nv_cache->chunks;

	return (chunk->offset - first_chunk->offset) / chunk->nv_cache->chunk_blocks;
}

int
ftl_nv_cache_init(struct spdk_ftl_dev *dev)
{
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;
	struct ftl_nv_cache_chunk *chunk;
	struct ftl_nv_cache_chunk_md *md;
	struct ftl_nv_cache_compactor *compactor;
	uint64_t i, offset;

	nv_cache->halt = true;

	nv_cache->md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	if (!nv_cache->md) {
		FTL_ERRLOG(dev, "No NV cache metadata object\n");
		return -1;
	}

	nv_cache->md_pool = ftl_mempool_create(dev->conf.user_io_pool_size,
					       nv_cache->md_size * dev->xfer_size,
					       FTL_BLOCK_SIZE, SPDK_ENV_SOCKET_ID_ANY);
	if (!nv_cache->md_pool) {
		FTL_ERRLOG(dev, "Failed to initialize NV cache metadata pool\n");
		return -1;
	}

	/*
	 * Initialize chunk info
	 */
	// 1.初始化chunk/block参数
	nv_cache->chunk_blocks = dev->layout.nvc.chunk_data_blocks;
	nv_cache->chunk_count = dev->layout.nvc.chunk_count;
	nv_cache->tail_md_chunk_blocks = ftl_nv_cache_chunk_tail_md_num_blocks(nv_cache);

	/* Allocate chunks */
	nv_cache->chunks = calloc(nv_cache->chunk_count,
				  sizeof(nv_cache->chunks[0]));
	if (!nv_cache->chunks) {
		FTL_ERRLOG(dev, "Failed to initialize NV cache chunks\n");
		return -1;
	}

	// 2.初始化 nv_cache 的 chunk 状态链表
	TAILQ_INIT(&nv_cache->chunk_free_list);
	TAILQ_INIT(&nv_cache->chunk_open_list);
	TAILQ_INIT(&nv_cache->chunk_full_list);
	TAILQ_INIT(&nv_cache->chunk_comp_list);
	TAILQ_INIT(&nv_cache->needs_free_persist_list);

	/* First chunk metadata */
	md = ftl_md_get_buffer(nv_cache->md);
	if (!md) {
		FTL_ERRLOG(dev, "No NV cache metadata\n");
		return -1;
	}

	nv_cache->chunk_free_count = nv_cache->chunk_count;

	chunk = nv_cache->chunks;
	offset = nvc_data_offset(nv_cache);
	for (i = 0; i < nv_cache->chunk_count; i++, chunk++, md++) {
		chunk->nv_cache = nv_cache;
		chunk->md = md;
		nvc_validate_md(nv_cache, md);
		chunk->offset = offset;
		offset += nv_cache->chunk_blocks;
		// 初始化时所有的chunk都是free状态，都插入到chunk_free_list中
		TAILQ_INSERT_TAIL(&nv_cache->chunk_free_list, chunk, entry);

		// [wzc]static
		chunk->compact_valid_blocks = 0;
		chunk->io_cnt = 0;
	}
	assert(offset <= nvc_data_offset(nv_cache) + nvc_data_blocks(nv_cache));

	/* Start compaction when full chunks exceed given % of entire chunks */
	// 3.初始化 compact 阈值
	// 当写满chunk的数量大于chunk_compaction_threshold时，开始compaction
	nv_cache->chunk_compaction_threshold = nv_cache->chunk_count *
					       dev->conf.nv_cache.chunk_compaction_threshold / 100;

	// [WZC]static

	nv_cache->compaction_read_blocks = 0;
	nv_cache->compaction_start_time = 0;
	nv_cache->trigger_throttle_cnt = 0;
	nv_cache->interval_throttle_cnt = 0;
	nv_cache->throttle_cpu_cnt = 0;
	nv_cache->CPU_HZ = spdk_get_ticks_hz();

	
	SPDK_NOTICELOG("[WZC_INIT]nvcache_tt_chunks: %lu, blocks_per_chunk: %lu, tail_blocks: %lu\n", 
		nv_cache->chunk_count, nv_cache->chunk_blocks, nv_cache->tail_md_chunk_blocks);
	SPDK_NOTICELOG("[WZC_INIT]conf_thres: %u%%, compact_thres_chunks: %lu\n", 
		dev->conf.nv_cache.chunk_compaction_threshold, nv_cache->chunk_compaction_threshold);
	SPDK_NOTICELOG("[WZC_INIT]CPU_HZ: %lu\n", nv_cache->CPU_HZ);

	// 4.初始化compactor_list
	TAILQ_INIT(&nv_cache->compactor_list);
	// 初始化compactor
	for (i = 0; i < FTL_NV_CACHE_NUM_COMPACTORS; i++) {
		compactor = compactor_alloc(dev);

		if (!compactor) {
			FTL_ERRLOG(dev, "Cannot allocate compaction process\n");
			return -1;
		}

		TAILQ_INSERT_TAIL(&nv_cache->compactor_list, compactor, entry);
	}

	// 5.初始化 mempool
#define FTL_MAX_OPEN_CHUNKS 2
	nv_cache->p2l_pool = ftl_mempool_create(FTL_MAX_OPEN_CHUNKS,
						nv_cache_p2l_map_pool_elem_size(nv_cache),
						FTL_BLOCK_SIZE,
						SPDK_ENV_SOCKET_ID_ANY);
	if (!nv_cache->p2l_pool) {
		return -ENOMEM;
	}

	/* One entry per open chunk */
	nv_cache->chunk_md_pool = ftl_mempool_create(FTL_MAX_OPEN_CHUNKS,
				  sizeof(struct ftl_nv_cache_chunk_md),
				  FTL_BLOCK_SIZE,
				  SPDK_ENV_SOCKET_ID_ANY);
	if (!nv_cache->chunk_md_pool) {
		return -ENOMEM;
	}

	/* Each compactor can be reading a different chunk which it needs to switch state to free to at the end,
	 * plus one backup each for high invalidity chunks processing (if there's a backlog of chunks with extremely
	 * small, even 0, validity then they can be processed by the compactors quickly and trigger a lot of updates
	 * to free state at once) */
	nv_cache->free_chunk_md_pool = ftl_mempool_create(2 * FTL_NV_CACHE_NUM_COMPACTORS,
				       sizeof(struct ftl_nv_cache_chunk_md),
				       FTL_BLOCK_SIZE,
				       SPDK_ENV_SOCKET_ID_ANY);
	if (!nv_cache->free_chunk_md_pool) {
		return -ENOMEM;
	}

	// 1.初始化 throttle.interval_tsc, chunk_free_target
	nv_cache->throttle.interval_tsc = FTL_NV_CACHE_THROTTLE_INTERVAL_MS *
					  (spdk_get_ticks_hz() / 1000);
	nv_cache->chunk_free_target = spdk_divide_round_up(nv_cache->chunk_count *
				      dev->conf.nv_cache.chunk_free_target,
				      100);
	return 0;
}

void
ftl_nv_cache_deinit(struct spdk_ftl_dev *dev)
{
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;
	struct ftl_nv_cache_compactor *compactor;

	while (!TAILQ_EMPTY(&nv_cache->compactor_list)) {
		compactor = TAILQ_FIRST(&nv_cache->compactor_list);
		TAILQ_REMOVE(&nv_cache->compactor_list, compactor, entry);

		compactor_free(dev, compactor);
	}

	ftl_mempool_destroy(nv_cache->md_pool);
	ftl_mempool_destroy(nv_cache->p2l_pool);
	ftl_mempool_destroy(nv_cache->chunk_md_pool);
	ftl_mempool_destroy(nv_cache->free_chunk_md_pool);
	nv_cache->md_pool = NULL;
	nv_cache->p2l_pool = NULL;
	nv_cache->chunk_md_pool = NULL;
	nv_cache->free_chunk_md_pool = NULL;

	free(nv_cache->chunks);
	nv_cache->chunks = NULL;
}

static uint64_t
chunk_get_free_space(struct ftl_nv_cache *nv_cache,
		     struct ftl_nv_cache_chunk *chunk)
{
	assert(chunk->md->write_pointer + nv_cache->tail_md_chunk_blocks <=
	       nv_cache->chunk_blocks);
	return nv_cache->chunk_blocks - chunk->md->write_pointer -
	       nv_cache->tail_md_chunk_blocks;
}

static bool
chunk_is_closed(struct ftl_nv_cache_chunk *chunk)
{
	return chunk->md->write_pointer == chunk->nv_cache->chunk_blocks;
}

static void ftl_chunk_close(struct ftl_nv_cache_chunk *chunk);

static uint64_t
ftl_nv_cache_get_wr_buffer(struct ftl_nv_cache *nv_cache, struct ftl_io *io)
{
	uint64_t address = FTL_LBA_INVALID;
	uint64_t num_blocks = io->num_blocks;
	uint64_t free_space;
	struct ftl_nv_cache_chunk *chunk;

	do {
		chunk = nv_cache->chunk_current;
		/* Chunk has been closed so pick new one */
		if (chunk && chunk_is_closed(chunk))  {
			chunk = NULL;
		}

		// 1.如果 chunk_current 为空，从open_list中取出一个chunk
		if (!chunk) {
			chunk = TAILQ_FIRST(&nv_cache->chunk_open_list);
			if (chunk && chunk->md->state == FTL_CHUNK_STATE_OPEN) {
				TAILQ_REMOVE(&nv_cache->chunk_open_list, chunk, entry);
				nv_cache->chunk_current = chunk;
			} else {
				break;
			}
		}

		// 2.获取当前chunk可用的空间
		free_space = chunk_get_free_space(nv_cache, chunk);

		if (free_space >= num_blocks) {
			/* Enough space in chunk */

			/* Calculate address in NV cache */
			address = chunk->offset + chunk->md->write_pointer;

			/* Set chunk in IO */
			io->nv_cache_chunk = chunk;

			/* Move write pointer */
			// 推进chunk的写指针
			chunk->md->write_pointer += num_blocks;
			break;
		}

		/* Not enough space in nv_cache_chunk */
		nv_cache->chunk_current = NULL;

		if (0 == free_space) {
			continue;
		}

		chunk->md->blocks_skipped = free_space;
		chunk->md->blocks_written += free_space;
		chunk->md->write_pointer += free_space;

		// 3.判断chunk 是否写满，写满则关闭
		if (chunk->md->blocks_written == chunk_tail_md_offset(nv_cache)) {
			// chunk的写满了，需要关闭
			// 此时将chunk的p2l metadata数据写入到 cache-ssd 中，size = tail_md_chunk_blocks
			// 在 chunk_close_cb 将chunk放到chunk_full_list中，将状态设置为CLOSED
			ftl_chunk_close(chunk);
		}
	} while (1);

	// 这里返回的address是chunk的offset + chunk的write_pointer
	// 相当于 lba，第几个block
	return address;
}

void
ftl_nv_cache_fill_md(struct ftl_io *io)
{
	struct ftl_nv_cache_chunk *chunk = io->nv_cache_chunk;
	uint64_t i;
	union ftl_md_vss *metadata = io->md;
	uint64_t lba = ftl_io_get_lba(io, 0);

	// per data block' vss' metadata
	// fill it's vss metadata
	for (i = 0; i < io->num_blocks; ++i, lba++, metadata++) {
		metadata->nv_cache.lba = lba;
		metadata->nv_cache.seq_id = chunk->md->seq_id;
	}
}

uint64_t
chunk_tail_md_offset(struct ftl_nv_cache *nv_cache)
{
	return nv_cache->chunk_blocks - nv_cache->tail_md_chunk_blocks;
}

static void
chunk_advance_blocks(struct ftl_nv_cache *nv_cache, struct ftl_nv_cache_chunk *chunk,
		     uint64_t advanced_blocks)
{
	chunk->md->blocks_written += advanced_blocks;

	assert(chunk->md->blocks_written <= nv_cache->chunk_blocks);

	if (chunk->md->blocks_written == chunk_tail_md_offset(nv_cache)) {
		ftl_chunk_close(chunk);
	}
}

static uint64_t
chunk_user_blocks_written(struct ftl_nv_cache_chunk *chunk)
{
	return chunk->md->blocks_written - chunk->md->blocks_skipped -
	       chunk->nv_cache->tail_md_chunk_blocks;
}

static bool
is_chunk_compacted(struct ftl_nv_cache_chunk *chunk)
{
	assert(chunk->md->blocks_written != 0);

	// 获取chunk中用于用户的block数
	if (chunk_user_blocks_written(chunk) == chunk->md->blocks_compacted) {
		return true;
	}

	return false;
}

static int
ftl_chunk_alloc_md_entry(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];

	p2l_map->chunk_dma_md = ftl_mempool_get(nv_cache->chunk_md_pool);

	if (!p2l_map->chunk_dma_md) {
		return -ENOMEM;
	}

	memset(p2l_map->chunk_dma_md, 0, region->entry_size * FTL_BLOCK_SIZE);
	return 0;
}

static void
ftl_chunk_free_md_entry(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	ftl_mempool_put(chunk->nv_cache->chunk_md_pool, p2l_map->chunk_dma_md);
	p2l_map->chunk_dma_md = NULL;
}

static void
ftl_chunk_free(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;

	/* Reset chunk */
	memset(chunk->md, 0, sizeof(*chunk->md));

	TAILQ_INSERT_TAIL(&nv_cache->needs_free_persist_list, chunk, entry);
	nv_cache->chunk_free_persist_count++;
}

static int
ftl_chunk_alloc_chunk_free_entry(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];

	p2l_map->chunk_dma_md = ftl_mempool_get(nv_cache->free_chunk_md_pool);

	if (!p2l_map->chunk_dma_md) {
		return -ENOMEM;
	}

	memset(p2l_map->chunk_dma_md, 0, region->entry_size * FTL_BLOCK_SIZE);
	return 0;
}

static void
ftl_chunk_free_chunk_free_entry(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	ftl_mempool_put(chunk->nv_cache->free_chunk_md_pool, p2l_map->chunk_dma_md);
	p2l_map->chunk_dma_md = NULL;
}

static void
chunk_free_cb(int status, void *ctx)
{
	struct ftl_nv_cache_chunk *chunk = (struct ftl_nv_cache_chunk *)ctx;

	if (spdk_likely(!status)) {
		struct ftl_nv_cache *nv_cache = chunk->nv_cache;

		// 1. 将chunk放到chunk_free_list中,同时将chunk的状态设置为 FREE
		//    同时增减chunk_free_persist_count, chunk_free_count, chunk_free_count
		nv_cache->chunk_free_persist_count--;
		TAILQ_INSERT_TAIL(&nv_cache->chunk_free_list, chunk, entry);
		nv_cache->chunk_free_count++;
		nv_cache->chunk_full_count--;
		chunk->md->state = FTL_CHUNK_STATE_FREE;
		chunk->md->close_seq_id = 0;
		// 2. 将chunk->nv_cache->free_chunk_md_pool内存池中的chunk->p2l_map->chunk_dma_md 释放
		ftl_chunk_free_chunk_free_entry(chunk);
	} else {
#ifdef SPDK_FTL_RETRY_ON_ERROR
		ftl_md_persist_entry_retry(&chunk->md_persist_entry_ctx);
#else
		ftl_abort();
#endif
	}
}

static void
ftl_chunk_persist_free_state(struct ftl_nv_cache *nv_cache)
{
	int rc;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map;
	struct ftl_md *md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	struct ftl_nv_cache_chunk *tchunk, *chunk = NULL;

	TAILQ_FOREACH_SAFE(chunk, &nv_cache->needs_free_persist_list, entry, tchunk) {
		p2l_map = &chunk->p2l_map;
		// 1.重置 chunk->p2l_map->chunk_dma_md 元数据
		rc = ftl_chunk_alloc_chunk_free_entry(chunk);
		if (rc) {
			break;
		}

		TAILQ_REMOVE(&nv_cache->needs_free_persist_list, chunk, entry);

		// 2. 将chunk的p2l_map->chunk_dma_md的状态设置为 FREE 状态
		memcpy(p2l_map->chunk_dma_md, chunk->md, region->entry_size * FTL_BLOCK_SIZE);
		p2l_map->chunk_dma_md->state = FTL_CHUNK_STATE_FREE;
		p2l_map->chunk_dma_md->close_seq_id = 0;
		p2l_map->chunk_dma_md->p2l_map_checksum = 0;
		// 3. 持久化chunk的p2l_map->chunk_dma_md 元数据
		ftl_md_persist_entry(md, get_chunk_idx(chunk), p2l_map->chunk_dma_md, NULL,
				     chunk_free_cb, chunk, &chunk->md_persist_entry_ctx);
					// 4. chunk_free_cb 回调函数将chunk放到chunk_free_list中,同时
					//    将chunk的状态设置为 FREE
	}
}

static void
compaction_stats_update(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct compaction_bw_stats *compaction_bw = &nv_cache->compaction_recent_bw;
	double *ptr;

	if (spdk_unlikely(chunk->compaction_length_tsc == 0)) {
		return;
	}

	if (spdk_likely(compaction_bw->count == FTL_NV_CACHE_COMPACTION_SMA_N)) {
		ptr = compaction_bw->buf + compaction_bw->first;
		compaction_bw->first++;
		if (compaction_bw->first == FTL_NV_CACHE_COMPACTION_SMA_N) {
			compaction_bw->first = 0;
		}
		compaction_bw->sum -= *ptr;
	} else {
		ptr = compaction_bw->buf + compaction_bw->count;
		compaction_bw->count++;
	}

	*ptr = (double)chunk->md->blocks_compacted * FTL_BLOCK_SIZE / chunk->compaction_length_tsc;

	compaction_bw->sum += *ptr;
	nv_cache->compaction_sma = compaction_bw->sum / compaction_bw->count;

	SPDK_NOTICELOG("[WZC_CMP_ED]tt_cmp_blks: %lu, chk->seq_id: %lu, cmp_blks: %u, valid_blks: %lu, cmp_long: %lu, cmp_bw:%.2f\n",
			  nv_cache->compaction_read_blocks, chunk->md->seq_id, chunk->md->blocks_compacted, 
			  chunk->compact_valid_blocks, chunk->compaction_length_tsc, nv_cache->compaction_sma);
	SPDK_NOTICELOG("[WZC_CMP_ED]chk_seq_id: %lu, chk_io_cnt: %lu, cmp_long: %lu, st_time: %lu, invalid_time: %lu, read_valid_time: %lu, incosis_time: %lu, write_valid_time: %lu\n",
			  chunk->md->seq_id, chunk->io_cnt, chunk->compaction_length_tsc, chunk->cmp_st_time, chunk->cmp_invalid_time,
			  chunk->cmp_read_valid_time, chunk->cmp_inconsistent_time, chunk->cmp_write_valid_time);

	chunk->compaction_length_tsc = 0;
	chunk->compact_valid_blocks = 0;
	chunk->io_cnt = 0;
}

static void
chunk_compaction_advance(struct ftl_nv_cache_chunk *chunk, uint64_t num_blocks)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	uint64_t tsc = spdk_thread_get_last_tsc(spdk_get_thread());

	// 1.增加compaction的持续时间
	//   最后算得compaction的时间包括各种函数调用，回调，数据读取的时间
	chunk->compaction_length_tsc += tsc - chunk->compaction_start_tsc;
	chunk->cmp_tmp_time = tsc - chunk->compaction_start_tsc;
	chunk->compaction_start_tsc = tsc;

	// 1.1 这里的blocks_compacted并不是真正需要读取的block数，而是compact过程中已经处理的block数
	//     blocks_compacted = (valid + invalid) != valid
	//     用于做下面的阈值做退出判断
	chunk->md->blocks_compacted += num_blocks;


	// 2.判断chunk里用户写的block是否等于compacted处理block
	if (!is_chunk_compacted(chunk)) {
		return;
	}

	/* Remove chunk from compacted list */
	// 3.将chunk从compacted list中移除
	TAILQ_REMOVE(&nv_cache->chunk_comp_list, chunk, entry);
	nv_cache->chunk_comp_count--;

	// 4.统计compact的带宽
	compaction_stats_update(chunk);

	// 5.将chunk的元数据清空,然后放到needs_free_persist_list
	ftl_chunk_free(chunk);
}

static bool
is_compaction_required(struct ftl_nv_cache *nv_cache)
{
	uint64_t full;

	if (spdk_unlikely(nv_cache->halt)) {
		return false;
	}

	// 满的chunk数量 = full - 正在compaction的chunk数量
	full = nv_cache->chunk_full_count - nv_cache->compaction_active_count;
	if (full >= nv_cache->chunk_compaction_threshold) {
		return true;
	}

	return false;
}

static void compaction_process_finish_read(struct ftl_nv_cache_compactor *compactor);
static void compaction_process_pin_lba(struct ftl_nv_cache_compactor *comp);

static void
_compaction_process_pin_lba(void *_comp)
{
	struct ftl_nv_cache_compactor *comp = _comp;

	compaction_process_pin_lba(comp);
}

static void
compaction_process_pin_lba_cb(struct spdk_ftl_dev *dev, int status, struct ftl_l2p_pin_ctx *pin_ctx)
{
	struct ftl_nv_cache_compactor *comp = pin_ctx->cb_ctx;
	struct ftl_rq *rq = comp->rd;

	if (status) {
		rq->iter.status = status;
		pin_ctx->lba = FTL_LBA_INVALID;
	}

	if (--rq->iter.remaining == 0) {
		if (rq->iter.status) {
			/* unpin and try again */
			ftl_rq_unpin(rq);
			spdk_thread_send_msg(spdk_get_thread(), _compaction_process_pin_lba, comp);
			return;
		}

		compaction_process_finish_read(comp);
	}
}

static void
compaction_process_pin_lba(struct ftl_nv_cache_compactor *comp)
{
	union ftl_md_vss *md;
	struct ftl_nv_cache_chunk *chunk = comp->rd->owner.priv;
	struct spdk_ftl_dev *dev = comp->rd->dev;
	uint64_t i;
	uint32_t count = comp->rd->iter.count;
	struct ftl_rq_entry *entry;
	struct ftl_l2p_pin_ctx *pin_ctx;

	assert(comp->rd->iter.idx == 0);
	comp->rd->iter.remaining = count;
	comp->rd->iter.status = 0;

	for (i = 0; i < count; i++) {
		entry = &comp->rd->entries[i];
		pin_ctx = &entry->l2p_pin_ctx;
		md = entry->io_md;
		if (md->nv_cache.lba == FTL_LBA_INVALID || md->nv_cache.seq_id != chunk->md->seq_id) {
			ftl_l2p_pin_skip(dev, compaction_process_pin_lba_cb, comp, pin_ctx);
		} else {
			ftl_l2p_pin(dev, md->nv_cache.lba, 1, compaction_process_pin_lba_cb, comp, pin_ctx);
		}
	}
}

static int compaction_submit_read(struct ftl_nv_cache_compactor *compactor, ftl_addr addr,
				  uint64_t num_blocks);

static void
compaction_retry_read(void *_compactor)
{
	struct ftl_nv_cache_compactor *compactor = _compactor;
	struct ftl_rq *rq = compactor->rd;
	struct spdk_bdev *bdev;
	int ret;

	ret = compaction_submit_read(compactor, rq->io.addr, rq->iter.count);

	if (spdk_likely(!ret)) {
		return;
	}

	if (ret == -ENOMEM) {
		bdev = spdk_bdev_desc_get_bdev(compactor->nv_cache->bdev_desc);
		compactor->bdev_io_wait.bdev = bdev;
		compactor->bdev_io_wait.cb_fn = compaction_retry_read;
		compactor->bdev_io_wait.cb_arg = compactor;
		spdk_bdev_queue_io_wait(bdev, compactor->nv_cache->cache_ioch, &compactor->bdev_io_wait);
	} else {
		ftl_abort();
	}
}

static void
compaction_process_read_cb(struct spdk_bdev_io *bdev_io,
			   bool success, void *cb_arg)
{
	struct ftl_nv_cache_compactor *compactor = cb_arg;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(compactor->nv_cache, struct spdk_ftl_dev, nv_cache);

	ftl_stats_bdev_io_completed(dev, FTL_STATS_TYPE_CMP, bdev_io);

	spdk_bdev_free_io(bdev_io);

	if (!success) {
		/* retry */
		spdk_thread_send_msg(spdk_get_thread(), compaction_retry_read, compactor);
		return;
	}

	compaction_process_pin_lba(compactor);
}

static bool
is_chunk_to_read(struct ftl_nv_cache_chunk *chunk)
{
	assert(chunk->md->blocks_written != 0);

	if (chunk_user_blocks_written(chunk) == chunk->md->read_pointer) {
		return false;
	}

	return true;
}

static struct ftl_nv_cache_chunk *
get_chunk_for_compaction(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_chunk *chunk = NULL;

	// 1.从chunk_comp_list中获取chunk
	if (!TAILQ_EMPTY(&nv_cache->chunk_comp_list)) {
		chunk = TAILQ_FIRST(&nv_cache->chunk_comp_list);
		// 1.1.如果chunk的read_pointer != 用于写的blocks_written,则该chunk还有有效数据需要读取
		if (is_chunk_to_read(chunk)) {
			return chunk;
		}
	}

	// 2.从chunk_full_list中获取chunk
	if (!TAILQ_EMPTY(&nv_cache->chunk_full_list)) {
		chunk = TAILQ_FIRST(&nv_cache->chunk_full_list);
		TAILQ_REMOVE(&nv_cache->chunk_full_list, chunk, entry);

		assert(chunk->md->write_pointer);
	} else {
		return NULL;
	}

	// 2.1 将从chunk_full_list中获取chunk的放到从chunk_comp_list中获取chunk中
	if (spdk_likely(chunk)) {
		assert(chunk->md->write_pointer != 0);
		TAILQ_INSERT_HEAD(&nv_cache->chunk_comp_list, chunk, entry);
		nv_cache->chunk_comp_count++;
	}

	return chunk;
}

static uint64_t
chunk_blocks_to_read(struct ftl_nv_cache_chunk *chunk)
{
	uint64_t blocks_written;
	uint64_t blocks_to_read;

	assert(chunk->md->blocks_written >= chunk->md->blocks_skipped);
	blocks_written = chunk_user_blocks_written(chunk);

	assert(blocks_written >= chunk->md->read_pointer);
	blocks_to_read = blocks_written - chunk->md->read_pointer;

	return blocks_to_read;
}

static void
compactor_deactivate(struct ftl_nv_cache_compactor *compactor)
{
	struct ftl_nv_cache *nv_cache = compactor->nv_cache;

	nv_cache->compaction_active_count--;
	TAILQ_INSERT_TAIL(&nv_cache->compactor_list, compactor, entry);
}

static int
compaction_submit_read(struct ftl_nv_cache_compactor *compactor, ftl_addr addr,
		       uint64_t num_blocks)
{
	struct ftl_nv_cache *nv_cache = compactor->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);

	return ftl_nv_cache_bdev_readv_blocks_with_md(dev, nv_cache->bdev_desc,
			nv_cache->cache_ioch,
			compactor->rd->io_vec, num_blocks,
			compactor->rd->io_md,
			ftl_addr_to_nvc_offset(dev, addr), num_blocks,
			compaction_process_read_cb,
			compactor);
}

static void
compaction_process_pad(struct ftl_nv_cache_compactor *compactor)
{
	struct ftl_rq *wr = compactor->wr;
	const uint64_t num_entries = wr->num_blocks;
	struct ftl_rq_entry *iter;

	iter = &wr->entries[wr->iter.idx];

	while (wr->iter.idx < num_entries) {
		iter->addr = FTL_ADDR_INVALID;
		iter->owner.priv = NULL;
		iter->lba = FTL_LBA_INVALID;
		iter->seq_id = 0;
		iter++;
		wr->iter.idx++;
	}
}

static void
compaction_process(struct ftl_nv_cache_compactor *compactor)
{
	struct ftl_nv_cache *nv_cache = compactor->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache,
				   struct spdk_ftl_dev, nv_cache);
	struct ftl_nv_cache_chunk *chunk;
	uint64_t to_read, addr, begin, end, offset;
	int rc;

	/* Check if all read blocks done */
	// 1.先检查这个 compactor
	assert(compactor->rd->iter.idx <= compactor->rd->iter.count);
	if (compactor->rd->iter.idx < compactor->rd->iter.count) {
		// 1.1 如果compactor没有读完，则继续读
		compaction_process_finish_read(compactor);
		return;
	}

	/*
	 * Get currently handled chunk
	 */
	// 2.获取当前要处理的chunk
	chunk = get_chunk_for_compaction(nv_cache);
	if (!chunk) {
		/* No chunks to compact, pad this request */
		// 2.1 如果没有要处理的chunk, 填充空的compactor->wr ftl_rq 插入到base-ssd writer_user的ftl_rq队列中 
		compaction_process_pad(compactor);
		ftl_writer_queue_rq(&dev->writer_user, compactor->wr);
		return;
	}

	// 统计chunk这次compaction的开始时间 (最多256 blks)
	// 一开始相当于等于 0
	chunk->compaction_start_tsc = spdk_thread_get_last_tsc(spdk_get_thread());
	chunk->cmp_st_time = chunk->compaction_start_tsc;

	/*
	 * Get range of blocks to read
	 */
	// 3.获取chunk要读取的block的数量
	// to_read = chunk->user_write_blocks - chunk->md->read_pointer
	to_read = chunk_blocks_to_read(chunk);
	assert(to_read > 0);

	// addr = chunk->offset + chunk->md->read_pointer + dev->layout.base.total_blocks
	// begin (从valid_map中找到第一个有效bit)
	addr = ftl_addr_from_nvc_offset(dev, chunk->offset + chunk->md->read_pointer);
	begin = ftl_bitmap_find_first_set(dev->valid_map, addr, addr + to_read);
	// to_read, begin - addr -> offset 
	if (begin != UINT64_MAX) {
		// 不等于0说明有无效数据
		offset = spdk_min(begin - addr, to_read);
	} else {
		offset = to_read;
	}

	// 3.0 off != 0, 说明有无效数据
	if (offset) {
		chunk->md->read_pointer += offset;
		// 3.1 num_compact = offset
		// 如果cmp_blks到末尾，则将chunk的元数据清空,将chunk从chunk_comp_list移出然后放到needs_free_persist_list, 同时统计compact的带宽信息
		// [trace chk_cmp_advance 1]: advance invalid_data 
		chunk_compaction_advance(chunk, offset);
		chunk->cmp_invalid_time += chunk->cmp_tmp_time;
		chunk->cmp_tmp_time = 0;

		to_read -= offset;
		if (!to_read) {
			// 3.2 如果to_read == 0,则compactor结束
			compactor_deactivate(compactor);
			return;
		}
	}

	// end (从valid_map中找到第一个无效的bit)
	// begin -> addr, (end - begin) -> to_read
	end = ftl_bitmap_find_first_clear(dev->valid_map, begin + 1, begin + to_read);
	if (end != UINT64_MAX) {
		to_read = end - begin;
	}
	addr = begin;
	to_read = spdk_min(to_read, compactor->rd->num_blocks);

	/* Read data and metadata from NV cache */
	// 4.从nv_cache的addr位置读取to_read个block的数据放到compactor->rd中
	// 4.1 之后调用compaction_process_read_cb回调函数->同时调用compaction_process_pin_lba
	// 4.2 之后调用compaction_process_pin_lba_cb回调函数->同时调用compaction_process_finish_read
	// 	   在compaction_process_finish_read函数中将 compactor->rd中的数据拷贝到compactor->wr中,
	//     然后将compactor->wr请求插入到base-ssd writer_user的ftl_rq队列中

	SPDK_NOTICELOG("[WZC_CMP]cmp_chk_seq_id: %lu, chk_oft: %lu, chk_rd_pointer: %u\n",
		chunk->md->seq_id, chunk->offset,  chunk->md->read_pointer);
	SPDK_NOTICELOG("[WZC_CMP]cmp_chk_read_blks: %lu, chk_begin_lba: %lu, chk_end_lba: %lu\n",
		to_read, begin - dev->layout.base.total_blocks - chunk->offset, end - dev->layout.base.total_blocks - chunk->offset);
	rc = compaction_submit_read(compactor, addr, to_read);
	if (spdk_unlikely(rc)) {
		/* An error occurred, inactivate this compactor, it will retry
		 * in next iteration
		 */
		// 4.3 如果读失败，则直接compact结束
		compactor_deactivate(compactor);
		return;
	}
	chunk->io_cnt += 1;
	SPDK_NOTICELOG("[WZC_CMP]cmp_chk_seq_id: %lu, cmp_st: %lu, cmp_tmp_read: %lu\n",
		chunk->md->seq_id, chunk->cmp_st_time, chunk->cmp_tmp_read_time);

	/* IO has started, initialize compaction */
	// 5.设置compactor->rd用于回调处理
	compactor->rd->owner.priv = chunk;
	compactor->rd->iter.idx = 0;
	compactor->rd->iter.count = to_read;
	compactor->rd->io.addr = addr;

	/* Move read pointer in the chunk */
	chunk->md->read_pointer += to_read;

	// [wzc_cmp]
	chunk->compact_valid_blocks += to_read;
	nv_cache->compaction_read_blocks += to_read;
}

static void
compaction_process_start(struct ftl_nv_cache_compactor *compactor)
{
	compactor->nv_cache->compaction_active_count++;
	compaction_process(compactor);
}

static void
compaction_process_ftl_done(struct ftl_rq *rq)
{
	struct spdk_ftl_dev *dev = rq->dev;
	struct ftl_nv_cache_compactor *compactor = rq->owner.priv;
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;
	struct ftl_band *band = rq->io.band;
	struct ftl_rq_entry *entry;
	ftl_addr addr;
	uint64_t i;

	if (spdk_unlikely(false == rq->success)) {
		/* IO error retry writing */
#ifdef SPDK_FTL_RETRY_ON_ERROR
		ftl_writer_queue_rq(&dev->writer_user, rq);
		return;
#else
		ftl_abort();
#endif
	}

	/* Update L2P table */
	addr = rq->io.addr;
	for (i = 0, entry = rq->entries; i < rq->num_blocks; i++, entry++) {
		struct ftl_nv_cache_chunk *chunk = entry->owner.priv;

		if (entry->lba == FTL_LBA_INVALID) {
			assert(entry->addr == FTL_ADDR_INVALID);
			addr = ftl_band_next_addr(band, addr, 1);
			continue;
		}

		ftl_l2p_update_base(dev, entry->lba, addr, entry->addr);
		ftl_l2p_unpin(dev, entry->lba, 1);
		// 在 compactor->wr 的回调用中更新了 chunk->compact_blks 数
		// 那这里是相当于与数据写入了base-ssd 也算在 chunk->cmp_long 的时间里
		// [thrace_chk_advance 3]: advance valid_data
		chunk_compaction_advance(chunk, 1);
		chunk->cmp_write_valid_time += chunk->cmp_tmp_time;
		chunk->cmp_tmp_time = 0;
		addr = ftl_band_next_addr(band, addr, 1);
	}

	compactor->wr->iter.idx = 0;

	if (is_compaction_required(nv_cache)) {
		compaction_process(compactor);
	} else {
		compactor_deactivate(compactor);
	}
}

static void
compaction_process_finish_read(struct ftl_nv_cache_compactor *compactor)
{
	struct ftl_rq *wr = compactor->wr;
	struct ftl_rq *rd = compactor->rd;
	ftl_addr cache_addr = rd->io.addr;
	struct ftl_nv_cache_chunk *chunk = rd->owner.priv;
	struct spdk_ftl_dev *dev;
	struct ftl_rq_entry *iter;
	union ftl_md_vss *md;
	ftl_addr current_addr;
	const uint64_t num_entries = wr->num_blocks;
	uint64_t tsc = spdk_thread_get_last_tsc(spdk_get_thread());

	// 1.再次更新compaction的持续时间
	//   到这里增加的时间是数据读取的时间(主要)，各种函数回调、调用的时间
	chunk->compaction_length_tsc += tsc - chunk->compaction_start_tsc;
	chunk->cmp_tmp_time = tsc - chunk->compaction_start_tsc;
	chunk->compaction_start_tsc = tsc;
	chunk->cmp_tmp_read_time = chunk->cmp_tmp_time;
	chunk->cmp_read_valid_time += chunk->cmp_tmp_time;
	chunk->cmp_tmp_time = 0;

	dev = SPDK_CONTAINEROF(compactor->nv_cache,
			       struct spdk_ftl_dev, nv_cache);

	assert(wr->iter.idx < num_entries);
	assert(rd->iter.idx < rd->iter.count);

	cache_addr += rd->iter.idx;
	iter = &wr->entries[wr->iter.idx];

	// 2.循环处理，将compactor->rd中的数据拷贝到compactor->wr中
	// [trace_chk_advance 2]: advance invalid_data | inconsistent_data
	uint64_t st = spdk_thread_get_last_tsc(spdk_get_thread());	
	while (wr->iter.idx < num_entries && rd->iter.idx < rd->iter.count) {
		/* Get metadata */
		md = rd->entries[rd->iter.idx].io_md;
		// 无效数据？
		if (md->nv_cache.lba == FTL_LBA_INVALID || md->nv_cache.seq_id != chunk->md->seq_id) {
			cache_addr++;
			rd->iter.idx++;
			chunk_compaction_advance(chunk, 1);
			continue;
		}

		current_addr = ftl_l2p_get(dev, md->nv_cache.lba);
		if (current_addr == cache_addr) {
			/* Swap payload */
			// 2.1 将compactor->rd中的数据拷贝到compactor->wr中
			ftl_rq_swap_payload(wr, wr->iter.idx, rd, rd->iter.idx);

			/*
			 * Address still the same, we may continue to compact it
			 * back to  FTL, set valid number of entries within
			 * this batch
			 */
			iter->addr = current_addr;
			iter->owner.priv = chunk;
			iter->lba = md->nv_cache.lba;
			iter->seq_id = chunk->md->seq_id;

			/* Advance within batch */
			iter++;
			wr->iter.idx++;
		} else {
			/* This address already invalidated, just omit this block */
			chunk_compaction_advance(chunk, 1);
			ftl_l2p_unpin(dev, md->nv_cache.lba, 1);
		}

		/* Advance within reader */
		rd->iter.idx++;
		cache_addr++;
	}
	uint64_t ed = spdk_thread_get_last_tsc(spdk_get_thread());	
	chunk->cmp_inconsistent_time += ed - st;

	if (num_entries == wr->iter.idx) {
		/*
		 * Request contains data to be placed on FTL, compact it
		 */
		// 3.将compactor->wr请求写入到 base-SSD 的 writer_user 的 ftl_rq 队列中
		ftl_writer_queue_rq(&dev->writer_user, wr);
	} else {
		// 0.继续compact
		if (is_compaction_required(compactor->nv_cache)) {
			compaction_process(compactor);
		} else {
			// 出错，comcactor结束, 把compactor放到compactor_list中
			compactor_deactivate(compactor);
		}
	}
}

static void
compactor_free(struct spdk_ftl_dev *dev, struct ftl_nv_cache_compactor *compactor)
{
	if (!compactor) {
		return;
	}

	ftl_rq_del(compactor->wr);
	ftl_rq_del(compactor->rd);
	free(compactor);
}

static struct ftl_nv_cache_compactor *
compactor_alloc(struct spdk_ftl_dev *dev)
{
	struct ftl_nv_cache_compactor *compactor;

	compactor = calloc(1, sizeof(*compactor));
	if (!compactor) {
		goto error;
	}

	/* Allocate help request for writing */
	compactor->wr = ftl_rq_new(dev, dev->md_size);
	if (!compactor->wr) {
		goto error;
	}

	/* Allocate help request for reading */
	compactor->rd = ftl_rq_new(dev, dev->nv_cache.md_size);
	if (!compactor->rd) {
		goto error;
	}

	compactor->nv_cache = &dev->nv_cache;
	compactor->wr->owner.priv = compactor;
	// 设置compactor->wr的回调函数
	compactor->wr->owner.cb = compaction_process_ftl_done;
	compactor->wr->owner.compaction = true;

	return compactor;

error:
	compactor_free(dev, compactor);
	return NULL;
}

static void
ftl_nv_cache_submit_cb_done(struct ftl_io *io)
{
	struct ftl_nv_cache *nv_cache = &io->dev->nv_cache;

	// 推进chunk已经写的block数
	chunk_advance_blocks(nv_cache, io->nv_cache_chunk, io->num_blocks);
	io->nv_cache_chunk = NULL;

	ftl_mempool_put(nv_cache->md_pool, io->md);
	ftl_io_complete(io);
}

static void
ftl_nv_cache_l2p_update(struct ftl_io *io)
{
	struct spdk_ftl_dev *dev = io->dev;
	ftl_addr next_addr = io->addr;
	size_t i;

	for (i = 0; i < io->num_blocks; ++i, ++next_addr) {
		ftl_l2p_update_cache(dev, ftl_io_get_lba(io, i), next_addr, io->map[i]);
	}

	ftl_l2p_unpin(dev, io->lba, io->num_blocks);
	ftl_nv_cache_submit_cb_done(io);
}

static void
ftl_nv_cache_submit_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct ftl_io *io = cb_arg;

	ftl_stats_bdev_io_completed(io->dev, FTL_STATS_TYPE_USER, bdev_io);

	spdk_bdev_free_io(bdev_io);

	if (spdk_unlikely(!success)) {
		FTL_ERRLOG(io->dev, "Non-volatile cache write failed at %"PRIx64"\n",
			   io->addr);
		io->status = -EIO;
		ftl_nv_cache_submit_cb_done(io);
	} else {
		ftl_nv_cache_l2p_update(io);
	}
}

static void
nv_cache_write(void *_io)
{
	struct ftl_io *io = _io;
	struct spdk_ftl_dev *dev = io->dev;
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;
	int rc;

	rc = ftl_nv_cache_bdev_writev_blocks_with_md(dev,
			nv_cache->bdev_desc, nv_cache->cache_ioch,
			io->iov, io->iov_cnt, io->md,
			ftl_addr_to_nvc_offset(dev, io->addr), io->num_blocks,
			ftl_nv_cache_submit_cb, io);
	if (spdk_unlikely(rc)) {
		if (rc == -ENOMEM) {
			struct spdk_bdev *bdev = spdk_bdev_desc_get_bdev(nv_cache->bdev_desc);
			io->bdev_io_wait.bdev = bdev;
			io->bdev_io_wait.cb_fn = nv_cache_write;
			io->bdev_io_wait.cb_arg = io;
			spdk_bdev_queue_io_wait(bdev, nv_cache->cache_ioch, &io->bdev_io_wait);
		} else {
			ftl_abort();
		}
	}
}

static void
ftl_nv_cache_pin_cb(struct spdk_ftl_dev *dev, int status, struct ftl_l2p_pin_ctx *pin_ctx)
{
	struct ftl_io *io = pin_ctx->cb_ctx;
	size_t i;

	if (spdk_unlikely(status != 0)) {
		/* Retry on the internal L2P fault */
		FTL_ERRLOG(dev, "Cannot PIN LBA for NV cache write failed at %"PRIx64"\n",
			   io->addr);
		io->status = -EAGAIN;
		ftl_nv_cache_submit_cb_done(io);
		return;
	}

	/* Remember previous l2p mapping to resolve conflicts in case of outstanding write-after-write */
	for (i = 0; i < io->num_blocks; ++i) {
		io->map[i] = ftl_l2p_get(dev, ftl_io_get_lba(io, i));
	}

	assert(io->iov_pos == 0);

	ftl_trace_submission(io->dev, io, io->addr, io->num_blocks);

	// 这里真正将数据写下去
	// 包括 io的数据和metadata(4KB data + 64B VSS metadata)
	nv_cache_write(io);
}

bool
ftl_nv_cache_write(struct ftl_io *io)
{
	struct spdk_ftl_dev *dev = io->dev;
	uint64_t cache_offset;

	io->md = ftl_mempool_get(dev->nv_cache.md_pool);
	if (spdk_unlikely(!io->md)) {
		return false;
	}

	/* Reserve area on the write buffer cache */
	// 1.获取nv_cache的当前写入的chunk的lba地址
	cache_offset = ftl_nv_cache_get_wr_buffer(&dev->nv_cache, io);
	if (cache_offset == FTL_LBA_INVALID) {
		/* No free space in NV cache, resubmit request */
		ftl_mempool_put(dev->nv_cache.md_pool, io->md);
		return false;
	}
	// 2.chunk's lba + base'blocks
	io->addr = ftl_addr_from_nvc_offset(dev, cache_offset);
	io->nv_cache_chunk = dev->nv_cache.chunk_current;

	ftl_nv_cache_fill_md(io);
	// ftl_l2p_pin -> ftl_nv_cache_pin_cb -> nv_cache_write -> ftl_nv_cache_submit_cb -> ftl_nv_cache_l2p_update -> ftl_nv_cache_submit_cb_done -> ftl_io_complete -> ftl_io_cb -> spdk_ring_enqueue(CQ)
	ftl_l2p_pin(io->dev, io->lba, io->num_blocks,
		    ftl_nv_cache_pin_cb, io,   // 回调参数为io
		    &io->l2p_pin_ctx);

	// 3.[WZC]static for throttle
	dev->nv_cache.throttle.blocks_submitted += io->num_blocks;

	// static
	if (dev->st == 0) {
		dev->st = 1;
		dev->start_write_time = spdk_thread_get_last_tsc(spdk_get_thread()) / spdk_get_ticks_hz();
		SPDK_NOTICELOG("[WZC_ST]write start, start_write_time: %lus\n", dev->start_write_time);
	}
	return true;
}

int
ftl_nv_cache_read(struct ftl_io *io, ftl_addr addr, uint32_t num_blocks,
		  spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	int rc;
	struct ftl_nv_cache *nv_cache = &io->dev->nv_cache;

	assert(ftl_addr_in_nvc(io->dev, addr));

	rc = ftl_nv_cache_bdev_read_blocks_with_md(io->dev, nv_cache->bdev_desc, nv_cache->cache_ioch,
			ftl_io_iovec_addr(io), NULL, ftl_addr_to_nvc_offset(io->dev, addr), // nv_cache 盘的偏移块得用 addr - base'tt blocks
			num_blocks, cb, cb_arg);

	return rc;
}

bool
ftl_nv_cache_is_halted(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_compactor *compactor;

	if (nv_cache->compaction_active_count) {
		return false;
	}

	TAILQ_FOREACH(compactor, &nv_cache->compactor_list, entry) {
		if (compactor->rd->iter.idx != 0 || compactor->wr->iter.idx != 0) {
			return false;
		}
	}

	if (nv_cache->chunk_open_count > 0) {
		return false;
	}

	return true;
}

static void
ftl_nv_cache_compaction_reset(struct ftl_nv_cache_compactor *compactor)
{
	struct ftl_rq *rd = compactor->rd;
	struct ftl_rq *wr = compactor->wr;
	uint64_t lba;
	uint64_t i;

	for (i = rd->iter.idx; i < rd->iter.count; i++) {
		lba = ((union ftl_md_vss *)rd->entries[i].io_md)->nv_cache.lba;
		if (lba != FTL_LBA_INVALID) {
			ftl_l2p_unpin(rd->dev, lba, 1);
		}
	}

	rd->iter.idx = 0;
	rd->iter.count = 0;

	for (i = 0; i < wr->iter.idx; i++) {
		lba = wr->entries[i].lba;
		assert(lba != FTL_LBA_INVALID);
		ftl_l2p_unpin(wr->dev, lba, 1);
	}

	wr->iter.idx = 0;
}

void
ftl_chunk_map_set_lba(struct ftl_nv_cache_chunk *chunk,
		      uint64_t offset, uint64_t lba)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	ftl_lba_store(dev, p2l_map->chunk_map, offset, lba);
}

uint64_t
ftl_chunk_map_get_lba(struct ftl_nv_cache_chunk *chunk, uint64_t offset)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	return ftl_lba_load(dev, p2l_map->chunk_map, offset);
}

static void
ftl_chunk_set_addr(struct ftl_nv_cache_chunk *chunk, uint64_t lba, ftl_addr addr)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	uint64_t cache_offset = ftl_addr_to_nvc_offset(dev, addr);
	uint64_t offset;

	offset = (cache_offset - chunk->offset) % chunk->nv_cache->chunk_blocks;
	ftl_chunk_map_set_lba(chunk, offset, lba);
}

struct ftl_nv_cache_chunk *
ftl_nv_cache_get_chunk_from_addr(struct spdk_ftl_dev *dev, ftl_addr addr)
{
	struct ftl_nv_cache_chunk *chunk = dev->nv_cache.chunks;
	uint64_t chunk_idx;
	uint64_t cache_offset = ftl_addr_to_nvc_offset(dev, addr);

	assert(chunk != NULL);
	chunk_idx = (cache_offset - chunk->offset) / chunk->nv_cache->chunk_blocks;
	chunk += chunk_idx;

	return chunk;
}

void
ftl_nv_cache_set_addr(struct spdk_ftl_dev *dev, uint64_t lba, ftl_addr addr)
{
	struct ftl_nv_cache_chunk *chunk;

	chunk = ftl_nv_cache_get_chunk_from_addr(dev, addr);

	assert(lba != FTL_LBA_INVALID);

	ftl_chunk_set_addr(chunk, lba, addr);
	ftl_bitmap_set(dev->valid_map, addr);
}

static void
ftl_nv_cache_throttle_update(struct ftl_nv_cache *nv_cache)
{
	double err;
	double modifier;

	err = ((double)nv_cache->chunk_free_count - nv_cache->chunk_free_target) / nv_cache->chunk_count;
	modifier = FTL_NV_CACHE_THROTTLE_MODIFIER_KP * err;

	if (modifier < FTL_NV_CACHE_THROTTLE_MODIFIER_MIN) {
		modifier = FTL_NV_CACHE_THROTTLE_MODIFIER_MIN;
	} else if (modifier > FTL_NV_CACHE_THROTTLE_MODIFIER_MAX) {
		modifier = FTL_NV_CACHE_THROTTLE_MODIFIER_MAX;
	}

	// 1.在这里设置 throttle.blocks_submitted_limit 阈值
	if (spdk_unlikely(nv_cache->compaction_sma == 0 || nv_cache->compaction_active_count == 0)) {
		nv_cache->throttle.blocks_submitted_limit = UINT64_MAX;
	} else {
		// 1.1 根据compaction_sma, throttle.interval_tsc, 
		//        chunk_free_count, chunk_free_target, chunk_count -> err
		//        FTL_NV_CACHE_THROTTLE_MODIFIER_KP(20) * err -> modifier
		//        最后 blocks_submitted_limit = blocks_per_interval * (1.0 + modifier)
		//        所以块提交数限制是由上面这些因素来决定,其中固定的值有
		//        	throttle.interval_tsc, chunk_free_target, chunk_count
		//        动态变化的值有:
		//          compaction_sma, chunk_free_count -> err -> modifier (其趋势是受chunk_free_cnt影响)
		double blocks_per_interval = nv_cache->compaction_sma * nv_cache->throttle.interval_tsc /
					     FTL_BLOCK_SIZE;
		nv_cache->throttle.blocks_submitted_limit = blocks_per_interval * (1.0 + modifier);
		
		// static
		SPDK_NOTICELOG("[WZC_thr]throttle_update, throttle_interval: %lu, ck_free_tar: %lu, ck_free_cnt: %lu\n", 
						nv_cache->throttle.interval_tsc, nv_cache->chunk_free_target, nv_cache->chunk_free_count);
		SPDK_NOTICELOG("[WZC_thr]throttle_update, err: %.2f, modifier: %.2f, cmp_sma: %.2f, blks_per_interval: %.2f, blks_s_limits: %lu\n", 
						err, modifier, nv_cache->compaction_sma, blocks_per_interval, nv_cache->throttle.blocks_submitted_limit);
		SPDK_NOTICELOG("[WZC_thr]throttle_static, thro_cpu_cnt: %lu, interval_throttle_cnt: %lu\n", 
						nv_cache->throttle_cpu_cnt, nv_cache->interval_throttle_cnt);
	}
}

static void
ftl_nv_cache_process_throttle(struct ftl_nv_cache *nv_cache)
{
	uint64_t tsc = spdk_thread_get_last_tsc(spdk_get_thread());

	if (spdk_unlikely(!nv_cache->throttle.start_tsc)) {
		nv_cache->throttle.start_tsc = tsc;
		// 1. 更新throttle统计信息的条件是当前时间与上一次更新时间大于throttle
	} else if (tsc - nv_cache->throttle.start_tsc >= nv_cache->throttle.interval_tsc) {
		ftl_nv_cache_throttle_update(nv_cache);
		nv_cache->throttle.start_tsc = tsc;
		nv_cache->throttle.blocks_submitted = 0;

		nv_cache->throttle_cpu_cnt += 1;
		nv_cache->interval_throttle_cnt = 0;
	}
}

static void ftl_chunk_open(struct ftl_nv_cache_chunk *chunk);

void
ftl_nv_cache_process(struct spdk_ftl_dev *dev)
{
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;

	assert(dev->nv_cache.bdev_desc);

	// 1.如果打开chunk的数量小于最大打开chunk数量(2)，且没有halt，且free list不为空
	// 则从free_list中取出一个chunk，打开这个chunk,同时放入open_list中,
	// 在ftl_chunk_open中会将chunk的p2l_map->chunk_dma_md 元数据持久化
	// 在chunk_open_cb 里将 chunk 的状态设置为 open
	if (nv_cache->chunk_open_count < FTL_MAX_OPEN_CHUNKS && spdk_likely(!nv_cache->halt) &&
	    !TAILQ_EMPTY(&nv_cache->chunk_free_list)) {
		// 1.1 从chunk_free_list中获取一个chunk, 放入chunk_open_list中, 
		//     然后将chunk的状态设置为open
		struct ftl_nv_cache_chunk *chunk = TAILQ_FIRST(&nv_cache->chunk_free_list);
		TAILQ_REMOVE(&nv_cache->chunk_free_list, chunk, entry);
		TAILQ_INSERT_TAIL(&nv_cache->chunk_open_list, chunk, entry);
		nv_cache->chunk_free_count--;
		chunk->md->seq_id = ftl_get_next_seq_id(dev);
		ftl_chunk_open(chunk);
	}

	// 2.判断是否需要compaction
	// 如果full_chunk数量大于compaction的阈值，且compactor_list(每个entry包括wr/rd的ftl_rq)不为空
	if (is_compaction_required(nv_cache) && !TAILQ_EMPTY(&nv_cache->compactor_list)) {
		if (dev->st == 1) {
			dev->st = 2;
			nv_cache->compaction_start_time = spdk_thread_get_last_tsc(spdk_get_thread())  / spdk_get_ticks_hz();
			SPDK_NOTICELOG("[WZC_ST]compaction start, compact_start_time: %lus\n", nv_cache->compaction_start_time);
		}
		// 2.1 从 compactor_list 获取 compactor
		//     这里定义了 16 个 compactor
		struct ftl_nv_cache_compactor *comp =
			TAILQ_FIRST(&nv_cache->compactor_list);

		TAILQ_REMOVE(&nv_cache->compactor_list, comp, entry);

		// 2.2 开始进行compact
		compaction_process_start(comp);
	}

	// 3.处理 needs_free_persist_list 的 chunk
	// chunk 在compact过程中变化
	// chunk_full_list -> chunk_comp_list -> needs_free_persist_list 
	// 在 ftl_chunk_persist_free_state 之后的变化
	// needs_free_persist_list -> chunk_free_list
	ftl_chunk_persist_free_state(nv_cache);

	// 4.如果halt了，重置所有的compactor压缩器
	if (spdk_unlikely(nv_cache->halt)) {
		struct ftl_nv_cache_compactor *compactor;

		TAILQ_FOREACH(compactor, &nv_cache->compactor_list, entry) {
			// 4.1 实际操作unpin compactor->rd/wr 的l2p
			ftl_nv_cache_compaction_reset(compactor);
		}
	}

	// 5.更新throttle统计信息，重置throttle.blocks_submitted
	ftl_nv_cache_process_throttle(nv_cache);
}

static bool
ftl_nv_cache_full(struct ftl_nv_cache *nv_cache)
{
	if (0 == nv_cache->chunk_open_count && NULL == nv_cache->chunk_current) {
		return true;
	} else {
		return false;
	}
}

bool
ftl_nv_cache_throttle(struct spdk_ftl_dev *dev)
{
	struct ftl_nv_cache *nv_cache = &dev->nv_cache;
	//return false;

	if (dev->nv_cache.throttle.blocks_submitted >= nv_cache->throttle.blocks_submitted_limit ||
	    ftl_nv_cache_full(nv_cache)) {
		nv_cache->trigger_throttle_cnt += 1;
		nv_cache->interval_throttle_cnt += 1;
		// SPDK_NOTICELOG("[WZC_TR]触发节流, throttle_cnt: %lu, blks_submit: %lu, blk_submit_limit: %lu, free_ck: %lu\n", 
		// 				nv_cache->trigger_throttle_cnt, nv_cache->throttle.blocks_submitted, nv_cache->throttle.blocks_submitted_limit, nv_cache->chunk_free_count);
		return true;
	}

	return false;
}

static void
chunk_free_p2l_map(struct ftl_nv_cache_chunk *chunk)
{

	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	ftl_mempool_put(nv_cache->p2l_pool, p2l_map->chunk_map);
	p2l_map->chunk_map = NULL;

	ftl_chunk_free_md_entry(chunk);
}

int
ftl_nv_cache_save_state(struct ftl_nv_cache *nv_cache)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_nv_cache_chunk *chunk;
	int status = 0;
	uint64_t i;

	assert(nv_cache->chunk_open_count == 0);

	if (nv_cache->compaction_active_count) {
		FTL_ERRLOG(dev, "Cannot save NV cache state, compaction in progress\n");
		return -EINVAL;
	}

	chunk = nv_cache->chunks;
	if (!chunk) {
		FTL_ERRLOG(dev, "Cannot save NV cache state, no NV cache metadata\n");
		return -ENOMEM;
	}

	for (i = 0; i < nv_cache->chunk_count; i++, chunk++) {
		nvc_validate_md(nv_cache, chunk->md);

		if (chunk->md->read_pointer)  {
			/* Only full chunks can be compacted */
			if (chunk->md->blocks_written != nv_cache->chunk_blocks) {
				assert(0);
				status = -EINVAL;
				break;
			}

			/*
			 * Chunk in the middle of compaction, start over after
			 * load
			 */
			chunk->md->read_pointer = chunk->md->blocks_compacted = 0;
		} else if (chunk->md->blocks_written == nv_cache->chunk_blocks) {
			/* Full chunk */
		} else if (0 == chunk->md->blocks_written) {
			/* Empty chunk */
		} else {
			assert(0);
			status = -EINVAL;
			break;
		}
	}

	if (status) {
		FTL_ERRLOG(dev, "Cannot save NV cache state, inconsistent NV cache"
			   "metadata\n");
	}

	return status;
}

static int
sort_chunks_cmp(const void *a, const void *b)
{
	struct ftl_nv_cache_chunk *a_chunk = *(struct ftl_nv_cache_chunk **)a;
	struct ftl_nv_cache_chunk *b_chunk = *(struct ftl_nv_cache_chunk **)b;

	return a_chunk->md->seq_id - b_chunk->md->seq_id;
}

static int
sort_chunks(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_chunk **chunks_list;
	struct ftl_nv_cache_chunk *chunk;
	uint32_t i;

	if (TAILQ_EMPTY(&nv_cache->chunk_full_list)) {
		return 0;
	}

	chunks_list = calloc(nv_cache->chunk_full_count,
			     sizeof(chunks_list[0]));
	if (!chunks_list) {
		return -ENOMEM;
	}

	i = 0;
	TAILQ_FOREACH(chunk, &nv_cache->chunk_full_list, entry) {
		chunks_list[i] = chunk;
		i++;
	}
	assert(i == nv_cache->chunk_full_count);

	qsort(chunks_list, nv_cache->chunk_full_count, sizeof(chunks_list[0]),
	      sort_chunks_cmp);

	TAILQ_INIT(&nv_cache->chunk_full_list);
	for (i = 0; i < nv_cache->chunk_full_count; i++) {
		chunk = chunks_list[i];
		TAILQ_INSERT_TAIL(&nv_cache->chunk_full_list, chunk, entry);
	}

	free(chunks_list);
	return 0;
}

static int
chunk_alloc_p2l_map(struct ftl_nv_cache_chunk *chunk)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	assert(p2l_map->ref_cnt == 0);
	assert(p2l_map->chunk_map == NULL);

	p2l_map->chunk_map = ftl_mempool_get(nv_cache->p2l_pool);

	if (!p2l_map->chunk_map) {
		return -ENOMEM;
	}

	if (ftl_chunk_alloc_md_entry(chunk)) {
		ftl_mempool_put(nv_cache->p2l_pool, p2l_map->chunk_map);
		p2l_map->chunk_map = NULL;
		return -ENOMEM;
	}

	/* Set the P2L to FTL_LBA_INVALID */
	memset(p2l_map->chunk_map, -1, FTL_BLOCK_SIZE * nv_cache->tail_md_chunk_blocks);

	return 0;
}

int
ftl_nv_cache_load_state(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_chunk *chunk;
	uint64_t chunks_number, offset, i;
	int status = 0;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);

	nv_cache->chunk_current = NULL;
	TAILQ_INIT(&nv_cache->chunk_free_list);
	TAILQ_INIT(&nv_cache->chunk_full_list);
	nv_cache->chunk_full_count = nv_cache->chunk_free_count = 0;

	assert(nv_cache->chunk_open_count == 0);
	offset = nvc_data_offset(nv_cache);
	chunk = nv_cache->chunks;
	if (!chunk) {
		FTL_ERRLOG(dev, "No NV cache metadata\n");
		return -1;
	}

	for (i = 0; i < nv_cache->chunk_count; i++, chunk++) {
		chunk->nv_cache = nv_cache;
		nvc_validate_md(nv_cache, chunk->md);

		if (offset != chunk->offset) {
			status = -EINVAL;
			goto error;
		}

		if (chunk->md->blocks_written == nv_cache->chunk_blocks) {
			/* Chunk full, move it on full list */
			TAILQ_INSERT_TAIL(&nv_cache->chunk_full_list, chunk, entry);
			nv_cache->chunk_full_count++;
		} else if (0 == chunk->md->blocks_written) {
			/* Chunk empty, move it on empty list */
			TAILQ_INSERT_TAIL(&nv_cache->chunk_free_list, chunk, entry);
			nv_cache->chunk_free_count++;
		} else {
			status = -EINVAL;
			goto error;
		}

		offset += nv_cache->chunk_blocks;
	}

	chunks_number = nv_cache->chunk_free_count + nv_cache->chunk_full_count;
	assert(nv_cache->chunk_current == NULL);

	if (chunks_number != nv_cache->chunk_count) {
		FTL_ERRLOG(dev, "Inconsistent NV cache metadata\n");
		status = -EINVAL;
		goto error;
	}

	status = sort_chunks(nv_cache);
	if (status) {
		FTL_ERRLOG(dev, "FTL NV Cache: sorting chunks ERROR\n");
	}

	FTL_NOTICELOG(dev, "FTL NV Cache: full chunks = %lu, empty chunks = %lu\n",
		      nv_cache->chunk_full_count, nv_cache->chunk_free_count);

	if (0 == status) {
		FTL_NOTICELOG(dev, "FTL NV Cache: state loaded successfully\n");
	} else {
		FTL_ERRLOG(dev, "FTL NV Cache: loading state ERROR\n");
	}

error:
	return status;
}

void
ftl_nv_cache_get_max_seq_id(struct ftl_nv_cache *nv_cache, uint64_t *open_seq_id,
			    uint64_t *close_seq_id)
{
	uint64_t i, o_seq_id = 0, c_seq_id = 0;
	struct ftl_nv_cache_chunk *chunk;

	chunk = nv_cache->chunks;
	assert(chunk);

	/* Iterate over chunks and get their max open and close seq id */
	for (i = 0; i < nv_cache->chunk_count; i++, chunk++) {
		o_seq_id = spdk_max(o_seq_id, chunk->md->seq_id);
		c_seq_id = spdk_max(c_seq_id, chunk->md->close_seq_id);
	}

	*open_seq_id = o_seq_id;
	*close_seq_id = c_seq_id;
}

typedef void (*ftl_chunk_ops_cb)(struct ftl_nv_cache_chunk *chunk, void *cntx, bool status);

static void
write_brq_end(struct spdk_bdev_io *bdev_io, bool success, void *arg)
{
	struct ftl_basic_rq *brq = arg;
	struct ftl_nv_cache_chunk *chunk = brq->io.chunk;

	ftl_stats_bdev_io_completed(brq->dev, FTL_STATS_TYPE_MD_NV_CACHE, bdev_io);

	brq->success = success;
	if (spdk_likely(success)) {
		chunk_advance_blocks(chunk->nv_cache, chunk, brq->num_blocks);
	}

	spdk_bdev_free_io(bdev_io);
	brq->owner.cb(brq);
}

static void
_ftl_chunk_basic_rq_write(void *_brq)
{
	struct ftl_basic_rq *brq = _brq;
	struct ftl_nv_cache *nv_cache = brq->io.chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	int rc;

	// 写brq 元数据
	rc = ftl_nv_cache_bdev_write_blocks_with_md(dev, nv_cache->bdev_desc, nv_cache->cache_ioch,
			brq->io_payload, NULL, brq->io.addr,
			brq->num_blocks, write_brq_end, brq);
	if (spdk_unlikely(rc)) {
		if (rc == -ENOMEM) {
			struct spdk_bdev *bdev = spdk_bdev_desc_get_bdev(nv_cache->bdev_desc);
			brq->io.bdev_io_wait.bdev = bdev;
			brq->io.bdev_io_wait.cb_fn = _ftl_chunk_basic_rq_write;
			brq->io.bdev_io_wait.cb_arg = brq;
			spdk_bdev_queue_io_wait(bdev, nv_cache->cache_ioch, &brq->io.bdev_io_wait);
		} else {
			ftl_abort();
		}
	}
}

static void
ftl_chunk_basic_rq_write(struct ftl_nv_cache_chunk *chunk, struct ftl_basic_rq *brq)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);

	brq->io.chunk = chunk;
	brq->success = false;

	_ftl_chunk_basic_rq_write(brq);

	// Update chunk->md->write_pointer 
	chunk->md->write_pointer += brq->num_blocks;
	dev->stats.io_activity_total += brq->num_blocks;
}

static void
read_brq_end(struct spdk_bdev_io *bdev_io, bool success, void *arg)
{
	struct ftl_basic_rq *brq = arg;

	ftl_stats_bdev_io_completed(brq->dev, FTL_STATS_TYPE_MD_NV_CACHE, bdev_io);

	brq->success = success;

	brq->owner.cb(brq);
	spdk_bdev_free_io(bdev_io);
}

static int
ftl_chunk_basic_rq_read(struct ftl_nv_cache_chunk *chunk, struct ftl_basic_rq *brq)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	int rc;

	brq->io.chunk = chunk;
	brq->success = false;

	rc = ftl_nv_cache_bdev_read_blocks_with_md(dev, nv_cache->bdev_desc, nv_cache->cache_ioch,
			brq->io_payload, NULL, brq->io.addr, brq->num_blocks, read_brq_end, brq);

	if (spdk_likely(!rc)) {
		dev->stats.io_activity_total += brq->num_blocks;
	}

	return rc;
}

static void
chunk_open_cb(int status, void *ctx)
{
	struct ftl_nv_cache_chunk *chunk = (struct ftl_nv_cache_chunk *)ctx;

	if (spdk_unlikely(status)) {
#ifdef SPDK_FTL_RETRY_ON_ERROR
		ftl_md_persist_entry_retry(&chunk->md_persist_entry_ctx);
		return;
#else
		ftl_abort();
#endif
	}

	chunk->md->state = FTL_CHUNK_STATE_OPEN;
}

static void
ftl_chunk_open(struct ftl_nv_cache_chunk *chunk)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	struct ftl_md *md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];

	if (chunk_alloc_p2l_map(chunk)) {
		assert(0);
		/*
		 * We control number of opening chunk and it shall be consistent with size of chunk
		 * P2L map pool
		 */
		ftl_abort();
		return;
	}

	chunk->nv_cache->chunk_open_count++;

	assert(chunk->md->write_pointer == 0);
	assert(chunk->md->blocks_written == 0);

	memcpy(p2l_map->chunk_dma_md, chunk->md, region->entry_size * FTL_BLOCK_SIZE);
	p2l_map->chunk_dma_md->state = FTL_CHUNK_STATE_OPEN;
	p2l_map->chunk_dma_md->p2l_map_checksum = 0;

	ftl_md_persist_entry(md, get_chunk_idx(chunk), p2l_map->chunk_dma_md,
			     NULL, chunk_open_cb, chunk,
			     &chunk->md_persist_entry_ctx);
}

static void
chunk_close_cb(int status, void *ctx)
{
	struct ftl_nv_cache_chunk *chunk = (struct ftl_nv_cache_chunk *)ctx;

	assert(chunk->md->write_pointer == chunk->nv_cache->chunk_blocks);

	if (spdk_likely(!status)) {
		chunk->md->p2l_map_checksum = chunk->p2l_map.chunk_dma_md->p2l_map_checksum;
		chunk_free_p2l_map(chunk);

		assert(chunk->nv_cache->chunk_open_count > 0);
		chunk->nv_cache->chunk_open_count--;

		/* Chunk full move it on full list */
		// 将chunk从open_list中移除，放入full_list中
		TAILQ_INSERT_TAIL(&chunk->nv_cache->chunk_full_list, chunk, entry);
		chunk->nv_cache->chunk_full_count++;

		chunk->nv_cache->last_seq_id = chunk->md->close_seq_id;
		
		// 2.将 chunk 状态设置为 closed
		chunk->md->state = FTL_CHUNK_STATE_CLOSED;
	} else {
#ifdef SPDK_FTL_RETRY_ON_ERROR
		ftl_md_persist_entry_retry(&chunk->md_persist_entry_ctx);
#else
		ftl_abort();
#endif
	}
}

static void
chunk_map_write_cb(struct ftl_basic_rq *brq)
{
	struct ftl_nv_cache_chunk *chunk = brq->io.chunk;
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	struct ftl_md *md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	uint32_t chunk_map_crc;

	if (spdk_likely(brq->success)) {
		chunk_map_crc = spdk_crc32c_update(p2l_map->chunk_map,
						   chunk->nv_cache->tail_md_chunk_blocks * FTL_BLOCK_SIZE, 0);
		memcpy(p2l_map->chunk_dma_md, chunk->md, region->entry_size * FTL_BLOCK_SIZE);
		// chunk's p2l 标记当前chunk的状态为closed
		p2l_map->chunk_dma_md->state = FTL_CHUNK_STATE_CLOSED;
		p2l_map->chunk_dma_md->p2l_map_checksum = chunk_map_crc;
		ftl_md_persist_entry(md, get_chunk_idx(chunk), chunk->p2l_map.chunk_dma_md,
				     NULL, chunk_close_cb, chunk,
				     &chunk->md_persist_entry_ctx);
	} else {
#ifdef SPDK_FTL_RETRY_ON_ERROR
		/* retry */
		chunk->md->write_pointer -= brq->num_blocks;
		ftl_chunk_basic_rq_write(chunk, brq);
#else
		ftl_abort();
#endif
	}
}

static void
ftl_chunk_close(struct ftl_nv_cache_chunk *chunk)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_basic_rq *brq = &chunk->metadata_rq;
	void *metadata = chunk->p2l_map.chunk_map;

	chunk->md->close_seq_id = ftl_get_next_seq_id(dev);
	ftl_basic_rq_init(dev, brq, metadata, chunk->nv_cache->tail_md_chunk_blocks);
	// 将 chunk 的状态设置为 closed 移入 full_list
	ftl_basic_rq_set_owner(brq, chunk_map_write_cb, chunk);

	assert(chunk->md->write_pointer == chunk_tail_md_offset(chunk->nv_cache));
	// brq->io_lba = cur_md_lba
	// brq->num_blocks = tail_md_chunk_blocks
	brq->io.addr = chunk->offset + chunk->md->write_pointer;


	ftl_chunk_basic_rq_write(chunk, brq);
}

static int ftl_chunk_read_tail_md(struct ftl_nv_cache_chunk *chunk, struct ftl_basic_rq *brq,
				  void (*cb)(struct ftl_basic_rq *brq), void *cb_ctx);
static void read_tail_md_cb(struct ftl_basic_rq *brq);
static void recover_open_chunk_cb(struct ftl_basic_rq *brq);

static void
restore_chunk_close_cb(int status, void *ctx)
{
	struct ftl_basic_rq *parent = (struct ftl_basic_rq *)ctx;
	struct ftl_nv_cache_chunk *chunk = parent->io.chunk;
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;

	if (spdk_unlikely(status)) {
		parent->success = false;
	} else {
		chunk->md->p2l_map_checksum = p2l_map->chunk_dma_md->p2l_map_checksum;
		chunk->md->state = FTL_CHUNK_STATE_CLOSED;
	}

	read_tail_md_cb(parent);
}

static void
restore_fill_p2l_map_cb(struct ftl_basic_rq *parent)
{
	struct ftl_nv_cache_chunk *chunk = parent->io.chunk;
	struct ftl_p2l_map *p2l_map = &chunk->p2l_map;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_md *md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	struct ftl_layout_region *region = &dev->layout.region[FTL_LAYOUT_REGION_TYPE_NVC_MD];
	uint32_t chunk_map_crc;

	/* Set original callback */
	ftl_basic_rq_set_owner(parent, recover_open_chunk_cb, parent->owner.priv);

	if (spdk_unlikely(!parent->success)) {
		read_tail_md_cb(parent);
		return;
	}

	chunk_map_crc = spdk_crc32c_update(p2l_map->chunk_map,
					   chunk->nv_cache->tail_md_chunk_blocks * FTL_BLOCK_SIZE, 0);
	memcpy(p2l_map->chunk_dma_md, chunk->md, region->entry_size * FTL_BLOCK_SIZE);
	p2l_map->chunk_dma_md->state = FTL_CHUNK_STATE_CLOSED;
	p2l_map->chunk_dma_md->write_pointer = chunk->nv_cache->chunk_blocks;
	p2l_map->chunk_dma_md->blocks_written = chunk->nv_cache->chunk_blocks;
	p2l_map->chunk_dma_md->p2l_map_checksum = chunk_map_crc;

	ftl_md_persist_entry(md, get_chunk_idx(chunk), p2l_map->chunk_dma_md, NULL,
			     restore_chunk_close_cb, parent, &chunk->md_persist_entry_ctx);
}

static void
restore_fill_tail_md(struct ftl_basic_rq *parent, struct ftl_nv_cache_chunk *chunk)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	void *metadata;

	chunk->md->close_seq_id = ftl_get_next_seq_id(dev);

	metadata = chunk->p2l_map.chunk_map;
	ftl_basic_rq_init(dev, parent, metadata, chunk->nv_cache->tail_md_chunk_blocks);
	ftl_basic_rq_set_owner(parent, restore_fill_p2l_map_cb, parent->owner.priv);

	parent->io.addr = chunk->offset + chunk_tail_md_offset(chunk->nv_cache);
	parent->io.chunk = chunk;

	ftl_chunk_basic_rq_write(chunk, parent);
}

static void
read_open_chunk_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct ftl_rq *rq = (struct ftl_rq *)cb_arg;
	struct ftl_basic_rq *parent = (struct ftl_basic_rq *)rq->owner.priv;
	struct ftl_nv_cache_chunk *chunk = parent->io.chunk;
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	union ftl_md_vss *md;
	uint64_t cache_offset = bdev_io->u.bdev.offset_blocks;
	uint64_t len = bdev_io->u.bdev.num_blocks;
	ftl_addr addr = ftl_addr_from_nvc_offset(dev, cache_offset);
	int rc;

	ftl_stats_bdev_io_completed(dev, FTL_STATS_TYPE_USER, bdev_io);

	spdk_bdev_free_io(bdev_io);

	if (!success) {
		parent->success = false;
		read_tail_md_cb(parent);
		return;
	}

	while (rq->iter.idx < rq->iter.count) {
		/* Get metadata */
		md = rq->entries[rq->iter.idx].io_md;
		if (md->nv_cache.seq_id != chunk->md->seq_id) {
			md->nv_cache.lba = FTL_LBA_INVALID;
		}
		/*
		 * The p2l map contains effectively random data at this point (since it contains arbitrary
		 * blocks from potentially not even filled tail md), so even LBA_INVALID needs to be set explicitly
		 */

		ftl_chunk_set_addr(chunk,  md->nv_cache.lba, addr + rq->iter.idx);
		rq->iter.idx++;
	}

	if (cache_offset + len < chunk->offset + chunk_tail_md_offset(nv_cache)) {
		cache_offset += len;
		len = spdk_min(dev->xfer_size, chunk->offset + chunk_tail_md_offset(nv_cache) - cache_offset);
		rq->iter.idx = 0;
		rq->iter.count = len;

		rc = ftl_nv_cache_bdev_readv_blocks_with_md(dev, nv_cache->bdev_desc,
				nv_cache->cache_ioch,
				rq->io_vec, len,
				rq->io_md,
				cache_offset, len,
				read_open_chunk_cb,
				rq);

		if (rc) {
			ftl_rq_del(rq);
			parent->success = false;
			read_tail_md_cb(parent);
			return;
		}
	} else {
		ftl_rq_del(rq);
		restore_fill_tail_md(parent, chunk);
	}
}

static void
restore_open_chunk(struct ftl_nv_cache_chunk *chunk, struct ftl_basic_rq *parent)
{
	struct ftl_nv_cache *nv_cache = chunk->nv_cache;
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(nv_cache, struct spdk_ftl_dev, nv_cache);
	struct ftl_rq *rq;
	uint64_t addr;
	uint64_t len = dev->xfer_size;
	int rc;

	/*
	 * We've just read the p2l map, prefill it with INVALID LBA
	 * TODO we need to do this because tail md blocks (p2l map) are also represented in the p2l map, instead of just user data region
	 */
	memset(chunk->p2l_map.chunk_map, -1, FTL_BLOCK_SIZE * nv_cache->tail_md_chunk_blocks);

	/* Need to read user data, recalculate chunk's P2L and write tail md with it */
	rq = ftl_rq_new(dev, dev->nv_cache.md_size);
	if (!rq) {
		parent->success = false;
		read_tail_md_cb(parent);
		return;
	}

	rq->owner.priv = parent;
	rq->iter.idx = 0;
	rq->iter.count = len;

	addr = chunk->offset;

	len = spdk_min(dev->xfer_size, chunk->offset + chunk_tail_md_offset(nv_cache) - addr);

	rc = ftl_nv_cache_bdev_readv_blocks_with_md(dev, nv_cache->bdev_desc,
			nv_cache->cache_ioch,
			rq->io_vec, len,
			rq->io_md,
			addr, len,
			read_open_chunk_cb,
			rq);

	if (rc) {
		ftl_rq_del(rq);
		parent->success = false;
		read_tail_md_cb(parent);
	}
}

static void
read_tail_md_cb(struct ftl_basic_rq *brq)
{
	brq->owner.cb(brq);
}

static int
ftl_chunk_read_tail_md(struct ftl_nv_cache_chunk *chunk, struct ftl_basic_rq *brq,
		       void (*cb)(struct ftl_basic_rq *brq), void *cb_ctx)
{
	struct spdk_ftl_dev *dev = SPDK_CONTAINEROF(chunk->nv_cache, struct spdk_ftl_dev, nv_cache);
	void *metadata;
	int rc;

	metadata = chunk->p2l_map.chunk_map;
	ftl_basic_rq_init(dev, brq, metadata, chunk->nv_cache->tail_md_chunk_blocks);
	ftl_basic_rq_set_owner(brq, cb, cb_ctx);

	brq->io.addr = chunk->offset + chunk_tail_md_offset(chunk->nv_cache);
	rc = ftl_chunk_basic_rq_read(chunk, brq);

	return rc;
}

struct restore_chunk_md_ctx {
	ftl_chunk_md_cb cb;
	void *cb_ctx;
	int status;
	uint64_t qd;
	uint64_t id;
};

static inline bool
is_chunk_count_valid(struct ftl_nv_cache *nv_cache)
{
	uint64_t chunk_count = 0;

	chunk_count += nv_cache->chunk_open_count;
	chunk_count += nv_cache->chunk_free_count;
	chunk_count += nv_cache->chunk_full_count;
	chunk_count += nv_cache->chunk_comp_count;

	return chunk_count == nv_cache->chunk_count;
}

static void
walk_tail_md_cb(struct ftl_basic_rq *brq)
{
	struct ftl_mngt_process *mngt = brq->owner.priv;
	struct ftl_nv_cache_chunk *chunk = brq->io.chunk;
	struct restore_chunk_md_ctx *ctx = ftl_mngt_get_step_ctx(mngt);
	int rc = 0;

	if (brq->success) {
		rc = ctx->cb(chunk, ctx->cb_ctx);
	} else {
		rc = -EIO;
	}

	if (rc) {
		ctx->status = rc;
	}
	ctx->qd--;
	chunk_free_p2l_map(chunk);
	ftl_mngt_continue_step(mngt);
}

static void
ftl_mngt_nv_cache_walk_tail_md(struct spdk_ftl_dev *dev, struct ftl_mngt_process *mngt,
			       uint64_t seq_id, ftl_chunk_md_cb cb, void *cb_ctx)
{
	struct ftl_nv_cache *nvc = &dev->nv_cache;
	struct restore_chunk_md_ctx *ctx;

	ctx = ftl_mngt_get_step_ctx(mngt);
	if (!ctx) {
		if (ftl_mngt_alloc_step_ctx(mngt, sizeof(*ctx))) {
			ftl_mngt_fail_step(mngt);
			return;
		}
		ctx = ftl_mngt_get_step_ctx(mngt);
		assert(ctx);

		ctx->cb = cb;
		ctx->cb_ctx = cb_ctx;
	}

	/*
	 * This function generates a high queue depth and will utilize ftl_mngt_continue_step during completions to make sure all chunks
	 * are processed before returning an error (if any were found) or continuing on.
	 */
	if (0 == ctx->qd && ctx->id == nvc->chunk_count) {
		if (!is_chunk_count_valid(nvc)) {
			FTL_ERRLOG(dev, "Recovery ERROR, invalid number of chunk\n");
			assert(false);
			ctx->status = -EINVAL;
		}

		if (ctx->status) {
			ftl_mngt_fail_step(mngt);
		} else {
			ftl_mngt_next_step(mngt);
		}
		return;
	}

	while (ctx->id < nvc->chunk_count) {
		struct ftl_nv_cache_chunk *chunk = &nvc->chunks[ctx->id];
		int rc;

		if (!chunk->recovery) {
			/* This chunk is empty and not used in recovery */
			ctx->id++;
			continue;
		}

		if (seq_id && (chunk->md->close_seq_id <= seq_id)) {
			ctx->id++;
			continue;
		}

		if (chunk_alloc_p2l_map(chunk)) {
			/* No more free P2L map, break and continue later */
			break;
		}
		ctx->id++;

		rc = ftl_chunk_read_tail_md(chunk, &chunk->metadata_rq, walk_tail_md_cb, mngt);

		if (0 == rc) {
			ctx->qd++;
		} else {
			chunk_free_p2l_map(chunk);
			ctx->status = rc;
		}
	}

	if (0 == ctx->qd) {
		/*
		 * No QD could happen due to all leftover chunks being in free state.
		 * Additionally ftl_chunk_read_tail_md could fail starting with the first IO in a given patch.
		 * For streamlining of all potential error handling (since many chunks are reading P2L at the same time),
		 * we're using ftl_mngt_continue_step to arrive at the same spot of checking for mngt step end (see beginning of function).
		 */
		ftl_mngt_continue_step(mngt);
	}

}

void
ftl_mngt_nv_cache_restore_l2p(struct spdk_ftl_dev *dev, struct ftl_mngt_process *mngt,
			      ftl_chunk_md_cb cb, void *cb_ctx)
{
	ftl_mngt_nv_cache_walk_tail_md(dev, mngt, dev->sb->ckpt_seq_id, cb, cb_ctx);
}

static void
restore_chunk_state_cb(struct spdk_ftl_dev *dev, struct ftl_md *md, int status)
{
	struct ftl_mngt_process *mngt = md->owner.cb_ctx;
	struct ftl_nv_cache *nvc = &dev->nv_cache;
	struct ftl_nv_cache_chunk *chunk;
	uint64_t i;

	if (status) {
		/* Restore error, end step */
		ftl_mngt_fail_step(mngt);
		return;
	}

	for (i = 0; i < nvc->chunk_count; i++) {
		chunk = &nvc->chunks[i];

		switch (chunk->md->state) {
		case FTL_CHUNK_STATE_FREE:
			break;
		case FTL_CHUNK_STATE_OPEN:
			TAILQ_REMOVE(&nvc->chunk_free_list, chunk, entry);
			nvc->chunk_free_count--;

			TAILQ_INSERT_TAIL(&nvc->chunk_open_list, chunk, entry);
			nvc->chunk_open_count++;

			/* Chunk is not empty, mark it to be recovered */
			chunk->recovery = true;
			break;
		case FTL_CHUNK_STATE_CLOSED:
			TAILQ_REMOVE(&nvc->chunk_free_list, chunk, entry);
			nvc->chunk_free_count--;

			TAILQ_INSERT_TAIL(&nvc->chunk_full_list, chunk, entry);
			nvc->chunk_full_count++;

			/* Chunk is not empty, mark it to be recovered */
			chunk->recovery = true;
			break;
		default:
			status = -EINVAL;
		}
	}

	if (status) {
		ftl_mngt_fail_step(mngt);
	} else {
		ftl_mngt_next_step(mngt);
	}
}

void
ftl_mngt_nv_cache_restore_chunk_state(struct spdk_ftl_dev *dev, struct ftl_mngt_process *mngt)
{
	struct ftl_md *md = dev->layout.md[FTL_LAYOUT_REGION_TYPE_NVC_MD];

	md->owner.cb_ctx = mngt;
	md->cb = restore_chunk_state_cb;
	ftl_md_restore(md);
}

static void
recover_open_chunk_cb(struct ftl_basic_rq *brq)
{
	struct ftl_mngt_process *mngt = brq->owner.priv;
	struct ftl_nv_cache_chunk *chunk = brq->io.chunk;
	struct ftl_nv_cache *nvc = chunk->nv_cache;
	struct spdk_ftl_dev *dev = ftl_mngt_get_dev(mngt);

	chunk_free_p2l_map(chunk);

	if (!brq->success) {
		FTL_ERRLOG(dev, "Recovery chunk ERROR, offset = %"PRIu64", seq id %"PRIu64"\n", chunk->offset,
			   chunk->md->seq_id);
		ftl_mngt_fail_step(mngt);
		return;
	}

	FTL_NOTICELOG(dev, "Recovered chunk, offset = %"PRIu64", seq id %"PRIu64"\n", chunk->offset,
		      chunk->md->seq_id);

	TAILQ_REMOVE(&nvc->chunk_open_list, chunk, entry);
	nvc->chunk_open_count--;

	TAILQ_INSERT_TAIL(&nvc->chunk_full_list, chunk, entry);
	nvc->chunk_full_count++;

	/* This is closed chunk */
	chunk->md->write_pointer = nvc->chunk_blocks;
	chunk->md->blocks_written = nvc->chunk_blocks;

	ftl_mngt_continue_step(mngt);
}

void
ftl_mngt_nv_cache_recover_open_chunk(struct spdk_ftl_dev *dev, struct ftl_mngt_process *mngt)
{
	struct ftl_nv_cache *nvc = &dev->nv_cache;
	struct ftl_nv_cache_chunk *chunk;
	struct ftl_basic_rq *brq = ftl_mngt_get_step_ctx(mngt);

	if (!brq) {
		if (TAILQ_EMPTY(&nvc->chunk_open_list)) {
			FTL_NOTICELOG(dev, "No open chunks to recover P2L\n");
			ftl_mngt_next_step(mngt);
			return;
		}

		if (ftl_mngt_alloc_step_ctx(mngt, sizeof(*brq))) {
			ftl_mngt_fail_step(mngt);
			return;
		}
		brq = ftl_mngt_get_step_ctx(mngt);
		ftl_basic_rq_set_owner(brq, recover_open_chunk_cb, mngt);
	}

	if (TAILQ_EMPTY(&nvc->chunk_open_list)) {
		if (!is_chunk_count_valid(nvc)) {
			FTL_ERRLOG(dev, "Recovery ERROR, invalid number of chunk\n");
			ftl_mngt_fail_step(mngt);
			return;
		}

		/*
		 * Now all chunks loaded and closed, do final step of restoring
		 * chunks state
		 */
		if (ftl_nv_cache_load_state(nvc)) {
			ftl_mngt_fail_step(mngt);
		} else {
			ftl_mngt_next_step(mngt);
		}
	} else {
		chunk = TAILQ_FIRST(&nvc->chunk_open_list);
		if (chunk_alloc_p2l_map(chunk)) {
			ftl_mngt_fail_step(mngt);
			return;
		}

		brq->io.chunk = chunk;

		FTL_NOTICELOG(dev, "Start recovery open chunk, offset = %"PRIu64", seq id %"PRIu64"\n",
			      chunk->offset, chunk->md->seq_id);
		restore_open_chunk(chunk, brq);
	}
}

int
ftl_nv_cache_chunks_busy(struct ftl_nv_cache *nv_cache)
{
	/* chunk_current is migrating to closed status when closing, any others should already be
	 * moved to free chunk list. Also need to wait for free md requests */
	return nv_cache->chunk_open_count == 0 && nv_cache->chunk_free_persist_count == 0;
}

void
ftl_nv_cache_halt(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_chunk *chunk;
	uint64_t free_space;

	nv_cache->halt = true;

	/* Set chunks on open list back to free state since no user data has been written to it */
	while (!TAILQ_EMPTY(&nv_cache->chunk_open_list)) {
		chunk = TAILQ_FIRST(&nv_cache->chunk_open_list);

		/* Chunks are moved between lists on metadata update submission, but state is changed
		 * on completion. Breaking early in such a case to make sure all the necessary resources
		 * will be freed (during next pass(es) of ftl_nv_cache_halt).
		 */
		if (chunk->md->state != FTL_CHUNK_STATE_OPEN) {
			break;
		}

		TAILQ_REMOVE(&nv_cache->chunk_open_list, chunk, entry);
		chunk_free_p2l_map(chunk);
		memset(chunk->md, 0, sizeof(*chunk->md));
		assert(nv_cache->chunk_open_count > 0);
		nv_cache->chunk_open_count--;
	}

	/* Close current chunk by skipping all not written blocks */
	chunk = nv_cache->chunk_current;
	if (chunk != NULL) {
		nv_cache->chunk_current = NULL;
		if (chunk_is_closed(chunk)) {
			return;
		}

		free_space = chunk_get_free_space(nv_cache, chunk);
		chunk->md->blocks_skipped = free_space;
		chunk->md->blocks_written += free_space;
		chunk->md->write_pointer += free_space;
		ftl_chunk_close(chunk);
	}
}

uint64_t
ftl_nv_cache_acquire_trim_seq_id(struct ftl_nv_cache *nv_cache)
{
	struct ftl_nv_cache_chunk *chunk = nv_cache->chunk_current;
	uint64_t seq_id, free_space;

	if (!chunk) {
		chunk = TAILQ_FIRST(&nv_cache->chunk_open_list);
		if (chunk && chunk->md->state == FTL_CHUNK_STATE_OPEN) {
			return chunk->md->seq_id;
		} else {
			return 0;
		}
	}

	if (chunk_is_closed(chunk)) {
		return 0;
	}

	seq_id = nv_cache->chunk_current->md->seq_id;
	free_space = chunk_get_free_space(nv_cache, chunk);

	chunk->md->blocks_skipped = free_space;
	chunk->md->blocks_written += free_space;
	chunk->md->write_pointer += free_space;
	if (chunk->md->blocks_written == chunk_tail_md_offset(nv_cache)) {
		ftl_chunk_close(chunk);
	}
	nv_cache->chunk_current = NULL;

	seq_id++;
	return seq_id;
}
