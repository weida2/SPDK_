/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/likely.h"

#include "ftl_writer.h"
#include "ftl_band.h"

void
ftl_writer_init(struct spdk_ftl_dev *dev, struct ftl_writer *writer,
		uint64_t limit, enum ftl_band_type type)
{
	memset(writer, 0, sizeof(*writer));
	writer->dev = dev;
	TAILQ_INIT(&writer->rq_queue);
	TAILQ_INIT(&writer->full_bands);
	writer->limit = limit;
	writer->halt = true;
	writer->writer_type = type;
}

static bool
can_write(struct ftl_writer *writer)
{
	if (spdk_unlikely(writer->halt)) {
		return false;
	}

	return writer->band->md->state == FTL_BAND_STATE_OPEN;
}

void
ftl_writer_band_state_change(struct ftl_band *band)
{
	struct ftl_writer *writer = band->owner.priv;

	switch (band->md->state) {
	case FTL_BAND_STATE_FULL:
		assert(writer->band == band);
		TAILQ_INSERT_TAIL(&writer->full_bands, band, queue_entry);
		writer->band = NULL;
		break;

	case FTL_BAND_STATE_CLOSED:
		assert(writer->num_bands > 0);
		writer->num_bands--;
		ftl_band_clear_owner(band, ftl_writer_band_state_change, writer);
		writer->last_seq_id = band->md->close_seq_id;
		break;

	default:
		break;
	}
}

static void
close_full_bands(struct ftl_writer *writer)
{
	struct ftl_band *band, *next;

	TAILQ_FOREACH_SAFE(band, &writer->full_bands, queue_entry, next) {
		if (band->queue_depth) {
			continue;
		}

		// 从 write->full_bands 中移除
		TAILQ_REMOVE(&writer->full_bands, band, queue_entry);
		// 和ftl_chunk_close一样,写满了关闭,同时将band的p2l metadata写入base-ssd
		// band 的状态转换过程 CLOSING -> (tmp) FULL -> CLOSED
		ftl_band_close(band);
	}
}

static bool
is_active(struct ftl_writer *writer)
{
	if (writer->dev->limit < writer->limit) {
		return false;
	}

	return true;
}

static struct ftl_band *
get_band(struct ftl_writer *writer)
{
	if (spdk_unlikely(!writer->band)) {
		// 1.判断当前 user 写入是否达到 limit
		if (!is_active(writer)) {
			return NULL;
		}

		// 2.判断 next_band 是否可用
		if (spdk_unlikely(NULL != writer->next_band)) {
			if (FTL_BAND_STATE_OPEN == writer->next_band->md->state) {
				writer->band = writer->next_band;
				writer->next_band = NULL;

				return writer->band;
			} else {
				assert(FTL_BAND_STATE_OPEN == writer->next_band->md->state);
				ftl_abort();
			}
		}

		// 3.判断当前(user_compact, gc)打开的band数量是否超过限制
		if (writer->num_bands >= FTL_LAYOUT_REGION_TYPE_P2L_COUNT / 2) {  // 2
			/* Maximum number of opened band exceed (we split this
			 * value between and compaction and GC writer
			 */
			return NULL;
		}

		// 4.获取一个可用的band
		writer->band = ftl_band_get_next_free(writer->dev);
		if (writer->band) {
			writer->num_bands++;
			ftl_band_set_owner(writer->band,
					   ftl_writer_band_state_change, writer);

			// 4.1 band的状态为 PREP 时
			//     初始化 band->p2l_map, band->p2l_ckpt, band_iter, band_seqid
			if (ftl_band_write_prep(writer->band)) {
				/*
				 * This error might happen due to allocation failure. However number
				 * of open bands is controlled and it should have enough resources
				 * to do it. So here is better to perform a crash and recover from
				 * shared memory to bring back stable state.
				 *  */
				ftl_abort();
			}
		} else { // 无可用band
			return NULL;
		}
	}

	if (spdk_likely(writer->band->md->state == FTL_BAND_STATE_OPEN)) {
		return writer->band;
	} else {
		if (spdk_unlikely(writer->band->md->state == FTL_BAND_STATE_PREP)) {
			// 4.2 如果是通过4步骤获取的band,那么其状态是PREP,需要将打开
			//     这里的话 band 的状态转换为 PREP -> OPENING -> OPEN
			//     从 OPENING -> OPEN 需要持久化元数据
			ftl_band_open(writer->band, writer->writer_type);
		}
		return NULL;
	}
}

void
ftl_writer_run(struct ftl_writer *writer)
{
	struct ftl_band *band;
	struct ftl_rq *rq;

	// 0.从 write_full_band 取出 band 作处理，然后设置其状态为 close
	close_full_bands(writer);

	if (!TAILQ_EMPTY(&writer->rq_queue)) {
		// 1.获取band
		band = get_band(writer);
		if (spdk_unlikely(!band)) {
			return;
		}

		// 1.1 再次判断band的状态是否为OPEN
		if (!can_write(writer)) {
			return;
		}

		/* Finally we can write to band */
		rq = TAILQ_FIRST(&writer->rq_queue);
		TAILQ_REMOVE(&writer->rq_queue, rq, qentry);
		// 2.处理向 base-ssd 的 band 中写入数据的逻辑
		ftl_band_rq_write(writer->band, rq);

		// // static
		// if (writer->writer_type == FTL_BAND_TYPE_GC) {
		// 	// 2.1 如果是gc writer,则将band的状态设置为 PREP
		// 	writer->gc_tt_blocks += rq->num_blocks;
		// }
	}
}

bool
ftl_writer_is_halted(struct ftl_writer *writer)
{
	if (spdk_unlikely(!TAILQ_EMPTY(&writer->full_bands))) {
		return false;
	}

	if (writer->band) {
		if (writer->band->md->state != FTL_BAND_STATE_OPEN) {
			return false;
		}

		if (writer->band->queue_depth) {
			return false;
		}
	}

	return writer->halt;
}

uint64_t
ftl_writer_get_free_blocks(struct ftl_writer *writer)
{
	uint64_t free_blocks = 0;

	if (writer->band) {
		free_blocks += ftl_band_user_blocks_left(writer->band,
				writer->band->md->iter.offset);
	}

	if (writer->next_band) {
		free_blocks += ftl_band_user_blocks_left(writer->next_band,
				writer->next_band->md->iter.offset);
	}

	return free_blocks;
}
