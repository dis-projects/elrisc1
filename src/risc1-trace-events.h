/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2022 RnD Center "ELVEES", JSC
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM risc1

#if !defined(RISC1_TRACE_EVENTS_H) || defined(TRACE_HEADER_MULTI_READ)
#define RISC1_TRACE_EVENTS_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/time.h>

struct userptr_mapper;
struct risc1_buf_desc;

DECLARE_EVENT_CLASS(risc1_buffer,

	TP_PROTO(const char *type, size_t size),

	TP_ARGS(type, size),

	TP_STRUCT__entry(
		__field(size_t, size)
		__string(type, type)
	),

	TP_fast_assign(
		__entry->size = size;
		__assign_str(type, type);
	),

	TP_printk("type: %s size: %lx",
		  __get_str(type), __entry->size)
);

DEFINE_EVENT(risc1_buffer, risc1_buf_create,

	TP_PROTO(const char *type, size_t size),

	TP_ARGS(type, size)
);

DEFINE_EVENT(risc1_buffer, risc1_buf_release,

	TP_PROTO(const char *type, size_t size),

	TP_ARGS(type, size)
);

TRACE_EVENT(risc1_syscall,

	TP_PROTO(const char *name, size_t arg0_mem_size, size_t arg1_mem_size),

	TP_ARGS(name, arg0_mem_size, arg1_mem_size),

	TP_STRUCT__entry(
		__string(name, name)
		__field(size_t, arg0_mem_size)
		__field(size_t, arg1_mem_size)
	),

	TP_fast_assign(
		__assign_str(name, name);
		__entry->arg0_mem_size = arg0_mem_size;
		__entry->arg1_mem_size = arg1_mem_size;
	),

	TP_printk("%s arg0_mem_size=%lx arg1_mem_size=%lx",
		  __get_str(name),
		  __entry->arg0_mem_size,
		  __entry->arg1_mem_size)
);

TRACE_EVENT(risc1_buf_sync,

	TP_PROTO(size_t size),

	TP_ARGS(size),

	TP_STRUCT__entry(
		__field(size_t, size)
	),

	TP_fast_assign(
		__entry->size = size;
	),

	TP_printk("size=%lx", __entry->size)
);

TRACE_EVENT(risc1_mmu_map,

	TP_PROTO(struct risc1_buf_desc *buf_desc),

	TP_ARGS(buf_desc),

	TP_STRUCT__entry(
		__field(u64, buf_vaddr)
		__field(size_t, buf_size)
	),

	TP_fast_assign(
		__entry->buf_vaddr = buf_desc->vaddr_mmu_risc1;
		__entry->buf_size = buf_desc->mapper->size_aligned;
	),

	TP_printk("vaddr_mmu_risc1=%llx size=%lx",
		  __entry->buf_vaddr,
		  __entry->buf_size)
);

TRACE_EVENT(risc1_uptime,

	TP_PROTO(struct risc1_priv *core, const char *kernel_name),

	TP_ARGS(core, kernel_name),

	TP_STRUCT__entry(
		__string(kernel_name, kernel_name)
		__field(u64, tic_cntr)
	),

	TP_fast_assign(
		__assign_str(kernel_name, kernel_name);
		__entry->tic_cntr = risc1_read64(core, DSP_TIC_CNTR);
	),

	TP_printk("DSP uptime: %llu kernel_name: %s", __entry->tic_cntr,
		  __get_str(kernel_name))
);





#endif /* RISC1_TRACE_EVENTS_H */

/* This is needed because the name of this file doesn't match TRACE_SYSTEM. */
#define TRACE_INCLUDE_FILE risc1-trace-events
#define TRACE_INCLUDE_PATH .

/* This part must be outside protection */
#include <trace/define_trace.h>
