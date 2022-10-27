/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2018-2022 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_RISC1_H
#define _LINUX_RISC1_H

#include <stddef.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#define RISC1_MAGIC 'r'

#define SC_GETTIMEOFDAY	1
#define SC_WRITE	2
#define SC_READ		3
#define SC_OPEN		4
#define SC_CLOSE	5
#define SC_FSTAT	6
#define SC_LSEEK	7
#define SC_ISATTY	8
#define SC_CHDIR	9
#define SC_STAT		10
#define SC_TIMES	11
#define SC_LINK		12
#define SC_UNLINK	13
#define SC_EXIT		99
#define SC_GET_ENV	100

#define EVENT_VCPU_BASE	200
#define EVENT_VCPU_PUTCHAR	(EVENT_VCPU_BASE + 1)
#define EVENT_VCPU_PUTSTR	(EVENT_VCPU_BASE + 2)

#define RISC1_MAX_JOB_ARGS 32

#define RISC1_MAX_ELF_SECTIONS 64

#define RISC1_MAX_JOB_INSTANCE 255

enum risc1_job_arg_type {
	RISC1_TYPE_GLOBAL_MEMORY,
	RISC1_TYPE_NC_GLOBAL_MEMORY,
	RISC1_TYPE_LOCAL_MEMORY,
	RISC1_TYPE_BASIC,
	RISC1_TYPE_BASIC_FLOAT,
	RISC1_TYPE_DMA_MEMORY
};

struct risc1_job_arg {
	enum risc1_job_arg_type type;
	union {
		struct {
			int mapper_fd;
		} global_memory;
		struct {
			__u32 size;
		} local_memory;
		struct {
			__u32 size;
			__u64 p;
		} basic;
		struct {
			int mapper_fd;
		} dma_memory;
	};
};

enum risc1_job_elf_section_type {
	RISC1_ELF_SECTION_CODE,
	RISC1_ELF_SECTION_DATA,
	RISC1_ELF_SECTION_DATA_CONST,
	RISC1_ELF_SECTION_LAST = RISC1_ELF_SECTION_DATA_CONST
};

struct risc1_job_elf_section {
	enum risc1_job_elf_section_type type;
	int mapper_fd;
	__u32 size;
	__u32 risc1_virtual_address;
};

enum risc1_message_type {
	RISC1_MESSAGE_EMPTY = 0,
	RISC1_MESSAGE_SYSCALL_REPLY = 1,
	RISC1_MESSAGE_SYSCALL = 2,
};

struct risc1_message {
	enum risc1_message_type type;
	int num;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__s32 retval;
};

struct risc1_job {
	__u32 num_elf_sections;
	struct risc1_job_elf_section elf_sections[RISC1_MAX_ELF_SECTIONS];
	int hugepages;
	int stack_fd;
	int job_fd;
};

struct risc1_job_instance {
	int job_fd;
	__u32 argc;
	struct risc1_job_arg args[RISC1_MAX_JOB_ARGS];
	__u32 entry_point_virtual_address;
	__u32 launcher_virtual_address;
	char name[255];
	int debug_enable;
	__u32 catch_mode;
	int job_instance_fd;
	int debug_fd;
};

struct risc1_job_instance_info {
	long id;
	int pid;
	char name[255];
};

struct risc1_job_instance_list {
	__u32 job_instance_count;
	struct risc1_job_instance_info *info;
	__u32 job_instance_ret;
};

enum risc1_job_instance_state {
	RISC1_JOB_STATUS_ENQUEUED,
	RISC1_JOB_STATUS_RUN,
	RISC1_JOB_STATUS_INTERRUPTED,
	RISC1_JOB_STATUS_SYSCALL,
	RISC1_JOB_STATUS_DONE
};

enum risc1_job_instance_error {
	RISC1_JOB_STATUS_SUCCESS,
	RISC1_JOB_STATUS_ERROR
};

struct risc1_job_instance_status {
	int job_instance_fd;
	enum risc1_job_instance_state state;
	enum risc1_job_instance_error error;
};

struct risc1_job_instance_dbg {
	long job_instance_id;
	int job_instance_dbg_fd;
};

struct risc1_caps {
	char drvname[32];
	__u32 hw_id;
};

struct risc1_device_info {
	int nclusters;
	int cluster_id;
	int cluster_cap;
	int core_in_cluster_id;
};

enum risc1_buf_type {
	RISC1_CACHED_BUFFER_FROM_UPTR,
	RISC1_NONCACHED_BUFFER
};

struct risc1_buf {
	int dmabuf_fd;
	int mapper_fd;
	enum risc1_buf_type type;
	__u64 p;
	__u64 size;
};

enum risc1_buf_sync_dir {
	RISC1_BUF_SYNC_DIR_TO_CPU,
	RISC1_BUF_SYNC_DIR_TO_DEVICE
};

struct risc1_buf_sync {
	int mapper_fd;
	size_t offset;
	size_t size;
	enum risc1_buf_sync_dir dir;
};

struct risc1_dbg_mem {
	__u32 vaddr;
	size_t size;
	void *data;
};

enum risc1_stop_reason {
	RISC1_STOP_REASON_HW_BREAKPOINT,
	RISC1_STOP_REASON_SW_BREAKPOINT,
	RISC1_STOP_REASON_EXTERNAL_REQUEST,
	RISC1_STOP_REASON_STEP,
	RISC1_STOP_REASON_DBG_INTERRUPT,
	RISC1_STOP_REASON_APP_EXCEPTION
};

struct risc1_dbg_stop_reason {
	enum risc1_stop_reason reason;
};

/* Dump flags */
#define RISC1_DUMP_TOP		0x001
#define RISC1_DUMP_ONCD		0x002
#define RISC1_DUMP_REG		0x004
#define RISC1_DUMP_FPU		0x008
#define RISC1_DUMP_CP0		0x010
#define RISC1_DUMP_HILO		0x020
#define RISC1_DUMP_CP1		0x040
#define RISC1_DUMP_TLB		0x080
#define RISC1_DUMP_MAIN		0x01f
#define RISC1_DUMP_MEM		0x100
#define RISC1_DUMP_VMMU		0x200

#define RISC1_IOC_ENQUEUE_JOB \
	_IOWR(RISC1_MAGIC, 1, struct risc1_job_instance *)

#define RISC1_IOC_GET_JOB_STATUS \
	_IOWR(RISC1_MAGIC, 2, struct risc1_job_status *)

#define RISC1_IOC_GET_CORE_IDX \
	_IOR(RISC1_MAGIC, 3, struct risc1_device_info *)

#define RISC1_IOC_CREATE_BUFFER \
	_IOR(RISC1_MAGIC, 4, struct risc1_buf *)

#define RISC1_IOC_CREATE_MAPPER \
	_IOR(RISC1_MAGIC, 5, struct risc1_buf *)

#define RISC1_IOC_SYNC_BUFFER \
	_IOR(RISC1_MAGIC, 6, struct risc1_buf_sync *)

#define RISC1_IOC_CREATE_JOB \
	_IOR(RISC1_MAGIC, 7, struct risc1_job *)

#define RISC1_IOC_GET_JOB_COUNT \
	_IOR(RISC1_MAGIC, 8, __u32 *)

#define RISC1_IOC_GET_JOB_LIST \
	_IOWR(RISC1_MAGIC, 9, struct risc1_job_instance_list *)

#define RISC1_IOC_DBG_JOB_ATTACH \
	_IOR(RISC1_MAGIC, 10, struct risc1_job_instance_dbg *)

#define RISC1_IOC_DBG_MEMORY_READ \
	_IOWR(RISC1_MAGIC, 11, struct risc1_dbg_mem *)

#define RISC1_IOC_DBG_MEMORY_WRITE \
	_IOWR(RISC1_MAGIC, 12, struct risc1_dbg_mem *)

#define RISC1_IOC_DBG_REGISTER_READ \
	_IOWR(RISC1_MAGIC, 13, struct risc1_dbg_mem *)

#define RISC1_IOC_DBG_REGISTER_WRITE \
	_IOWR(RISC1_MAGIC, 14, struct risc1_dbg_mem *)

#define RISC1_IOC_DBG_JOB_INSTANCE_INTERRUPT \
	_IO(RISC1_MAGIC, 15)

#define RISC1_IOC_DBG_JOB_INSTANCE_CONTINUE \
	_IO(RISC1_MAGIC, 16)

#define RISC1_IOC_DBG_GET_STOP_REASON \
	_IOWR(RISC1_MAGIC, 17, struct risc1_dbg_stop_reason *)

#define RISC1_IOC_DBG_HW_BREAKPOINT_SET \
	_IOWR(RISC1_MAGIC, 18, __u32 *)

#define RISC1_IOC_DBG_HW_BREAKPOINT_CLEAR \
	_IOWR(RISC1_MAGIC, 19, __u32 *)

#define RISC1_IOC_DBG_STEP \
	_IOWR(RISC1_MAGIC, 20, __u32 *)

#define RISC1_IOC_DUMP \
	_IOWR(RISC1_MAGIC, 21, __u32 *)

#define RISC1_GET_CAPS \
	_IOR(RISC1_MAGIC, 255, struct elcore_caps *)

#endif
