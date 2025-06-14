#ifndef __TRACING_UTILS_H__
#define __TRACING_UTILS_H__

#ifndef BPF_CORE
typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;
#endif // BPF_CORE

#ifndef BPF_MAX_STACK_DEPTH
#define BPF_MAX_STACK_DEPTH 127
#endif

#define MAX_ENUM_FUNCTIONS 16

enum Domain
{
  GUEST = 0,
  HOST = 1,
  QEMU = 2,
};

enum FunctionName
{
  IOMMU_MAP = 0,
  IOMMU_MAP_INTERNAL = 1,
  IOMMU_IOTLB_SYNC_MAP = 2, // intel_iommu_iotlb_sync_map
  IOMMU_UNMAP = 3,
  IOMMU_UNMAP_INTERNAL = 4,
  IOMMU_TLB_SYNC = 5, // intel_iommu_tlb_sync
  PAGE_POOL_ALLOC = 6,
  PAGE_POOL_SLOW = 7,
  // VFIO_IOCTL_MAP_DMA = 6,
  // VFIO_IOCTL_UNMAP_DMA = 7,
  // QEMU_ADDRESS_SPACE_RW = 8,
  // QEMU_ADDRESS_SPACE_WRITE = 9,
  // QEMU_SHADOW_PAGE_TABLE = 8,
  // QEMU_VTD_MEM_WRITE = 9,
  // QEMU_VFIO_DMA_MAP = 10,
  // QEMU_VFIO_DMA_UNMAP = 11,
  // QEMU_VFIO_REGION_WRITE = 12,
  // QEMU_VTD_IOMMU_TRANSLATE = 13,
  FUNCTION_NAME_MAX,
};

struct entry_key_t
{
  u64 id;
  u64 cookie;
};

struct entry_val_t
{
  u64 ts;
};

struct ioctl_trace_val_t
{
  u64 ts;           // Timestamp of the entry
  unsigned int cmd; // The ioctl command being traced
};

struct data_t
{
  enum Domain domain;
  enum FunctionName func_name;
  u32 pid;
  u32 tid;
  u32 cpu_id;
  u64 timestamp_ns;
  u64 duration_ns;
  s64 kern_stack_id;
  s64 user_stack_id;
};

struct latency_stats_t
{
  u64 count;
  u64 total_duration_ns;  // Sum of all durations
  u64 sum_sq_duration_us; // Sum of (duration * duration)
};

#endif // __TRACING_UTILS_H__
