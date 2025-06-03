#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tracing_utils.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, struct entry_key_t);
  __type(value, struct entry_val_t);
} entry_traces SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, 16384);
  __type(key, u32);
  __type(value, u64[BPF_MAX_STACK_DEPTH]);
} stack_traces SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct latency_stats_t);
  __uint(max_entries, MAX_ENUM_FUNCTIONS);
} func_latency_stats SEC(".maps");

static __always_inline int
_bpf_utils_trace_func_entry(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 cookie = bpf_get_attach_cookie(ctx);
  struct entry_key_t key = {.id = pid_tgid, .cookie = cookie};
  struct entry_val_t val = {.ts = bpf_ktime_get_ns()};
  return bpf_map_update_elem(&entry_traces, &key, &val, BPF_ANY);
}

static __always_inline int
_bpf_utils_trace_func_exit(struct pt_regs *ctx, enum Domain domain, bool is_uprobe)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 cookie = bpf_get_attach_cookie(ctx);
  struct entry_key_t key = {.id = pid_tgid, .cookie = cookie};
  struct entry_val_t *entry_val_p;
  u64 duration_ns;
  u64 duration_us;
  bool is_sampled_event;
  u32 func_enum_key;

  entry_val_p = bpf_map_lookup_elem(&entry_traces, &key);
  if (!entry_val_p)
  {
    return 0;
  }

  duration_ns = bpf_ktime_get_ns() - entry_val_p->ts;
  func_enum_key = (u32)key.cookie;

  struct latency_stats_t *stats = bpf_map_lookup_elem(&func_latency_stats, &func_enum_key);
  if (stats)
  {
    stats->count++;
    stats->total_duration_ns += duration_ns;

    // Convert duration to microseconds for sum of squares to prevent overflow
    duration_us = duration_ns / 1000;
    stats->sum_sq_duration_us += duration_us * duration_us;
  }

  u32 random = bpf_get_prandom_u32();
  is_sampled_event = ((random & 0x3FF) == 0);

  if (is_sampled_event)
  {
    struct data_t data = {};
    data.domain = domain;
    data.func_name = (enum FunctionName)key.cookie;
    data.duration_ns = duration_ns;
    data.timestamp_ns = entry_val_p->ts;
    data.pid = key.id >> 32;
    data.tid = (u32)key.id;
    data.cpu_id = bpf_get_smp_processor_id();
    data.user_stack_id = -1;
    data.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

    if (is_uprobe)
    {
      data.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
  }

  bpf_map_delete_elem(&entry_traces, &key);
  return 0;
}

SEC("kprobe/iommu_map")
int BPF_KPROBE(kprobe_iommu_map, struct iommu_domain *domain, unsigned long iova,
               phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/iommu_map")
int BPF_KRETPROBE(kretprobe_iommu_map, int ret)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("kprobe/__iommu_map")
int BPF_KPROBE(kprobe___iommu_map, struct iommu_domain *domain, unsigned long iova,
               phys_addr_t paddr, size_t size, int prot, gfp_t gfp)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/__iommu_map")
int BPF_KRETPROBE(kretprobe___iommu_map, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("kprobe/intel_iommu_iotlb_sync_map")
int BPF_KPROBE(kprobe_intel_iommu_iotlb_sync_map, struct iommu_domain *domain,
               unsigned long iova, size_t size)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/intel_iommu_iotlb_sync_map")
int BPF_KRETPROBE(kretprobe_intel_iommu_iotlb_sync_map, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("kprobe/iommu_unmap")
int BPF_KPROBE(kprobe_iommu_unmap, struct iommu_domain *domain,
               unsigned long iova, size_t size)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/iommu_unmap")
int BPF_KRETPROBE(kretprobe_iommu_unmap, size_t ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("kprobe/__iommu_unmap")
int BPF_KPROBE(kprobe___iommu_unmap, struct iommu_domain *domain,
               unsigned long iova, size_t size,
               struct iommu_iotlb_gather *iotlb_gather)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/__iommu_unmap")
int BPF_KRETPROBE(kretprobe___iommu_unmap, size_t ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("kprobe/intel_iommu_tlb_sync")
int BPF_KPROBE(kprobe_intel_iommu_tlb_sync, struct iommu_domain *domain,
               struct iommu_iotlb_gather *gather)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/intel_iommu_tlb_sync")
int BPF_KRETPROBE(kretprobe_intel_iommu_tlb_sync)
{
  return _bpf_utils_trace_func_exit(ctx, HOST, false);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:address_space_rw")
int BPF_UPROBE(uprobe_address_space_rw, void *as, u64 addr, u64 attrs,
               void *buf, u64 len, int is_write)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:address_space_rw")
int BPF_URETPROBE(uretprobe_address_space_rw, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:address_space_write")
int BPF_UPROBE(uprobe_address_space_write, void *as, u64 addr, u64 attrs,
               const void *buf, u64 len)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:address_space_write")
int BPF_URETPROBE(uretprobe_address_space_write, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vtd_mem_write")
int BPF_UPROBE(uprobe_vtd_mem_write, void *opaque, u64 addr,
               u64 val, unsigned int size)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vtd_mem_write")
int BPF_URETPROBE(uretprobe_vtd_mem_write)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_container_dma_map")
int BPF_UPROBE(uprobe_vfio_container_dma_map, void *bcontainer, u64 iova,
               u64 size, void *vaddr, int readonly)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_container_dma_map")
int BPF_URETPROBE(uretprobe_vfio_container_dma_map, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_container_dma_unmap")
int BPF_UPROBE(uprobe_vfio_container_dma_unmap, void *bcontainer, u64 iova,
               u64 size, void *iotlb)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_container_dma_unmap")
int BPF_URETPROBE(uretprobe_vfio_container_dma_unmap, int ret_val)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_region_write")
int BPF_UPROBE(uprobe_vfio_region_write, void *opaque, u64 addr,
               u64 data, unsigned int size)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vfio_region_write")
int BPF_URETPROBE(uretprobe_vfio_region_write)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}

SEC("uprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vtd_iommu_translate")
int BPF_UPROBE(uprobe_vtd_iommu_translate, void *iommu, u64 addr,
               u64 flag, int iommu_idx)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("uretprobe//home/saksham/viommu/vanilla-source-code/qemu-viommu/build/qemu-system-x86_64:vtd_iommu_translate")
int BPF_URETPROBE(uretprobe_vtd_iommu_translate, void *ret_val_ptr)
{
  return _bpf_utils_trace_func_exit(ctx, QEMU, true);
}
