#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tracing_utils.h"

char LICENSE[] SEC("license") = "GPL";

#define SAMPLE_RATE_POW2 1024
#define SAMPLE_MASK (SAMPLE_RATE_POW2 - 1)

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, 16384);
  __type(key, struct entry_key_t);
  __type(value, struct entry_val_t);
} entry_traces SEC(".maps");

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
  // u32 rnd = bpf_get_prandom_u32();
  // if (rnd & SAMPLE_MASK)
  //   return 0;

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

  entry_val_p = bpf_map_lookup_elem(&entry_traces, &key);
  if (!entry_val_p)
  {
    return 0;
  }

  u64 duration_ns;
  u64 duration_us;
  bool is_sampled_event;
  u32 func_enum_key;

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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
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
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
}

SEC("kprobe/page_pool_alloc_netmem")
int BPF_KPROBE(kprobe_page_pool_alloc_netmem, struct page_pool *pool, gfp_t gfp)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/page_pool_alloc_netmem")
int BPF_KRETPROBE(kretprobe_page_pool_alloc_netmem, void *ret)
{
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
}

SEC("kprobe/__page_pool_alloc_pages_slow")
int BPF_KPROBE(kprobe___page_pool_alloc_pages_slow, struct page_pool *pool, gfp_t gfp)
{
  return _bpf_utils_trace_func_entry(ctx);
}

SEC("kretprobe/__page_pool_alloc_pages_slow")
int BPF_KRETPROBE(kretprobe___page_pool_alloc_pages_slow, void *ret)
{
  return _bpf_utils_trace_func_exit(ctx, GUEST, false);
}