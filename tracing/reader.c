#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

// Include our tracing_utils.h so we get struct data_t and enums
#include "tracing_utils.h"

// Maximum stack depth matches the BPF program
#define MAX_STACK_DEPTH 127

// A simple structure to hold one stack_id → array of IPs
typedef struct
{
  uint32_t stack_id;
  uint32_t frame_count;
  uint64_t *ips; // array of length frame_count
} stack_entry;

// A dynamically growing list of stack_entry
static stack_entry *stacks = NULL;
static size_t num_stacks = 0;

// Look up a stack_id in our array; returns pointer to its ips[] and sets out_count.
// If not found, returns NULL and out_count = 0.
static uint64_t *lookup_stack(uint32_t sid, uint32_t *out_count)
{
  for (size_t i = 0; i < num_stacks; i++)
  {
    if (stacks[i].stack_id == sid)
    {
      *out_count = stacks[i].frame_count;
      return stacks[i].ips;
    }
  }
  *out_count = 0;
  return NULL;
}

// Reimplementation of func_name_to_string, copied from loader for consistency
static const char *func_name_to_string(enum FunctionName fn)
{
  switch (fn)
  {
  case IOMMU_MAP:
    return "iommu_map";
  case IOMMU_MAP_INTERNAL:
    return "__iommu_map";
  case IOMMU_IOTLB_SYNC_MAP:
    return "intel_iommu_iotlb_sync_map";
  case IOMMU_UNMAP:
    return "iommu_unmap";
  case IOMMU_UNMAP_INTERNAL:
    return "__iommu_unmap";
  case IOMMU_TLB_SYNC:
    return "intel_iommu_tlb_sync";
  case QEMU_ADDRESS_SPACE_RW:
    return "qemu:address_space_rw";
  case QEMU_ADDRESS_SPACE_WRITE:
    return "qemu:address_space_write";
  case QEMU_VTD_MEM_WRITE:
    return "qemu:vtd_mem_write";
  case QEMU_VFIO_DMA_MAP:
    return "qemu:vfio_container_dma_map";
  case QEMU_VFIO_DMA_UNMAP:
    return "qemu:vfio_container_dma_unmap";
  case QEMU_VFIO_REGION_WRITE:
    return "qemu:vfio_region_write";
  case QEMU_VTD_IOMMU_TRANSLATE:
    return "qemu:vtd_iommu_translate";
  default:
    return "UnknownFunction";
  }
}

// KRT = $(grep " [tT] _text$" / proc / kallsyms | awk '{print $1}')
// KLN = $(nm ~/ viommu / vanilla - source - code / linux - 6.12.9 / vmlinux | grep " T _text$" | awk '{print $1}')
// Compute slide and offset, then call addr2line on a given IP(e.g.IP_RUN):
// IP_RUN = 0xffffffffc05f7484
// Convert hex to decimal, then back to hex after subtraction:
// slide = $((0x $KRT - 0x $KLN))
// OFFSET = $((0x $IP_RUN - slide))
// addr2line -f - C - e ~/viommu/vanilla-source-code/linux-6.12.9/vmlinux $(printf "0x%x" $OFFSET)
static void resolve_and_print(const char *binary_path, uint64_t ip)
{
  // addr2line -f -C -e <binary> <hex_address>
  // The "-f" prints the function name, "-C" demangles C++.
  char cmd[512];
  snprintf(cmd, sizeof(cmd),
           "addr2line -f -C -e %s %llx 2>/dev/null",
           binary_path, (unsigned long long)ip);
  FILE *pipe = popen(cmd, "r");
  if (!pipe)
  {
    fprintf(stderr, "    [addr2line error for %s at 0x%llx]\n",
            binary_path, (unsigned long long)ip);
    return;
  }
  char line[512];
  while (fgets(line, sizeof(line), pipe))
  {
    // Each line from addr2line ends in a newline already.
    printf("    %s", line);
  }
  pclose(pipe);
}

int main(int argc, char **argv)
{
  if (argc != 5)
  {
    fprintf(stderr,
            "Usage: %s <events_file> <stacks_file> <vmlinux_path> <qemu_path>\n"
            "  events_file:    binary dump of struct data_t from tracer\n"
            "  stacks_file:    binary dump of (stack_id, frame_count, ips[])\n"
            "  vmlinux_path:   path to the vmlinux image for kernel symbols\n"
            "  qemu_path:      path to the QEMU binary for user symbols\n",
            argv[0]);
    return 1;
  }
  const char *events_path = argv[1];
  const char *stacks_path = argv[2];
  const char *vmlinux_path = argv[3];
  const char *qemu_path = argv[4];

  // --- 1) Load all stack traces into memory ---
  FILE *sf = fopen(stacks_path, "rb");
  if (!sf)
  {
    fprintf(stderr, "ERROR: fopen stacks_file '%s': %s\n", stacks_path, strerror(errno));
    return 1;
  }
  while (true)
  {
    uint32_t sid;
    if (fread(&sid, sizeof(sid), 1, sf) != 1)
    {
      // Either EOF or error; break if feof, otherwise report.
      if (feof(sf))
        break;
      fprintf(stderr, "ERROR: reading stack_id: %s\n", strerror(errno));
      fclose(sf);
      return 1;
    }
    uint32_t frame_count;
    if (fread(&frame_count, sizeof(frame_count), 1, sf) != 1)
    {
      fprintf(stderr, "ERROR: reading frame_count for stack_id %u\n", sid);
      fclose(sf);
      return 1;
    }
    uint64_t *ips = NULL;
    if (frame_count > 0)
    {
      ips = malloc(frame_count * sizeof(uint64_t));
      if (!ips)
      {
        fprintf(stderr, "ERROR: malloc for ips[%u]\n", frame_count);
        fclose(sf);
        return 1;
      }
      if (fread(ips, sizeof(uint64_t), frame_count, sf) != frame_count)
      {
        fprintf(stderr, "ERROR: reading IPs for stack_id %u\n", sid);
        free(ips);
        fclose(sf);
        return 1;
      }
    }
    // Append to our stacks[] array
    stack_entry *tmp = realloc(stacks, (num_stacks + 1) * sizeof(stack_entry));
    if (!tmp)
    {
      fprintf(stderr, "ERROR: realloc for stacks array\n");
      free(ips);
      fclose(sf);
      return 1;
    }
    stacks = tmp;
    stacks[num_stacks].stack_id = sid;
    stacks[num_stacks].frame_count = frame_count;
    stacks[num_stacks].ips = ips;
    num_stacks++;
  }
  fclose(sf);
  printf("Loaded %zu stack(s) from '%s'\n", num_stacks, stacks_path);

  // --- 2) Open events file and process each event ---
  FILE *ef = fopen(events_path, "rb");
  if (!ef)
  {
    fprintf(stderr, "ERROR: fopen events_file '%s': %s\n", events_path, strerror(errno));
    // Free stacks memory
    for (size_t i = 0; i < num_stacks; i++)
    {
      free(stacks[i].ips);
    }
    free(stacks);
    return 1;
  }

  struct data_t event;
  while (fread(&event, sizeof(event), 1, ef) == 1)
  {
    // Print the basic event information
    const char *dom_str = (event.domain == GUEST) ? "GUEST" : (event.domain == HOST) ? "HOST"
                                                                                     : "QEMU";
    const char *fn_str = func_name_to_string(event.func_name);
    printf("EVENT: domain=%s func=%s pid=%u tid=%u cpu=%u ts_ns=%llu dur_ns=%llu\n",
           dom_str,
           fn_str,
           event.pid,
           event.tid,
           event.cpu_id,
           (unsigned long long)event.timestamp_ns,
           (unsigned long long)event.duration_ns);

    // --- Resolve kernel stack if present ---
    if (event.kern_stack_id >= 0)
    {
      uint32_t fc = 0;
      uint64_t *ips = lookup_stack((uint32_t)event.kern_stack_id, &fc);
      if (ips && fc > 0)
      {
        printf("  Kernel Stack (id=%u, %u frames):\n",
               (uint32_t)event.kern_stack_id, fc);
        for (uint32_t i = 0; i < fc; i++)
        {
          printf("    [%2u] 0x%016llx\n", i, (unsigned long long)ips[i]);
          resolve_and_print(vmlinux_path, ips[i]);
        }
      }
      else
      {
        printf("  Kernel Stack: [no frames or not found for id=%u]\n",
               (uint32_t)event.kern_stack_id);
      }
    }

    // --- Resolve user (QEMU) stack if present ---
    if (event.user_stack_id >= 0)
    {
      uint32_t fc = 0;
      uint64_t *ips = lookup_stack((uint32_t)event.user_stack_id, &fc);
      if (ips && fc > 0)
      {
        printf("  User Stack (id=%u, %u frames):\n",
               (uint32_t)event.user_stack_id, fc);
        for (uint32_t i = 0; i < fc; i++)
        {
          resolve_and_print(qemu_path, ips[i]);
        }
      }
      else
      {
        printf("  User Stack: [no frames or not found for id=%u]\n",
               (uint32_t)event.user_stack_id);
      }
    }
    printf("\n");
  }

  fclose(ef);

  // --- Cleanup ---
  for (size_t i = 0; i < num_stacks; i++)
  {
    free(stacks[i].ips);
  }
  free(stacks);

  return 0;
}