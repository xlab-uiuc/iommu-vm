#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <argp.h>
#include <limits.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "guest_tracer.skel.h"
#include "tracing_utils.h"

#define PERF_BUFFER_PAGES 64
#define MAX_PROBES 50
#define MAX_STACK_DEPTH 127

static volatile bool exiting = false;
static FILE *output_event_file = NULL;
static FILE *output_agg_data_file = NULL;
static FILE *stack_trace_file = NULL;

// --- Command Line Argument Parsing ---
static struct arguments
{
  int duration_sec;
  bool verbose;
  char *output_filepath;
  char *agg_data_filepath;
  char *stack_trace_filepath;
} args = {
    .duration_sec = 30,
    .verbose = false,
    .output_filepath = "guest_trace_events.bin",
    .agg_data_filepath = "guest_aggregate.csv",
    .stack_trace_filepath = "guest_stack_trace.bin"};

static char doc[] = "eBPF loader for kernel tracing.";
static char args_doc[] = "";
static struct argp_option opts[] = {
    {"duration", 'd', "SECONDS", 0, "Duration to run the tracer (0 for infinite, default: 30)"},
    {"verbose", 'v', NULL, 0, "Enable libbpf verbose logging"},
    {"agg-data-file", 'h', "FILE", 0, "Output structured aggregate data to CSV FILE (e.g., agg_data.csv)."},
    {"output-file", 'o', "FILE", 0, "Output sampled events to binary FILE "},
    {"stack-file", 's', "FILE", 0, "Output stack traces to binary FILE "},
    {NULL}};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;
  switch (key)
  {
  case 'd':
    arguments->duration_sec = atoi(arg);
    break;
  case 'v':
    arguments->verbose = true;
    break;
  case 'h':
    arguments->agg_data_filepath = arg;
    break;
  case 'o':
    arguments->output_filepath = arg;
    break;
  case 's':
    arguments->stack_trace_filepath = arg;
    break;
  case ARGP_KEY_ARG:
    return ARGP_ERR_UNKNOWN;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}
static struct argp argp_parser = {
    .options = opts,
    .parser = parse_arg,
    .args_doc = args_doc,
    .doc = doc,
};

static void sig_handler(int sig)
{
  (void)sig;
  exiting = true;
}

// Probe Definitions (ensure FunctionName enum values match cookies)
typedef enum
{
  PROBE_TYPE_KPROBE,
  PROBE_TYPE_KRETPROBE,
} probe_type_t;

typedef struct
{
  const char *bpf_prog_name;
  const char *target_name;
  probe_type_t type;
  enum FunctionName cookie;
} probe_def_t;

probe_def_t probes_to_attach[] = {
    {"kprobe_iommu_map", "iommu_map", PROBE_TYPE_KPROBE, IOMMU_MAP},
    {"kretprobe_iommu_map", "iommu_map", PROBE_TYPE_KRETPROBE, IOMMU_MAP},
    {"kprobe___iommu_map", "__iommu_map", PROBE_TYPE_KPROBE, IOMMU_MAP_INTERNAL},
    {"kretprobe___iommu_map", "__iommu_map", PROBE_TYPE_KRETPROBE, IOMMU_MAP_INTERNAL},
    {"kprobe_intel_iommu_iotlb_sync_map", "intel_iommu_iotlb_sync_map", PROBE_TYPE_KPROBE, IOMMU_IOTLB_SYNC_MAP},
    {"kretprobe_intel_iommu_iotlb_sync_map", "intel_iommu_iotlb_sync_map", PROBE_TYPE_KRETPROBE, IOMMU_IOTLB_SYNC_MAP},
    {"kprobe_iommu_unmap", "iommu_unmap", PROBE_TYPE_KPROBE, IOMMU_UNMAP},
    {"kretprobe_iommu_unmap", "iommu_unmap", PROBE_TYPE_KRETPROBE, IOMMU_UNMAP},
    {"kprobe___iommu_unmap", "__iommu_unmap", PROBE_TYPE_KPROBE, IOMMU_UNMAP_INTERNAL},
    {"kretprobe___iommu_unmap", "__iommu_unmap", PROBE_TYPE_KRETPROBE, IOMMU_UNMAP_INTERNAL},
    {"kprobe_intel_iommu_tlb_sync", "intel_iommu_tlb_sync", PROBE_TYPE_KPROBE, IOMMU_TLB_SYNC},
    {"kretprobe_intel_iommu_tlb_sync", "intel_iommu_tlb_sync", PROBE_TYPE_KRETPROBE, IOMMU_TLB_SYNC},
};
const int num_probes_to_attach = sizeof(probes_to_attach) / sizeof(probes_to_attach[0]);
struct bpf_link *attached_links[MAX_PROBES];

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args_list)
{
  if (level == LIBBPF_DEBUG && !args.verbose)
    return 0;
  return vfprintf(stderr, format, args_list);
}

const char *func_name_to_string(enum FunctionName fn)
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
  default:
    return "UnknownFunction";
  }
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
  struct data_t *event = (struct data_t *)data;
  fwrite(event, sizeof(struct data_t), 1, output_event_file);
}

static void dump_aggregate_to_file(FILE *fp, struct guest_tracer_bpf *skel)
{
  int err = 0;
  int num_cpus;

  if (!fp)
    return;

  int map_fd = bpf_map__fd(skel->maps.func_latency_stats);
  if (map_fd < 0)
  {
    fprintf(stderr, "Failed to get func_latency_stats map FD: %s\n", strerror(errno));
    return;
  }

  num_cpus = libbpf_num_possible_cpus();
  if (num_cpus <= 0)
  {
    fprintf(stderr, "ERROR: Could not get number of possible CPUs\n");
    return;
  }

  // Columns: function_name, total_count, total_duration_ns, mean_ns, variance_us
  fprintf(fp, "function,count,total_duration_ns,mean_ns,variance_us\n");

  // For each FunctionName enum (0..FUNCTION_NAME_MAX-1), pull the per-CPU array
  for (int fn = 0; fn < FUNCTION_NAME_MAX; fn++)
  {
    size_t per_cpu_sz = sizeof(struct latency_stats_t);
    size_t buf_sz = per_cpu_sz * num_cpus;
    struct latency_stats_t *percpu_stats = malloc(buf_sz);
    if (!percpu_stats)
    {
      fprintf(stderr, "WARNING: malloc failed for function %d\n", fn);
      continue;
    }

    err = bpf_map_lookup_elem(map_fd, &fn, percpu_stats);
    if (err)
    {
      free(percpu_stats);
      continue;
    }

    // Combine per‐CPU stats
    __u64 total_count = 0;
    __u64 total_duration_ns = 0;
    __u64 total_sum_sq_us = 0;

    for (int cpu = 0; cpu < num_cpus; cpu++)
    {
      struct latency_stats_t *s = &percpu_stats[cpu];
      total_count += s->count;
      total_duration_ns += s->total_duration_ns;
      total_sum_sq_us += s->sum_sq_duration_us;
    }
    free(percpu_stats);

    if (total_count == 0)
    {
      continue;
    }

    double mean_ns = (double)total_duration_ns / (double)total_count;
    double mean_us = mean_ns / 1000.0;

    // variance in µs units = E[x²] – (E[x])², where x is duration in µs
    double variance_us = ((double)total_sum_sq_us / (double)total_count) - (mean_us * mean_us);

    fprintf(fp, "%s,%llu,%llu,%.2f,%.2f\n",
            func_name_to_string((enum FunctionName)fn),
            (unsigned long long)total_count,
            (unsigned long long)total_duration_ns,
            mean_ns,
            variance_us);
  }
}

static void dump_stack_trace_map(FILE *fp, struct guest_tracer_bpf *skel)
{
  if (!fp)
    return;

  int map_fd = bpf_map__fd(skel->maps.stack_traces);
  if (map_fd < 0)
  {
    fprintf(stderr, "Failed to get stack_traces map FD: %s\n", strerror(errno));
    return;
  }

  u32 prev_key = (u32)-1, next_key;
  // walk all stack_ids in the map
  while (bpf_map_get_next_key(map_fd, &prev_key, &next_key) == 0)
  {
    // next_key is a valid stack_id
    u64 ips[MAX_STACK_DEPTH];
    if (bpf_map_lookup_elem(map_fd, &next_key, ips) != 0)
    {
      fprintf(stderr, "WARN: Failed to lookup stack_id %u while dumping\n", next_key);
      prev_key = next_key;
      continue;
    }

    if (fwrite(&next_key, sizeof(next_key), 1, fp) != 1)
      goto write_err;
    u32 frame_count = 0;
    for (int i = 0; i < MAX_STACK_DEPTH; i++)
    {
      if (ips[i] == 0)
        break;
      frame_count++;
    }
    if (fwrite(&frame_count, sizeof(frame_count), 1, fp) != 1)
      goto write_err;
    if (frame_count > 0)
    {
      if (fwrite(ips, sizeof(u64) * frame_count, 1, fp) != 1)
        goto write_err;
    }

    prev_key = next_key;
  }
  return;

write_err:
  perror("Failed to write to stack map dump");
}

int main(int argc, char **argv)
{
  struct guest_tracer_bpf *skel = NULL;
  struct perf_buffer *pb = NULL;
  int err = 0;
  struct timespec start_ts, now_ts;
  int attached_count = 0;

  err = argp_parse(&argp_parser, argc, argv, 0, NULL, &args);
  if (err)
    return err;

  if (args.output_filepath)
  {
    output_event_file = fopen(args.output_filepath, "wb");
    if (!output_event_file)
    {
      perror("Failed to open output binary file");
      return EXIT_FAILURE;
    }
    printf("Outputting sampled events to binary file: %s\n", args.output_filepath);
  }
  if (args.agg_data_filepath)
  {
    output_agg_data_file = fopen(args.agg_data_filepath, "w"); // Create/overwrite
    if (!output_agg_data_file)
    {
      perror("Failed to open output file for aggregate data");
      if (output_event_file)
        fclose(output_event_file);
      return EXIT_FAILURE;
    }
    printf("Outputting structured aggregate data to: %s\n", args.agg_data_filepath);
  }
  if (args.stack_trace_filepath)
  {
    stack_trace_file = fopen(args.stack_trace_filepath, "wb");
    if (!stack_trace_file)
    {
      perror("Failed to open output file for stack traces");
      if (output_event_file)
        fclose(output_event_file);
      if (output_agg_data_file)
        fclose(output_agg_data_file);
      return EXIT_FAILURE;
    }
    printf("Outputting stack traces to: %s\n", args.stack_trace_filepath);
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_print_fn);

  skel = guest_tracer_bpf__open_and_load();
  if (!skel)
  {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    err = 1;
    goto cleanup_file;
  }

  printf("Attaching probes...\n");
  for (int i = 0; i < num_probes_to_attach; i++)
  {
    probe_def_t *p_def = &probes_to_attach[i];
    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, p_def->bpf_prog_name);
    if (!prog)
    {
      fprintf(stderr, "Failed to find BPF program '%s' in skeleton\n", p_def->bpf_prog_name);
      err = -ENOENT;
      goto cleanup_file;
    }

    struct bpf_link *link = NULL;
    if (p_def->type == PROBE_TYPE_KPROBE)
    {
      LIBBPF_OPTS(bpf_kprobe_opts, k_opts, .bpf_cookie = p_def->cookie);
      link = bpf_program__attach_kprobe_opts(prog, p_def->target_name, &k_opts);
    }
    else if (p_def->type == PROBE_TYPE_KRETPROBE)
    {
      LIBBPF_OPTS(bpf_kprobe_opts, kr_opts, .bpf_cookie = p_def->cookie, .retprobe = true);
      link = bpf_program__attach_kprobe_opts(prog, p_def->target_name, &kr_opts);
    }

    if (!link || libbpf_get_error(link))
    {
      err = libbpf_get_error(link);
      fprintf(stderr, "Failed to attach %s '%s' to '%s': %s\n",
              p_def->type == PROBE_TYPE_KPROBE ? "kprobe" : "kretprobe",
              p_def->bpf_prog_name, p_def->target_name, strerror(-err));
      goto cleanup_file;
    }
    attached_links[attached_count++] = link;
  }
  printf("All %d probes attached successfully.\n", attached_count);

  // For perf buffer, pass skel as context if not writing to file,
  // otherwise output_event_file is used directly in handle_event.
  // To keep handle_event signature stable, we pass skel.
  pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
                        handle_event, NULL, skel, NULL);
  if (!pb)
  {
    err = -errno;
    fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(-err));
    goto cleanup_file;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  printf("Tracer started. Hit Ctrl-C to end or run for %d seconds.\n", args.duration_sec);

  clock_gettime(CLOCK_MONOTONIC, &start_ts);

  while (!exiting)
  {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
    if (err == -EINTR)
    {
      err = 0;
      continue;
    }
    if (err < 0)
    {
      if (err != -EBADF)
      {
        fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
      }
      break;
    }

    if (args.duration_sec > 0)
    {
      clock_gettime(CLOCK_MONOTONIC, &now_ts);
      if (now_ts.tv_sec - start_ts.tv_sec >= args.duration_sec)
      {
        exiting = true;
        break;
      }
    }
  }
  perf_buffer__poll(pb, 0);

  // Final histogram print and stack map dump
  if (skel)
  {
    if (output_agg_data_file)
      dump_aggregate_to_file(output_agg_data_file, skel);

    if (stack_trace_file)
      dump_stack_trace_map(stack_trace_file, skel);
  }

cleanup_file:
  if (output_event_file)
  {
    printf("Closing binary output file: %s\n", args.output_filepath);
    if (fclose(output_event_file) != 0)
      perror("Failed to close output binary file");
    output_event_file = NULL;
  }
  if (output_agg_data_file)
  {
    printf("Closing aggregate data file: %s\n", args.agg_data_filepath);
    if (fclose(output_agg_data_file) != 0)
      perror("Failed to close aggregate data file");
    output_agg_data_file = NULL;
  }
  if (stack_trace_file)
  {
    printf("Closing binary stack trace output file: %s\n", args.stack_trace_filepath);
    if (fclose(stack_trace_file) != 0)
      perror("Failed to close output binary file");
    stack_trace_file = NULL;
  }

  printf("Cleaning up BPF resources...\n");
  if (pb)
  { // Free perf buffer before destroying links that might be in use by callback
    perf_buffer__free(pb);
    pb = NULL;
  }
  for (int i = 0; i < attached_count; i++)
  {
    if (attached_links[i])
    {
      bpf_link__destroy(attached_links[i]);
      attached_links[i] = NULL;
    }
  }
  if (skel)
  {
    guest_tracer_bpf__destroy(skel);
    skel = NULL;
  }
  printf("Cleanup complete. Exiting with code %d.\n", err ? 1 : 0);
  return err ? 1 : 0;
}
