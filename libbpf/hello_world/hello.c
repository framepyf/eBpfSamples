#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
        int trace_fd;

        trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
        if (trace_fd < 0)
                return;

        while (1) {
                static char buf[4096];
                ssize_t sz;

                sz = read(trace_fd, buf, sizeof(buf));
                if (sz > 0) {
                        buf[sz] = 0;
                        puts(buf);
                }
        }
}


int main(int argc, char **argv) {
   struct bpf_object *obj;
   struct bpf_program *prog;
   char filename[256] = {0};
   int err = 0;
    struct bpf_link *link = NULL;

   snprintf(filename, sizeof(filename), "%s", argv[1]);
   
   obj = bpf_object__open_file(filename, NULL);

   if (libbpf_get_error(obj))
                return 1;

    prog = bpf_object__find_program_by_name(obj, "bpf_prog");
    if (!prog) {
                fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
                goto cleanup;
        }


    err = bpf_object__load(obj);
        if (err)
                return 1;


 link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
                fprintf(stderr, "ERROR: bpf_program__attach failed\n");
                link = NULL;
                goto cleanup;
        }

  read_trace_pipe();

cleanup:
        bpf_link__destroy(link);
        bpf_object__close(obj);
  return 0;
}
