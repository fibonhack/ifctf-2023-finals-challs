

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <fcntl.h>
#include <string.h>

#include <seccomp.h>


#define CODE_SIZE 0x1000
#define STACK_SIZE 0x200000
#define MAPS_COUNT 0x30


typedef struct memory_map {
  void* start;
  size_t size;
} memory_map_t;


void enter_shellcode(void* code, void* stack, memory_map_t* maps);
void shellcode_end();

void setup() {
  setvbuf(stdout, (char*) NULL, 2, 0);
  setvbuf(stdin, (char*) NULL, 2, 0);
  setvbuf(stderr, (char*) NULL, 2, 0);
}

void fatal(char*) __attribute__((noreturn));

void fatal(char* errmsg) {
  perror(errmsg);
  exit(-1);
}

uint64_t addr_to_page(uint64_t addr) {
  addr >>= 12;
  addr <<= 12;
  addr <<= 16;
  addr >>= 16;
  return addr;
}

void* try_map(size_t size) {
  uint64_t addr;
  char random_buf[8];
  void* region;

  for (int i = 0; i < 5; i++) {
    if (getrandom(random_buf, 8, GRND_RANDOM) == -1) fatal("Random number");
    addr = *((uint64_t*) random_buf);
    addr = addr_to_page(addr);
    region = mmap((void*) addr, size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) fatal("Region allocation");
    if (region == (void*) addr) return region;
    munmap(region, size);
  }
  fatal("Region different from position");
}

void get_memory_maps(memory_map_t* maps) {
  char content[0x2000];
  int done = 0;
  ssize_t count;
  char* scorr;
  int fd;

  fd = open("/proc/self/maps", O_RDONLY);
  if (fd < 0) fatal("open maps");
  count = read(fd, content, 0x2000);
  if (count < 0) fatal("Read error");
  if (count == 0x2000) fatal("Buf size");

  scorr = strtok(content, "\n");
  for (scorr = strtok(NULL, "\n"); scorr != NULL; scorr = strtok(NULL, "\n")) {
    uint64_t start = 0, end = 0;
    sscanf(scorr, "%lx-%lx", &start, &end);
    maps[done].start = (void*) start;
    maps[done].size = end - start;
    // printf("Memory map: %p sz %p\n", maps[done].start, (void*) maps[done].size);
    done++;
    if (done > MAPS_COUNT) fatal("too many maps");
  }
}

void get_shellcode(void** code_ptr, void** stack_ptr, memory_map_t** maps_ptr) {
  void *code, *stack;
  memory_map_t maps[MAPS_COUNT];
  uint64_t size = ((uint64_t) shellcode_end) - ((uint64_t) enter_shellcode);

  memset(maps, 0, sizeof(memory_map_t)*MAPS_COUNT);
  get_memory_maps(maps);

  code = try_map(CODE_SIZE);
  stack = try_map(STACK_SIZE);
  memset(code, 0x90, CODE_SIZE);
  memcpy(stack, maps, sizeof(memory_map_t)*MAPS_COUNT);

  memcpy(code, (void*) enter_shellcode, size);
  if (read(STDIN_FILENO, (void*) (((uint64_t) code) + size + 0x10), CODE_SIZE - size - 0x10) < 0) fatal("Read failed");
  if (mprotect(code, CODE_SIZE, PROT_READ | PROT_EXEC) == -1) fatal("mprotect failed");

  *code_ptr = code;
  *stack_ptr = (void*) ((uint64_t) stack + STACK_SIZE);
  *maps_ptr = stack;

}


void sandbox() {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_load(ctx);
}


int main() {
  void *code, *stack;
  memory_map_t* maps;


  setup();
  get_shellcode(&code, &stack, &maps);
  sandbox();
  enter_shellcode(code, stack, maps);

  return 0;
}
