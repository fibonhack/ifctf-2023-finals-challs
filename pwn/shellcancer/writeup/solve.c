#define _GNU_SOURCE
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF_SIZE 0x1000
#define FLAG_SIZE 0x80

struct linux_dirent {
  unsigned long  d_ino;
  off_t          d_off;
  unsigned short d_reclen;
  char           d_name[];
};


void fatal(char* msg) {
  char buf[5];
  buf[0] = 'F';
  buf[1] = 'A';
  buf[2] = 'T';
  buf[3] = 'A';
  buf[4] = 'L';
  write(STDOUT_FILENO, buf, 5);
  puts(msg);
  exit(-1);
}



int puts(const char* msg) {
  const char* scorr = msg;
  int size = 0;
  while (*scorr != 0) {
    size++;
    scorr++;
  }
  write(STDOUT_FILENO, msg, size);

  char cusu = 0xa;
  write(STDOUT_FILENO, &cusu, 0x1);
}

void dfs(int rootfd) {
  char d_type;
  char buf[BUF_SIZE];
  char flag[FLAG_SIZE];
  long nread;
  struct linux_dirent  *d;
  int fd;

  for (;;) {
    nread = syscall(SYS_getdents, rootfd, buf, BUF_SIZE);
    if (nread == -1) fatal("getdents");
    if (nread == 0) break;

    for (size_t bpos = 0; bpos < nread;) {
      d = (struct linux_dirent *) (buf + bpos);
      d_type = *(buf + bpos + d->d_reclen - 1);
      switch (d_type) {
      case DT_DIR:
        if (d->d_name[0] == '.') break;
        // puts(d->d_name);
        fd = openat(rootfd, d->d_name, O_RDONLY | O_DIRECTORY);
        if (fd < 0) fatal("Failed openat directory");
        dfs(fd);
        close(fd);
        break;
      case DT_REG: case DT_LNK:
        fd = openat(rootfd, d->d_name, O_RDONLY);
        if (fd < 0) fatal("Failed openat file");
        read(fd, flag, FLAG_SIZE);
        close(fd);
        puts(flag);
        break;
      default:
        puts("Unhandled case for file");
        break;
      }
      bpos += d->d_reclen;
    }
  }
}


void _start() {
  char buf[8];
  buf[0] = '.';
  buf[1] = '\0';
  int rootfd = open(buf, O_RDONLY);
  if (rootfd < 0) fatal("failed open");
  dfs(rootfd);
  exit(0);
}
