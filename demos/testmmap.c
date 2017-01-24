/*
  Test memory-mapped access to peripheral space.

  Copyright (C) 2014 ARM Ltd.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void show_mem(void const *vav, unsigned long size, unsigned long phys_addr)
{
    unsigned char const *va = (unsigned char const *) vav;
    int i;
    for (i = 0; i < size && i < 4096; i += 32) {
        int j;
        printf("V:0x%lx P:0x%lx ", (unsigned long) (va + i),
               phys_addr + i);
        for (j = 0; j < 32; ++j) {
            printf(" %02x", va[i + j]);
        }
        printf("\n");
    }
}


int usage(void)
{
    fprintf(stderr, "testmmap [--file <fn>] <addr> <size>\n");
    return EXIT_FAILURE;
}


int main(int argc, char **argv)
{
    unsigned long phys_addr;
    unsigned long size;
    unsigned long page_size;
    void *virt_addr;
    int fd;
    off_t seek_rc;
    char const *mem_file = "/dev/mem";
    int got_phys_addr = 0, got_size = 0;

    page_size = sysconf(_SC_PAGE_SIZE);
    fprintf(stderr, "page size: %lu\n", page_size);
    fprintf(stderr, "sizeof(void *) == %u\n",
            (unsigned int) sizeof(void *));
    fprintf(stderr, "sizeof(off_t) == %u\n", (unsigned int) sizeof(off_t));

    while (*++argv) {
        char const *arg = *argv;
        if (arg[0] == '-') {
            ++arg;
            if (!strcmp(arg, "-file")) {
                ++argv;
                if (!*argv)
                    return usage();
                mem_file = *argv;
            } else {
                return usage();
            }
        } else {
            if (!got_phys_addr) {
                sscanf(arg, "%lx", &phys_addr);
                got_phys_addr = 1;
            } else if (!got_size) {
                sscanf(arg, "%lx", &size);
                got_size = 1;
            } else {
                return usage();
            }
        }
    }
    if (!got_size)
        return usage();
    fd = open(mem_file, O_RDONLY);
    if (fd < 0) {
        perror(mem_file);
        return 1;
    }
    fprintf(stderr, "opened %s, mapping 0x%lX size 0x%lX\n", mem_file,
            phys_addr, size);
    virt_addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, phys_addr);
#if 0
    if (virt_addr == MAP_FAILED) {
        /* Try variant that specifies offset in pages not bytes */
        virt_addr =
            mmap2(NULL, size, PROT_READ, MAP_SHARED, fd, phys_addr >> 12);
    }
#endif
    if (virt_addr != MAP_FAILED) {
        fprintf(stderr, "mapped at %p\n", virt_addr);
        show_mem(virt_addr, size, phys_addr);
        munmap(virt_addr, size);
    } else {
        perror("mmap");
    }
    /* Now try seeking */
    seek_rc = lseek64(fd, phys_addr, SEEK_SET);
    if (seek_rc != (off_t) (-1)) {
        int n;
        unsigned char *buf = (unsigned char *) malloc(size);
        fprintf(stderr, "seeked ok\n");
        n = read(fd, buf, size);
        if (n < 0) {
            perror("read");
        } else {
            fprintf(stderr, "read %u bytes\n", n);
        }
    } else {
        perror("lseek");
        fprintf(stderr, "could not seek to 0x%lX\n", phys_addr);
    }
    close(fd);
    return 0;
}

/* end of testmmap.c */
