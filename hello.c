#include <stdio.h>
int x = 8;

int main(int argc, char ** argv) {
  unsigned char * p = (unsigned char *) &main;
  x += argc;
  long off = - ((long) p & 4095);
  printf("Sizeof(long)=%ld, x=%d\n", sizeof(long), x);
  while (off < 0) {
    printf("0x%lx = %d\n", (long)p+off, p[off]);
    off++;
  }

  printf("Hi world\n");
  printf("Hello world\n");
}
