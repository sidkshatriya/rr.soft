#include "locations.h"
#include <stdint.h>
#include <stdio.h>

volatile int64_t *const ticks = (volatile int64_t *const)RR_CUSTOM_TICKS_ADDR;

int main() {
  //   printf("Current ticks: %ld\n", *ticks);
  return 0;
}
