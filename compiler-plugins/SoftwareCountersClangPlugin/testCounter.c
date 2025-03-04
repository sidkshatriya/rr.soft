#include "locations.h"
#include <stdint.h>
#include <stdio.h>

volatile int64_t *const curr_ticks = (volatile int64_t *)RR_CUSTOM_TICKS_ADDR;
volatile int64_t *const accum_ticks = (volatile int64_t *)RR_CUSTOM_ACCUM_TICKS_ADDR;
__attribute__((visibility("hidden"))) extern int __soft_cnt_enable;

int main() {
  for (int i = 0; i < 20; i++) {
    printf("Loop variable i: %d\n", i);
    if (__soft_cnt_enable > 0) {
      printf("Current ticks: %ld\n", *accum_ticks + *curr_ticks);
    }
  }
  if (__soft_cnt_enable > 0) {
    printf("Current ticks: %ld\n", *accum_ticks + *curr_ticks);
  }
  return 0;
}
