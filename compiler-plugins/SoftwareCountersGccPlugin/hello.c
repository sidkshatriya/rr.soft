#include <cerrno>
#include <stdio.h>
#include <assert.h>

extern int __attribute__((visibility("hidden"), weak)) volatile __soft_cnt_enable;
extern "C" void __attribute__((visibility("hidden"), weak))
__do_software_count(void);

int bye() {
  // Manually insert to make sure it is possible to make a call manually
  __do_software_count();
  return 42;
}

int main() {
  int ret = printf("__soft_cnt_enable value: 0x%x\n", __soft_cnt_enable);
  assert(__soft_cnt_enable == 0x8000'0000 || __soft_cnt_enable == -ENOSYS ||
         __soft_cnt_enable == 1);
  if (ret > 14) {
    // plugin should add a call to __do_software_count() in this block
    puts("hello again!");
  }
  printf("__soft_cnt_enable value now: %d\n", __soft_cnt_enable);
  // Gets set to 1 if running under rr
  assert(__soft_cnt_enable == -ENOSYS || __soft_cnt_enable == 1);
  printf("bye() says: %d\n", bye());
  return 0;
}
