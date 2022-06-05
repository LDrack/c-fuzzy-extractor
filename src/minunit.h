// file: minunit.h
// https://jera.com/techinfo/jtns/jtn002

// Adapted by LD: print OK and FAIL message stating test name 2022-02-13

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                               if (message) { printf("[FAIL] error in %s\n", #test);\
                                              printf("%s\n", message); } \
                               printf("[OK] %s finished\n", #test); } while (0)
                                   /*     return message; } \  */   // this returns after a fail, printf doesn't
extern int tests_run;
