#include <stdint.h>

#define F (1<<14)
#define INT_MAX ((1<<31) - 1)
#define INT_MIN (-(1<<31))

int n_to_fp(int n) {return n*F;}

int fp_to_n(int x) {return x/F;}

int fp_to_n_rounded(int x) {return (x >=0 ? (x + F/2)/F : (x - F/2)/F);}

int add_fp(int x, int y) {return x + y;}

int add_n_to_fp(int x, int n) {return x + n*F;}

int sub_fp(int x, int y) {return x - y;}

int sub_n_from_fp(int x, int n) {return x - n*F;}

int mul_fp(int x, int y) {return ((int64_t)x)*y/F;}

int mul_fp_by_n(int x, int n) {return x*n;}

int div_fp(int x, int y) {return ((int64_t)x)*F/y;}

int div_dp_by_n(int x, int n) {return x/n;}