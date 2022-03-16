#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H
#include <stdint.h>
#define F (1<<14)
#define INT_MAX ((1<<31) - 1)
#define INT_MIN (-(1<<31))

static inline int n_to_fp(int n) {return n*F;}
static inline int fp_to_n(int x) {return x/F;}
static inline int fp_to_n_rounded(int x) {return (x >=0 ? (x + F/2)/F : (x - F/2)/F);}
static inline int fp_plus_fp(int x, int y) {return x + y;}
static inline int fp_plus_n(int x, int n) {return x + n*F;}
static inline int fp_minus_fp(int x, int y) {return x - y;}
static inline int fp_minus_n(int x, int n) {return x - n*F;}
static inline int fp_mul_fp(int x, int y) {return ((int64_t)x)*y/F;}
static inline int fp_mul_n(int x, int n) {return x*n;}
static inline int fp_div_fp(int x, int y) {return ((int64_t)x)*F/y;}
static inline int fp_div_n(int x, int n) {return x/n;}

#endif /* threads/fixed-point.h */