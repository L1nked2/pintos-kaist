#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <debug.h>
#include <round.h>
#include <stdbool.h>
#include <stdint.h>

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

void timer_print_stats (void);

/* functions for thread sleep */
void thread_sleep_until(int64_t ticks);
void refresh_sleep_list(void);
bool compare_thread_wakeup(struct list_elem* a,
	struct list_elem* b, void* aux UNUSED);
#endif /* devices/timer.h */
