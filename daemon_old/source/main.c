#include "pool.h"

int main(void) {
	event_thread_pool_t *pool = event_thread_pool_new();
	event_thread_pool_start(pool);
	event_thread_pool_send_notification(pool, "HEN-V started");
	event_thread_pool_wait(pool);
	event_thread_pool_join(pool);
	event_thread_pool_delete(pool);
	return 0;
}
