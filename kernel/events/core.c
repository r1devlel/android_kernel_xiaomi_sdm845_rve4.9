	event->clock = &local_clock;
	if (parent_event)
		event->clock = parent_event->clock;

	if (!overflow_handler && parent_event) {
		overflow_handler = parent_event->overflow_handler;
		context = parent_event->overflow_handler_context;
#if defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_EVENT_TRACING)
		if (overflow_handler == bpf_overflow_handler) {
			struct bpf_prog *prog = parent_event->prog;

			bpf_prog_inc(prog);
			event->prog = prog;
			event->orig_overflow_handler =
				parent_event->orig_overflow_handler;
		}
#endif
	}

	if (overflow_handler) {
		event->overflow_handler	= overflow_handler;