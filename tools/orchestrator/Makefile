PYTHON ?= python3

.PHONY: check test-scheduled test-dut-server-detach-root test-loadgen-detach-root test-remote-preflights-root

check:
	$(PYTHON) -m py_compile orchestrate.py orchestration/scheduled_exec.py plotting/plot_reference_client.py
	bash -n scripts/install_local_dependencies.sh
	bash -n scripts/deploy_remote_helpers.sh
	bash -n scripts/check_ssh_access.sh
	bash -n scripts/campaign_init.sh
	bash -n scripts/run_iperf_logged.sh
	sh -n remote/tee-tls-dut-agent
	@if command -v busybox >/dev/null 2>&1; then busybox sh -n remote/tee-tls-dut-agent; fi
	bash -n remote/tee-tls-loadgen-agent
	$(PYTHON) tests/test_config_render.py
	$(PYTHON) tests/test_ssh_config.py
	$(PYTHON) tests/test_external_tcp_support.py
	$(PYTHON) tests/test_clock_probe.py
	$(PYTHON) tests/test_archive_transfer.py
	$(PYTHON) tests/test_reference_config.py
	$(PYTHON) tests/test_cli_defaults.py
	$(PYTHON) tests/test_run_validation.py
	$(PYTHON) tests/test_campaign_lock.py
	$(PYTHON) tests/test_sweep_matrix.py
	$(MAKE) test-scheduled

test-scheduled:
	bash tests/test_scheduled_exec.sh
	bash tests/test_remote_agent_environment.sh
	bash tests/test_agent_archive.sh
	bash tests/test_dut_server_detach.sh
	bash tests/test_loadgen_detach.sh
	bash tests/test_remote_preflights.sh

# The production DUT agent intentionally requires UID 0. The default check
# remains usable from the unprivileged orchestrator account; this explicit
# target exercises the detached server lifecycle with its real root check.
test-dut-server-detach-root:
	bash tests/test_dut_server_detach.sh --require-root

# Exercises the detached load-generator scheduler lifecycle as root.
test-loadgen-detach-root:
	bash tests/test_loadgen_detach.sh --require-root

# Exercises both generated remote preflight contracts with mock binaries/configs.
test-remote-preflights-root:
	bash tests/test_remote_preflights.sh --require-root
