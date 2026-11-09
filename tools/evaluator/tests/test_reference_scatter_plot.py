from tee_tls_eval.reporting import _reference_plot_points


def test_reference_points_preserve_independent_successes_and_missed_slots():
    rows = [
        {"elapsed_run_us":"70","scheduled_elapsed_us":"0","missed_slots_before":"0","result_code":"0","probe_total_us":"20000"},
        {"elapsed_run_us":"1000084","scheduled_elapsed_us":"1000000","missed_slots_before":"0","result_code":"0","probe_total_us":"21000"},
        # Slots at 2 s and 3 s were missed before the emitted 4 s probe.
        {"elapsed_run_us":"4000500","scheduled_elapsed_us":"4000000","missed_slots_before":"2","result_code":"0","probe_total_us":"25000"},
        {"elapsed_run_us":"5000200","scheduled_elapsed_us":"5000000","missed_slots_before":"0","result_code":"-2","probe_total_us":""},
    ]
    points = _reference_plot_points(rows, "probe_total_us")
    assert points["success_x"] == [0.0, 1.0, 4.0]
    assert points["success_y"] == [20.0, 21.0, 25.0]
    assert points["failed_x"] == [5.0]
    assert points["missed_x"] == [2.0, 3.0]


def test_reference_points_use_metric_only_for_successes():
    rows = [
        {"elapsed_run_us":"1000000","scheduled_elapsed_us":"1000000","missed_slots_before":"0","result_code":"-1","app_rtt_us":""},
    ]
    points = _reference_plot_points(rows, "app_rtt_us")
    assert points["success_x"] == []
    assert points["success_y"] == []
    assert points["failed_x"] == [1.0]
