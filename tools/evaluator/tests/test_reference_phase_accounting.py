from tee_tls_eval.analysis import reconstruct_reference_opportunities, phase_opportunities, phase_summary


def test_missed_slots_are_assigned_to_their_own_phases():
    # A long emitted probe at 1 s causes the 2, 3, 4 and 5 s schedule slots
    # to be missed before the next emitted probe at 6 s.  The load ends at
    # 4.5 s, so 2/3/4 belong to load while 5 belongs to recovery.
    rows = [
        {"scheduled_elapsed_us":"0","elapsed_run_us":"70","missed_slots_before":"0","result_code":"0","probe_total_us":"20000"},
        {"scheduled_elapsed_us":"1000000","elapsed_run_us":"1000080","missed_slots_before":"0","result_code":"-2","failure_stage":"tcp_connect","probe_total_us":""},
        {"scheduled_elapsed_us":"6000000","elapsed_run_us":"6000500","missed_slots_before":"4","result_code":"0","probe_total_us":"21000"},
    ]
    opportunities, period_us = reconstruct_reference_opportunities(rows, 1000.0)
    assert period_us == 1_000_000.0
    assert [o["_scheduled_elapsed_s"] for o in opportunities] == [0.0,1.0,2.0,3.0,4.0,5.0,6.0]

    baseline = phase_summary(phase_opportunities(opportunities, 0.0, 1.0))
    load = phase_summary(phase_opportunities(opportunities, 1.0, 4.5))
    recovery = phase_summary(phase_opportunities(opportunities, 4.5, 7.0))

    assert baseline["scheduled_opportunities"] == 1
    assert baseline["successes"] == 1
    assert load["scheduled_opportunities"] == 4
    assert load["successes"] == 0
    assert load["missed_slots"] == 3
    assert load["failure_stages"] == {"tcp_connect": 1, "missed_slot": 3}
    assert recovery["scheduled_opportunities"] == 2
    assert recovery["successes"] == 1
    assert recovery["missed_slots"] == 1


def test_period_can_be_inferred_from_missed_slot_gap():
    rows = [
        {"scheduled_elapsed_us":"0","elapsed_run_us":"0","missed_slots_before":"0","result_code":"0"},
        {"scheduled_elapsed_us":"5000000","elapsed_run_us":"5000100","missed_slots_before":"4","result_code":"0"},
    ]
    opportunities, period_us = reconstruct_reference_opportunities(rows)
    assert period_us == 1_000_000.0
    assert [o["_scheduled_elapsed_s"] for o in opportunities] == [0.0,1.0,2.0,3.0,4.0,5.0]
