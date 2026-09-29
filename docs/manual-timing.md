# Manual audit timing

Method: for each trial I start the stopwatch, run `show running-config` (or open the file), and work through docs/manual-checklist.md until every rule is marked pass or fail. I search the config for each rule instead of reading it top to bottom. Each trial uses a different target, so I can't answer from memory. My stopwatch starts after login, while the tool's clock includes login, so the comparison favors the manual audit. I report the median.

| Trial | Date | Target | Minutes:seconds | Rules I marked failing | Rules ConfigSentry marked failing |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-09-28 | Practice file with 4 hidden faults | 5:53 | CS-01, CS-02, CS-03, CS-05, CS-07, CS-08, CS-09, CS-10 | CS-01, CS-07, CS-08, CS-10 |
| 2 | 2026-09-28 | DevNet Cat8K (live) | 5:07 | CS-03, CS-04, CS-08, CS-09, CS-10 | CS-01, CS-05, CS-06, CS-12 |
| 3 | 2026-09-28 | Second practice file with 4 hidden faults | 4:55 | CS-01, CS-05, CS-08, CS-12 | CS-01, CS-05, CS-08, CS-12 |

Network used for both measurements: campus Wi-Fi. Manual median: 5:07.
ConfigSentry median from results/timing-c8k.json: 3.83 seconds over 10 runs (range 3.57 to 4.11 s).

Notes:

- This was my first time auditing CIS rules by hand. I matched ConfigSentry on 11 of 15 rules in trial 1, 6 of 15 in trial 2, and 15 of 15 in trial 3.
- Most of my misses were missing lines. A missing `ip ssh version 2` or `ip ssh time-out` means fail, but a missing `exec-timeout` means the 10-minute default, which passes. In trial 1 I also read the fake `line vty` config inside the practice file's banner as real config.
- An earlier attempt on the Cat8K (55 seconds) is not counted, because I ticked the boxes without checking the config.
- I had already seen ConfigSentry's report for the Cat8K before trial 2. The tool's answers for trial 2 come from an audit run later the same evening.
- The DevNet Cat9K sandbox was unreachable all evening (SSH reset before the login banner, and HTTPS returned 502 from Cisco's gateway), so the second practice file replaced the planned Cat9K trial.
