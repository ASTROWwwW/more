# Validation

How the changes were checked, with the real results. Part 3 covers the branch `isolation/ledger-process`, part 2 the branch `hardening/ledger-authority`. Parts 2 and 1 are the reports written for those branches, kept as they were.

## Part 3: `isolation/ledger-process`

Environment: Linux, Rust 1.97.0, November 10, 2026. Baseline: `main` at `8ed2001`. Commit checked: `7efdd07`. The commits after it change documentation only: `git diff 7efdd07 HEAD -- crates tests scripts .github Cargo.toml Cargo.lock` prints nothing.

This part covers the whole branch: the ledger in its own process (step 1) and the review of that step. It does not cover persistence, which is out of scope: the ledger process loses its state when it stops and is not for credits that are worth anything.

### Commands and results

| Command | Where | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | local, CI | Clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | local, CI | Clean |
| `cargo check --workspace --all-targets` on Rust 1.88 | CI | Passes |
| `python3 scripts/mutation.py --check` | local, CI | 208 of 208 anchors match exactly one place |
| `cargo test --workspace` (overflow checks on) | local, CI | 194 passed, 0 failed, 3 ignored: the cost measurement and the two that need root |
| `cargo test --release --workspace` | local, CI | 194 passed, 0 failed, 3 ignored |
| The process tests with `--ignored`, started as root | local, CI job `isolation` | 2 passed: three system users, then the differential tests as the orchestrator's user |
| `PROPTEST_CASES=5000 cargo test --release --workspace` | local, CI | 194 passed. Locally: 17,544 traces, 3,290,510 commands checked, property tests 114.3 s |
| `PROPTEST_CASES=16000 cargo test --release -p more-ledgerd --test process p3` | local | 3,000 daemons started; 60,867 hostile calls, 12,253 transactions and 113,052 commands compared; 45 s |
| `PROPTEST_CASES=20000 cargo test --release -p gpu-ledger --test hostile` | local | 20,000 hostile sequences of up to 119 ledger calls, no violation, 40 s |
| `python3 scripts/mutation.py --shard=K/4`, K = 0..3 | CI | 208 of 208 mutants caught by a failing test; 0 compile errors; 0 missed |

CI is GitHub Actions run [42845772394](https://github.com/ASTROWwwW/more/actions/runs/42845772394) on `7efdd07`: format, lints, minimum Rust version, debug and release tests, the three-users job, the reference run and the four mutation shards.

### The review, point by point

| Asked | What was done | Tests | Mutants |
| --- | --- | --- | --- |
| Lose the answer exactly after a `Commit` was applied | A link that fails at a chosen request, in process and in front of the real daemon. The ledger commits; the coordinator gets nothing, stops, reconnects, asks, takes the state that goes with the commit. Both ledgers hold the same journal afterwards: applied once | `link_faults::r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice`, `r5_a_commit_applied_by_the_daemon_whose_answer_was_lost_is_found_again`, `r5_a_commit_is_done_not_applied_or_unknown_and_a_failed_connection_is_dead` | M181, M182, M183, M184, M185, M188 |
| A stable transaction identity and a way to ask for its state | `TxId` (instance, counter), used once; outcome log of 1,024; `TxStatus`, answered to the orchestrator whatever the ledger is doing | `r5_the_outcome_of_a_transaction_can_be_asked_and_a_name_is_used_once` | M172 to M177, M179 |
| Never run again a transaction whose outcome is unknown | The coordinator refuses every command until the ledger has answered; "open" and "unknown" keep it stopped; a name is never reused | `link_faults::r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `…r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline`, `…r5_an_outcome_the_ledger_forgot_is_left_to_a_person`, `…r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome` | M183, M186, M187, M192, M193 |
| No claim of full distributed atomicity | `SECURITY_ARCHITECTURE.md` section 11 says what holds and what does not; LEDGER-025 | | |
| The deadline applies to the owner's own requests | Checked on every request, the owner's first | `r5_a_deadline_binds_the_owner_of_a_transaction_too` (active, commit late) | M144, M168, M169 |
| Idle transaction | The daemon's timer; `LedgerHost::sweep` | same test (idle), `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` (total silence, timer seen on standard error) | M178, M201 |
| Active transaction past its deadline | | both tests above | M169 |
| Nested transaction | The deadline is the outermost one's | both tests above | M170, M151 |
| Cut connection | Rolled back, recorded as such, nothing kept about the connection | `a_killed_orchestrator_leaves_nothing_half_done`, `a_transaction_is_all_or_nothing_and_bounded`, `r5_a_connection_that_timed_out_is_not_used_again` | M147, M165, M171, M180, M205 |
| Expired transactions cleaned up, resources released | Snapshots dropped at rollback; the list of connections to tell is emptied when they close; outcome log bounded | `r5_a_deadline_binds_the_owner_of_a_transaction_too` (`retained`), `r5_the_outcome_…` | M171, M175 |
| Two distinct system users | Ledger, orchestrator and a bystander under three users; the differential tests run as the orchestrator's user | `r5_two_users_the_orchestrator_reaches_the_ledger_through_its_socket_only` (root) | M194, M196 |
| A socket policy that fits, never all local users | `--allow-uid` (kernel-reported peer), `--socket-group` (0660), default 0600 | `r5_the_socket_admits_listed_users_only`, `r5_the_daemon_checks_its_own_options` | M163, M194 to M197, M206 |
| Persistence out of scope, losses documented | LEDGER-026; `SECURITY_ARCHITECTURE.md` section 11 | | |
| Identifiers and protocol ready for recovery | Transaction names, outcome log, incarnation in `Info` and `TxStatus` | `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_restarted_daemon_is_another_ledger_and_says_so` | M189, M190, M191, M202 |
| Not presented as ready for real credits | Banner at every start; README; LEDGER-026 | `r5_a_restarted_daemon_is_another_ledger_and_says_so` reads it | M203 |
| Also found: no deadline on authentication | 2 s for the whole handshake | `r5_a_connection_that_does_not_authenticate_in_time_is_closed` | M198, M199, M200, M204 |

### Differential tests against the real process

Every figure here is from a run against `more-ledgerd` started as a separate process and reached over its Unix socket. The loopback runs are listed for comparison only.

| Test | Where the ledger is | What is compared | Volume |
| --- | --- | --- | --- |
| TEST-P35 | This process, behind the link's messages | Hostile calls: answer, balances, journal, whole state | 5,000 sequences of up to 119 calls (reference run) |
| TEST-P35 | `more-ledgerd`, a daemon per sequence | Hostile calls: answer, balances, journal | Reference run: 312 daemons, 19,213 calls. `PROPTEST_CASES=16000`: 1,000 daemons, 60,867 calls |
| TEST-P35 | `more-ledgerd` under another system user | Same | One daemon, one trace of 20,000 calls (local as root, and CI job `isolation`) |
| TEST-P36 | This process, behind the link's messages | Transactions committed or aborted against copy-and-restore: whole state | 5,000 sequences of up to 23 transactions (reference run) |
| TEST-P36 | `more-ledgerd`, a daemon per sequence | Same, as the daemon's auditor sees it: balances, journal, position, clock | Reference run: 312 daemons, 3,772 transactions. `PROPTEST_CASES=16000`: 1,000 daemons, 12,253 transactions |
| TEST-P36 | `more-ledgerd` under another system user | Same | One daemon, 1,000 transactions |
| TEST-P37 | This process, behind the link's messages | Two coordinators and two ledgers, command by command | 1,250 traces, 230,206 commands (reference run) |
| TEST-P37 | `more-ledgerd`, a daemon per trace | Same | Reference run: 312 daemons, 35,213 commands. `PROPTEST_CASES=16000`: 1,000 daemons, 113,052 commands |
| TEST-P37 | `more-ledgerd` under another system user | Same | One daemon, one trace of 4,122 commands |
| Answer lost after a commit, and commit lost on the way | `more-ledgerd` | Both coordinators and both ledgers once the outcome has been asked | One scenario each way, then more commands on both sides |

What the comparison is: after every call (TEST-P35) the two ledgers must give the same answer and hold the same balances and journal head; after every command (TEST-P37) the two coordinators must give the same answer and hold the same jobs, slices, registry, delivery book, audit log and log position, and the two ledgers the same balances, journal and clock. One difference fails the test.

The three-users run uses one daemon per deployment, so each property gets one long trace there instead of many short ones. The daemon's user is 61001, the test's 61002, and the socket's group 61500. The services on the test's side (orchestrator, treasury, clock, platform admin, auditor, identity) all connect from user 61002, each with its own key.

### Tests, before and after

| Suite | `main` | Now | Added on this branch |
| --- | --- | --- | --- |
| `more-identity` (unit) | 8 | 10 | a service's key and certificate, signed revocations |
| `gpu-ledger` (unit) | 6 | 6 | |
| `gpu-ledger` (API) | 29 | 29 | |
| `gpu-ledger` (link, in process) | 0 | 20 | encoding, handshake, roles, transactions, TEST-P35, TEST-P36; review: outcomes, deadlines, the three ends of a commit |
| `gpu-ledger` (doc test) | 1 | 1 | |
| `gpu-protocol` (unit) | 4 | 4 | |
| `tests/properties` | 5 | 6 | TEST-P37; one ignored cost measurement |
| `tests/scenarios` | 46 | 46 | |
| `tests/regressions` | 10 | 10 | |
| `tests/security` | 41 | 47 | six tests of a link that fails around a commit |
| `more-ledgerd` (real process) | 0 | 15 | TEST-P35, TEST-P36 and TEST-P37 against the daemon, killed orchestrator, garbage on the socket, private files, memory; review: deadlines, lost answer, restart, timed-out connection, authentication deadline, admitted users, options, ping. Two more need root (three users) |
| **Total** | **150** | **194** | plus 2 that need root |

No test was removed. Changes to existing tests are listed with their reason in `docs/AUDIT_CODE.md` ("Test changes that need a justification", isolation and review of step 1).

### Mutation campaign

208 mutants: the 134 of part 2, 35 for step 1 (M133 to M167, nine of them re-anchored after the review), 39 for the review (M168 to M206). Each one puts a defect back into the production code; the whole suite then runs in release mode with 300 traces per generator. The counting rules are those of part 2. One was added: a suite that does not end within 25 minutes is stopped with every process it started and counts as a detection. It did not happen in this campaign.

Result on `7efdd07`: **208 of 208 caught by a failing test. Compile errors: none. Missed: none.** Each shard printed `commit 7efdd079034cb88a1607f9e719cac1507932cc79` before its first mutant.

Before the campaign, the 48 mutants added or re-anchored for the review were run locally without the four random generators and without TEST-P30: identity, the ledger's API and link tests (TEST-P35 and TEST-P36 included), protocol, the daemon's tests, scenarios, regressions, security, and TEST-P37. All 48 fail at least one of them. The 14 whose tests changed afterwards were run again the same way: all 14 fail.

#### What the campaign found

- **First full run, on `35f7ebf`: 207 of 208.** M166 (the daemon reads a frame of any length) passed. Its test expects the daemon to close a connection that announces four gigabytes. The authentication deadline added in the review closed that connection after two seconds whatever it had sent, inside the three seconds the test waited. The rule was still there; its test no longer showed it. The test now starts its daemon with a one-minute deadline (`090318f`).
- **A test that failed once under load.** While re-checking M166 with the directed tests, `r5_a_connection_that_timed_out_is_not_used_again` was listed as failing too. Run alone under the same mutant it passes three times out of three: the mutant has nothing to do with it. The test used a 200 ms answer timeout for a whole handshake and asserted that a dead connection refused in less than that. The process tests now use delays of one second and no assertion on speed (`7efdd07`); eight runs with three busy loops on two cores pass.
- **Second full run, on `7efdd07`: 208 of 208.** This is the commit this part describes.

One mutant is killed by a test binary that dies and not by an assertion: M156 (a list length trusted before the bytes are there) makes the decoder allocate until the process aborts. The runner reports it as such.

Defects without a mutant, and why:

- the time between `bind` and the change of the socket's mode. A connection made in that instant is checked against the list of users like any other (M194); there is nothing else to remove;
- a coordinator that reuses a transaction name. The counter only grows and no line resets it. The ledger's refusal of a known name has a mutant (M172).

The mutants of this branch:

| Mutation | Injected bug | Result | Caught by |
| --- | --- | --- | --- |
| M133 | A checked certificate vouches for another key | caught | `credential_cannot_be_altered` |
| M134 | The authority's signature does not cover the service's key | caught | `credential_cannot_be_altered` |
| M135 | An identity file may carry a key that is not the certified one | caught | `a_certificate_without_its_key_proves_nothing` |
| M136 | A revocation is accepted without the authority's signature | caught | `a_damaged_request_from_a_reader_writes_nothing`, `a_revoked_service_is_cut_off_on_its_next_request`, `revocations_travel_signed` |
| M137 | Link: a certificate opens a connection without proof of its key | caught | `a_copied_certificate_does_not_open_a_connection`, `a_recorded_handshake_cannot_be_replayed` |
| M138 | Link: any certificate is accepted at hello | caught | `a_revoked_service_is_cut_off_on_its_next_request`, `a_service_connects_as_itself_only`, `a_signed_revocation_reaches_a_ledger_that_only_knows_the_authoritys_key` and 1 more |
| M139 | Link: a hello for another deployment is accepted | caught | `a_service_connects_as_itself_only` |
| M140 | Link: any protocol version is accepted | caught | `a_service_connects_as_itself_only` |
| M141 | Link: a revoked service keeps its open connection | caught | `a_revoked_service_is_cut_off_on_its_next_request`, `a_signed_revocation_reaches_a_ledger_that_only_knows_the_authoritys_key`, `r5_a_commit_is_done_not_applied_or_unknown_and_a_failed_connection_is_dead` |
| M142 | Link: request numbers are not checked | caught | `the_handshake_has_one_order` |
| M143 | Link: others act on a ledger held by a transaction | caught | `a_killed_orchestrator_leaves_nothing_half_done`, `a_transaction_is_all_or_nothing_and_bounded`, `r5_a_deadline_binds_the_owner_of_a_transaction_too` and 1 more |
| M144 | Link: a transaction never times out | caught | `r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline`, `r5_a_deadline_binds_the_owner_of_a_transaction_too`, `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M145 | Link: any service may open a transaction | caught | `a_connection_has_its_own_rights_and_no_other` |
| M146 | Link: an aborted transaction is not undone | caught | `a_transaction_is_all_or_nothing_and_bounded`, `p36_transactions_in_the_daemon_match_copy_and_restore`, `p36_transactions_match_copy_and_restore` |
| M147 | Link: a closed connection keeps its uncommitted work | caught | `a_killed_orchestrator_leaves_nothing_half_done`, `a_revoked_service_is_cut_off_on_its_next_request`, `a_transaction_is_all_or_nothing_and_bounded` and 4 more |
| M148 | Link: no limit on the size of a transaction | caught | `a_transaction_too_large_is_rolled_back`, `r5_the_outcome_of_a_transaction_can_be_asked_and_a_name_is_used_once` |
| M149 | Link: no limit on nested transactions | caught | `a_transaction_is_all_or_nothing_and_bounded` |
| M150 | Link: any service may register account keys | caught | `a_connection_has_its_own_rights_and_no_other` |
| M151 | Link: a full rollback stops at the innermost transaction | caught | `a_transaction_is_all_or_nothing_and_bounded` |
| M152 | Link: the proof does not depend on the ledger's nonce (replay) | caught | `a_recorded_handshake_cannot_be_replayed` |
| M153 | Link: the client accepts a peer that is not a ledger | caught | `a_client_refuses_anything_but_its_deployments_ledger` |
| M154 | Link: the client does not check the ledger's proof | caught | `a_client_refuses_anything_but_its_deployments_ledger` |
| M155 | Link: bytes after a message are ignored | caught | `every_message_round_trips_and_nothing_else_decodes` |
| M156 | Link: a list length is trusted before the bytes are there | caught | `(a test binary died)` |
| M157 | Link: no limit on the length of a text | caught | `the_decoder_never_trusts_a_length` |
| M158 | Coordinator: no transaction around a command | caught | `a_coordinator_behind_the_link_matches_the_one_in_process`, `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there` and 7 more |
| M159 | Coordinator: a refused command is not rolled back at the ledger | caught | `a_coordinator_behind_the_link_matches_the_one_in_process`, `r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice`, `p37_a_coordinator_drives_a_ledger_in_another_process` and 1 more |
| M160 | Coordinator: an applied command is never committed | caught | `a_coordinator_behind_the_link_matches_the_one_in_process`, `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there` and 7 more |
| M161 | Coordinator: a repeated command leaves its transaction open | caught | `a_coordinator_behind_the_link_matches_the_one_in_process`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome`, `p37_a_coordinator_drives_a_ledger_in_another_process` and 1 more |
| M162 | Daemon: memory left readable by the same user | caught | `another_process_of_the_same_user_cannot_read_the_ledgers_memory` |
| M163 | Daemon: socket left with the default permissions | caught | `r5_the_socket_admits_listed_users_only`, `the_socket_and_the_key_file_are_private` |
| M164 | Daemon: key file readable by others accepted | caught | `r5_ping_answers_for_a_service_and_for_no_one_else`, `the_socket_and_the_key_file_are_private` |
| M165 | Daemon: a dead connection keeps its transaction | caught | `a_killed_orchestrator_leaves_nothing_half_done`, `r5_a_commit_applied_by_the_daemon_whose_answer_was_lost_is_found_again` |
| M166 | Daemon: a frame of any length is read | caught | `garbage_on_the_socket_does_not_stop_the_daemon` |
| M167 | Ledger: an operation runs under another role than the connection's | caught | `a_connection_has_its_own_rights_and_no_other`, `a_damaged_request_from_a_reader_writes_nothing`, `compromise_delivery_cannot_issue_or_move_credits` and 5 more |
| M168 | Link: the owner of a rolled-back transaction goes on outside it | caught | `r5_a_commit_is_done_not_applied_or_unknown_and_a_failed_connection_is_dead`, `r5_a_deadline_binds_the_owner_of_a_transaction_too`, `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M169 | Link: a transaction's deadline does not bind its owner | caught | `r5_a_deadline_binds_the_owner_of_a_transaction_too` |
| M170 | Link: a nested transaction restarts the deadline | caught | `r5_a_deadline_binds_the_owner_of_a_transaction_too`, `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M171 | Link: a connection that is gone stays on the list of expired ones | caught | `r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline`, `r5_a_deadline_binds_the_owner_of_a_transaction_too` |
| M172 | Link: a transaction name can be used twice | caught | `r5_the_outcome_of_a_transaction_can_be_asked_and_a_name_is_used_once` |
| M173 | Link: what became of a closed transaction is not recorded | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome`, `r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice` and 4 more |
| M174 | Link: a rollback is recorded as a commit | caught | `a_killed_orchestrator_leaves_nothing_half_done`, `a_transaction_is_all_or_nothing_and_bounded`, `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again` and 5 more |
| M175 | Link: the outcome log grows without bound | caught | `r5_an_outcome_the_ledger_forgot_is_left_to_a_person`, `r5_the_outcome_of_a_transaction_can_be_asked_and_a_name_is_used_once` |
| M176 | Link: any service may ask what became of a transaction | caught | `a_connection_has_its_own_rights_and_no_other`, `r5_the_outcome_of_a_transaction_can_be_asked_and_a_name_is_used_once` |
| M177 | Link: the outcome question waits behind an open transaction | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome`, `r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline` and 3 more |
| M178 | Link: a swept transaction's owner is not told | caught | `r5_a_commit_is_done_not_applied_or_unknown_and_a_failed_connection_is_dead`, `r5_a_deadline_binds_the_owner_of_a_transaction_too`, `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M179 | Link: a second Begin replaces the open transaction | caught | `a_transaction_is_all_or_nothing_and_bounded` |
| M180 | Client: a connection goes on after an answer was lost | caught | `r5_a_commit_is_done_not_applied_or_unknown_and_a_failed_connection_is_dead`, `r5_a_connection_that_timed_out_is_not_used_again` |
| M181 | Client: a commit without answer is reported as not applied | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome` and 5 more |
| M182 | Client: a commit without answer is reported as done | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome` and 5 more |
| M183 | Coordinator: goes on after a commit of unknown outcome | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline`, `r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice` and 2 more |
| M184 | Coordinator: a commit of unknown outcome is taken as applied | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome` and 4 more |
| M185 | Coordinator: a commit of unknown outcome is taken as not applied | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome` and 4 more |
| M186 | Coordinator: a transaction still open is taken as rolled back | caught | `r5_a_transaction_still_open_keeps_the_coordinator_stopped_until_its_deadline` |
| M187 | Coordinator: an outcome the ledger forgot is taken as rolled back | caught | `r5_an_outcome_the_ledger_forgot_is_left_to_a_person` |
| M188 | Coordinator: a committed transaction is resolved without taking its state | caught | `r5_a_lost_answer_inside_a_command_is_not_an_unknown_outcome`, `r5_an_answer_lost_after_the_commit_is_asked_about_and_nothing_is_sent_twice`, `r5_a_commit_applied_by_the_daemon_whose_answer_was_lost_is_found_again` |
| M189 | Coordinator: a restarted ledger is taken for the one that was there | caught | `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_restarted_daemon_is_another_ledger_and_says_so` |
| M190 | Coordinator: goes on against a ledger that lost its state | caught | `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there`, `r5_a_restarted_daemon_is_another_ledger_and_says_so` |
| M191 | Coordinator: stopped for a lost ledger, it takes a new connection all the same | caught | `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there` |
| M192 | Coordinator: the failed connection is kept open after reconnection | caught | `r5_a_commit_that_never_arrived_is_rolled_back_and_can_be_sent_again`, `r5_a_commit_applied_by_the_daemon_whose_answer_was_lost_is_found_again` |
| M193 | Coordinator: a connection that does not answer is taken | caught | `r5_a_ledger_that_restarted_is_not_mistaken_for_the_one_that_was_there` |
| M194 | Daemon: any local user may connect | caught | `r5_the_socket_admits_listed_users_only` |
| M195 | Daemon: its own user is admitted whatever the list says | caught | `r5_the_daemon_checks_its_own_options`, `r5_the_socket_admits_listed_users_only` |
| M196 | Daemon: root is admitted whatever the list says | caught | `r5_the_daemon_checks_its_own_options` |
| M197 | Daemon: a socket opened to a group is opened to everyone | caught | `r5_the_socket_admits_listed_users_only` |
| M198 | Daemon: no deadline on authentication | caught | `r5_a_connection_that_does_not_authenticate_in_time_is_closed` |
| M199 | Daemon: the authentication deadline restarts at every byte | caught | `r5_a_connection_that_does_not_authenticate_in_time_is_closed` |
| M200 | Daemon: an authenticated service is cut off after the authentication delay | caught | `r5_a_connection_that_does_not_authenticate_in_time_is_closed`, `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M201 | Daemon: nothing ends an idle transaction | caught | `r5_the_daemon_ends_a_transaction_past_its_deadline_by_itself` |
| M202 | Daemon: every start is the same incarnation | caught | `r5_a_restarted_daemon_is_another_ledger_and_says_so` |
| M203 | Daemon: starts without saying what it is not | caught | `r5_a_restarted_daemon_is_another_ledger_and_says_so` |
| M204 | Daemon: a timeout of zero is accepted | caught | `r5_the_daemon_checks_its_own_options` |
| M205 | Daemon client: waits for ever for an answer | caught | `r5_a_connection_that_timed_out_is_not_used_again` |
| M206 | Daemon: an option given twice is silently accepted | caught | `r5_the_daemon_checks_its_own_options` |

### What is not shown

- **Persistence and recovery.** Nothing is written to disk. No test restarts a coordinator, and none recovers a ledger: there is nothing to recover from.
- **A coordinator that dies with a commit in doubt.** The state that went with the commit is lost with it. The ledger may then hold a commit no coordinator knows of.
- **Other systems than Linux.** The daemon checks its peers with `SO_PEERCRED` and seals its memory with `prctl`; it does not build elsewhere.
- **A share of the ledger per service.** An authenticated service can hold all 64 connections, or open one 5 s transaction after another.
- **Time.** The process tests of deadlines use real delays: deadlines of one second, checks several hundred milliseconds away from them. A machine stalled for longer than that could make one fail. The same rules are tested without any clock in `crates/ledger/tests/link.rs`.
- **The three-users test needs root** and is skipped by a plain `cargo test`. CI runs it in the job `isolation`.
- **A network.** The link is for a local socket. Nothing here was tried across machines.

## Part 2: `hardening/ledger-authority`

Environment: Linux, Rust 1.97.0, November 10, 2026. Baseline: `main` at `e398159`. Commit checked: `bf61300`. Its production code is that of `6351a3f`; the two differ by two test files (see "What the campaign found"). The commits after `bf61300` change documentation only: `git diff bf61300 HEAD -- crates tests scripts .github Cargo.toml Cargo.lock` prints nothing.

### Commands and results

| Command | Where | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | local, CI | Clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | local, CI | Clean |
| `cargo check --workspace --all-targets` on Rust 1.88 | CI | Passes |
| `python3 scripts/mutation.py --check` | local, CI | 134 of 134 anchors match exactly one place |
| `cargo test --workspace` (overflow checks on) | local, CI | 150 passed, 0 failed, 1 ignored (the cost measurement) |
| `cargo test --release --workspace` | local, CI | 150 passed, 0 failed |
| `PROPTEST_CASES=5000 cargo test --release --workspace` | local, CI | 150 passed; 17,544 traces, 3,274,716 commands checked; property tests 101.6 s locally |
| `PROPTEST_CASES=20000 cargo test --release -p gpu-ledger --test hostile` | local | 20,000 hostile sequences of up to 119 ledger calls, no violation, 34 s |
| `python3 scripts/mutation.py --shard=K/4`, K = 0..3 | CI | 134 of 134 mutants caught by a failing test; 0 compile errors; 0 missed |

CI is GitHub Actions run [42810472870](https://github.com/ASTROWwwW/more/actions/runs/42810472870) on `bf61300`: format, lints, minimum Rust version, debug and release tests, the reference run and the four mutation shards. The local figures (reference run, cost) were measured on `6351a3f`, whose production code is the same.

### Tests, before and after

| Suite | `main` | Now | Added on this branch |
| --- | --- | --- | --- |
| `more-identity` (unit) | 4 | 8 | statements never collide, every statement is bound to its deployment, a restoration covers exactly the segments it names, the domain is the authority |
| `gpu-ledger` (unit) | 5 | 6 | a failed multi-entry operation writes nothing (moved inside the crate) |
| `gpu-ledger` (API, from outside the crate) | 9 | 29 | `authority.rs`: 19 direct attacks with a valid Orchestrator credential; `hostile.rs`: TEST-P30 and its coverage check |
| `gpu-ledger` (doc test) | 1 | 1 | |
| `gpu-protocol` (unit) | 4 | 4 | signature coverage now includes the deployment |
| `tests/properties` | 5 | 5 | TEST-P30 to TEST-P34 inside the same four generators; one ignored cost measurement |
| `tests/scenarios` | 46 | 46 | harness brings clusters up node by node |
| `tests/regressions` | 8 | 10 | CE-08, CE-09 |
| `tests/security` | 19 | 41 | per-node leases (6), recovery and corroboration (11), finality, segments, limits and fault sweep (5); one existing test extended for envelopes of another deployment |
| **Total** | **101** | **150** | |

No test was removed. Assertions that changed are listed with their reason in `docs/AUDIT_CODE.md` ("Test changes that need a justification", both sections).

### The third review, point by point

| Asked | Rule | Tests | Mutants that put the defect back |
| --- | --- | --- | --- |
| One contest window per payment; non-regression test for the day 0 / day 6 case | LEDGER-018, JOB-R22 | `ce09_staggered_payments_keep_their_own_contest_window`, `r3_staggered_payments_each_have_their_own_window`, `r2_contests_follow_a_bounded_cycle`, TEST-P33 | M97, M98, M104, M106, M107, M131 |
| A restoration receipt pays a segment only if it names it | JOB-R18, LEDGER-016 | `r3_a_corroboration_pays_only_the_segments_it_names`, `r3_a_segment_the_recipient_did_not_name_is_not_paid`, `a_restoration_covers_exactly_the_segments_it_names` | M92, M95, M103, M105, M121, M122, M123, M124, M127 |
| Signatures bound to a cryptographic domain identifier | LEDGER-019, PROTO-010 | `r3_statements_signed_for_another_deployment_are_refused`, `r3_statements_for_another_deployment_are_refused_by_the_coordinator`, `every_statement_is_bound_to_its_domain`, `unsigned_or_altered_messages_are_refused`, `r3_a_coordinator_refuses_a_ledger_it_cannot_rely_on` | M120, M129, M130, M132 |
| Lender or recipient revoked between the restoration signature and the corroboration; admissibility on recorded anteriority | JOB-R18, LEDGER-020 | `r3_no_proof_is_added_after_the_revocation`, `r3_a_corroboration_after_the_lender_is_revoked_proves_nothing`, `r3_a_corroboration_after_the_recipient_lease_expired_proves_nothing`, `r3_a_corroboration_by_an_expired_witness_proves_nothing`, `r3_a_right_withdrawn_before_the_corroboration_voids_it`, TEST-P34 | M108 to M119, M125, M126, M128 |

### Coverage of the reference run

`PROPTEST_CASES=5000`, four generators. Figures from `target/coverage/*.tsv`.

| Measure | General | Failures | Partial reserve | Delivery | Total |
| --- | --- | --- | --- | --- | --- |
| Traces | 5,011 | 5,011 | 2,511 | 5,011 | 17,544 |
| Commands run and checked | 667,617 | 1,044,356 | 491,000 | 1,071,743 | 3,274,716 |
| accepted | 475,812 | 758,994 | 363,403 | 834,042 | 2,432,251 |
| `UNAUTHORIZED` refusals | 8,804 | 10,085 | 4,568 | 10,361 | 33,818 |
| `INADMISSIBLE_PROOF` refusals | 3,046 | 3,546 | 1,538 | 12,347 | 20,477 |
| `LEASE_EXPIRED` refusals | 17,474 | 65,284 | 30,065 | 48,600 | 161,423 |
| Attempts revoked with an expired lease | 4,649 | 9,549 | 4,412 | 15,502 | 34,112 |
| Attempts revoked for one silent node | 638 | 1,453 | 679 | 1,429 | 4,199 |
| Resumes | 2,840 | 8,720 | 3,879 | 13,090 | 28,529 |
| Restorations corroborated | 14,027 | 33,171 | 15,552 | 37,813 | 100,563 |
| Recovery payments | 51 | 496 | 195 | 487 | 1,229 |
| Recovery held (cap or no corroboration) | 10 | 88 | 45 | 102 | 245 |
| Contribution payments | 521 | 2,933 | 1,218 | 2,477 | 7,149 |
| Items disputed | 30 | 471 | 188 | 167 | 856 |
| Payments by arbitration | 4 | 78 | 27 | 13 | 122 |
| Rewards released | 252 | 1,640 | 632 | 1,401 | 3,925 |
| Reward contests | 15 | 153 | 64 | 86 | 318 |

The generators do not withdraw pool rights in the middle of a job and rarely pay the same line twice at different dates. Those two paths are covered by the directed tests (`r3_a_right_withdrawn_…`, CE-09, `r3_staggered_payments_…`), not by the random traces.

### Mutation campaign

134 mutants: the 64 of part 1, 43 added for the second audit and its first two reviews, 27 for the third review (M106 to M132). Each one puts a defect back into the production code; the whole suite then runs in release mode with 300 traces per generator.

How a mutant is counted, as asked in review:

- caught only if at least one test fails. A mutant that does not compile is reported as `COMPILE ERROR` and counts for nothing;
- the generator coverage check does not count as a detection;
- seeds found against one mutant are discarded before the next;
- the script refuses to run on a modified tree and prints the commit it runs on.

Result on `bf61300`: **134 of 134 caught by a failing test. Compile errors: none. Missed: none.** Each shard printed `commit bf61300d7db4245cd88f2bfcb05af8625c4557c2` before its first mutant.

The 39 mutants re-anchored or added for the third review, and the two that the first run let through (see below), were also run locally against the directed tests alone (identity, ledger API, protocol, scenarios, regressions, security; no random traces). All 41 fail at least one of them, so each is killed by an assertion written for that rule and not only by a property that happens to notice.

Two defects that have no mutant, and why:

- removing the per-payment hold in the coordinator's release changes nothing: the coordinator releases a line only after its slice has been final for the JOB-R22 window, which is never shorter than the ledger's hold. The ledger's own check has a mutant (M97);
- removing the coordinator's check that a named segment was committed by the lender gives the same refusal, because the ledger refuses it too. The ledger's check has a mutant (M92). The same double barrier exists for a corroboration after the revocation; there the test also asserts that the coordinator refused without asking the ledger, which makes the coordinator's check killable (M111).

| Mutation | Injected bug | Result | Caught by |
| --- | --- | --- | --- |
| M01 | v2.1 bug: JOB-T04 resets execution_intent to initial | caught | TEST-P07; `f07_client_disconnect_stops_after_k_then_pauses`, `f10_low_escrow_blocks_window_then_pause_and_topup`, `f14_preemption_settles_slice_then_resumes` and 2 more |
| M02 | v2.1 bug: contribution payable on another attempt | caught | TEST-P06, TEST-P16; `f20_unvalidated_positions_are_wasted_not_billed` |
| M03 | v2.2 bug: contribution id without layer range | caught | TEST-P06, TEST-P16, TEST-P23; `ce03_commitment_after_slice_closure_proves_nothing`, `ce03_commitment_before_closure_still_counts`, `ce04_voided_output_after_closure_does_not_block_evaluation` and 27 more |
| M04 | v2.2 bug: no pending_evaluation at closure | caught | TEST-P06, TEST-P12, TEST-P16; `ce02_pool_relay_never_benefits_the_borrower`, `ce03_commitment_after_slice_closure_proves_nothing`, `ce03_commitment_before_closure_still_counts` and 37 more |
| M05 | Contest that creates credits | caught | TEST-P12; `ce02_pool_relay_never_benefits_the_borrower`, `ce09_staggered_payments_keep_their_own_contest_window`, `f40_sliding_cap_holds_across_midnight_and_after_refunds` and 2 more |
| M06 | Cancel allowed while settling | caught | `f09_cancel_and_finish_race` |
| M06b | Cancel allowed while settling (transition table too) | caught | TEST-P11; `f09_cancel_and_finish_race` |
| M07 | Flow control disabled | caught | TEST-P09; `f32_rewind_revokes_live_attempt_built_on_voided_outputs`, `f07_client_disconnect_stops_after_k_then_pauses` |
| M08 | Anti-collusion cap ignored | caught | TEST-P08; `ce09_staggered_payments_keep_their_own_contest_window`, `f40_sliding_cap_holds_across_midnight_and_after_refunds`, `f17_receipts_fabricated_after_revocation` and 1 more |
| M09 | Late commitment accepted as prior | caught | TEST-P08; `ce03_commitment_after_slice_closure_proves_nothing`, `f17_receipts_fabricated_after_revocation` |
| M09b | CE-03 back: bound = revocation, not slice closure | caught | TEST-P08; `ce03_commitment_after_slice_closure_proves_nothing` |
| M10 | Settlement forgets OutputHold | caught | TEST-P13, TEST-P30; `ce02_pool_relay_never_benefits_the_borrower`, `ce03_commitment_after_slice_closure_proves_nothing`, `ce03_commitment_before_closure_still_counts` and 38 more |
| M11 | CE-01 back: pool relay without active escrow | caught | TEST-P13, TEST-P17; `ce01_pool_cannot_fund_a_job_without_active_escrow` |
| M12 | CE-02 back: pool share returned to the borrower | caught | TEST-P06, TEST-P16; `ce01_pool_cannot_fund_a_job_without_active_escrow`, `ce02_pool_relay_never_benefits_the_borrower`, `r2_a_fault_at_any_entry_of_a_multi_job_reconciliation_leaves_nothing_half_done` and 5 more |
| M13 | Resume without state restore | caught | TEST-P07, TEST-P25; `f26_lost_ack_then_resume_replays_without_double_billing`, `f19_resume_after_pause_keeps_intent` |
| M14 | Work accepted on a revoked attempt | caught | TEST-P04; `expired_or_revoked_attempt_cannot_send_work`, `f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing`, `f03_work_after_revocation_rejected_prior_receipts_paid` and 1 more |
| M15 | Reconciliation without default dispute arbitration | caught | TEST-P06, TEST-P23; `f40_sliding_cap_holds_across_midnight_and_after_refunds`, `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_payment_is_contestable_for_a_bounded_time_then_final` and 6 more |
| M16 | Unvalidated window coverage disabled (JOB-R25) | caught | TEST-P18; `f10_low_escrow_blocks_window_then_pause_and_topup` |
| M17 | Pool relay used before the borrower budget | caught | TEST-P06, TEST-P16; `ce02_pool_relay_never_benefits_the_borrower`, `r2_a_fault_at_any_entry_of_a_multi_job_reconciliation_leaves_nothing_half_done` |
| M18 | Recovery not capped by the earmark | caught | TEST-P06, TEST-P16; `extreme_values_are_refused_without_panic` |
| M19 | Flow budget measured from delivered positions (colluding witness unbounded) | caught | TEST-P09; `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| M20 | Attestation from someone other than the assigned witness accepted | caught | TEST-P20; `lender_cannot_act_as_witness`, `f25_lender_cannot_attest_its_own_delivery`, `delivery_attested_by_a_lender_is_inadmissible` |
| M21 | Non-independent witness accepted at placement | caught | `f25_lender_cannot_attest_its_own_delivery` |
| M22 | Contribution evaluated while its output is provisional | caught | TEST-P22; `f27_lost_replay_buffer_contest_refunds_and_rewinds` |
| M23 | Rewind without cascade: only the lost position is voided | caught | TEST-P05; `f33_signed_heartbeat_without_replay_receipt_is_refunded`, `f27_lost_replay_buffer_contest_refunds_and_rewinds`, `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| M24 | Rewind without revoking the live attempt | caught | TEST-P25; `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| M25 | Work accepted under an expired lease | caught | TEST-P24; `expired_or_revoked_attempt_cannot_send_work`, `f29_expired_lease_rejects_work_until_reconciliation_revokes`, `r2_a_heartbeat_renews_only_its_own_lease` and 1 more |
| M26 | Reconciliation does not revoke expired leases | caught | TEST-P24; `expired_or_revoked_attempt_cannot_send_work`, `ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open`, `ce08_reconciliation_reports_a_ledger_failure` and 8 more |
| M27 | Heartbeat renews an expired lease | caught | TEST-P24; `expired_or_revoked_attempt_cannot_send_work`, `f29_expired_lease_rejects_work_until_reconciliation_revokes`, `r2_a_heartbeat_renews_only_its_own_lease` |
| M28 | Delivery window closed without waiting for revocation | caught | TEST-P20 |
| M29 | Client may confirm beyond delivered | caught | TEST-P16; `f30_client_cannot_overstate_or_unconfirm_or_contest_live_output` |
| M30 | Resume from validated positions: delivered ones are regenerated | caught | TEST-P09; `f26_lost_ack_then_resume_replays_without_double_billing`, `f32_rewind_revokes_live_attempt_built_on_voided_outputs` |
| M31 | CE-04 back: already decided item evaluated twice | caught | TEST-P06, TEST-P16; `ce04_voided_output_after_closure_does_not_block_evaluation`, `f27_lost_replay_buffer_contest_refunds_and_rewinds`, `f17_receipts_fabricated_after_revocation` |
| M32 | CE-05 back: zero reward never closed | caught | TEST-P23; `ce05_zero_reward_in_free_pool_completes_at_payment` |
| M33 | Closure loses claims (fairness) | caught | TEST-P23; `ce04_voided_output_after_closure_does_not_block_evaluation`, `ce09_staggered_payments_keep_their_own_contest_window`, `f41_supplementary_proof_before_deadline_is_paid_after_is_refused` and 28 more |
| M34 | Proven contribution refunded when its output becomes definitive (fairness) | caught | TEST-P23; `f27_lost_replay_buffer_contest_refunds_and_rewinds` |
| M35 | Automatic reward release disabled | caught | TEST-P06, TEST-P23; `ce03_commitment_before_closure_still_counts`, `ce04_voided_output_after_closure_does_not_block_evaluation`, `ce08_reconciliation_reports_a_ledger_failure` and 29 more |
| M36 | Attestation beyond produced accepted | caught | TEST-P09, TEST-P21 |
| M37 | Contest closed by the replay alone | caught | TEST-P20, TEST-P22; `f33_signed_heartbeat_without_replay_receipt_is_refunded`, `f34_cumulative_ack_covering_the_replay_bills_definitively`, `f39_contest_just_before_window_end_keeps_the_buffer` and 1 more |
| M38 | Client liveness signal resolves contests | caught | TEST-P20; `f33_signed_heartbeat_without_replay_receipt_is_refunded` |
| M39 | Frame digest not checked on attestation | caught | TEST-P20; `f35_declaration_or_attestation_from_another_session_is_rejected`, `f36_frame_different_from_the_signed_digest_is_rejected` |
| M40 | Client declaration not bound to the stream | caught | TEST-P20; `f35_declaration_or_attestation_from_another_session_is_rejected` |
| M41 | Late attestation without prior commitment | caught | TEST-P20; `f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing` |
| M42 | Commitment accepted after revocation and counted as prior | caught | TEST-P20; `f38_commitment_after_revocation_or_attestation_after_drain_proves_nothing` |
| M43 | Buffer purged despite an open contest | caught | TEST-P26; `f39_contest_just_before_window_end_keeps_the_buffer` |
| M44 | Per-calendar-day cap instead of a sliding window | caught | TEST-P08; `f40_sliding_cap_holds_across_midnight_and_after_refunds` |
| M45 | Refund restores the quota (net amounts) | caught | TEST-P08; `f40_sliding_cap_holds_across_midnight_and_after_refunds` |
| M46 | Refund for missing proof before the deadline | caught | TEST-P28; `ce03_commitment_after_slice_closure_proves_nothing`, `ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open`, `f41_supplementary_proof_before_deadline_is_paid_after_is_refused` and 1 more |
| M47 | Expired window ignores contests | caught | TEST-P20, TEST-P27; `f39_contest_just_before_window_end_keeps_the_buffer` |
| M48 | Contest deadline never enforced | caught | TEST-P06; `f33_signed_heartbeat_without_replay_receipt_is_refunded` |
| M49 | CE-06 back: slice finished before the deadline with an awaiting contribution | caught | TEST-P12; `ce06_awaiting_contribution_reverting_to_pending_keeps_slice_open`, `f27_lost_replay_buffer_contest_refunds_and_rewinds` |
| M50 | Supplementary proof accepted after the deadline | caught | TEST-P28; `f41_supplementary_proof_before_deadline_is_paid_after_is_refused` |
| M51 | Authorization skipped before execution | caught | TEST-P29; `borrower_cannot_ack_or_confirm_another_borrowers_tokens`, `borrower_cannot_cancel_another_borrowers_job`, `lender_cannot_act_as_witness` and 13 more |
| M52 | Ledger accepts any service role for any operation | caught | `compromise_delivery_cannot_issue_or_move_credits`, `compromise_scheduler_cannot_move_arbitrary_balances`, `only_treasury_issues` and 2 more |
| M53 | Ledger opens an escrow without checking the borrower's mandate | caught | `escrow_needs_the_owners_signed_mandate`, `r3_statements_signed_for_another_deployment_are_refused` |
| M54 | Ledger lets reservations exceed the signed mandate | caught | `compromise_scheduler_cannot_move_arbitrary_balances` |
| M55 | Receipts committed by anyone, the producer included | caught | `receipt_commitments_come_from_the_recipient_only`, `r2_an_accomplice_cannot_collect_recovery_without_corroboration` |
| M56 | Exact retransmission runs the command again | caught | `retransmission_gets_the_first_answer_and_runs_nothing` |
| M57 | One lender may hold several ranges of an attempt | caught | `one_lender_holds_one_range` |
| M58 | Tariff above MAX_PRICE accepted | caught | `extreme_values_are_refused_without_panic` |
| M59 | Clock allowed beyond MAX_TIME | caught | `extreme_values_are_refused_without_panic` |
| M60 | Signature checked but its result ignored | caught | `lender_cannot_act_as_witness`, `receipt_commitments_come_from_the_recipient_only`, `unsigned_or_altered_messages_are_refused` and 19 more |
| M61 | Coordinator accepts revoked or forged service credentials | caught | `revoked_service_credential_is_refused_by_the_coordinator` |
| M62 | Service credential accepted without checking the authority's signature | caught | `credential_from_another_authority_is_rejected`, `credential_cannot_be_altered`, `credential_from_another_authority_is_rejected` |
| M63 | Finding 1: a recovery reserve refunded to the output hold | caught | TEST-P17; `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_payment_is_contestable_for_a_bounded_time_then_final`, `r3_a_segment_the_recipient_did_not_name_is_not_paid` and 6 more |
| M64 | Finding 2: settlement accepted with an undecided item | caught | `r2_settlement_waits_for_every_item_and_is_final` |
| M65 | Finding 2: a refund still accepted after settlement | caught | `r2_settlement_waits_for_every_item_and_is_final` |
| M66 | Finding 3: lease accepted without the lender's signature | caught | `r2_lease_steps_are_ordered_personal_and_signed`, `r2_only_a_lender_that_signed_its_lease_gets_a_line`, `r3_statements_signed_for_another_deployment_are_refused` |
| M67 | Finding 3: line reserved for a lender that never accepted | caught | `r2_only_a_lender_that_signed_its_lease_gets_a_line` |
| M68 | Finding 3: line reserved for an account outside the attempt's stage | caught | `r2_only_a_lender_that_signed_its_lease_gets_a_line` |
| M69 | Finding 3: contribution paid without the recipient's receipt | caught | `r2_no_payment_without_the_recipients_receipt` |
| M70 | Finding 3: receipt kept whoever signed it | caught | `receipt_commitments_come_from_the_recipient_only`, `r2_an_uncommitted_claim_needs_the_recipients_receipt`, `r2_a_replayed_receipt_never_pays_twice` and 2 more |
| M71 | Finding 3: the caller's share replaces the signed terms (double share) | caught | TEST-P06, TEST-P16, TEST-P23; `ce03_commitment_after_slice_closure_proves_nothing`, `ce03_commitment_before_closure_still_counts`, `ce04_voided_output_after_closure_does_not_block_evaluation` and 34 more |
| M72 | Recovery reserved before every lender signed ready | caught | `r2_recovery_needs_readiness_and_stays_within_the_earmark` |
| M73 | Recovery reserved above the attempt's earmark | caught | `r2_recovery_needs_readiness_and_stays_within_the_earmark` |
| M74 | Pool relay accepted without its admin's signature | caught | `compromise_scheduler_cannot_move_arbitrary_balances`, `r2_pool_relay_needs_its_admins_signature`, `r2_pool_relay_needs_the_admins_consent` and 1 more |
| M75 | Ledger splits recovery pool first | caught | TEST-P06, TEST-P16; `ce02_pool_relay_never_benefits_the_borrower`, `r2_a_fault_at_any_entry_of_a_multi_job_reconciliation_leaves_nothing_half_done`, `r2_recovery_split_and_contest_follow_the_ledgers_records` |
| M76 | Output voided while its shares are still reserved | caught | `r2_charges_and_voids_follow_the_ledgers_records` |
| M77 | Finding 4: one ready lender starts the cluster | caught | TEST-P31; `borrower_cannot_ack_or_confirm_another_borrowers_tokens`, `borrower_cannot_cancel_another_borrowers_job`, `expired_or_revoked_attempt_cannot_send_work` and 85 more |
| M78 | Finding 4: lease steps can be skipped | caught | TEST-P31; `r2_lease_steps_are_ordered_personal_and_signed` |
| M79 | Finding 4: a stage loaded with the wrong configuration | caught | `r2_lease_steps_are_ordered_personal_and_signed` |
| M80 | Finding 5: a heartbeat renews every lease of the attempt | caught | TEST-P31; `f40_sliding_cap_holds_across_midnight_and_after_refunds`, `f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders`, `f25_lender_cannot_attest_its_own_delivery` and 10 more |
| M81 | Finding 5: the attempt lives while one lease is still valid | caught | TEST-P24; `r2_a_heartbeat_renews_only_its_own_lease`, `r2_the_witness_lease_is_its_own`, `r2_a_ready_lease_does_not_outlive_another_nodes_expiry` and 1 more |
| M82 | Finding 5: the witness's lease never expires | caught | TEST-P24; `r2_the_witness_lease_is_its_own` |
| M83 | A lender renews or readies another lender's lease | caught | TEST-P29; `r2_a_heartbeat_renews_only_its_own_lease`, `r2_lease_steps_are_ordered_personal_and_signed` |
| M84 | Uncommitted claim decided without looking for the receipt | caught | `r2_an_uncommitted_claim_needs_the_recipients_receipt` |
| M85 | Attempt registered with a layout that does not cover the signed model | caught | `r2_attempts_are_checked_against_the_signed_terms` |
| M86 | A pool's admin can be registered again at the ledger | caught | `r2_pool_relay_needs_the_admins_consent` |
| M87 | CE-08 back: reconciliation skips a transition the ledger failed | caught | `ce08_reconciliation_reports_a_ledger_failure`, `r2_a_fault_during_a_partial_settlement_then_restart_and_reconciliation` |
| M88 | Ledger pays recovery without a corroborated restoration | caught | `r2_a_corroboration_is_bound_to_what_was_restored`, `r2_recovery_is_settled_only_on_a_corroborated_restoration`, `r3_a_corroboration_pays_only_the_segments_it_names` and 1 more |
| M89 | Restoration corroborated by any signer | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_corroboration_is_bound_to_what_was_restored`, `r2_recovery_is_settled_only_on_a_corroborated_restoration` and 4 more |
| M90 | A ruling pays recovery nobody corroborated | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r3_a_segment_the_recipient_did_not_name_is_not_paid`, `r2_an_accomplice_cannot_collect_recovery_without_corroboration` and 1 more |
| M91 | Evaluation pays recovery on the lender's word alone | caught | TEST-P06, TEST-P16; `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_payment_is_contestable_for_a_bounded_time_then_final`, `r3_a_segment_the_recipient_did_not_name_is_not_paid` and 5 more |
| M92 | Corroboration accepted for a segment the lender never committed to | caught | `r3_a_corroboration_pays_only_the_segments_it_names` |
| M93 | Recovery held before the deadline instead of waiting for its corroboration | caught | `r2_an_accomplice_cannot_collect_recovery_without_corroboration` |
| M94 | A corroboration can be replaced by another one | caught | `r2_a_recorded_proof_cannot_be_replaced` |
| M95 | Recovery paid for a segment the corroboration does not cover | caught | `r2_a_corroboration_is_bound_to_what_was_restored`, `r3_a_corroboration_pays_only_the_segments_it_names` |
| M96 | A recorded receipt replaced by a contradictory one | caught | `r2_a_recorded_proof_cannot_be_replaced` |
| M97 | A payment released inside its own contest window | caught | `r2_contests_follow_a_bounded_cycle`, `r3_staggered_payments_each_have_their_own_window` |
| M98 | A payment contested past its own limit | caught | `ce09_staggered_payments_keep_their_own_contest_window`, `r2_contests_follow_a_bounded_cycle`, `r3_staggered_payments_each_have_their_own_window` |
| M99 | The ledger's clock can go back | caught | `r2_contests_follow_a_bounded_cycle` |
| M100 | Coordinator lets a second corroboration through | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else` |
| M101 | Corroboration signature does not cover the state commitment | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_corroboration_is_bound_to_what_was_restored` |
| M102 | Corroboration signature does not cover the layer range | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_corroboration_is_bound_to_what_was_restored` |
| M103 | Corroboration signature does not cover the segments | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_corroboration_is_bound_to_what_was_restored`, `r3_a_corroboration_pays_only_the_segments_it_names` and 1 more |
| M104 | Coordinator ignores the contest limit | caught | `ce09_staggered_payments_keep_their_own_contest_window`, `r2_a_payment_is_contestable_for_a_bounded_time_then_final` |
| M105 | Coordinator pays recovery beyond the corroborated segments | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r3_a_segment_the_recipient_did_not_name_is_not_paid` |
| M106 | Ledger closes every payment of the line on a release or a contest | caught | TEST-P06, TEST-P16, TEST-P23; `ce09_staggered_payments_keep_their_own_contest_window`, `f40_sliding_cap_holds_across_midnight_and_after_refunds`, `f24_withheld_acks_with_witness_bill_provisionally_and_pay_lenders` and 18 more |
| M107 | Coordinator closes every payment of the line on a contest | caught | `ce09_staggered_payments_keep_their_own_contest_window` |
| M108 | Ledger records a corroboration after the attempt's revocation | caught | `r3_no_proof_is_added_after_the_revocation` |
| M109 | Ledger records a lease acceptance on a revoked attempt | caught | `r3_no_proof_is_added_after_the_revocation` |
| M110 | Ledger records a readiness on a revoked attempt | caught | `r3_no_proof_is_added_after_the_revocation` |
| M111 | Coordinator takes a corroboration after the revocation | caught | `r3_a_corroboration_after_the_lender_is_revoked_proves_nothing`, `r3_a_corroboration_after_the_recipient_lease_expired_proves_nothing` |
| M112 | Revocation not recorded at the ledger | caught | `r3_a_corroboration_after_the_lender_is_revoked_proves_nothing` |
| M113 | Corroboration taken on the producer's expired lease | caught | `r3_a_corroboration_after_the_recipient_lease_expired_proves_nothing` |
| M114 | Corroboration taken on the recipient's expired lease | caught | TEST-P34; `r3_a_corroboration_after_the_recipient_lease_expired_proves_nothing`, `r3_a_corroboration_by_an_expired_witness_proves_nothing` |
| M115 | Witness's expiry ignored when it is the recipient | caught | `r3_a_corroboration_by_an_expired_witness_proves_nothing` |
| M116 | Producer's withdrawn right ignored | caught | `r3_a_right_withdrawn_before_the_corroboration_voids_it` |
| M117 | Recipient's withdrawn right ignored | caught | `r3_a_right_withdrawn_before_the_corroboration_voids_it` |
| M118 | Granting a right again erases its withdrawal | caught | `r3_a_right_withdrawn_before_the_corroboration_voids_it` |
| M119 | Any withdrawn right of the producer voids its restoration | caught | `r3_a_right_withdrawn_before_the_corroboration_voids_it` |
| M120 | Statements not bound to the deployment | caught | `r3_statements_signed_for_another_deployment_are_refused`, `r3_statements_for_another_deployment_are_refused_by_the_coordinator`, `every_statement_is_bound_to_its_domain` |
| M121 | Corroboration does not bind each segment's commitment | caught | `r2_a_corroboration_covers_what_was_restored_and_nothing_else`, `r2_a_corroboration_is_bound_to_what_was_restored`, `a_restoration_covers_exactly_the_segments_it_names` |
| M122 | Readiness does not bind the segment commitments | caught | `r3_a_corroboration_pays_only_the_segments_it_names` |
| M123 | Ledger takes a segment named twice or out of order | caught | `r3_a_corroboration_pays_only_the_segments_it_names` |
| M124 | No limit on the segments a lender commits to | caught | `r3_a_corroboration_pays_only_the_segments_it_names` |
| M125 | A revocation can be recorded twice | caught | `r3_no_proof_is_added_after_the_revocation` |
| M126 | Ledger records carry no order | caught | TEST-P30; `ce02_pool_relay_never_benefits_the_borrower`, `ce09_staggered_payments_keep_their_own_contest_window`, `r2_a_corroboration_covers_what_was_restored_and_nothing_else` and 10 more |
| M127 | Coordinator lets an unordered segment list through | caught | `r3_a_segment_the_recipient_did_not_name_is_not_paid` |
| M128 | Witness's withdrawn right looked up as a right to lend | caught | `r3_a_right_withdrawn_before_the_corroboration_voids_it` |
| M129 | Envelope signed for another deployment accepted | caught | `unsigned_or_altered_messages_are_refused` |
| M130 | Envelope signature does not cover the deployment | caught | `unsigned_or_altered_messages_are_refused`, `signature_covers_every_field` |
| M131 | Limits that can strand a payment accepted | caught | `r3_a_coordinator_refuses_a_ledger_it_cannot_rely_on` |
| M132 | Coordinator runs on another deployment's ledger | caught | `r3_a_coordinator_refuses_a_ledger_it_cannot_rely_on` |

#### What the campaign found

The first complete run was on `6351a3f` ([run 42806966893](https://github.com/ASTROWwwW/more/actions/runs/42806966893)): 132 of 134 caught, no compile error, two missed. Both are mutants written for the second audit, and both show the same weakness in a test: another check refused the same call, so the test could not tell which check had fired.

- **M65** (a refund still accepted after settlement). `reserved_item` no longer asked for a live escrow, and the refund was still refused, because no item is ever reserved after a settlement. The test only asserted "refused". It now asserts that each late operation is refused with `EscrowSettled`.
- **M76** (an output voided while its shares are reserved). With the check removed, the void was still refused in the test, by the journal: the reserved share had left the output hold, which no longer held the price. With a second output charged, the void would have gone through and left the hold short. The test now charges a second output first and asserts the refusal by its reason and unchanged balances. TEST-P30 also checks, after every hostile call, that a share holding or having taken money keeps its output charged.

No production code changed. The campaign was run again in full on the resulting commit.

### Cost

Reference run, property tests only, same machine:

| Code | Commands checked | Time | Commands per second |
| --- | --- | --- | --- |
| `main` (`e398159`) | 2,309,112 | 31.5 s | 73,000 |
| `1ea3d26` (before the third review) | 3,274,498 | 90.9 s | 36,000 |
| `6351a3f` | 3,274,716 | 101.6 s | 32,200 |

Per command, measured by `cargo test --release --test properties cost_breakdown -- --ignored --nocapture` (400 traces, 141,402 commands, three runs):

| Part | `1ea3d26` | `6351a3f` |
| --- | --- | --- |
| The checker's copy of the state | 5.8 µs | 8.6 to 9.5 µs |
| The coordinator running the command | 16.7 µs | 20.9 to 22.9 µs |
| of which signature checks (20,856 at about 44 µs) | 6.5 µs | 6.4 to 7.0 µs |
| of which one copy of the state, for rollback | 10.2 µs | 14.4 to 15.5 µs |
| The invariant checker | 9.8 µs | 10.5 to 11.9 µs |

Against `main`, the cost comes from three things: real signatures on every lease step, corroboration and receipt; a cluster that starts in three steps per lender plus one corroboration per stage, so traces hold more commands; and state copies. The third review added about 12 % on top: signature work did not change, the copies did. A lease now holds lists (one commitment per segment, the segments a recipient named), and so does the ledger's record of the attempt, so each copy of the state allocates more. Sharing those lists between copies would take most of it back. It was left as is: this is the cost of the test harness, which copies the whole state twice per command, and says little about a deployed service.

### Limits of this validation

- Ledger, coordinator and registry still run in one process. The ledger checks signatures and its own records, yet a compromised process holds all three (`docs/SECURITY_ARCHITECTURE.md`, section 11).
- A receipt or a corroboration is what one account says it received from another. Nothing here verifies the computation itself.
- The ledger sees a revocation when the orchestrator records it. Lease deadlines and pool rights are checked by the coordinator only.
- State and segment commitments are symbolic values in the model; the ledger checks that two accounts signed the same ones, which is all it could do with real digests too.
- Digests of frames, receipts and the ledger chain are still FNV-1a.
- Properties are checked on finite random traces, 17,544 in the reference run. They are not proven for all traces.
- The claims are the checks listed above and the mutants they catch. The number of green tests is not one of them.

## Part 1: `hardening/security-architecture`

How the changes of branch `hardening/security-architecture` were checked, with the real results. Environment: Linux, Rust 1.97.0, one machine, November 9, 2026. Baseline: `8e020bd`. Final code: `ae43129`.

### Commands and results

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | Clean, with the new workspace lints (no `unsafe`, `unwrap`, `expect`, `panic!` in production crates) |
| `cargo test --workspace` (test profile: overflow checks on, 512 traces per generator) | 101 tests passed, 0 failed |
| `cargo test --release --workspace` | 101 passed, 0 failed |
| `cargo clean && PROPTEST_CASES=5000 cargo test --release --workspace` | 101 passed, 0 failed; 74 s including build, property tests 31.5 s |
| `python3 scripts/mutation.py` | 60 of 62 on `ac03abf`; the 2 others fixed and caught on the final code, with the 2 mutants added after (64 of 64) |

GitHub Actions (format and lints, minimum Rust version, debug tests, release tests) passed on `b8e790b` and runs on every later push. The first CI run had failed twice: newer clippy flagged redundant glob imports that 1.97 accepts, and `proptest` 1.12 needs Rust 1.88, not the 1.87 first declared. Both fixed; the minimum is now 1.88 and CI checks it.

#### Tests, before and after

| Suite | Baseline | Now | Added |
| --- | --- | --- | --- |
| `more-identity` (unit) | — | 4 | credential forgery, other authority, revocation, signatures |
| `gpu-ledger` (unit) | 5 | 5 | |
| `gpu-ledger` (API, from outside the crate) | — | 9 | role matrix, forged and revoked credentials, issuance limits near `u64::MAX`, mandates, compromised scheduler and delivery service, atomic rollback, read scopes |
| `gpu-ledger` (doc test) | — | 1 | the generic transfer does not compile from outside the crate |
| `gpu-protocol` (unit) | 4 | 4 | signature coverage, replay policy, bounded retransmission window; three older tests now run on signed envelopes in `tests/security/`, under their original names |
| `tests/properties` | 5 | 5 | TEST-P29 and impersonation in every generator |
| `tests/scenarios` | 46 | 46 | JOB-F41 (M50) and JOB-F25 (M21) strengthened |
| `tests/regressions` | 7 | 8 | CE-07 |
| `tests/security` | — | 19 | the ten attacks of the audit, three simulated compromises, unsigned or altered messages, a revoked service credential, distinct lenders, and the three protocol tests kept by name |
| **Total** | **67** | **101** | |

No test was deleted. The two counterexample seeds found during this work are in `tests/properties/proptest-regressions.txt` (11 seeds in total).

#### The ten required security cases

| # | Case | Test | Checked |
| --- | --- | --- | --- |
| 1 | Account A cancels account B's job | `borrower_cannot_cancel_another_borrowers_job` | `UNAUTHORIZED`, state unchanged |
| 2 | Account A confirms B's tokens | `borrower_cannot_ack_or_confirm_another_borrowers_tokens` | same |
| 3 | A lender passes itself off as the witness | `lender_cannot_act_as_witness` | `INADMISSIBLE_PROOF` as itself, `BAD_SIGNATURE` in the witness's name, `UNAUTHORIZED` for the witness's buffer |
| 4 | A lender renews another's lease | `only_lenders_of_the_attempt_renew_its_lease` | `UNAUTHORIZED` |
| 5 | Receipt commitment in another lender's name | `receipt_commitments_come_from_the_recipient_only` | producer and wrong recipient refused, wrong digest `INADMISSIBLE_PROOF`, right recipient accepted |
| 6 | Expired attempt still sending work | `expired_or_revoked_attempt_cannot_send_work` | `LEASE_EXPIRED`, then `STALE_ATTEMPT` |
| 7 | Price fraudulently set to zero | `the_client_never_sets_the_price` | no price field; tariff from the catalog; budget below cost refused; only admins set tariffs; no tariff in free pools |
| 8 | Non-member in a private pool | `non_member_cannot_use_a_private_pool` | `UNAUTHORIZED`; self-join refused in a private pool, allowed in an open one without the witness right |
| 9 | Amounts near `u64::MAX` | `extreme_values_are_refused_without_panic`, `issuance_limits_hold_near_u64_max` | `LIMIT_EXCEEDED`, `INVALID_INPUT`, `ARITHMETIC_OVERFLOW`; no panic in debug or release; balances unchanged |
| 10 | Refused answer, then retransmission with the same business key | `retransmission_gets_the_first_answer_and_runs_nothing` | same answer, nothing run twice; new number: domain idempotency (`AlreadyApplied`); same number, other content: `REPLAY` |

Every refusal test compares the whole coordinator state before and after.

#### Coverage of the reference run

Written by the tests themselves in `target/coverage/` during the 5,000-trace run.

| Measure | General | Failures | Partial reserve | Delivery | Total |
| --- | --- | --- | --- | --- | --- |
| Traces | 5,011 | 5,011 | 2,511 | 5,011 | 17,544 |
| Commands run and checked | 543,495 | 715,509 | 338,786 | 711,322 | 2,309,112 |
| accepted | 380,049 | 513,874 | 247,751 | 547,730 | 1,689,404 |
| `UNAUTHORIZED` refusals (impersonation) | 9,364 | 11,445 | 5,271 | 10,722 | 36,802 |
| `INADMISSIBLE_PROOF` refusals | 1,961 | 2,016 | 936 | 11,171 | 16,084 |
| `LEASE_EXPIRED` refusals | 5,820 | 27,391 | 12,724 | 18,056 | 63,991 |
| Outputs charged on ack | 409 | 1,632 | 732 | 711 | 3,484 |
| Outputs charged provisionally | 383 | 2,069 | 789 | 2,487 | 5,728 |
| Contribution payments | 616 | 3,247 | 1,309 | 2,747 | 7,919 |
| Recovery payments | 60 | 724 | 306 | 643 | 1,733 |
| Rewinds | 5 | 45 | 22 | 428 | 500 |
| Payments by arbitration | 1 | 61 | 23 | 14 | 99 |
| Rewards released | 290 | 1,891 | 770 | 1,652 | 4,603 |

Impersonation operations send a realistic command from a random account or service. 36,802 of them were refused as unauthorized; the ones that happened to come from the right sender were accepted, and TEST-P29 checked every accepted command against the independent oracle.

### Mutation campaign

64 mutants: the 52 of v2.5, 16 of them with anchors moved to the new code with the same bug, and 12 new ones on the trust boundaries (M51 to M62). The suite run for each mutant is now the whole workspace (unit, ledger API, security, properties at 300 traces, scenarios, regressions), not only the conformance tests.

Full campaign on `ac03abf`: 60 of 62 caught in 27 min. The two others were fixed (below) and rerun on the final code with M60, M61 and M62: all caught. **64 of 64 caught on the final code, 48 of them by a property in the full campaign.**

| Mutation | Injected bug | Result | Caught by |
| --- | --- | --- | --- |
| M01 | v2.1 bug: JOB-T04 resets execution_intent to initial | caught | TEST-P07 |
| M02 | v2.1 bug: contribution payable on another attempt | caught | TEST-P04 |
| M03 | v2.2 bug: contribution id without layer range | caught | TEST-P23 |
| M04 | v2.2 bug: no pending_evaluation at closure | caught | TEST-P06, TEST-P12, TEST-P16 |
| M05 | Contest that creates credits | caught | TEST-P12 |
| M06 | Cancel allowed while settling | caught | `f09_*` |
| M06b | Cancel allowed while settling (transition table too) | caught | TEST-P11 |
| M07 | Flow control disabled | caught | TEST-P09 |
| M08 | Anti-collusion cap ignored | caught | TEST-P08 |
| M09 | Late commitment accepted as prior | caught | TEST-P08 |
| M09b | CE-03 back: bound = revocation, not slice closure | caught | TEST-P08 |
| M10 | Settlement forgets OutputHold | caught | TEST-P13 |
| M11 | CE-01 back: pool relay without active escrow | caught | TEST-P13, TEST-P17 |
| M12 | CE-02 back: pool share returned to the borrower | caught | TEST-P17 |
| M13 | Resume without state restore | caught | TEST-P07, TEST-P25 |
| M14 | Work accepted on a revoked attempt | caught | TEST-P04 |
| M15 | Reconciliation without default dispute arbitration | caught | TEST-P06, TEST-P23 |
| M16 | Unvalidated window coverage disabled (JOB-R25) | caught | TEST-P18 |
| M17 | Pool relay used before the borrower budget | caught | TEST-P17 |
| M18 | Recovery not capped by the earmark | caught | TEST-P06, TEST-P14, TEST-P16 |
| M19 | Flow budget measured from delivered positions (colluding witness unbounded) | caught | TEST-P09 |
| M20 | Attestation from someone other than the assigned witness accepted | caught | TEST-P20 |
| M21 | Non-independent witness accepted at placement | missed, then caught after the fix below | TEST-P20, `f25_*` |
| M22 | Contribution evaluated while its output is provisional | caught | TEST-P22 |
| M23 | Rewind without cascade: only the lost position is voided | caught | TEST-P05, TEST-P06, TEST-P27 |
| M24 | Rewind without revoking the live attempt | caught | TEST-P25 |
| M25 | Work accepted under an expired lease | caught | TEST-P24 |
| M26 | Reconciliation does not revoke expired leases | caught | TEST-P24 |
| M27 | Heartbeat renews an expired lease | caught | TEST-P24 |
| M28 | Delivery window closed without waiting for revocation | caught | TEST-P20 |
| M29 | Client may confirm beyond delivered | caught | TEST-P16 |
| M30 | Resume from validated positions: delivered ones are regenerated | caught | TEST-P09 |
| M31 | CE-04 back: already decided item evaluated twice | caught | TEST-P06, TEST-P16, TEST-P23 |
| M32 | CE-05 back: zero reward never closed | caught | TEST-P23 |
| M33 | Closure loses claims (fairness) | caught | TEST-P23 |
| M34 | Proven contribution refunded when its output becomes definitive (fairness) | caught | TEST-P23 |
| M35 | Automatic reward release disabled | caught | TEST-P06, TEST-P23 |
| M36 | Attestation beyond produced accepted | caught | TEST-P09, TEST-P21 |
| M37 | Contest closed by the replay alone | caught | TEST-P20, TEST-P22 |
| M38 | Client liveness signal resolves contests | did not compile, then caught after the fix below | `f33_*` |
| M39 | Frame digest not checked on attestation | caught | TEST-P20 |
| M40 | Client declaration not bound to the stream | caught | `f35_*` |
| M41 | Late attestation without prior commitment | caught | TEST-P20 |
| M42 | Commitment accepted after revocation and counted as prior | caught | TEST-P20 |
| M43 | Buffer purged despite an open contest | caught | TEST-P26 |
| M44 | Per-calendar-day cap instead of a sliding window | caught | TEST-P08 |
| M45 | Refund restores the quota (net amounts) | caught | `f40_*` |
| M46 | Refund for missing proof before the deadline | caught | TEST-P28 |
| M47 | Expired window ignores contests | caught | TEST-P20, TEST-P27 |
| M48 | Contest deadline never enforced | caught | TEST-P06, TEST-P27 |
| M49 | CE-06 back: slice finished before the deadline with an awaiting contribution | caught | TEST-P12 |
| M50 | Supplementary proof accepted after the deadline | caught | TEST-P28 |
| M51 | Authorization skipped before execution | caught | TEST-P29 |
| M52 | Ledger accepts any service role for any operation | caught | `compromise_*`, `compromise_*`, `only_*` |
| M53 | Ledger opens an escrow without checking the borrower's mandate | caught | `escrow_*` |
| M54 | Ledger lets reservations exceed the signed mandate | caught | `compromise_*` |
| M55 | Receipts committed by anyone, the producer included | caught | `receipt_*` |
| M56 | Exact retransmission runs the command again | caught | `retransmission_*` |
| M57 | One lender may hold several ranges of an attempt | caught | `one_*` |
| M58 | Tariff above MAX_PRICE accepted | caught | `extreme_*` |
| M59 | Clock allowed beyond MAX_TIME | caught | `extreme_*` |
| M60 | Signature checked but its result ignored | caught | `escrow_*`, `lender_*`, `replayed_*` |
| M61 | Coordinator accepts revoked or forged service credentials | caught (added after the campaign, run on the final code) | `revoked_service_credential_*` |
| M62 | Service credential accepted without checking the authority's signature | caught (same) | identity unit tests, ledger API tests |

The two that did not pass the full campaign:

- **M21** (non-independent witness accepted): JOB-F25 placed a lender as witness, but that lender had no witness right, so the new rights check refused it before the independence check was reached. Removing the independence check went unnoticed. JOB-F25 now uses the lender that does hold the witness right, so only the independence rule can refuse it. TEST-P20 also catches it, on some runs.
- **M38** (liveness signal resolves contests): the mutant still referred to a field that moved into `DeliveryBook`, so it did not compile. Rewritten against the book; caught by JOB-F33.

Mutants caught only by a scenario or a security test: M06 changes an error code only; M40 and M45 were caught by properties in earlier runs, not in this one; M52 to M62 test the ledger API, the identity crate and the protocol edge, which the property generators do not drive (they authenticate through `test-support`) and which their own tests cover.

#### Defects found in the campaign script

- A mutant that does not compile used to be reported as "missed" (its test list was empty). Compile errors are now reported as such. Earlier campaigns were not inflated by this: a compile error could only lower their score.
- M57 did not compile as first written (type inference on an unused set); rewritten.
- Failing tests inside modules (`lifecycle::f09_...`, after the scenarios were split into files) were not recognized, so a mutant caught only by such a test was reported missed (M06 in a first, interrupted run). The script now reads module paths and runs every test binary (`--no-fail-fast`). The campaign was restarted from scratch after this fix.
- M58 survived its first run: the security test checked all catalog bounds with one input that broke all of them, so removing one bound was invisible. The test now checks each bound separately; M58 is caught.

### Benchmark

Same machine, same command (`PROPTEST_CASES=5000 cargo test --release --workspace`), property tests only:

| | Commands checked | Time | Commands per second |
| --- | --- | --- | --- |
| Baseline `8e020bd` | 1,998,359 | 18.8 s | 106,000 |
| `ae43129` | 2,309,112 | 31.5 s | 73,000 |

About 31 % slower per command: authorization before every command, a credential check on every ledger operation and every service command (signature verified once per credential, revocation each time), checked arithmetic and the extra checker work (TEST-P29). Each command also clones a slightly larger state. These figures describe the in-memory model and its checker, not a PostgreSQL coordinator.

### Limits of this validation

- Boundaries between trust domains are in-process (compiler, private types, checks on every call). Process, OS and database isolation are specified in `docs/SECURITY_ARCHITECTURE.md` but not built.
- Envelope signatures are real Ed25519; frame, receipt and ledger-chain digests are still FNV-1a. Delivery on a real network is not shown.
- The simulation authenticates accounts through the `test-support` feature; signatures themselves are tested at the protocol edge and in `tests/security/`.
- Properties are checked on finite random traces; they are not proven for all traces.
- A green test count is not the claim. The claims are the specific checks listed above, the mutants they catch, and the open issues of `docs/AUDIT_CODE.md`.
