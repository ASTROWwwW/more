//! Security scenarios (SEC-001 to SEC-006, SAFE-001): attacks through the signed protocol edge and
//! from compromised services. Every refused attempt must leave the state exactly as it was.

use gpu_domain::*;
use gpu_protocol::*;
use gpu_simulation::*;
use more_identity::UserKey;

mod attacks;
mod compromise;
mod finality;
mod leases;
mod protocol;
mod recovery;

const J1: JobId = JobId(1);
const J2: JobId = JobId(2);
const GEN: WorkType = WorkType::Generate;

/// A simulated world plus the protocol edge (key directory, replay guard).
struct Edge {
    sim: Sim,
    guard: ReplayGuard,
    seq: u64,
}

impl Edge {
    /// Job 1 running on lenders 10, 11, 12 with two tokens produced.
    fn running() -> Self {
        let mut sim = Sim::default();
        for c in [
            Command::Reserve { job: J1 },
            Command::Place {
                job: J1,
                lenders: LENDERS[..3].to_vec(),
                layout: layout_of(J1),
                recovery_estimate: 0,
                witness: WITNESS,
                expected_version: None,
            },
        ] {
            sim.exec(c).unwrap();
        }
        sim.start_cluster(J1, 1, [0; 3]).unwrap();
        sim.exec(Command::Produce {
            job: J1,
            attempt: 1,
            wt: GEN,
            upto: 2,
        })
        .unwrap();
        Edge {
            sim,
            guard: ReplayGuard::default(),
            seq: 0,
        }
    }

    fn envelope(&mut self, from: AccountId, body: Message) -> Envelope {
        self.seq += 1;
        Envelope::signed(sim_domain(), from, 1, self.seq, body, &user_key(from))
    }

    fn send_env(&mut self, env: &Envelope) -> Answer {
        let keys = self.sim.ids.keys.clone();
        handle(&mut self.guard, &keys, &mut self.sim.coord, env)
    }

    fn send(&mut self, from: AccountId, body: Message) -> Answer {
        let env = self.envelope(from, body);
        self.send_env(&env)
    }

    /// Sends and expects a refusal with `code` that changes nothing.
    #[track_caller]
    fn refused(&mut self, from: AccountId, body: Message, code: &str) {
        let before = self.sim.coord.clone();
        let r = self.send(from, body.clone());
        assert_eq!(r.map_err(|e| e.code()), Err(code), "{from:?} {body:?}");
        assert_eq!(
            before, self.sim.coord,
            "a refused message changed the state"
        );
    }
}

fn total_user_balances(sim: &Sim) -> Vec<(Account, i128)> {
    sim.ledger().accounts().map(|(a, b)| (*a, *b)).collect()
}
