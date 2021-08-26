// Copyright(C) Facebook, Inc. and its affiliates.
use crate::dolphin::virtual_state::VirtualState;
use crate::state::{Dag, State};
use config::{Committee, Stake};
use log::debug;
use primary::{Certificate, Round};
use std::collections::HashSet;

pub struct Committer {
    /// The committee information.
    committee: Committee,
}

impl Committer {
    pub fn new(committee: Committee) -> Self {
        Self { committee }
    }

    /// Try to commit. If we succeed, output am ordered sequence.
    pub fn try_commit(
        &self,
        certificate: &Certificate,
        state: &mut State,
        virtual_state: &mut VirtualState,
    ) -> Vec<Certificate> {
        let mut sequence = Vec::new();

        // Update the leader mode to decide whether we can commit the leader.
        if let Some(leader) = self.update_validator_mode(&certificate, virtual_state) {
            // Get an ordered list of past leaders that are linked to the current leader.
            let last_committed_wave = (state.last_committed_round + 1) / 2;
            while let Some(leader) = self
                .order_leaders(&leader, &virtual_state, last_committed_wave)
                .pop()
            {
                // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                for x in state.flatten(&leader) {
                    // Update and clean up internal state.
                    state.update(&x);
                    // Add the certificate to the sequence.
                    sequence.push(x);
                }
            }

            // Cleanup the virtual dag.
            virtual_state.cleanup(&state.last_committed_round);
        }
        sequence
    }

    /// Updates the authorities mode (steady state vs fallback) and return whether we can commit
    /// the leader of the wave.
    fn update_validator_mode(
        &self,
        certificate: &Certificate,
        state: &mut VirtualState,
    ) -> Option<Certificate> {
        let steady_wave = (certificate.virtual_round() + 1) / 2;
        let fallback_wave = (certificate.virtual_round() + 1) / 4;

        // If we already updated the validator mode for this wave, there is nothing else to do.
        if state
            .steady_authorities_sets
            .entry(steady_wave)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin())
            || state
                .fallback_authorities_sets
                .entry(fallback_wave)
                .or_insert_with(HashSet::new)
                .contains(&certificate.origin())
        {
            return None;
        }

        // Check whether the author of the certificate is in the steady state for this round.
        if state
            .steady_authorities_sets
            .entry(steady_wave - 1)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin())
        {
            let leader = self.check_steady_commit(certificate, steady_wave - 1, state);
            if leader.is_some() {
                debug!(
                    "{} is in the steady state in wave {}",
                    certificate.origin(),
                    steady_wave
                );
                state
                    .steady_authorities_sets
                    .get_mut(&steady_wave)
                    .unwrap()
                    .insert(certificate.origin());
            }
            return leader;
        } else if state
            .fallback_authorities_sets
            .entry(fallback_wave - 1)
            .or_insert_with(HashSet::new)
            .contains(&certificate.origin())
        {
            let leader = self.check_fallback_commit(certificate, fallback_wave - 1, state);
            if leader.is_some() {
                debug!(
                    "{} is in the steady state in wave {}",
                    certificate.origin(),
                    steady_wave
                );
                state
                    .steady_authorities_sets
                    .get_mut(&steady_wave)
                    .unwrap()
                    .insert(certificate.origin());
            }
            return leader;
        }
        debug!(
            "{} is in the fallback state in wave {}",
            certificate.origin(),
            steady_wave
        );
        state
            .fallback_authorities_sets
            .get_mut(&fallback_wave)
            .unwrap()
            .insert(certificate.origin());
        None
    }

    fn check_steady_commit(
        &self,
        certificate: &Certificate,
        wave: Round,
        state: &VirtualState,
    ) -> Option<Certificate> {
        state
            .steady_leader(wave)
            .map(|(_, leader)| {
                (state
                    .dag
                    .get(&(certificate.virtual_round() - 1))
                    .expect("We should have all the history")
                    .values()
                    .filter(|(digest, certificate)| {
                        certificate.virtual_parents().contains(&digest)
                            && state
                                .steady_authorities_sets
                                .get(&wave)
                                .map_or_else(|| false, |x| x.contains(&certificate.origin()))
                            && self.strong_path(leader, certificate, &state.dag)
                    })
                    .map(|(_, certificate)| self.committee.stake(&certificate.origin()))
                    .sum::<Stake>()
                    >= self.committee.quorum_threshold())
                .then(|| leader.clone())
            })
            .flatten()
    }

    fn check_fallback_commit(
        &self,
        certificate: &Certificate,
        wave: Round,
        state: &VirtualState,
    ) -> Option<Certificate> {
        state
            .fallback_leader(wave)
            .map(|(_, leader)| {
                (state
                    .dag
                    .get(&(certificate.virtual_round() - 1))
                    .expect("We should have all the history")
                    .values()
                    .filter(|(digest, certificate)| {
                        certificate.virtual_parents().contains(&digest)
                            && state
                                .fallback_authorities_sets
                                .get(&wave)
                                .map_or_else(|| false, |x| x.contains(&certificate.origin()))
                            && self.strong_path(leader, certificate, &state.dag)
                    })
                    .map(|(_, certificate)| self.committee.stake(&certificate.origin()))
                    .sum::<Stake>()
                    >= self.committee.quorum_threshold())
                .then(|| leader.clone())
            })
            .flatten()
    }

    /// Checks if there is a path between two leaders.
    fn strong_path(&self, leader: &Certificate, prev_leader: &Certificate, dag: &Dag) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.virtual_round()..leader.virtual_round()).rev() {
            parents = dag
                .get(&r)
                .expect("We should have the whole history by now")
                .values()
                .filter(|(digest, _)| {
                    parents
                        .iter()
                        .any(|x| x.virtual_parents().contains(&digest))
                })
                .map(|(_, certificate)| certificate)
                .collect();
        }
        parents.contains(&prev_leader)
    }

    /// Order the past leaders that we didn't already commit.
    fn order_leaders(
        &self,
        leader: &Certificate,
        state: &VirtualState,
        last_committed_wave: Round,
    ) -> Vec<Certificate> {
        let mut to_commit = vec![leader.clone()];
        let steady_wave = (leader.virtual_round() + 1) / 2;
        let mut leader = leader;
        for w in (last_committed_wave + 1..steady_wave).rev() {
            let (_, v) = state
                .dag
                .get(&(2 * w + 1))
                .expect("We should have at least one node")
                .get(&leader.origin())
                .expect("Certificates have parents of the same author");
            let votes: Vec<_> = state
                .dag
                .get(&(v.virtual_round() - 1))
                .expect("We should have the whole history")
                .values()
                .filter(|(x, _)| v.virtual_parents().contains(&x))
                .map(|(_, x)| x)
                .collect();

            let steady_leader = state.steady_leader(w).map(|(_, x)| x);
            let steady_votes: Stake = steady_leader.map_or_else(
                || 0,
                |leader| {
                    votes
                        .iter()
                        .filter(|voter| {
                            state.steady_authorities_sets.get(&w).map_or_else(
                                || false,
                                |x| {
                                    x.contains(&voter.origin())
                                        && self.strong_path(voter, leader, &state.dag)
                                },
                            )
                        })
                        .map(|voter| self.committee.stake(&voter.origin()))
                        .sum()
                },
            );

            let fallback_leader = state.fallback_leader(w / 2).map(|(_, x)| x);
            let mut fallback_votes: Stake = fallback_leader.map_or_else(
                || 0,
                |leader| {
                    votes
                        .iter()
                        .filter(|voter| {
                            state.fallback_authorities_sets.get(&(w / 2)).map_or_else(
                                || false,
                                |x| {
                                    x.contains(&voter.origin())
                                        && self.strong_path(voter, leader, &state.dag)
                                },
                            )
                        })
                        .map(|voter| self.committee.stake(&voter.origin()))
                        .sum()
                },
            );
            if w % 2 != 0 {
                fallback_votes = 0;
            }

            if let Some(steady_leader) = steady_leader {
                if steady_votes >= self.committee.validity_threshold()
                    && fallback_votes < self.committee.validity_threshold()
                {
                    to_commit.push(steady_leader.clone());
                    leader = steady_leader
                }
            }

            if let Some(fallback_leader) = fallback_leader {
                if fallback_votes >= self.committee.validity_threshold()
                    && steady_votes < self.committee.validity_threshold()
                {
                    to_commit.push(fallback_leader.clone());
                    leader = fallback_leader
                }
            }
        }
        to_commit
    }
}