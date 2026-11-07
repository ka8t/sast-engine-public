//! Taint lattice — faithful port of `Audit/sca/dataflow/lattice.py`.
//!
//! ```text
//! T  ::=  ⊥                          (Clean — untainted)
//!      |  Tainted(kinds, source)     (kinds ⊆ Kinds, source: SourceInfo)
//!      |  ⊤                          (Top — over-approximation)
//! ```

use std::collections::{BTreeMap, BTreeSet};

/// Metadata of a taint's source — allows reconstructing the
/// flow (source → sink) for reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    /// Line where the taint was introduced (source).
    pub line: usize,
    /// Textual representation of the source (for reports).
    pub expr: String,
    /// Nature of the taint (http, cli, env, etc.).
    pub kind: String,
}

/// Lattice element: `⊥` (Clean) | `Tainted(kinds, source)` | `⊤` (Top).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taint {
    Clean,
    Tainted {
        kinds: BTreeSet<String>,
        source: SourceInfo,
    },
    Top,
}

impl Taint {
    /// Builds a taint — panics if `kinds` is empty (a
    /// `Tainted` without a kind makes no sense; use `Taint::Clean`).
    /// Mirrors `Tainted.__post_init__` (Python raises `ValueError`).
    pub fn tainted(kinds: impl IntoIterator<Item = String>, source: SourceInfo) -> Self {
        let kinds: BTreeSet<String> = kinds.into_iter().collect();
        assert!(
            !kinds.is_empty(),
            "Taint::tainted: kinds ne doit pas être vide (utiliser Taint::Clean)"
        );
        Taint::Tainted { kinds, source }
    }

    pub fn is_clean(&self) -> bool {
        matches!(self, Taint::Clean)
    }

    pub fn is_top(&self) -> bool {
        matches!(self, Taint::Top)
    }

    pub fn is_tainted(&self) -> bool {
        !self.is_clean()
    }
}

/// `⊔` — merges two taints at a confluence point of the control
/// flow. Rules (spec §1/§4.3 Python):
/// ```text
/// ⊥ ⊔ x = x        x ⊔ ⊥ = x
/// ⊤ ⊔ x = ⊤        x ⊔ ⊤ = ⊤
/// Tainted(K₁,S₁) ⊔ Tainted(K₂,S₂) = Tainted(K₁ ∪ K₂, earliest_source)
/// ```
pub fn join(a: &Taint, b: &Taint) -> Taint {
    match (a, b) {
        (Taint::Top, _) | (_, Taint::Top) => Taint::Top,
        (Taint::Clean, x) => x.clone(),
        (x, Taint::Clean) => x.clone(),
        (
            Taint::Tainted {
                kinds: k1,
                source: s1,
            },
            Taint::Tainted {
                kinds: k2,
                source: s2,
            },
        ) => Taint::Tainted {
            kinds: k1.union(k2).cloned().collect(),
            source: merge_source(s1, s2),
        },
    }
}

/// `⊓` — intersects two taints (rarely used). Rules:
/// ```text
/// ⊥ ⊓ x = ⊥        x ⊓ ⊥ = ⊥
/// ⊤ ⊓ x = x        x ⊓ ⊤ = x
/// Tainted(K₁,S₁) ⊓ Tainted(K₂,S₂) = Tainted(K₁ ∩ K₂, S₁) if non-empty, else ⊥
/// ```
pub fn meet(a: &Taint, b: &Taint) -> Taint {
    match (a, b) {
        (Taint::Clean, _) | (_, Taint::Clean) => Taint::Clean,
        (Taint::Top, x) => x.clone(),
        (x, Taint::Top) => x.clone(),
        (
            Taint::Tainted {
                kinds: k1,
                source: s1,
            },
            Taint::Tainted { kinds: k2, .. },
        ) => {
            let inter: BTreeSet<String> = k1.intersection(k2).cloned().collect();
            if inter.is_empty() {
                Taint::Clean
            } else {
                Taint::Tainted {
                    kinds: inter,
                    source: s1.clone(),
                }
            }
        }
    }
}

/// `⊑` — the lattice's partial order.
/// ```text
/// ⊥ ⊑ x for all x       x ⊑ ⊤ for all x
/// Tainted(K₁,_) ⊑ Tainted(K₂,_) iff K₁ ⊆ K₂
/// ```
pub fn leq(a: &Taint, b: &Taint) -> bool {
    match (a, b) {
        (Taint::Clean, _) => true,
        (_, Taint::Top) => true,
        (_, Taint::Clean) => false, // a non-clean, b clean
        (Taint::Top, _) => false,   // a top, b non-top (and b non-⊤, case already handled above)
        (Taint::Tainted { kinds: k1, .. }, Taint::Tainted { kinds: k2, .. }) => k1.is_subset(k2),
    }
}

/// `∇` — widening operator, forces convergence over unstable
/// loops. Rule: if `iteration > max_iter` and `old != new`,
/// returns `⊤`; otherwise returns `new`.
pub fn widen(old: &Taint, new: &Taint, iteration: u32, max_iter: u32) -> Taint {
    if iteration > max_iter && old != new {
        Taint::Top
    } else {
        new.clone()
    }
}

/// Keeps the source whose line is the earliest (report consistency).
fn merge_source(s1: &SourceInfo, s2: &SourceInfo) -> SourceInfo {
    if s1.line <= s2.line {
        s1.clone()
    } else {
        s2.clone()
    }
}

/// Dataflow state: maps each LValue (canonical name) to its taint.
/// Keys whose value is `Clean` are absent from the map, to
/// stay compact — mirrors `state_set` (Python removes the key rather
/// than explicitly storing `⊥` in it).
pub type State = BTreeMap<String, Taint>;

pub fn empty_state() -> State {
    BTreeMap::new()
}

pub fn state_get(state: &State, key: &str) -> Taint {
    state.get(key).cloned().unwrap_or(Taint::Clean)
}

/// Functional update: returns a new state with `key` updated.
/// If `taint` is `Clean`, the key is removed.
pub fn state_set(state: &State, key: &str, taint: Taint) -> State {
    let mut new_state = state.clone();
    if taint.is_clean() {
        new_state.remove(key);
    } else {
        new_state.insert(key.to_string(), taint);
    }
    new_state
}

/// `⊔` on states: merges the taint of each key present in either state.
pub fn state_join(s1: &State, s2: &State) -> State {
    let mut result = State::new();
    let keys: BTreeSet<&String> = s1.keys().chain(s2.keys()).collect();
    for k in keys {
        let merged = join(&state_get(s1, k), &state_get(s2, k));
        if !merged.is_clean() {
            result.insert(k.clone(), merged);
        }
    }
    result
}

pub fn state_equal(s1: &State, s2: &State) -> bool {
    s1 == s2
}

/// Element-by-element widening of a state relative to its previous iteration.
pub fn state_widen(old: &State, new: &State, iteration: u32, max_iter: u32) -> State {
    let mut result = State::new();
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for k in keys {
        let v = widen(&state_get(old, k), &state_get(new, k), iteration, max_iter);
        if !v.is_clean() {
            result.insert(k.clone(), v);
        }
    }
    result
}

pub fn pretty_taint(t: &Taint) -> String {
    match t {
        Taint::Clean => "⊥".to_string(),
        Taint::Top => "⊤".to_string(),
        Taint::Tainted { kinds, source } => {
            let kinds_str = kinds.iter().cloned().collect::<Vec<_>>().join(",");
            format!("Tainted{{{kinds_str}}}@{}", source.line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(line: usize) -> SourceInfo {
        SourceInfo {
            line,
            expr: String::new(),
            kind: "http".to_string(),
        }
    }

    fn tainted(line: usize, kinds: &[&str]) -> Taint {
        Taint::tainted(kinds.iter().map(|s| s.to_string()), src(line))
    }

    #[test]
    fn test_join_clean_identity() {
        let t = tainted(1, &["http"]);
        assert_eq!(join(&Taint::Clean, &t), t);
        assert_eq!(join(&t, &Taint::Clean), t);
    }

    #[test]
    fn test_join_top_absorbs() {
        assert_eq!(join(&Taint::Top, &tainted(1, &["http"])), Taint::Top);
        assert_eq!(join(&tainted(1, &["http"]), &Taint::Top), Taint::Top);
    }

    #[test]
    fn test_join_tainted_unions_kinds_keeps_earliest_source() {
        let a = tainted(5, &["http"]);
        let b = tainted(2, &["cli"]);
        let result = join(&a, &b);
        match result {
            Taint::Tainted { kinds, source } => {
                assert_eq!(
                    kinds,
                    BTreeSet::from(["http".to_string(), "cli".to_string()])
                );
                assert_eq!(source.line, 2); // the earliest
            }
            _ => panic!("attendu Tainted"),
        }
    }

    #[test]
    fn test_meet_clean_absorbs() {
        assert_eq!(meet(&Taint::Clean, &tainted(1, &["http"])), Taint::Clean);
    }

    #[test]
    fn test_meet_top_identity() {
        let t = tainted(1, &["http"]);
        assert_eq!(meet(&Taint::Top, &t), t);
    }

    #[test]
    fn test_meet_disjoint_kinds_is_clean() {
        let a = tainted(1, &["http"]);
        let b = tainted(1, &["cli"]);
        assert_eq!(meet(&a, &b), Taint::Clean);
    }

    #[test]
    fn test_meet_overlapping_kinds_intersects() {
        let a = tainted(1, &["http", "cli"]);
        let b = tainted(1, &["cli", "env"]);
        match meet(&a, &b) {
            Taint::Tainted { kinds, .. } => assert_eq!(kinds, BTreeSet::from(["cli".to_string()])),
            _ => panic!("attendu Tainted"),
        }
    }

    #[test]
    fn test_leq_clean_bottom_of_everything() {
        assert!(leq(&Taint::Clean, &Taint::Clean));
        assert!(leq(&Taint::Clean, &tainted(1, &["http"])));
        assert!(leq(&Taint::Clean, &Taint::Top));
    }

    #[test]
    fn test_leq_top_is_top_of_everything() {
        assert!(leq(&tainted(1, &["http"]), &Taint::Top));
        assert!(leq(&Taint::Top, &Taint::Top));
        assert!(!leq(&Taint::Top, &tainted(1, &["http"])));
    }

    #[test]
    fn test_leq_kinds_subset() {
        let small = tainted(1, &["http"]);
        let big = tainted(1, &["http", "cli"]);
        assert!(leq(&small, &big));
        assert!(!leq(&big, &small));
    }

    #[test]
    fn test_widen_stable_keeps_new() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["http"]);
        assert_eq!(widen(&old, &new, 5, 3), new);
    }

    #[test]
    fn test_widen_unstable_past_max_iter_becomes_top() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["cli"]);
        assert_eq!(widen(&old, &new, 4, 3), Taint::Top);
    }

    #[test]
    fn test_widen_unstable_before_max_iter_keeps_new() {
        let old = tainted(1, &["http"]);
        let new = tainted(1, &["cli"]);
        assert_eq!(widen(&old, &new, 2, 3), new);
    }

    #[test]
    fn test_state_set_clean_removes_key() {
        let mut state = empty_state();
        state.insert("x".to_string(), tainted(1, &["http"]));
        let updated = state_set(&state, "x", Taint::Clean);
        assert!(!updated.contains_key("x"));
    }

    #[test]
    fn test_state_get_absent_key_is_clean() {
        let state = empty_state();
        assert_eq!(state_get(&state, "missing"), Taint::Clean);
    }

    #[test]
    fn test_state_join_merges_both_keys() {
        let mut s1 = empty_state();
        s1.insert("x".to_string(), tainted(1, &["http"]));
        let mut s2 = empty_state();
        s2.insert("y".to_string(), tainted(2, &["cli"]));
        let joined = state_join(&s1, &s2);
        assert_eq!(joined.len(), 2);
    }

    #[test]
    fn test_state_join_omits_clean_results() {
        // x tainted on one side, absent (so clean) on the other → join =
        // the non-clean value, present in the result (no loss).
        let mut s1 = empty_state();
        s1.insert("x".to_string(), tainted(1, &["http"]));
        let s2 = empty_state();
        let joined = state_join(&s1, &s2);
        assert!(joined.contains_key("x"));
    }
}
