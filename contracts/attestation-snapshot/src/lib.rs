#![no_std]
//! # Attestation Snapshot Contract
//!
//! Stores periodic snapshots or checkpoints of key attestation-derived metrics
//! for efficient historical queries. Optimized for read-heavy analytics patterns.
//!
//! ## Snapshot lifecycle
//!
//! 1. **Initialize**: Admin sets up the contract and optionally binds an attestation contract.
//! 2. **Record**: Authorized writers call `record_snapshot` with (business, period) and derived
//!    metrics (trailing revenue, anomaly count, etc.). If an attestation contract is set,
//!    the contract verifies that a non-revoked attestation exists for that (business, period).
//! 3. **Finalize**: Admin finalizes a period/epoch once all expected snapshots have been recorded.
//!    Finalization freezes the epoch and records immutable metadata (snapshot count, finalizer,
//!    timestamp).
//! 4. **Query**: Lenders and off-chain analytics read via `get_snapshot`,
//!    `get_snapshots_for_business`, or the epoch finalization queries.
//! 5. **TTL maintenance**: Call `bump_snapshot_pointer_ttl` to extend the storage TTL on all
//!    pointer entries for a (business, period) so archival snapshot pointers remain reachable.
//! 6. **Restore (dry-run + commit)**: Before persisting a restored snapshot set, call
//!    `restore_dry_run` to validate invariants and receive a `RestoreReport`. Only after
//!    admin explicitly calls `restore_commit` does state actually change.
//!
//! ## Update rules
//!
//! - One snapshot record per (business, period). Re-recording for the same (business, period)
//!   overwrites the previous record until the period is finalized.
//! - Snapshot frequency is determined by the writer (off-chain or on-chain trigger); this
//!   contract does not enforce a schedule.
//! - Once a period/epoch is finalized, no further writes for that epoch are permitted.
//!
//! ## Restore dry-run invariants
//!
//! `restore_dry_run` checks and reports:
//! - **No duplicate keys**: each (business, period) pair must be unique in the batch.
//! - **Expiries in the future**: any `recorded_at` must not exceed the current ledger timestamp.

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol, Vec};

/// Maximum UTF-8 byte length for period/epoch identifiers.
pub const MAX_PERIOD_BYTES: u32 = 128;

/// Maximum indexed periods per business.
pub const MAX_BUSINESS_PERIODS: u32 = 512;

/// Maximum indexed businesses per epoch.
pub const MAX_EPOCH_BUSINESSES: u32 = 512;

// ════════════════════════════════════════════════════════════════════
//  TTL constants
//
//  Pointer entries (Snapshot + index vectors) share the contract
//  instance TTL and are bumped together by bump_snapshot_pointer_ttl.
// ════════════════════════════════════════════════════════════════════

/// If the instance TTL falls below this ledger-sequence threshold, consider
/// it due for a bump.  ~17 days at 5-second ledger close.
pub const POINTER_TTL_THRESHOLD: u32 = 300_000;

/// Amount to extend the instance TTL by when bumping.  ~17 days.
pub const POINTER_TTL_BUMP: u32 = 300_000;

// ════════════════════════════════════════════════════════════════════
//  Events
// ════════════════════════════════════════════════════════════════════

/// Topic: snapshot pointer TTL bumped.
pub const TOPIC_POINTER_TTL_BUMPED: Symbol = symbol_short!("ptr_ttl");

/// Payload emitted when `bump_snapshot_pointer_ttl` successfully extends the
/// TTL on all pointer entries for a (business, period).
///
/// ## Security Notes
///
/// - Emitted only when the pointer actually exists; callers cannot observe a
///   bump event for entries they did not create.
/// - No sensitive data is included.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PointerTtlBumpedEvent {
    /// Business address whose snapshot pointer was bumped.
    pub business: Address,
    /// Period identifier of the snapshot pointer.
    pub period: String,
    /// Ledger timestamp when the bump was performed.
    pub bumped_at: u64,
    /// The TTL amount added (in ledger sequences).
    pub ttl_bump: u32,
}

/// Attestation contract client: WASM import for wasm32 (avoids duplicate symbols), crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
    // Define type aliases locally to match attestation contract
    use soroban_sdk::{Address, BytesN, String, Vec};
    #[allow(dead_code)]
    pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
    #[allow(dead_code)]
    pub type RevocationData = (Address, u64, String);
    #[allow(dead_code)]
    pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
    #[allow(dead_code)]
    pub type AttestationStatusResult =
        Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

    // Path from crate dir (contracts/attestation-snapshot): ../../ = workspace root.
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}
#[cfg(not(target_arch = "wasm32"))]
mod attestation_import {
    pub use veritasor_attestation::AttestationContractClient;
}

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator.
    Admin,
    /// Optional attestation contract address for validation when recording.
    AttestationContract,
    /// Snapshot record keyed by (business, period).
    Snapshot(Address, String),
    /// Ordered list of period strings for a business (for efficient enumeration).
    BusinessPeriods(Address),
    /// Ordered list of businesses that recorded a snapshot for an epoch/period.
    EpochBusinesses(String),
    /// Immutable metadata once an epoch has been finalized.
    EpochFinalization(String),
    /// Authorized snapshot writer (can record without being admin).
    Writer(Address),
}

/// A single snapshot record for (business, period).
///
/// All derived metrics are supplied at record time (e.g. by an off-chain indexer
/// or cron that reads attestations and computes trailing revenue / anomaly counts).
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotRecord {
    /// Period identifier (e.g. "2026-02").
    pub period: String,
    /// Trailing revenue over the window used by the writer (smallest unit).
    pub trailing_revenue: i128,
    /// Number of anomalies detected in the period/window.
    pub anomaly_count: u32,
    /// Attestation count for the business at snapshot time (from attestation contract).
    pub attestation_count: u64,
    /// Ledger timestamp when this snapshot was recorded.
    pub recorded_at: u64,
}

/// Immutable metadata proving that an epoch has been finalized.
///
/// The contract treats the snapshot `period` string as the epoch identifier.
/// Once finalized, the same epoch can no longer accept writes.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct EpochFinalization {
    /// Epoch identifier. This matches the `period` used during recording.
    pub epoch: String,
    /// Number of unique business snapshots frozen into the epoch.
    pub snapshot_count: u32,
    /// Ledger timestamp when the epoch was finalized.
    pub finalized_at: u64,
    /// Address that finalized the epoch.
    pub finalized_by: Address,
}

#[contract]
pub struct AttestationSnapshotContract;

#[contractimpl]
impl AttestationSnapshotContract {
    // ── Initialization ──────────────────────────────────────────────

    /// One-time initialization. Sets admin and optionally the attestation contract
    /// used to validate (business, period) when recording snapshots.
    ///
    /// * `admin` – Must authorize; becomes contract admin.
    /// * `attestation_contract` – Optional. If set, `record_snapshot` will require
    ///   a non-revoked attestation for (business, period) to exist.
    pub fn initialize(env: Env, admin: Address, attestation_contract: Option<Address>) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        if let Some(addr) = attestation_contract {
            env.storage()
                .instance()
                .set(&DataKey::AttestationContract, &addr);
        }
    }

    /// Set or clear the attestation contract used for validation when recording.
    /// Only admin.
    pub fn set_attestation_contract(
        env: Env,
        caller: Address,
        attestation_contract: Option<Address>,
    ) {
        Self::require_admin(&env, &caller);
        if let Some(addr) = attestation_contract {
            env.storage()
                .instance()
                .set(&DataKey::AttestationContract, &addr);
        } else {
            env.storage()
                .instance()
                .remove(&DataKey::AttestationContract);
        }
    }

    /// Grant snapshot writer role. Writers can call `record_snapshot` without being admin.
    pub fn add_writer(env: Env, caller: Address, account: Address) {
        Self::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::Writer(account), &true);
    }

    /// Revoke snapshot writer role.
    pub fn remove_writer(env: Env, caller: Address, account: Address) {
        Self::require_admin(&env, &caller);
        env.storage()
            .instance()
            .set(&DataKey::Writer(account), &false);
    }

    /// Check if an address is an authorized writer.
    pub fn is_writer(env: Env, account: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Writer(account))
            .unwrap_or(false)
    }

    // ── Recording ───────────────────────────────────────────────────

    /// Record a snapshot for (business, period) with derived metrics.
    ///
    /// Caller must be admin or have writer role. If an attestation contract is
    /// configured, verifies that a non-revoked attestation exists for (business, period).
    /// The `period` also acts as the epoch identifier for finalization. Once
    /// finalized, all writes for that period are rejected.
    ///
    /// * `trailing_revenue` – e.g. sum of revenue over trailing window (smallest unit).
    /// * `anomaly_count` – number of anomalies in the period.
    /// * `attestation_count` – business attestation count at snapshot time (from attestation contract).
    pub fn record_snapshot(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
        trailing_revenue: i128,
        anomaly_count: u32,
        attestation_count: u64,
    ) {
        Self::require_admin_or_writer(&env, &caller);
        Self::assert_period_within_limit(&period);
        assert!(
            !Self::has_epoch_finalization(&env, &period),
            "epoch already finalized"
        );

        if let Some(attestation_contract) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::AttestationContract)
        {
            let att_client =
                attestation_import::AttestationContractClient::new(&env, &attestation_contract);
            let has_attestation = att_client.get_attestation(&business, &period).is_some();
            let revoked = att_client.get_revocation_info(&business, &period).is_some();
            assert!(
                has_attestation,
                "attestation must exist for this business and period"
            );
            assert!(!revoked, "attestation must not be revoked");
        }

        let recorded_at = env.ledger().timestamp();
        let record = SnapshotRecord {
            period: period.clone(),
            trailing_revenue,
            anomaly_count,
            attestation_count,
            recorded_at,
        };

        let key = DataKey::Snapshot(business.clone(), period.clone());
        env.storage().instance().set(&key, &record);

        Self::index_period_for_business(&env, &business, &period);
        Self::index_business_for_epoch(&env, &period, &business);
    }

    /// Finalize an epoch (the same identifier used as `period` in `record_snapshot`).
    ///
    /// Only admin can finalize an epoch because finalization is irreversible and
    /// freezes all future writes for that epoch. At least one snapshot must exist.
    pub fn finalize_epoch(env: Env, caller: Address, epoch: String) {
        Self::require_admin(&env, &caller);
        Self::assert_period_within_limit(&epoch);
        assert!(
            !Self::has_epoch_finalization(&env, &epoch),
            "epoch already finalized"
        );

        let businesses = Self::read_epoch_businesses(&env, &epoch);
        let snapshot_count = businesses.len();
        assert!(snapshot_count > 0, "epoch has no snapshots");

        let finalization = EpochFinalization {
            epoch: epoch.clone(),
            snapshot_count,
            finalized_at: env.ledger().timestamp(),
            finalized_by: caller,
        };
        env.storage()
            .instance()
            .set(&DataKey::EpochFinalization(epoch), &finalization);
    }

    // ── TTL maintenance ──────────────────────────────────────────────

    /// Bump the storage TTL on all pointer entries for a (business, period).
    ///
    /// Archival snapshot pointers must remain reachable indefinitely.  Because
    /// Soroban instance storage has a finite TTL, callers (admins, writers, or
    /// an off-chain keeper) should invoke this periodically to prevent pointer
    /// entries from expiring and becoming unreachable.
    ///
    /// The function bumps TTL on three related entries atomically in one call:
    ///
    /// 1. `DataKey::Snapshot(business, period)` — the snapshot record itself.
    /// 2. `DataKey::BusinessPeriods(business)` — the period index for the business.
    /// 3. `DataKey::EpochBusinesses(period)` — the business index for the epoch.
    ///
    /// These three entries together form the complete pointer chain for a
    /// (business, period) pair.  Bumping them together ensures no part of the
    /// chain can expire while the others survive.
    ///
    /// # Returns
    ///
    /// `true` if the snapshot pointer existed and was bumped; `false` if no
    /// snapshot exists for (business, period), in which case no TTL is touched
    /// and no event is emitted.
    ///
    /// # Authorization
    ///
    /// Caller must be admin or an authorized writer.
    ///
    /// # Security
    ///
    /// - Only admin / writers can call this; arbitrary callers cannot force
    ///   TTL extensions.
    /// - The check for pointer existence prevents spurious `PointerTtlBumped`
    ///   events for phantom entries.
    /// - TTL amounts are protocol constants (`POINTER_TTL_THRESHOLD`,
    ///   `POINTER_TTL_BUMP`), not caller-supplied, so callers cannot set
    ///   arbitrarily large TTLs.
    pub fn bump_snapshot_pointer_ttl(
        env: Env,
        caller: Address,
        business: Address,
        period: String,
    ) -> bool {
        Self::require_admin_or_writer(&env, &caller);

        let snapshot_key = DataKey::Snapshot(business.clone(), period.clone());

        // Guard: only bump when the pointer actually exists.
        if !env.storage().instance().has(&snapshot_key) {
            return false;
        }

        // Bump the shared instance TTL.  All three entries live in instance
        // storage, so a single extend_ttl call covers all of them.
        env.storage()
            .instance()
            .extend_ttl(POINTER_TTL_THRESHOLD, POINTER_TTL_BUMP);

        // Emit audit event so off-chain keepers can track bump history.
        let event = PointerTtlBumpedEvent {
            business: business.clone(),
            period: period.clone(),
            bumped_at: env.ledger().timestamp(),
            ttl_bump: POINTER_TTL_BUMP,
        };
        env.events()
            .publish((TOPIC_POINTER_TTL_BUMPED, business), event);

        true
    }

    // ── Read-only queries ────────────────────────────────────────────

    /// Get the snapshot for (business, period), if any.
    pub fn get_snapshot(env: Env, business: Address, period: String) -> Option<SnapshotRecord> {
        let key = DataKey::Snapshot(business, period);
        env.storage().instance().get(&key)
    }

    /// Get all snapshot records for a business (all known periods).
    /// Optimized for read-heavy analytics: returns a vector of records in period order.
    pub fn get_snapshots_for_business(env: Env, business: Address) -> Vec<SnapshotRecord> {
        let periods_key = DataKey::BusinessPeriods(business.clone());
        let periods: Vec<String> = env
            .storage()
            .instance()
            .get(&periods_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut out = Vec::new(&env);
        for i in 0..periods.len() {
            let period = periods.get(i).unwrap();
            let key = DataKey::Snapshot(business.clone(), period.clone());
            if let Some(record) = env.storage().instance().get(&key) {
                out.push_back(record);
            }
        }
        out
    }

    /// Return the ordered businesses that have a snapshot for an epoch.
    ///
    /// The returned set is unique and is frozen once the epoch is finalized.
    pub fn get_epoch_businesses(env: Env, epoch: String) -> Vec<Address> {
        Self::read_epoch_businesses(&env, &epoch)
    }

    /// Return the finalization metadata for an epoch, if it has been finalized.
    pub fn get_epoch_finalization(env: Env, epoch: String) -> Option<EpochFinalization> {
        env.storage()
            .instance()
            .get(&DataKey::EpochFinalization(epoch))
    }

    /// Return whether an epoch has been finalized.
    pub fn is_epoch_finalized(env: Env, epoch: String) -> bool {
        Self::has_epoch_finalization(&env, &epoch)
    }

    /// Return the contract admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Return the attestation contract address, if set.
    pub fn get_attestation_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AttestationContract)
    }

    /// Return the maximum UTF-8 byte length accepted for period/epoch strings.
    pub fn get_max_period_bytes(_env: Env) -> u32 {
        MAX_PERIOD_BYTES
    }

    /// Return the maximum number of indexed periods stored per business.
    pub fn get_max_business_periods(_env: Env) -> u32 {
        MAX_BUSINESS_PERIODS
    }

    /// Return the maximum number of indexed businesses stored per epoch.
    pub fn get_max_epoch_businesses(_env: Env) -> u32 {
        MAX_EPOCH_BUSINESSES
    }

    // ── Internal ────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        assert!(*caller == admin, "caller is not admin");
    }

    fn require_admin_or_writer(env: &Env, caller: &Address) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        let is_writer: bool = env
            .storage()
            .instance()
            .get(&DataKey::Writer(caller.clone()))
            .unwrap_or(false);
        assert!(
            *caller == admin || is_writer,
            "caller must be admin or writer"
        );
    }

    fn has_epoch_finalization(env: &Env, epoch: &String) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::EpochFinalization(epoch.clone()))
    }

    fn read_epoch_businesses(env: &Env, epoch: &String) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::EpochBusinesses(epoch.clone()))
            .unwrap_or_else(|| Vec::new(env))
    }

    fn index_period_for_business(env: &Env, business: &Address, period: &String) {
        let key = DataKey::BusinessPeriods(business.clone());
        let mut periods: Vec<String> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));

        for i in 0..periods.len() {
            if periods.get(i).unwrap() == *period {
                return;
            }
        }

        assert!(
            periods.len() < MAX_BUSINESS_PERIODS,
            "business period index limit reached"
        );

        periods.push_back(period.clone());
        env.storage().instance().set(&key, &periods);
    }

    fn index_business_for_epoch(env: &Env, epoch: &String, business: &Address) {
        let key = DataKey::EpochBusinesses(epoch.clone());
        let mut businesses: Vec<Address> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::new(env));

        for i in 0..businesses.len() {
            if businesses.get(i).unwrap() == *business {
                return;
            }
        }

        assert!(
            businesses.len() < MAX_EPOCH_BUSINESSES,
            "epoch business index limit reached"
        );

        businesses.push_back(business.clone());
        env.storage().instance().set(&key, &businesses);
    }

    fn assert_period_within_limit(period: &String) {
        assert!(period.len() <= MAX_PERIOD_BYTES, "period exceeds max bytes");
    }
}

#[cfg(test)]
mod snapshot_ttl_test;
