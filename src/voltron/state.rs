use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TechniqueState {
    Queued,
    Dispatched,
    Running,
    CleanupPending,
    CleanupComplete,
    Done,
    Aborted,
    Failed,
}

impl TechniqueState {
    pub fn to_string(&self) -> &'static str {
        match self {
            TechniqueState::Queued => "QUEUED",
            TechniqueState::Dispatched => "DISPATCHED",
            TechniqueState::Running => "RUNNING",
            TechniqueState::CleanupPending => "CLEANUP_PENDING",
            TechniqueState::CleanupComplete => "CLEANUP_COMPLETE",
            TechniqueState::Done => "DONE",
            TechniqueState::Aborted => "ABORTED",
            TechniqueState::Failed => "FAILED",
        }
    }
    
    fn from_string(s: &str) -> Result<Self, JournalError> {
        match s {
            "QUEUED" => Ok(TechniqueState::Queued),
            "DISPATCHED" => Ok(TechniqueState::Dispatched),
            "RUNNING" => Ok(TechniqueState::Running),
            "CLEANUP_PENDING" => Ok(TechniqueState::CleanupPending),
            "CLEANUP_COMPLETE" => Ok(TechniqueState::CleanupComplete),
            "DONE" => Ok(TechniqueState::Done),
            "ABORTED" => Ok(TechniqueState::Aborted),
            "FAILED" => Ok(TechniqueState::Failed),
            _ => Err(JournalError::InvalidState(s.to_string())),
        }
    }
    
    pub fn can_transition_to(&self, new_state: &TechniqueState) -> bool {
        match (self, new_state) {
            // Normal progression (full lifecycle for complex techniques with artifacts)
            (TechniqueState::Queued, TechniqueState::Dispatched) => true,
            (TechniqueState::Dispatched, TechniqueState::Running) => true,
            (TechniqueState::Running, TechniqueState::CleanupPending) => true,
            (TechniqueState::CleanupPending, TechniqueState::CleanupComplete) => true,
            (TechniqueState::CleanupComplete, TechniqueState::Done) => true,
            
            // Direct completion paths (simple techniques without cleanup requirements)
            (TechniqueState::Queued, TechniqueState::Done) => true,
            (TechniqueState::Dispatched, TechniqueState::Done) => true,
            (TechniqueState::Running, TechniqueState::Done) => true,
            (TechniqueState::CleanupPending, TechniqueState::Done) => true,
            
            // Idempotent terminal state transitions (for multi-role techniques)
            // Both attacker and victim may report completion independently
            (TechniqueState::Done, TechniqueState::Done) => true,
            (TechniqueState::Failed, TechniqueState::Failed) => true,
            (TechniqueState::Aborted, TechniqueState::Aborted) => true,
            
            // Cross-terminal transitions for multi-role completion races
            // ABORTED→DONE: Client completes before processing abort (rare race)
            (TechniqueState::Aborted, TechniqueState::Done) => true,
            
            // DONE→FAILED: Temporary workaround for multi-role techniques
            // First role reports SUCCESS (journal→DONE), second role reports FAILED (journal→FAILED)
            // TODO: Replace with proper role-based completion tracking that only marks DONE when both roles succeed
            (TechniqueState::Done, TechniqueState::Failed) => true,
            
            // Failure paths - allow failures from any active state
            (TechniqueState::Queued, TechniqueState::Failed) => true,
            (TechniqueState::Dispatched, TechniqueState::Failed) => true,
            (TechniqueState::Running, TechniqueState::Failed) => true,
            (TechniqueState::CleanupPending, TechniqueState::Failed) => true,
            
            // Abort paths - allow operator-initiated abort from any non-terminal state
            (TechniqueState::Queued, TechniqueState::Aborted) => true,
            (TechniqueState::Dispatched, TechniqueState::Aborted) => true,
            (TechniqueState::Running, TechniqueState::Aborted) => true,
            (TechniqueState::CleanupPending, TechniqueState::Aborted) => true,
            
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueRecord {
    pub id: String,
    pub technique: String,
    pub state: TechniqueState,
    pub attacker: Option<String>,
    pub victim: Option<String>,
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub artifacts: Vec<String>,
    pub error: Option<String>,
    pub group_id: Option<String>,
}

pub struct TechniqueJournal {
    conn: Connection,
}

impl TechniqueJournal {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, JournalError> {
        let conn = Connection::open(path.as_ref())
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS technique_journal (
                id TEXT PRIMARY KEY,
                technique TEXT NOT NULL,
                state TEXT NOT NULL,
                attacker TEXT,
                victim TEXT,
                started_at INTEGER,
                completed_at INTEGER,
                artifacts_json TEXT NOT NULL,
                error TEXT,
                group_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| JournalError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_state ON technique_journal(state)",
            [],
        )
        .map_err(|e| JournalError::Database(e.to_string()))?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON technique_journal(created_at DESC)",
            [],
        )
        .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(TechniqueJournal { conn })
    }

    #[allow(dead_code)]
    pub fn create_record(&mut self, record: &TechniqueRecord) -> Result<(), JournalError> {
        let now = chrono::Utc::now().timestamp();
        let artifacts_json = serde_json::to_string(&record.artifacts)?;
        
        self.conn
            .execute(
                "INSERT INTO technique_journal 
                (id, technique, state, attacker, victim, started_at, completed_at, 
                 artifacts_json, error, group_id, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    record.id,
                    record.technique,
                    record.state.to_string(),
                    record.attacker,
                    record.victim,
                    record.started_at,
                    record.completed_at,
                    artifacts_json,
                    record.error,
                    record.group_id,
                    now,
                    now,
                ],
            )
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn add_technique(&mut self, id: &str, technique: &str, group_id: Option<&str>) -> Result<(), JournalError> {
        let record = TechniqueRecord {
            id: id.to_string(),
            technique: technique.to_string(),
            state: TechniqueState::Queued,
            attacker: None,
            victim: None,
            started_at: None,
            completed_at: None,
            artifacts: Vec::new(),
            error: None,
            group_id: group_id.map(|s| s.to_string()),
        };
        
        self.create_record(&record)
    }

    pub fn update_state(&mut self, id: &str, new_state: TechniqueState) -> Result<(), JournalError> {
        let current = self.get_record(id)?
            .ok_or_else(|| JournalError::RecordNotFound(id.to_string()))?;
        
        if !current.state.can_transition_to(&new_state) {
            return Err(JournalError::InvalidStateTransition {
                from: current.state.to_string().to_string(),
                to: new_state.to_string().to_string(),
            });
        }
        
        let now = chrono::Utc::now().timestamp();
        let mut completed_at = current.completed_at;
        
        if new_state == TechniqueState::Done || new_state == TechniqueState::Aborted || new_state == TechniqueState::Failed {
            completed_at = Some(now);
        }
        
        self.conn
            .execute(
                "UPDATE technique_journal 
                 SET state = ?1, completed_at = ?2, updated_at = ?3 
                 WHERE id = ?4",
                params![new_state.to_string(), completed_at, now, id],
            )
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(())
    }
    
    #[allow(dead_code)]
    pub fn update_error(&mut self, id: &str, error: &str) -> Result<(), JournalError> {
        let now = chrono::Utc::now().timestamp();
        
        self.conn
            .execute(
                "UPDATE technique_journal 
                 SET error = ?1, updated_at = ?2 
                 WHERE id = ?3",
                params![error, now, id],
            )
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(())
    }

    pub fn get_record(&self, id: &str) -> Result<Option<TechniqueRecord>, JournalError> {
        let result = self.conn.query_row(
            "SELECT id, technique, state, attacker, victim, started_at, completed_at, 
                    artifacts_json, error 
             FROM technique_journal 
             WHERE id = ?1",
            params![id],
            |row| self.row_to_record(row),
        );
        
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(JournalError::Database(e.to_string())),
        }
    }

    #[allow(dead_code)]
    pub fn get_incomplete_techniques(&self) -> Result<Vec<TechniqueRecord>, JournalError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, technique, state, attacker, victim, started_at, completed_at, 
                        artifacts_json, error 
                 FROM technique_journal 
                 WHERE state IN ('RUNNING', 'CLEANUP_PENDING', 'DISPATCHED')
                 ORDER BY created_at ASC"
            )
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        let records = stmt
            .query_map([], |row| self.row_to_record(row))
            .map_err(|e| JournalError::Database(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(records)
    }

    #[allow(dead_code)]
    pub fn get_recent_techniques(&self, limit: usize) -> Result<Vec<TechniqueRecord>, JournalError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT id, technique, state, attacker, victim, started_at, completed_at, 
                        artifacts_json, error 
                 FROM technique_journal 
                 ORDER BY created_at DESC 
                 LIMIT ?1"
            )
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        let records = stmt
            .query_map(params![limit], |row| self.row_to_record(row))
            .map_err(|e| JournalError::Database(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JournalError::Database(e.to_string()))?;
        
        Ok(records)
    }
    
    pub fn get_running_techniques_for_client(&self, hostname: &str) -> Vec<String> {
        // Query for all RUNNING techniques where attacker or victim matches hostname
        let query = "SELECT id FROM technique_journal 
                     WHERE state = 'RUNNING' 
                     AND (attacker = ?1 OR victim = ?1)";
        
        let mut stmt = match self.conn.prepare(query) {
            Ok(s) => s,
            Err(e) => {
                log::error!(" Failed to prepare query for running techniques: {}", e);
                return vec![];
            }
        };
        
        let technique_ids = stmt
            .query_map(params![hostname], |row| row.get::<_, String>(0))
            .ok()
            .map(|rows| {
                rows.filter_map(|r| r.ok()).collect::<Vec<String>>()
            })
            .unwrap_or_default();
        
        technique_ids
    }
    
    fn row_to_record(&self, row: &Row) -> rusqlite::Result<TechniqueRecord> {
        let state_str: String = row.get(2)?;
        let state = TechniqueState::from_string(&state_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(2, "state".to_string(), rusqlite::types::Type::Text))?;
        
        let artifacts_json: String = row.get(7)?;
        let artifacts: Vec<String> = serde_json::from_str(&artifacts_json)
            .unwrap_or_default();
        
        Ok(TechniqueRecord {
            id: row.get(0)?,
            technique: row.get(1)?,
            state,
            attacker: row.get(3)?,
            victim: row.get(4)?,
            started_at: row.get(5)?,
            completed_at: row.get(6)?,
            artifacts,
            error: row.get(8)?,
            group_id: row.get(9).ok(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Record not found: {0}")]
    RecordNotFound(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_state_transitions() {
        // Normal progression (full lifecycle for complex techniques)
        assert!(TechniqueState::Queued.can_transition_to(&TechniqueState::Dispatched));
        assert!(TechniqueState::Dispatched.can_transition_to(&TechniqueState::Running));
        assert!(TechniqueState::Running.can_transition_to(&TechniqueState::CleanupPending));
        assert!(TechniqueState::CleanupPending.can_transition_to(&TechniqueState::CleanupComplete));
        assert!(TechniqueState::CleanupComplete.can_transition_to(&TechniqueState::Done));
        
        // Direct completion paths (simple techniques without cleanup)
        assert!(TechniqueState::Queued.can_transition_to(&TechniqueState::Done));
        assert!(TechniqueState::Dispatched.can_transition_to(&TechniqueState::Done));
        assert!(TechniqueState::Running.can_transition_to(&TechniqueState::Done));
        assert!(TechniqueState::CleanupPending.can_transition_to(&TechniqueState::Done));
        
        // Invalid transitions
        assert!(!TechniqueState::Queued.can_transition_to(&TechniqueState::Running));
        assert!(!TechniqueState::Done.can_transition_to(&TechniqueState::Running));
        
        // FAILED from any active state
        assert!(TechniqueState::Queued.can_transition_to(&TechniqueState::Failed));
        assert!(TechniqueState::Dispatched.can_transition_to(&TechniqueState::Failed));
        assert!(TechniqueState::Running.can_transition_to(&TechniqueState::Failed));
        assert!(TechniqueState::CleanupPending.can_transition_to(&TechniqueState::Failed));
        
        // ABORTED from any active state
        assert!(TechniqueState::Queued.can_transition_to(&TechniqueState::Aborted));
        assert!(TechniqueState::Dispatched.can_transition_to(&TechniqueState::Aborted));
        assert!(TechniqueState::Running.can_transition_to(&TechniqueState::Aborted));
        assert!(TechniqueState::CleanupPending.can_transition_to(&TechniqueState::Aborted));
        
        // Cross-terminal transitions for multi-role completion races
        assert!(TechniqueState::Aborted.can_transition_to(&TechniqueState::Done));
        assert!(TechniqueState::Done.can_transition_to(&TechniqueState::Failed));
        
        // Rejected cross-terminal transitions (preserve dispatch failure semantics)
        assert!(!TechniqueState::Failed.can_transition_to(&TechniqueState::Aborted));
        assert!(!TechniqueState::Failed.can_transition_to(&TechniqueState::Done));
        assert!(!TechniqueState::Done.can_transition_to(&TechniqueState::Aborted));
        assert!(!TechniqueState::Aborted.can_transition_to(&TechniqueState::Failed));
        
        // Cannot transition from terminal states to non-terminal states
        assert!(!TechniqueState::Done.can_transition_to(&TechniqueState::Running));
        assert!(!TechniqueState::Failed.can_transition_to(&TechniqueState::Running));
        assert!(!TechniqueState::Aborted.can_transition_to(&TechniqueState::Running));
    }

    #[test]
    fn test_create_journal() {
        let tmp = NamedTempFile::new().unwrap();
        let journal = TechniqueJournal::new(tmp.path()).unwrap();
        assert!(journal.conn.is_autocommit());
    }

    #[test]
    fn test_create_and_get_record() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        let record = TechniqueRecord {
            id: "test-123".to_string(),
            technique: "T1021.005".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record).unwrap();
        
        let retrieved = journal.get_record("test-123").unwrap().unwrap();
        assert_eq!(retrieved.id, "test-123");
        assert_eq!(retrieved.technique, "T1021.005");
        assert_eq!(retrieved.state, TechniqueState::Queued);
        assert_eq!(retrieved.attacker, Some("attacker1".to_string()));
    }

    #[test]
    fn test_update_state() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        let record = TechniqueRecord {
            id: "test-456".to_string(),
            technique: "T1021.005".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record).unwrap();
        
        journal.update_state("test-456", TechniqueState::Dispatched).unwrap();
        let updated = journal.get_record("test-456").unwrap().unwrap();
        assert_eq!(updated.state, TechniqueState::Dispatched);
        
        journal.update_state("test-456", TechniqueState::Running).unwrap();
        journal.update_state("test-456", TechniqueState::CleanupPending).unwrap();
        journal.update_state("test-456", TechniqueState::CleanupComplete).unwrap();
        journal.update_state("test-456", TechniqueState::Done).unwrap();
        
        let final_record = journal.get_record("test-456").unwrap().unwrap();
        assert_eq!(final_record.state, TechniqueState::Done);
        assert!(final_record.completed_at.is_some());
    }

    #[test]
    fn test_invalid_state_transition() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        let record = TechniqueRecord {
            id: "test-789".to_string(),
            technique: "T1021.005".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record).unwrap();
        
        // Invalid: Queued -> Running (must go through Dispatched)
        let result = journal.update_state("test-789", TechniqueState::Running);
        assert!(result.is_err());
        match result {
            Err(JournalError::InvalidStateTransition { .. }) => {},
            _ => panic!("Expected InvalidStateTransition error"),
        }
        
        // Invalid: Queued -> CleanupPending (must go through Dispatched and Running)
        let result2 = journal.update_state("test-789", TechniqueState::CleanupPending);
        assert!(result2.is_err());
        match result2 {
            Err(JournalError::InvalidStateTransition { from, to }) => {
                assert_eq!(from, "QUEUED");
                assert_eq!(to, "CLEANUP_PENDING");
            },
            _ => panic!("Expected InvalidStateTransition error"),
        }
    }
    
    #[test]
    fn test_idempotent_terminal_states() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        // Test DONE -> DONE (multi-role techniques where both attacker and victim report completion)
        let record1 = TechniqueRecord {
            id: "test-done-done".to_string(),
            technique: "T1021.004-PROTO".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record1).unwrap();
        journal.update_state("test-done-done", TechniqueState::Done).unwrap();
        
        // Second DONE transition should succeed (idempotent)
        journal.update_state("test-done-done", TechniqueState::Done).unwrap();
        
        let final_record = journal.get_record("test-done-done").unwrap().unwrap();
        assert_eq!(final_record.state, TechniqueState::Done);
        
        // Test FAILED -> FAILED (idempotent)
        let record2 = TechniqueRecord {
            id: "test-failed-failed".to_string(),
            technique: "T1021.005-PROTO".to_string(),
            state: TechniqueState::Running,
            attacker: Some("attacker2".to_string()),
            victim: Some("victim2".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record2).unwrap();
        journal.update_state("test-failed-failed", TechniqueState::Failed).unwrap();
        
        // Second FAILED transition should succeed (idempotent)
        journal.update_state("test-failed-failed", TechniqueState::Failed).unwrap();
        
        let final_record2 = journal.get_record("test-failed-failed").unwrap().unwrap();
        assert_eq!(final_record2.state, TechniqueState::Failed);
    }

    #[test]
    fn test_cross_terminal_transitions() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        // Test ABORTED -> DONE (client completes before processing abort)
        // Scenario: Server sends abort, but client finishes successfully before receiving it
        let record1 = TechniqueRecord {
            id: "test-aborted-done".to_string(),
            technique: "T1021.004-PROTO".to_string(),
            state: TechniqueState::Running,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record1).unwrap();
        journal.update_state("test-aborted-done", TechniqueState::Aborted).unwrap();
        journal.update_state("test-aborted-done", TechniqueState::Done).unwrap();
        
        let final_record1 = journal.get_record("test-aborted-done").unwrap().unwrap();
        assert_eq!(final_record1.state, TechniqueState::Done);
        
        // Test DONE -> FAILED (multi-role techniques where one role fails)
        // Scenario: Attacker reports SUCCESS (journal→DONE), then victim reports FAILED
        let record2 = TechniqueRecord {
            id: "test-done-failed".to_string(),
            technique: "T1021.005-PROTO".to_string(),
            state: TechniqueState::Running,
            attacker: Some("attacker2".to_string()),
            victim: Some("victim2".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record2).unwrap();
        journal.update_state("test-done-failed", TechniqueState::Done).unwrap();
        journal.update_state("test-done-failed", TechniqueState::Failed).unwrap();
        
        let final_record2 = journal.get_record("test-done-failed").unwrap().unwrap();
        assert_eq!(final_record2.state, TechniqueState::Failed);
        
        // Test rejected cross-terminal transitions that preserve dispatch failure semantics
        
        // FAILED -> ABORTED should be rejected (dispatch failure stays failed)
        let record3 = TechniqueRecord {
            id: "test-failed-aborted-rejected".to_string(),
            technique: "T1021.005-PROTO".to_string(),
            state: TechniqueState::Dispatched,
            attacker: Some("attacker3".to_string()),
            victim: Some("victim3".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record3).unwrap();
        journal.update_state("test-failed-aborted-rejected", TechniqueState::Failed).unwrap();
        
        let result = journal.update_state("test-failed-aborted-rejected", TechniqueState::Aborted);
        assert!(result.is_err());
        match result {
            Err(JournalError::InvalidStateTransition { from, to }) => {
                assert_eq!(from, "FAILED");
                assert_eq!(to, "ABORTED");
            },
            _ => panic!("Expected InvalidStateTransition error"),
        }
        
        // FAILED -> DONE should be rejected (dispatch failure stays failed)
        let record4 = TechniqueRecord {
            id: "test-failed-done-rejected".to_string(),
            technique: "T1021.004-PROTO".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker4".to_string()),
            victim: Some("victim4".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record4).unwrap();
        journal.update_state("test-failed-done-rejected", TechniqueState::Failed).unwrap();
        
        let result2 = journal.update_state("test-failed-done-rejected", TechniqueState::Done);
        assert!(result2.is_err());
        match result2 {
            Err(JournalError::InvalidStateTransition { from, to }) => {
                assert_eq!(from, "FAILED");
                assert_eq!(to, "DONE");
            },
            _ => panic!("Expected InvalidStateTransition error"),
        }
    }

    #[test]
    fn test_early_failure_transitions() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        // Test QUEUED -> FAILED (early validation failure)
        let record1 = TechniqueRecord {
            id: "test-queued-fail".to_string(),
            technique: "T1021.005-PROTO".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker1".to_string()),
            victim: Some("victim1".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record1).unwrap();
        journal.update_state("test-queued-fail", TechniqueState::Failed).unwrap();
        
        let updated = journal.get_record("test-queued-fail").unwrap().unwrap();
        assert_eq!(updated.state, TechniqueState::Failed);
        
        // Test DISPATCHED -> FAILED (early setup failure before execution)
        let record2 = TechniqueRecord {
            id: "test-dispatched-fail".to_string(),
            technique: "T1021.004-PROTO".to_string(),
            state: TechniqueState::Queued,
            attacker: Some("attacker2".to_string()),
            victim: Some("victim2".to_string()),
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record2).unwrap();
        journal.update_state("test-dispatched-fail", TechniqueState::Dispatched).unwrap();
        journal.update_state("test-dispatched-fail", TechniqueState::Failed).unwrap();
        
        let updated2 = journal.get_record("test-dispatched-fail").unwrap().unwrap();
        assert_eq!(updated2.state, TechniqueState::Failed);
    }

    #[test]
    fn test_get_incomplete_techniques() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        let record1 = TechniqueRecord {
            id: "test-running".to_string(),
            technique: "T1021.005".to_string(),
            state: TechniqueState::Running,
            attacker: None,
            victim: None,
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        let record2 = TechniqueRecord {
            id: "test-done".to_string(),
            technique: "T1053.003".to_string(),
            state: TechniqueState::Done,
            attacker: None,
            victim: None,
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        let record3 = TechniqueRecord {
            id: "test-cleanup".to_string(),
            technique: "T1036.003".to_string(),
            state: TechniqueState::CleanupPending,
            attacker: None,
            victim: None,
            started_at: None,
            completed_at: None,
            artifacts: vec![],
            error: None,
            group_id: None,
        };
        
        journal.create_record(&record1).unwrap();
        journal.create_record(&record2).unwrap();
        journal.create_record(&record3).unwrap();
        
        let incomplete = journal.get_incomplete_techniques().unwrap();
        assert_eq!(incomplete.len(), 2);
        assert!(incomplete.iter().any(|r| r.id == "test-running"));
        assert!(incomplete.iter().any(|r| r.id == "test-cleanup"));
    }

    #[test]
    fn test_get_recent_techniques() {
        let tmp = NamedTempFile::new().unwrap();
        let mut journal = TechniqueJournal::new(tmp.path()).unwrap();
        
        for i in 0..10 {
            let record = TechniqueRecord {
                id: format!("test-{}", i),
                technique: "T1021.005".to_string(),
                state: TechniqueState::Done,
                attacker: None,
                victim: None,
                started_at: None,
                completed_at: None,
                artifacts: vec![],
                error: None,
                group_id: None,
            };
            journal.create_record(&record).unwrap();
        }
        
        let recent = journal.get_recent_techniques(5).unwrap();
        assert_eq!(recent.len(), 5);
        
        let all = journal.get_recent_techniques(100).unwrap();
        assert_eq!(all.len(), 10);
        
        let limited = journal.get_recent_techniques(3).unwrap();
        assert_eq!(limited.len(), 3);
    }
}
