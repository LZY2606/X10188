use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::model::{
    BranchEvaluation, BranchRecord, BudgetConfig, CandidateRecord, Evidence, FanoutView,
    ObjectEvaluation, SourceKind, SourceRecord,
};

pub struct Store {
    conn: Connection,
    data_dir: PathBuf,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir.join("sources"))
            .map_err(|error| format!("create data dir: {error}"))?;
        std::fs::create_dir_all(data_dir.join("objects"))
            .map_err(|error| format!("create object dir: {error}"))?;
        let conn = Connection::open(data_dir.join("packscope.sqlite"))
            .map_err(|error| format!("open sqlite: {error}"))?;
        let mut store = Store {
            conn,
            data_dir: data_dir.to_path_buf(),
        };
        store.migrate()?;
        store.ensure_default_branch()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                r#"
                create table if not exists sources (
                    id text primary key,
                    json text not null,
                    ordinal integer not null
                );
                create table if not exists candidates (
                    id text primary key,
                    source_id text not null,
                    json text not null
                );
                create table if not exists branches (
                    name text primary key,
                    json text not null
                );
                create table if not exists evaluations (
                    branch text not null,
                    candidate_id text not null,
                    json text not null,
                    primary key (branch, candidate_id)
                ) without rowid;
                create table if not exists fanout (
                    source_id text primary key,
                    json text not null
                );
                create table if not exists evidence (
                    id integer primary key autoincrement,
                    branch text not null,
                    candidate_id text not null,
                    json text not null
                );
                "#,
            )
            .map_err(|error| error.to_string())
    }

    fn ensure_default_branch(&self) -> Result<(), String> {
        let exists: i64 = self
            .conn
            .query_row(
                "select count(*) from branches where name = 'default'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if exists == 0 {
            let branch = BranchRecord {
                name: "default".into(),
                label: "默认确定性分支".into(),
                pins: Default::default(),
                max_depth: 64,
                max_total_bytes: 64 * 1024 * 1024,
                max_single_bytes: 32 * 1024 * 1024,
                used_bytes: 0,
                resumed_at: 0,
            };
            self.put_branch(&branch)?;
        }
        Ok(())
    }

    pub fn save_input(&self, id: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        let path = self.data_dir.join("sources").join(format!("{id}.bin"));
        if !path.exists() {
            std::fs::write(&path, bytes).map_err(|error| format!("write source: {error}"))?;
        }
        Ok(path)
    }

    pub fn read_source(&self, id: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.data_dir.join("sources").join(format!("{id}.bin")))
            .map_err(|error| format!("read source {id}: {error}"))
    }

    pub fn write_object(&self, candidate_id: &str, bytes: &[u8]) -> Result<(), String> {
        std::fs::write(self.object_path(candidate_id), bytes)
            .map_err(|error| format!("write object: {error}"))
    }

    pub fn read_object(&self, candidate_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.object_path(candidate_id)).ok()
    }

    pub fn delete_object(&self, candidate_id: &str) {
        let _ = std::fs::remove_file(self.object_path(candidate_id));
    }

    pub fn object_path(&self, candidate_id: &str) -> PathBuf {
        self.data_dir
            .join("objects")
            .join(format!("{candidate_id}.bin"))
    }

    pub fn source_exists(&self, id: &str) -> Result<bool, String> {
        self.conn
            .query_row(
                "select 1 from sources where id = ?1",
                params![id],
                |_| Ok(true),
            )
            .or_else(|error| {
                if error == rusqlite::Error::QueryReturnedNoRows {
                    Ok(false)
                } else {
                    Err(error.to_string())
                }
            })
    }

    pub fn put_source(&self, source: &SourceRecord) -> Result<(), String> {
        let ordinal: i64 = self
            .conn
            .query_row("select coalesce(max(ordinal)+1, 0) from sources", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())?;
        self.conn
            .execute(
                "insert or ignore into sources(id, json, ordinal) values(?1, ?2, ?3)",
                params![source.id, serde_json::to_string(source).unwrap(), ordinal],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_candidate(&self, candidate: &CandidateRecord) -> Result<(), String> {
        self.conn
            .execute(
                "insert or replace into candidates(id, source_id, json) values(?1, ?2, ?3)",
                params![
                    candidate.id,
                    candidate.source_id,
                    serde_json::to_string(candidate).unwrap()
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_branch(&self, branch: &BranchRecord) -> Result<(), String> {
        self.conn
            .execute(
                "insert or replace into branches(name, json) values(?1, ?2)",
                params![branch.name, serde_json::to_string(branch).unwrap()],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn update_budget(
        &self,
        branch: &str,
        budget: &BudgetConfig,
        resumed_at: i64,
    ) -> Result<BranchRecord, String> {
        let mut record = self.get_branch(branch)?;
        if let Some(value) = budget.max_depth {
            record.max_depth = value;
        }
        if let Some(value) = budget.max_total_bytes {
            record.max_total_bytes = value;
        }
        if let Some(value) = budget.max_single_bytes {
            record.max_single_bytes = value;
        }
        record.resumed_at = resumed_at;
        self.put_branch(&record)?;
        Ok(record)
    }

    pub fn replace_evaluation(&self, evaluation: &ObjectEvaluation) -> Result<(), String> {
        self.conn
            .execute(
                "insert or replace into evaluations(branch, candidate_id, json) values(?1, ?2, ?3)",
                params![
                    evaluation.candidate_id,
                    evaluation.candidate_id,
                    serde_json::to_string(evaluation).unwrap()
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn delete_evaluation(&self, branch: &str, candidate_id: &str) -> Result<(), String> {
        self.conn
            .execute(
                "delete from evaluations where branch=?1 and candidate_id=?2",
                params![branch, candidate_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn delete_candidate(&self, id: &str) -> Result<(), String> {
        self.conn
            .execute("delete from candidates where id=?1", params![id])
            .map(|_| ())
            .map_err(|error| error.to_string())?;
        self.conn
            .execute("delete from evaluations where candidate_id=?1", params![id])
            .map(|_| ())
            .map_err(|error| error.to_string())?;
        self.delete_object(id);
        Ok(())
    }

    pub fn delete_source_record(&self, id: &str) -> Result<(), String> {
        self.conn
            .execute("delete from sources where id=?1", params![id])
            .map(|_| ())
            .map_err(|error| error.to_string())?;
        self.conn
            .execute("delete from fanout where source_id=?1", params![id])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn source_ids_by_kind(&self, kind: SourceKind) -> Result<Vec<String>, String> {
        let mut statement = self
            .conn
            .prepare("select id from sources order by id")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            let id = row.map_err(|error| error.to_string())?;
            if self.get_source(&id)?.kind == kind {
                result.push(id);
            }
        }
        Ok(result)
    }

    pub fn get_source(&self, id: &str) -> Result<SourceRecord, String> {
        self.conn
            .query_row(
                "select json from sources where id=?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())
            .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
    }

    pub fn get_branch(&self, name: &str) -> Result<BranchRecord, String> {
        self.conn
            .query_row(
                "select json from branches where name=?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())
            .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
    }

    pub fn sources(&self) -> Result<Vec<SourceRecord>, String> {
        self.records("select json from sources order by ordinal")
    }

    pub fn candidates(&self) -> Result<Vec<CandidateRecord>, String> {
        self.records("select json from candidates order by id")
    }

    pub fn branches(&self) -> Result<Vec<BranchRecord>, String> {
        self.records("select json from branches order by name")
    }

    pub fn evaluations(&self, branch: &str) -> Result<Vec<ObjectEvaluation>, String> {
        self.records(&format!(
            "select json from evaluations where branch='{}' order by candidate_id",
            branch.replace('\'', "''")
        ))
    }

    fn records<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, String> {
        let mut statement = self.conn.prepare(sql).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            result.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        Ok(result)
    }

    pub fn put_fanout(&self, fanout: &FanoutView) -> Result<(), String> {
        self.conn
            .execute(
                "insert or replace into fanout(source_id, json) values(?1, ?2)",
                params![fanout.source_id, serde_json::to_string(fanout).unwrap()],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn fanout(&self) -> Result<Vec<FanoutView>, String> {
        self.records("select json from fanout order by source_id")
    }

    pub fn evidence(&self, branch: &str) -> Result<Vec<(String, Evidence)>, String> {
        let mut statement = self
            .conn
            .prepare(
                "select candidate_id, json from evidence where branch=?1 order by id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![branch], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?;
        let mut result = Vec::new();
        for row in rows {
            let (candidate_id, json) = row.map_err(|error| error.to_string())?;
            result.push((
                candidate_id,
                serde_json::from_str(&json).map_err(|error| error.to_string())?,
            ));
        }
        Ok(result)
    }

    pub fn clear_evidence(&self, branch: &str) -> Result<(), String> {
        self.conn
            .execute("delete from evidence where branch=?1", params![branch])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn add_evidence(
        &self,
        branch: &str,
        candidate_id: &str,
        evidence: &Evidence,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "insert into evidence(branch, candidate_id, json) values(?1, ?2, ?3)",
                params![branch, candidate_id, serde_json::to_string(evidence).unwrap()],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn branch_evaluation(
        &self,
        branch: &str,
    ) -> Result<(BranchRecord, BranchEvaluation), String> {
        let record = self.get_branch(branch)?;
        let mut objects = self.evaluations(branch)?;
        for object in &mut objects {
            object.evidence = self
                .evidence(branch)?
                .into_iter()
                .filter(|(candidate_id, _)| candidate_id == &object.candidate_id)
                .map(|(_, evidence)| evidence)
                .collect();
        }
        Ok((
            record,
            BranchEvaluation {
                branch: branch.into(),
                objects,
            },
        ))
    }
}
