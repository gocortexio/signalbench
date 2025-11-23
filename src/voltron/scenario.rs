use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Scenario {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ScenarioStep {
    pub id: String,
    pub technique: String,
    #[serde(default)]
    pub attacker: Vec<String>,
    pub victim: Option<String>,
    #[serde(default)]
    pub delay_before: Option<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[allow(dead_code)]
impl Scenario {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ScenarioError> {
        let contents = fs::read_to_string(&path)?;
        
        // Support both JSON and YAML formats based on file extension
        let path_str = path.as_ref().to_string_lossy();
        let scenario: Scenario = if path_str.ends_with(".yml") || path_str.ends_with(".yaml") {
            serde_yaml::from_str(&contents)
                .map_err(|e| ScenarioError::Yaml(e.to_string()))?
        } else {
            serde_json::from_str(&contents)?
        };
        
        scenario.validate()?;
        Ok(scenario)
    }

    pub fn validate(&self) -> Result<(), ScenarioError> {
        let step_ids: HashSet<_> = self.steps.iter().map(|s| s.id.as_str()).collect();
        
        for step in &self.steps {
            for dep_id in &step.depends_on {
                if !step_ids.contains(dep_id.as_str()) {
                    return Err(ScenarioError::InvalidDependency {
                        step: step.id.clone(),
                        missing: dep_id.clone(),
                    });
                }
            }
        }
        
        self.check_cycles()?;
        
        Ok(())
    }

    fn check_cycles(&self) -> Result<(), ScenarioError> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let deps: HashMap<_, _> = self
            .steps
            .iter()
            .map(|s| (s.id.as_str(), s.depends_on.iter().map(|d| d.as_str()).collect::<Vec<_>>()))
            .collect();

        for step in &self.steps {
            if !visited.contains(step.id.as_str()) {
                if self.has_cycle(&step.id, &deps, &mut visited, &mut rec_stack) {
                    return Err(ScenarioError::CircularDependency(step.id.clone()));
                }
            }
        }

        Ok(())
    }

    fn has_cycle(
        &self,
        step_id: &str,
        deps: &HashMap<&str, Vec<&str>>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> bool {
        visited.insert(step_id.to_string());
        rec_stack.insert(step_id.to_string());

        if let Some(dependencies) = deps.get(step_id) {
            for &dep in dependencies {
                if !visited.contains(dep) {
                    if self.has_cycle(dep, deps, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(dep) {
                    return true;
                }
            }
        }

        rec_stack.remove(step_id);
        false
    }

    pub fn parse_delay(delay_str: &str) -> Result<std::time::Duration, ScenarioError> {
        if let Some(secs) = delay_str.strip_suffix('s') {
            Ok(std::time::Duration::from_secs(
                secs.parse()
                    .map_err(|_| ScenarioError::InvalidDelay(delay_str.to_string()))?,
            ))
        } else if let Some(mins) = delay_str.strip_suffix('m') {
            Ok(std::time::Duration::from_secs(
                mins.parse::<u64>()
                    .map_err(|_| ScenarioError::InvalidDelay(delay_str.to_string()))?
                    * 60,
            ))
        } else {
            Err(ScenarioError::InvalidDelay(delay_str.to_string()))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum ScenarioError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(String),
    #[error("Invalid dependency: step '{step}' depends on missing step '{missing}'")]
    InvalidDependency { step: String, missing: String },
    #[error("Circular dependency detected at step '{0}'")]
    CircularDependency(String),
    #[error("Invalid delay format: '{0}' (use '30s' or '5m')")]
    InvalidDelay(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_dependency_detection() {
        let scenario = Scenario {
            name: "Test".to_string(),
            description: None,
            steps: vec![
                ScenarioStep {
                    id: "step1".to_string(),
                    technique: "T1021.005".to_string(),
                    attacker: vec!["A".to_string()],
                    victim: Some("B".to_string()),
                    delay_before: None,
                    depends_on: vec!["step2".to_string()],
                    params: serde_json::Value::Null,
                },
                ScenarioStep {
                    id: "step2".to_string(),
                    technique: "T1053.003".to_string(),
                    attacker: vec!["A".to_string()],
                    victim: Some("B".to_string()),
                    delay_before: None,
                    depends_on: vec!["step1".to_string()],
                    params: serde_json::Value::Null,
                },
            ],
        };

        assert!(scenario.validate().is_err());
    }

    #[test]
    fn test_delay_parsing() {
        assert_eq!(
            Scenario::parse_delay("30s").unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            Scenario::parse_delay("5m").unwrap(),
            std::time::Duration::from_secs(300)
        );
        assert!(Scenario::parse_delay("invalid").is_err());
    }
}
