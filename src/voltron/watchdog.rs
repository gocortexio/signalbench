use std::fs;
use std::io;

#[allow(dead_code)]
pub struct ResourceMonitor {
    memory_threshold: f32,
    fd_threshold: f32,
}

#[allow(dead_code)]
impl ResourceMonitor {
    pub fn new() -> Self {
        ResourceMonitor {
            memory_threshold: 0.80,
            fd_threshold: 0.80,
        }
    }

    pub fn check_memory(&self) -> Result<ResourceStatus, io::Error> {
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        
        let mut mem_total = 0u64;
        let mut mem_available = 0u64;
        
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                mem_total = parse_meminfo_line(line);
            } else if line.starts_with("MemAvailable:") {
                mem_available = parse_meminfo_line(line);
            }
        }
        
        if mem_total == 0 {
            return Ok(ResourceStatus::Unknown);
        }
        
        let usage = 1.0 - (mem_available as f32 / mem_total as f32);
        
        if usage > self.memory_threshold {
            Ok(ResourceStatus::Critical(format!(
                "Memory usage at {:.1}%",
                usage * 100.0
            )))
        } else if usage > self.memory_threshold * 0.9 {
            Ok(ResourceStatus::Warning(format!(
                "Memory usage at {:.1}%",
                usage * 100.0
            )))
        } else {
            Ok(ResourceStatus::Ok)
        }
    }

    pub fn check_file_descriptors(&self) -> Result<ResourceStatus, io::Error> {
        let fd_count = fs::read_dir("/proc/self/fd")?.count();
        
        let limits = fs::read_to_string("/proc/self/limits")?;
        let mut max_fds = 1024u64;
        
        for line in limits.lines() {
            if line.starts_with("Max open files") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(limit) = parts[3].parse::<u64>() {
                        max_fds = limit;
                    }
                }
            }
        }
        
        let usage = fd_count as f32 / max_fds as f32;
        
        if usage > self.fd_threshold {
            Ok(ResourceStatus::Critical(format!(
                "File descriptor usage at {:.1}% ({}/{})",
                usage * 100.0,
                fd_count,
                max_fds
            )))
        } else if usage > self.fd_threshold * 0.9 {
            Ok(ResourceStatus::Warning(format!(
                "File descriptor usage at {:.1}% ({}/{})",
                usage * 100.0,
                fd_count,
                max_fds
            )))
        } else {
            Ok(ResourceStatus::Ok)
        }
    }

    pub fn check_load_average(&self) -> Result<ResourceStatus, io::Error> {
        let loadavg = fs::read_to_string("/proc/loadavg")?;
        let parts: Vec<&str> = loadavg.split_whitespace().collect();
        
        if parts.is_empty() {
            return Ok(ResourceStatus::Unknown);
        }
        
        if let Ok(load_1min) = parts[0].parse::<f32>() {
            let cpu_count = num_cpus::get() as f32;
            let load_per_cpu = load_1min / cpu_count;
            
            if load_per_cpu > 2.0 {
                Ok(ResourceStatus::Critical(format!(
                    "Load average {:.2} (per-CPU: {:.2})",
                    load_1min, load_per_cpu
                )))
            } else if load_per_cpu > 1.5 {
                Ok(ResourceStatus::Warning(format!(
                    "Load average {:.2} (per-CPU: {:.2})",
                    load_1min, load_per_cpu
                )))
            } else {
                Ok(ResourceStatus::Ok)
            }
        } else {
            Ok(ResourceStatus::Unknown)
        }
    }

    pub fn check_all(&self) -> Vec<(String, ResourceStatus)> {
        let mut results = Vec::new();
        
        if let Ok(status) = self.check_memory() {
            results.push(("memory".to_string(), status));
        }
        
        if let Ok(status) = self.check_file_descriptors() {
            results.push(("file_descriptors".to_string(), status));
        }
        
        if let Ok(status) = self.check_load_average() {
            results.push(("load_average".to_string(), status));
        }
        
        results
    }
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ResourceStatus {
    Ok,
    Warning(String),
    Critical(String),
    Unknown,
}

#[allow(dead_code)]
fn parse_meminfo_line(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_monitor() {
        let monitor = ResourceMonitor::new();
        let results = monitor.check_all();
        assert!(!results.is_empty());
    }
}
