use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub mount: String,
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub fs: String,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub cpu_global: f32,
    pub cpu_cores: Vec<f32>,
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_free: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub load_avg_15m: f64,
    pub disks: Vec<DiskInfo>,
    pub uptime_secs: u64,
    pub hostname: Option<String>,
    pub os: Option<String>,
}

pub fn snapshot() -> SystemStats {
    let mut sys = System::new_all();
    sys.refresh_cpu_all();
    // sysinfo needs two samples with a gap to produce useful CPU %.
    std::thread::sleep(std::time::Duration::from_millis(180));
    sys.refresh_cpu_all();
    sys.refresh_memory();

    let cpu_cores: Vec<f32> = sys.cpus().iter().map(|c| c.cpu_usage()).collect();
    let cpu_global = if cpu_cores.is_empty() {
        0.0
    } else {
        cpu_cores.iter().sum::<f32>() / cpu_cores.len() as f32
    };

    let load = System::load_average();

    let mut disks_out = Vec::new();
    let disks = Disks::new_with_refreshed_list();
    for d in &disks {
        let mount = d.mount_point().display().to_string();
        // De-dup macOS firmlinks (e.g. /System/Volumes/Data often mirrors /).
        if disks_out
            .iter()
            .any(|ex: &DiskInfo| ex.total == d.total_space() && ex.available == d.available_space())
        {
            continue;
        }
        let total = d.total_space();
        let avail = d.available_space();
        disks_out.push(DiskInfo {
            mount,
            total,
            available: avail,
            used: total.saturating_sub(avail),
            fs: d.file_system().to_string_lossy().to_string(),
            is_removable: d.is_removable(),
        });
    }

    SystemStats {
        cpu_global,
        cpu_cores,
        mem_total: sys.total_memory(),
        mem_used: sys.used_memory(),
        mem_free: sys.free_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        load_avg_1m: load.one,
        load_avg_5m: load.five,
        load_avg_15m: load.fifteen,
        disks: disks_out,
        uptime_secs: System::uptime(),
        hostname: System::host_name(),
        os: System::long_os_version(),
    }
}
