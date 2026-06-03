use std::process::Command;
use std::path::Path;

fn get_roblox_pid() -> Option<u32> {
    let out = Command::new("sh")
        .arg("-c")
        .arg("pidof com.roblox.client")
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn inject() -> anyhow::Result<()> {
    let pid = get_roblox_pid().ok_or_else(|| anyhow::anyhow!("Roblox not running"))?;
    let lib_path = "/data/local/tmp/libexecutor.so";
    if !Path::new(lib_path).exists() {
        anyhow::bail!("libexecutor.so not found at {}", lib_path);
    }
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("cat {} > /proc/{}/mem", lib_path, pid))
        .status()?;
    if status.success() {
        println!("Injected into PID {}", pid);
        Ok(())
    } else {
        anyhow::bail!("Injection failed")
    }
}

fn main() -> anyhow::Result<()> {
    inject()
}