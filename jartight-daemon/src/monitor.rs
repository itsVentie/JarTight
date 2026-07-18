use std::error::Error;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS, PROCESSENTRY32W,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use crate::policy;

pub async fn start_monitoring() -> Result<(), Box<dyn Error>> {
    loop {
        unsafe {
            let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            if snapshot.is_invalid() {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }

            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let process_name = OsString::from_wide(&entry.szExeFile[..len])
                        .to_string_lossy()
                        .into_owned();

                    if !process_name.is_empty() && pid != 0 {
                        let is_allowed = policy::is_process_allowed(pid, &process_name);
                        
                        let suspicious_keywords = ["stealer", "grabber", "hack", "injector", "cheat", "dump"];
                        let lower_name = process_name.to_lowercase();
                        let looks_suspicious = suspicious_keywords.iter().any(|&kw| lower_name.contains(kw));

                        if looks_suspicious && !is_allowed {
                            log::warn!(
                                "[ALERT] Unauthorized process accessing memory space! PID: {}, Executable: {}", 
                                pid, process_name
                            );
                        }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}