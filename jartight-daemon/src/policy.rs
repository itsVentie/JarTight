use std::ffi::c_void;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};

pub fn is_admin() -> bool {
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        
        let mut elevation: u32 = 0;
        let mut returned_length = 0;
        
        let res = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut u32 as *mut c_void),
            std::mem::size_of::<u32>() as u32,
            &mut returned_length,
        );
        
        res.is_ok() && elevation != 0
    }
}

pub fn is_process_allowed(_pid: u32, path: &str) -> bool {
    let allowed_browsers = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"];
    let lower_path = path.to_lowercase();
    
    allowed_browsers.iter().any(|&browser| lower_path.contains(browser))
}