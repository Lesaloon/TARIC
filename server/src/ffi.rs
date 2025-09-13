use std::ffi::{CStr};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn taric_server_start(config_json: *const c_char) -> i32 {
    if config_json.is_null() { return -1; }
    let cfg = unsafe { CStr::from_ptr(config_json) }.to_string_lossy();
    crate::start(&cfg)
}

#[no_mangle]
pub extern "C" fn taric_server_stop() -> i32 {
    crate::stop()
}
