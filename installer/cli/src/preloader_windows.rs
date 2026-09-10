//! Present-device SetupAPI fallback for legacy VCOM drivers without USB metadata.
use crate::command::CommandError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{ffi::c_void, mem::size_of, ptr};

static CHARGING_OBSERVED: AtomicBool = AtomicBool::new(false);

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1isize as Handle;
const DIGCF_PRESENT: u32 = 2;
const DIGCF_ALLCLASSES: u32 = 4;
const SPDRP_HARDWAREID: u32 = 1;
const REG_MULTI_SZ: u32 = 7;
const REG_SZ: u32 = 1;

#[link(name = "cfgmgr32")]
extern "system" {
    fn CM_Get_DevNode_Status(status: *mut u32, problem: *mut u32, node: u32, flags: u32) -> u32;
}

fn device_started(result: u32, status: u32, problem: u32) -> bool {
    result == 0 && status & 0x0a == 0x0a && status & 0x400 == 0 && problem == 0
}

#[repr(C)]
struct DeviceInfo {
    size: u32,
    class_guid: [u32; 4],
    dev_inst: u32,
    reserved: usize,
}

#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class: *const c_void,
        enumerator: *const u16,
        window: Handle,
        flags: u32,
    ) -> Handle;
    fn SetupDiEnumDeviceInfo(set: Handle, index: u32, info: *mut DeviceInfo) -> i32;
    fn SetupDiDestroyDeviceInfoList(set: Handle) -> i32;
    fn SetupDiGetDeviceRegistryPropertyW(
        set: Handle,
        info: *mut DeviceInfo,
        property: u32,
        kind: *mut u32,
        buffer: *mut u8,
        size: u32,
        required: *mut u32,
    ) -> i32;
    fn SetupDiOpenDevRegKey(
        set: Handle,
        info: *mut DeviceInfo,
        scope: u32,
        profile: u32,
        key_type: u32,
        access: u32,
    ) -> Handle;
}
#[link(name = "advapi32")]
extern "system" {
    fn RegQueryValueExW(
        key: Handle,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Handle) -> i32;
}

struct DeviceSet(Handle);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: this handle came from SetupDiGetClassDevsW and is owned here.
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

fn exact_preloader_id(id: &str) -> bool {
    exact_usb_id(id, "PID_2000")
}

fn exact_usb_id(id: &str, product: &str) -> bool {
    let upper = id.to_ascii_uppercase();
    let Some(parts) = upper.strip_prefix("USB\\") else {
        return false;
    };
    let parts: Vec<_> = parts.split('&').collect();
    parts.first() == Some(&"VID_0E8D") && parts.get(1) == Some(&product)
}

fn com_name(value: &str) -> Option<String> {
    let value = value.to_ascii_uppercase();
    let digits = value.strip_prefix("COM")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(value)
}

pub(super) fn preloader_ports() -> Result<Vec<String>, CommandError> {
    enumerate_ports(false)
}

pub(super) fn port_started(port: &str) -> Result<bool, CommandError> {
    Ok(enumerate_ports(true)?
        .iter()
        .any(|candidate| candidate == port))
}

fn enumerate_ports(require_started: bool) -> Result<Vec<String>, CommandError> {
    // SAFETY: Win32 layouts and signatures above mirror setupapi.h. Every output
    // buffer is sized in bytes, handles are closed, and only present nodes and
    // read-only registry keys are inspected. No device is opened here.
    unsafe {
        let set = SetupDiGetClassDevsW(
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_ALLCLASSES,
        );
        if set == INVALID_HANDLE {
            return Err(enumeration_error());
        }
        let set = DeviceSet(set);
        let mut ports = Vec::new();
        let mut charging = false;
        for index in 0.. {
            let mut info = DeviceInfo {
                size: size_of::<DeviceInfo>() as u32,
                class_guid: [0; 4],
                dev_inst: 0,
                reserved: 0,
            };
            if SetupDiEnumDeviceInfo(set.0, index, &mut info) == 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(259) {
                    break;
                }
                return Err(enumeration_error());
            }
            let mut ids = vec![0u16; 4096];
            let mut kind = 0;
            let mut required = 0;
            if SetupDiGetDeviceRegistryPropertyW(
                set.0,
                &mut info,
                SPDRP_HARDWAREID,
                &mut kind,
                ids.as_mut_ptr().cast(),
                (ids.len() * 2) as u32,
                &mut required,
            ) == 0
                || kind != REG_MULTI_SZ
            {
                continue;
            }
            // Observed on an R1 showing charging, 2026-09-10. Diagnostic only:
            // this PID must never become a serial-command candidate.
            charging |= ids
                .split(|c| *c == 0)
                .any(|id| exact_usb_id(&String::from_utf16_lossy(id), "PID_20FF"));
            if !ids
                .split(|c| *c == 0)
                .any(|id| exact_preloader_id(&String::from_utf16_lossy(id)))
            {
                continue;
            }
            // DICS_FLAG_GLOBAL, DIREG_DEV, KEY_QUERY_VALUE.
            let key = SetupDiOpenDevRegKey(set.0, &mut info, 1, 0, 1, 1);
            if key == INVALID_HANDLE {
                continue;
            }
            let name: Vec<u16> = "PortName\0".encode_utf16().collect();
            let mut value = [0u16; 256];
            let mut bytes = (value.len() * 2) as u32;
            let status = RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null_mut(),
                &mut kind,
                value.as_mut_ptr().cast(),
                &mut bytes,
            );
            RegCloseKey(key);
            if status == 0 && kind == REG_SZ {
                let end = value.iter().position(|c| *c == 0).unwrap_or(value.len());
                if let Some(port) = com_name(&String::from_utf16_lossy(&value[..end])) {
                    if require_started {
                        let (mut status, mut problem) = (0, 0);
                        let result =
                            CM_Get_DevNode_Status(&mut status, &mut problem, info.dev_inst, 0);
                        if !device_started(result, status, problem) {
                            continue;
                        }
                    }
                    ports.push(port);
                }
            }
        }
        if charging && !CHARGING_OBSERVED.swap(charging, Ordering::Relaxed) {
            println!("Charging-mode USB observed: 0e8d:20ff. Waiting for the 0e8d:2000 preloader; no command sent to charging mode.");
        } else if !charging {
            CHARGING_OBSERVED.store(false, Ordering::Relaxed);
        }
        Ok(ports)
    }
}

fn enumeration_error() -> CommandError {
    CommandError::new(
        "JR-CLI-PRELOADER-PNP",
        format!(
            "cannot enumerate present Windows PnP devices: {}",
            std::io::Error::last_os_error()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn appearing_preloader_must_finish_driver_start() {
        // Recorded lifecycle: present, driver loaded, started, then disconnected.
        assert!(!device_started(0, 0x01806000, 0));
        assert!(!device_started(0, 0x01806002, 0));
        assert!(device_started(0, 0x0180600a, 0));
        assert!(!device_started(13, 0, 0));
        assert!(!device_started(0, 0x0180640a, 10));
        assert!(!device_started(0, 0x0180640a, 0));
    }
    #[test]
    fn hardware_identity_is_exact() {
        for id in [r"USB\VID_0E8D&PID_2000", r"usb\vid_0e8d&pid_2000&REV_0100"] {
            assert!(exact_preloader_id(id));
        }
        for id in [
            r"USB\VID_0E8D&PID_20000",
            r"USB\VID_0E8D&PID_2001",
            r"USB\VID_0E8D&PID_201C",
            r"USB\VID_FFFF&PID_2000",
            r"ROOT\VID_0E8D&PID_2000",
            "MediaTek PreLoader USB VCOM (COM6)",
        ] {
            assert!(!exact_preloader_id(id), "{id}");
        }
    }
    #[test]
    fn only_registry_com_names_are_accepted() {
        assert_eq!(com_name("com6"), Some("COM6".into()));
        assert_eq!(com_name("COM123"), Some("COM123".into()));
        for name in ["COM", "COM0", "COM6 extra", "LPT1", r"\\.\COM6"] {
            assert_eq!(com_name(name), None);
        }
    }
    #[test]
    fn charging_identity_is_diagnostic_only() {
        let id = r"USB\VID_0E8D&PID_20FF&REV_0223";
        assert!(exact_usb_id(id, "PID_20FF"));
        assert!(!exact_preloader_id(id));
        assert!(!exact_usb_id(r"USB\VID_0E8D&PID_20FFF", "PID_20FF"));
        assert!(!exact_usb_id(r"USB\VID_FFFF&PID_20FF", "PID_20FF"));
    }
    #[test]
    fn native_present_device_enumeration_is_read_only() {
        preloader_ports().expect("SetupAPI enumeration must work on the Windows host");
    }
}
