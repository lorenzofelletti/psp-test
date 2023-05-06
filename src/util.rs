use embedded_nal_async::{IpAddr, Ipv4Addr};
use psp::sys;
use psp::sys::{ApctlInfo, in_addr, SceNetApctlInfo};
use sha2::{Digest, Sha256};

/// Get SceNetApctlInfo
///
/// ## Arguments
/// * `code`: [ApctlInfo] - basically what we want the [SceNetApctlInfo] to contain
///
/// ## Return Value
/// [SceNetApctlInfo] containing the requested info
///
/// ## Example
/// ```
/// let ip = get_apctl_info(ApctlInfo::Ip).ip;
/// ```
pub unsafe fn get_apctl_info(code: ApctlInfo) -> SceNetApctlInfo {
    let mut info: SceNetApctlInfo = core::mem::zeroed();
    sys::sceNetApctlGetInfo(code, &mut info);
    return info;
}

/// Creates a DNS resolver to resolve hostnames/addresses
///
/// ## Return Value
/// [i32] containing the resolver id on success, Err on failure
///
/// ## Example
/// ```
/// // create a resolver
/// let rid = create_resolver().expect("failed to create resolver");
/// // use the resolver
/// let ip = resolve_hostname(&rid, b"example.com\0").expect("failed to resolve hostname");
/// ```
pub unsafe fn create_resolver() -> Result<i32, ()> {
    let mut rid: i32 = 0;
    let mut buf = [0u8; 1024];
    if sys::sceNetResolverCreate(&mut rid, buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len() as u32) < 0 {
        return Err(());
    } else {
        return Ok(rid);
    }
}

/// Resolves a hostname to an IP address
///
/// ## Arguments
/// * `rid` - resolver id
/// * `hostname` - hostname to resolve
///
/// ## Return Value
/// [IpAddr::V4] containing the resolved IP address
///
/// ## Example
/// ```
/// // create a resolver
/// let rid = create_resolver().expect("failed to create resolver");
/// // resolve the hostname
/// let ip = resolve_hostname(&rid, b"example.com\0").expect("failed to resolve hostname");
/// ```
pub unsafe fn resolve_hostname(rid: &i32, hostname: &[u8]) -> Result<IpAddr, ()> {
    let mut add: in_addr = core::mem::zeroed();
    if sys::sceNetResolverStartNtoA(*rid, hostname.as_ptr(), &mut add, 5, 2) < 0 {
        return Err(());
    } else {
        return Ok(IpAddr::V4(Ipv4Addr::from(add.0.swap_bytes())));
    }
}

/// Creates a random(ish) seed for the RNG
///
/// ## Return Value
/// [[u8; 32]][array] containing the seed
///
/// ## Notes
/// * sceRtcGetCurrentTick takes the time in usec from the PSP's RTC, which should be non-0 and non-constant, though hardly random.
/// * sceDisplayGetAccumulatedHcount provides a count of HSYNCs since the application started, seems slightly random.
/// * sceKernelGetSystemTimeWide provides the time in usec since the PSP was turned on, a little random at least.
/// * scePowerGetBatteryTemp provides the battery temperature, idk how random that is.
///
/// Values are SHA2 hashed to provide a more uniform distribution.
/// Those hashes are XORed together to provide the seed.
///
/// At least it's less guessable than just using the time ¯\\\_(ツ)_/¯.
/// Wish I knew where the PSP browser draws its entropy from.
///
/// TODO: poll input for real entropy
pub unsafe fn create_randomish_seed() -> [u8; 32] {
    let tick = {
        let mut seed: u64 = 0;
        sys::sceRtcGetCurrentTick(&mut seed as *mut u64);
        seed
    };
    let hcount = sys::sceDisplayGetAccumulatedHcount();
    let sys_time_wide = sys::sceKernelGetSystemTimeWide();
    let batt_temp = sys::scePowerGetBatteryTemp();

    let tick_sha2 = Sha256::digest(tick.to_ne_bytes());
    let hcount_sha2 = Sha256::digest(hcount.to_ne_bytes());
    let sys_time_wide_sha2 = Sha256::digest(sys_time_wide.to_ne_bytes());
    let batt_temp_sha2 = Sha256::digest(batt_temp.to_ne_bytes());

    // xor tick_sha2 and Hcount_sha2 together
    let mut step_one = [0u8; 32];
    for i in 0..32 {
        step_one[i] = tick_sha2[i] ^ hcount_sha2[i];
    }
    // xor step_one and timeWide_sha2 together
    let mut step_two = [0u8; 32];
    for i in 0..32 {
        step_two[i] = step_one[i] ^ sys_time_wide_sha2[i];
    }
    // xor step_two and batttemp_sha2 together
    let mut step_three = [0u8; 32];
    for i in 0..32 {
        step_three[i] = step_two[i] ^ batt_temp_sha2[i];
    }
    return step_three;
}