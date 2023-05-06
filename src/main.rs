// idc if returns are not idiomatic, they make skimming so much easier
#![allow(clippy::needless_return)]
#![deny(clippy::implicit_return)]

#![no_std]
#![no_main]
#![feature(async_fn_in_trait)]
#![feature(impl_trait_projections)]

extern crate alloc;

use alloc::vec;

use cassette::{Cassette, pin_mut};
use psp::{dprintln, sys};
use psp::sys::ApctlInfo;
use reqwless::client::{HttpClient, TlsConfig, TlsVerify};
use reqwless::request::{Method, RequestBuilder};

psp::module!("psp-reddit-test", 1, 1);

mod net;
mod util;

#[no_mangle]
fn psp_main() {
    psp::enable_home_button();
    // connect to wifi
    unsafe {
        load_modules();
        init();
        sys::sceNetApctlConnect(1);
        loop {
            let mut state: psp::sys::ApctlState = core::mem::zeroed();
            sys::sceNetApctlGetState(&mut state);
            if let sys::ApctlState::GotIp = state {
                dprintln!("Got IP: {}", core::str::from_utf8_unchecked(&util::get_apctl_info(ApctlInfo::Ip).ip));
                break;
            }
            sys::sceKernelDelayThread(50_000);
        }
    }

    let x = get_http_response();
    pin_mut!(x);
    let mut cass = Cassette::new(x);
    while cass.poll_on().is_none() {}
}

/// Load the required modules for networking
unsafe fn load_modules() {
    sys::sceUtilityLoadNetModule(psp::sys::NetModule::NetCommon);
    sys::sceUtilityLoadNetModule(psp::sys::NetModule::NetInet);
}

/// Initialize networking
unsafe fn init() {
    sys::sceNetInit(0x20000, 0x20, 0x1000, 0x20, 0x1000);
    sys::sceNetInetInit();
    sys::sceNetResolverInit();
    sys::sceNetApctlInit(0x1600, 42);
}

async fn get_http_response() {
    let tcp_connector = net::TcpConnector;
    let dns = net::PSPDns;

    let seed = unsafe { util::create_randomish_seed() };
    let seed_bytes = { // get first 8 bytes of seed because TlsConfig expects a u64
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&seed[..8]);
        arr
    };
    let mut read_record_buffer = [0; 16384];
    let mut write_record_buffer = [0; 16384];
    let tls_config = TlsConfig::new(u64::from_ne_bytes(seed_bytes),
                                    &mut read_record_buffer,
                                    &mut write_record_buffer,
                                    TlsVerify::None);

    let mut client = HttpClient::new_with_tls(&tcp_connector, &dns, tls_config);

    let mut header_buf = [0; 4096];
    let headers = [("User-Agent", "psp:psp-reddit-test:dev (by /u/timawesomeness)")];
    let mut request = client
        .request(Method::GET, "https://api.reddit.com/r/PSP/?limit=1")
        .await
        .expect("failed to create request")
        .headers(&headers);

    let response = request.send(&mut header_buf)
        .await
        .unwrap();

    dprintln!("Response status: {:?}, content length: {:?}", response.status as usize, response.content_length.unwrap());

    let content_length = response.content_length.unwrap();
    let mut body_reader = response.body().reader();
    let mut buf = vec![0u8; content_length];
    let read = body_reader.read_to_end(&mut buf).await.unwrap();

    let text = unsafe { alloc::string::String::from_utf8_unchecked(buf) };
    dprintln!("Received: {}", text);

    // TODO: parse the JSON with serde-json-core
}