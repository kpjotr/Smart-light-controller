#![no_std]
#![no_main]

extern crate alloc;

#[path = "../secrets.rs"]
#[allow(dead_code)]
mod secrets;

use alloc::{string::String, vec::Vec};
use core::{
    cell::RefCell,
    fmt::Write as _,
    sync::atomic::{AtomicU32, Ordering},
};
use critical_section::Mutex;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, Either4, select, select4};
use embassy_net::{
    DhcpConfig, IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources,
    StaticConfigV4,
    dns::{DnsQueryType, DnsSocket},
    icmp::{
        PacketMetadata as IcmpPacketMetadata,
        ping::{PingManager, PingParams},
    },
    tcp::{
        TcpSocket,
        client::{TcpClient, TcpClientState},
    },
    udp::{PacketMetadata, UdpSocket},
};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    mutex::Mutex as EmbassyMutex,
    signal::Signal,
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{Read as _, Write as _};
use esp_backtrace as _;
use esp_hal::{
    Async,
    gpio::{Input, Output},
    i2c::master::I2c,
    peripherals::{GPIO48, RMT},
    rmt::Rmt,
    rng::Rng,
    time::Rate,
    timer::timg::TimerGroup,
};
use esp_hal_smartled::{RmtSmartLeds, WS2812_TIMING, buffer_size, color_order};
use esp_println::println;
use esp_radio::wifi::{
    AuthenticationMethodConfig, Config, Interface, Ssid, WifiController, ap::AccessPointConfig,
    scan::ScanConfig, sta::StationConfig,
};
use esp_storage::FlashStorage;
use reqwless::{
    client::{HttpClient, TlsConfig, TlsVerify},
    headers::ContentType,
    request::{Method, RequestBuilder as _},
};
use serde::{Deserialize, Serialize};
use smart_leds::{RGB8, SmartLedsWrite, brightness};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const NVS_FALLBACK_OFFSET: u32 = 0x9000;
const NVS_LEGACY_MAGIC: [u8; 4] = *b"SLN2";
const NVS_LEGACY_VERSION: u8 = 3;
const NVS_LEGACY_RECORD_LEN: usize = 128;
const NVS_MAGIC: [u8; 4] = *b"SLN3";
const NVS_V4_VERSION: u8 = 4;
const NVS_VERSION: u8 = 5;
const NVS_RECORD_LEN: usize = 512;
const MAX_REFRESH_TOKEN_LEN: usize = 320;

const FACTORY_PASSKEY: &str = "K7M9P2X4R8";
const AP_IP: Ipv4Address = Ipv4Address::new(192, 168, 4, 1);
const AP_BOOT_WINDOW_SECS: u64 = 120;
const MAX_POST_BODY_BYTES: usize = 512;
const KEEPALIVE_INTERVAL_SECS: u64 = 15;
const VERIFY_PAIRING_URL: &str = "https://verifypairing-lfmgd4eena-uc.a.run.app";
const ESP_AUTH_TOKEN: &str = "ESP32_SECRET_TOKEN_998877";
const FIREBASE_WEB_API_KEY: &str = "AIzaSyCymXk2RyRcQ3Rn5JSvJvJeQIMAxH0KyQU";
const RTDB_HOST: &str = "okospilacsvezerlo-default-rtdb.europe-west1.firebasedatabase.app";
const AUTH_CUSTOM_TOKEN_URL_BASE: &str =
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=";
const AUTH_REFRESH_TOKEN_URL_BASE: &str = "https://securetoken.googleapis.com/v1/token?key=";
const TOKEN_REFRESH_INTERVAL_SECS: u64 = 45 * 60;
const RTDB_HEARTBEAT_INTERVAL_SECS: u64 = 20;
const SSE_READ_TIMEOUT_SECS: u64 = 60;
const MAX_ID_TOKEN_LEN: usize = 1536;

#[repr(align(4))]
struct AlignedBuf<const N: usize>([u8; N]);

struct NvsStorageState {
    flash: Option<FlashStorage<'static>>,
    nvs_offset: Option<u32>,
    scratch_nvs: NvsData,
    sector_buf: AlignedBuf<4096>,
}

impl NvsStorageState {
    const fn new() -> Self {
        Self {
            flash: None,
            nvs_offset: None,
            scratch_nvs: NvsData::empty(),
            sector_buf: AlignedBuf([0u8; 4096]),
        }
    }
}

static NVS_FLASH: EmbassyMutex<CriticalSectionRawMutex, NvsStorageState> =
    EmbassyMutex::new(NvsStorageState::new());

/// Fixed-capacity stack/static UTF-8 string buffer avoiding heap allocations.
struct FixedBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.len + bytes.len() > N {
            return false;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }
}

impl<const N: usize> core::fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if self.push_bytes(s.as_bytes()) {
            Ok(())
        } else {
            Err(core::fmt::Error)
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct WifiCredentials {
    ssid: String,
    password: String,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
struct DeviceConfig {
    threshold: u16,
    sensitivity: u8,
    duration: u64,
    safety_off_min: u16,
    lamp_wattage_w: u16,
}

impl DeviceConfig {
    fn is_configured(&self) -> bool {
        (1..=100).contains(&self.threshold)
            && (1..=100).contains(&self.sensitivity)
            && (10..=600).contains(&self.duration)
            && self.safety_off_min <= 1440
    }
}

#[derive(Clone)]
struct NvsData {
    config: DeviceConfig,
    wifi: Option<WifiCredentials>,
    refresh_token: [u8; MAX_REFRESH_TOKEN_LEN],
    refresh_token_len: u16,
}

impl Default for NvsData {
    fn default() -> Self {
        Self {
            config: DeviceConfig::default(),
            wifi: None,
            refresh_token: [0u8; MAX_REFRESH_TOKEN_LEN],
            refresh_token_len: 0,
        }
    }
}

impl NvsData {
    const fn empty() -> Self {
        Self {
            config: DeviceConfig {
                threshold: 0,
                sensitivity: 0,
                duration: 0,
                safety_off_min: 0,
                lamp_wattage_w: 0,
            },
            wifi: None,
            refresh_token: [0u8; MAX_REFRESH_TOKEN_LEN],
            refresh_token_len: 0,
        }
    }

    fn refresh_token_str(&self) -> Option<&str> {
        let len = self.refresh_token_len as usize;
        if len == 0 || len > MAX_REFRESH_TOKEN_LEN {
            return None;
        }
        core::str::from_utf8(&self.refresh_token[..len]).ok()
    }

    fn set_refresh_token(&mut self, token: &str) -> bool {
        let bytes = token.as_bytes();
        if bytes.len() > MAX_REFRESH_TOKEN_LEN {
            return false;
        }
        self.refresh_token.fill(0);
        self.refresh_token[..bytes.len()].copy_from_slice(bytes);
        self.refresh_token_len = bytes.len() as u16;
        true
    }

    fn clear_refresh_token(&mut self) {
        self.refresh_token.fill(0);
        self.refresh_token_len = 0;
    }
}

/// Background task driving the onboard WS2812 RGB LED exclusively to mirror `lamp_is_on`:
/// solid white (`255, 255, 255`) when ON and off (`0, 0, 0`) when OFF.
#[embassy_executor::task]
async fn led_task(rmt_periph: RMT<'static>, pin: GPIO48<'static>) -> ! {
    let rmt_freq = Rate::from_mhz(80);
    let rmt = Rmt::new(rmt_periph, rmt_freq).expect("RMT init failed");
    let mut led = RmtSmartLeds::<{ buffer_size::<RGB8>(1) }, _, RGB8, color_order::Grb>::new(
        WS2812_TIMING,
        rmt.channel0,
        pin,
        rmt_freq,
    )
    .expect("WS2812 init failed");

    let mut last_lamp_on: Option<bool> = None;

    loop {
        let lamp_on = {
            let state = DEVICE_STATE.lock().await;
            state.lamp_is_on
        };
        if last_lamp_on != Some(lamp_on) {
            if lamp_on {
                let _ = led.write(brightness(core::iter::once(RGB8::new(255, 255, 255)), 96));
            } else {
                let _ = led.write(brightness(core::iter::once(RGB8::new(0, 0, 0)), 0));
            }
            last_lamp_on = Some(lamp_on);
        }
        Timer::after(Duration::from_millis(50)).await;
    }
}

/// Computes a 32-bit FNV-1a checksum for legacy `SLN2` NVS migration verification.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Computes standard IEEE CRC32 checksum for `SLN3` NVS integrity verification.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Resolves and caches the NVS partition offset from `0x8000` using static word-aligned
/// `sector_buf` (`read_nor`, zero stack sector allocation), falling back to `0x9000`.
#[inline(never)]
fn resolve_nvs_offset(state: &mut NvsStorageState) -> u32 {
    if let Some(offset) = state.nvs_offset {
        return offset;
    }
    const PARTITION_TABLE_OFFSET: u32 = 0x8000;
    const PARTITION_TABLE_BYTES: usize = 0xC00;
    const ENTRY_LEN: usize = 32;
    const ENTRY_MAGIC: u16 = 0x50AA;
    const TYPE_DATA: u8 = 0x01;
    const SUBTYPE_NVS: u8 = 0x02;

    let mut resolved = NVS_FALLBACK_OFFSET;
    if let Some(flash) = state.flash.as_mut()
        && flash
            .read_nor(PARTITION_TABLE_OFFSET, &mut state.sector_buf.0)
            .is_ok()
    {
        for entry in state.sector_buf.0[..PARTITION_TABLE_BYTES].chunks_exact(ENTRY_LEN) {
            let magic = u16::from_le_bytes([entry[0], entry[1]]);
            if magic != ENTRY_MAGIC {
                break;
            }
            if entry[2] == TYPE_DATA && entry[3] == SUBTYPE_NVS {
                resolved = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                break;
            }
        }
    }
    state.nvs_offset = Some(resolved);
    resolved
}

/// Parses config and Wi-Fi credentials from the shared header bytes (bytes 5..124).
fn parse_nvs_config_and_wifi(buf: &[u8]) -> (DeviceConfig, Option<WifiCredentials>) {
    let lamp_wattage_w = if buf[0..4] == NVS_MAGIC && buf[4] >= NVS_VERSION {
        u16::from_le_bytes([buf[23], buf[24]]).min(5000)
    } else {
        0
    };
    let config = DeviceConfig {
        threshold: u16::from_le_bytes([buf[8], buf[9]]),
        duration: u64::from_le_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]),
        sensitivity: buf[18],
        safety_off_min: u16::from_le_bytes([buf[19], buf[20]]),
        lamp_wattage_w,
    };

    let has_wifi = buf[5] == 1;
    let wifi = if has_wifi {
        let ssid_len = buf[6] as usize;
        let pass_len = buf[7] as usize;
        if ssid_len == 0 || ssid_len > 32 || pass_len > 64 {
            None
        } else if let (Ok(ssid), Ok(password)) = (
            core::str::from_utf8(&buf[28..28 + ssid_len]),
            core::str::from_utf8(&buf[60..60 + pass_len]),
        ) {
            Some(WifiCredentials {
                ssid: String::from(ssid),
                password: String::from(password),
            })
        } else {
            None
        }
    } else {
        None
    };

    (config, wifi)
}

/// Reads and validates the `SLN3` (512-byte) NVS record into `state.scratch_nvs` using static
/// word-aligned sector buffers (`read_nor`), migrating legacy `SLN2` (128-byte) if present.
#[inline(never)]
fn load_nvs_data(state: &mut NvsStorageState) {
    state.scratch_nvs.config = DeviceConfig::default();
    state.scratch_nvs.wifi = None;
    state.scratch_nvs.clear_refresh_token();

    let offset = resolve_nvs_offset(state);
    let sector_base = offset & !(FlashStorage::SECTOR_SIZE - 1);
    let in_sector = (offset - sector_base) as usize;
    if in_sector + NVS_RECORD_LEN > state.sector_buf.0.len() {
        return;
    }

    let Some(flash) = state.flash.as_mut() else {
        return;
    };
    if flash.read_nor(sector_base, &mut state.sector_buf.0).is_err() {
        return;
    }

    let buf = &state.sector_buf.0[in_sector..in_sector + NVS_RECORD_LEN];

    if buf[0..4] == NVS_MAGIC && (buf[4] == NVS_VERSION || buf[4] == NVS_V4_VERSION) {
        let record_version = buf[4];
        let expected_crc = u32::from_le_bytes([buf[508], buf[509], buf[510], buf[511]]);
        if crc32(&buf[0..508]) != expected_crc {
            return;
        }
        let (config, wifi) = parse_nvs_config_and_wifi(buf);
        state.scratch_nvs.config = config;
        state.scratch_nvs.wifi = wifi;
        let rt_len = u16::from_le_bytes([buf[21], buf[22]]);
        if (rt_len as usize) <= MAX_REFRESH_TOKEN_LEN
            && let Ok(rt_str) = core::str::from_utf8(&buf[124..124 + rt_len as usize])
        {
            let _ = state.scratch_nvs.set_refresh_token(rt_str);
        }
        if record_version == NVS_V4_VERSION && save_nvs_data(state).is_ok() {
            println!("NVS: Migrated SLN3 v4 -> v5 (lamp_wattage_w=0).");
        }
        return;
    }

    if buf[0..4] == NVS_LEGACY_MAGIC && buf[4] == NVS_LEGACY_VERSION {
        let legacy_crc = u32::from_le_bytes([buf[124], buf[125], buf[126], buf[127]]);
        if fnv1a_32(&buf[0..NVS_LEGACY_RECORD_LEN - 4]) != legacy_crc {
            return;
        }
        let (config, wifi) = parse_nvs_config_and_wifi(&buf[..NVS_LEGACY_RECORD_LEN]);
        state.scratch_nvs.config = config;
        state.scratch_nvs.wifi = wifi;
        state.scratch_nvs.clear_refresh_token();
        if save_nvs_data(state).is_ok() {
            println!("NVS: Migrated legacy SLN2 (128B) -> SLN3 (512B) with CRC32.");
        }
    }
}

/// Serializes `state.scratch_nvs` and writes the 512-byte `SLN3` NVS record via static
/// word-aligned `sector_buf` (`read_nor` + `erase` + `write_nor`, zero 4 KB stack allocation).
#[inline(never)]
fn save_nvs_data(state: &mut NvsStorageState) -> Result<(), ()> {
    let rt_len = state.scratch_nvs.refresh_token_len as usize;
    if rt_len > MAX_REFRESH_TOKEN_LEN {
        return Err(());
    }

    let offset = resolve_nvs_offset(state);
    let sector_base = offset & !(FlashStorage::SECTOR_SIZE - 1);
    let in_sector = (offset - sector_base) as usize;
    if in_sector + NVS_RECORD_LEN > state.sector_buf.0.len() {
        return Err(());
    }

    if let Some(creds) = &state.scratch_nvs.wifi {
        let ssid_bytes = creds.ssid.as_bytes();
        let pass_bytes = creds.password.as_bytes();
        if ssid_bytes.is_empty() || ssid_bytes.len() > 32 || pass_bytes.len() > 64 {
            return Err(());
        }
    }

    let Some(flash) = state.flash.as_mut() else {
        return Err(());
    };
    flash
        .read_nor(sector_base, &mut state.sector_buf.0)
        .map_err(|_| ())?;

    {
        let buf = &mut state.sector_buf.0[in_sector..in_sector + NVS_RECORD_LEN];
        buf.fill(0);
        buf[0..4].copy_from_slice(&NVS_MAGIC);
        buf[4] = NVS_VERSION;

        buf[8..10].copy_from_slice(&state.scratch_nvs.config.threshold.to_le_bytes());
        buf[10..18].copy_from_slice(&state.scratch_nvs.config.duration.to_le_bytes());
        buf[18] = state.scratch_nvs.config.sensitivity;
        buf[19..21].copy_from_slice(&state.scratch_nvs.config.safety_off_min.to_le_bytes());
        buf[21..23].copy_from_slice(&state.scratch_nvs.refresh_token_len.to_le_bytes());
        buf[23..25].copy_from_slice(&state.scratch_nvs.config.lamp_wattage_w.to_le_bytes());

        if let Some(creds) = &state.scratch_nvs.wifi {
            let ssid_bytes = creds.ssid.as_bytes();
            let pass_bytes = creds.password.as_bytes();
            buf[5] = 1;
            buf[6] = ssid_bytes.len() as u8;
            buf[7] = pass_bytes.len() as u8;
            buf[28..28 + ssid_bytes.len()].copy_from_slice(ssid_bytes);
            buf[60..60 + pass_bytes.len()].copy_from_slice(pass_bytes);
        }

        if rt_len > 0 {
            buf[124..124 + rt_len].copy_from_slice(&state.scratch_nvs.refresh_token[..rt_len]);
        }

        let crc = crc32(&buf[0..508]);
        buf[508..512].copy_from_slice(&crc.to_le_bytes());
    }

    flash
        .erase(sector_base, sector_base + FlashStorage::SECTOR_SIZE)
        .map_err(|_| ())?;
    flash
        .write_nor(sector_base, &state.sector_buf.0)
        .map_err(|_| ())
}

#[inline(never)]
async fn nvs_read_with<R>(f: impl FnOnce(&NvsData) -> R) -> R {
    let mut state = NVS_FLASH.lock().await;
    load_nvs_data(&mut state);
    f(&state.scratch_nvs)
}

#[inline(never)]
async fn nvs_update<F: FnOnce(&mut NvsData) -> bool>(f: F) -> Result<bool, ()> {
    let mut state = NVS_FLASH.lock().await;
    load_nvs_data(&mut state);
    if f(&mut state.scratch_nvs) {
        save_nvs_data(&mut state)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Minimal DHCPv4 server on UDP port 67 for SoftAP clients.
async fn dhcp_server(stack: Stack<'_>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_buf = [0u8; 600];
    let mut tx_buf = [0u8; 600];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    let _ = socket.bind(67);

    let mut next_ip_last_octet: u8 = 2;

    loop {
        let mut pkt = [0u8; 576];
        let Ok((len, _)) = socket.recv_from(&mut pkt).await else {
            continue;
        };
        if len < 244 || pkt[0] != 1 {
            continue;
        }
        if pkt[236..240] != [99, 130, 83, 99] {
            continue;
        }

        let mut msg_type = 0u8;
        let mut idx = 240;
        while idx < len {
            let opt = pkt[idx];
            if opt == 255 {
                break;
            }
            if opt == 0 {
                idx += 1;
                continue;
            }
            if idx + 1 >= len {
                break;
            }
            let olen = pkt[idx + 1] as usize;
            if idx + 2 + olen > len {
                break;
            }
            if opt == 53 && olen == 1 {
                msg_type = pkt[idx + 2];
            }
            idx += 2 + olen;
        }

        let reply_type = match msg_type {
            1 => 2u8, // DISCOVER -> OFFER
            3 => 5u8, // REQUEST -> ACK
            _ => continue,
        };

        let offered_ip = [192, 168, 4, next_ip_last_octet];
        if msg_type == 3 {
            next_ip_last_octet = if next_ip_last_octet >= 20 {
                2
            } else {
                next_ip_last_octet + 1
            };
        }

        let mut resp = [0u8; 300];
        resp[0] = 2; // BOOTREPLY
        resp[1] = 1; // Ethernet
        resp[2] = 6; // HLEN
        resp[4..8].copy_from_slice(&pkt[4..8]); // XID
        resp[10..12].copy_from_slice(&[0x80, 0x00]); // Broadcast flag
        resp[16..20].copy_from_slice(&offered_ip); // YIADDR
        resp[20..24].copy_from_slice(&AP_IP.octets()); // SIADDR
        resp[28..34].copy_from_slice(&pkt[28..34]); // CHADDR
        resp[236..240].copy_from_slice(&[99, 130, 83, 99]); // Magic cookie

        let mut pos = 240;
        resp[pos..pos + 3].copy_from_slice(&[53, 1, reply_type]);
        pos += 3;
        resp[pos..pos + 2].copy_from_slice(&[54, 4]);
        resp[pos + 2..pos + 6].copy_from_slice(&AP_IP.octets());
        pos += 6;
        resp[pos..pos + 6].copy_from_slice(&[51, 4, 0, 0, 0x0e, 0x10]);
        pos += 6;
        resp[pos..pos + 6].copy_from_slice(&[1, 4, 255, 255, 255, 0]);
        pos += 6;
        resp[pos..pos + 2].copy_from_slice(&[3, 4]);
        resp[pos + 2..pos + 6].copy_from_slice(&AP_IP.octets());
        pos += 6;
        resp[pos..pos + 2].copy_from_slice(&[6, 4]);
        resp[pos + 2..pos + 6].copy_from_slice(&AP_IP.octets());
        pos += 6;
        resp[pos] = 255;
        pos += 1;

        let broadcast = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)), 68);
        let _ = socket.send_to(&resp[..pos], broadcast).await;
    }
}

/// Minimal DNS responder on UDP port 53 that resolves all queries to AP_IP for captive portal UX.
async fn dns_server(stack: Stack<'_>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_buf = [0u8; 512];
    let mut tx_buf = [0u8; 512];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    let _ = socket.bind(53);

    loop {
        let mut req = [0u8; 256];
        let Ok((len, remote)) = socket.recv_from(&mut req).await else {
            continue;
        };
        if len < 12 || len + 16 > 256 {
            continue;
        }

        let mut resp = [0u8; 256];
        resp[..len].copy_from_slice(&req[..len]);
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1
        resp[6] = 0x00;
        resp[7] = 0x01; // ANCOUNT = 1
        resp[8..12].fill(0);

        let answer: [u8; 16] = [
            0xC0, 0x0C, // Pointer to QNAME
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3C, // TTL 60s
            0x00, 0x04, // RDLENGTH 4
            192, 168, 4, 1, // AP_IP
        ];
        resp[len..len + 16].copy_from_slice(&answer);
        let _ = socket.send_to(&resp[..len + 16], remote).await;
    }
}

/// Decodes application/x-www-form-urlencoded values.
fn url_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[derive(Deserialize)]
struct WifiSubmitPayload {
    ssid: String,
    pass: String,
}

#[derive(Deserialize)]
struct ConfigSubmitPayload {
    threshold: u16,
    sensitivity: u8,
    duration: u64,
    safety_off_min: u16,
    #[serde(default)]
    lamp_wattage_w: i32,
}

#[derive(Serialize)]
struct PortalStatusJson<'a> {
    device_name: &'a str,
    has_saved_wifi: bool,
    saved_ssid: &'a str,
    wifi_error: bool,
    remaining_secs: Option<u64>,
    configured: bool,
    lamp_is_on: bool,
    remote_lamp_on: bool,
    threshold: u16,
    sensitivity: u8,
    duration: u64,
    safety_off_min: u16,
    lamp_wattage_w: u16,
}

enum PortalOutcome {
    ConnectWifi(WifiCredentials),
    TimeoutExpired,
}

/// Parses Wi-Fi submission from JSON (`{"ssid":...,"pass":...}`) or URL-encoded form body.
/// Only accepts non-empty SSID (dropdown selection) and non-empty password.
fn parse_wifi_submit(body: &str) -> Option<WifiCredentials> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        let parsed: WifiSubmitPayload = serde_json::from_str(trimmed).ok()?;
        if parsed.ssid.is_empty()
            || parsed.ssid.len() > 32
            || parsed.pass.is_empty()
            || parsed.pass.len() > 64
        {
            return None;
        }
        return Some(WifiCredentials {
            ssid: parsed.ssid,
            password: parsed.pass,
        });
    }

    let mut ssid = None;
    let mut password = None;
    for pair in trimmed.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let val = url_decode(v);
            match k {
                "ssid" if !val.is_empty() => ssid = Some(val),
                "pass" | "password" if !val.is_empty() => password = Some(val),
                _ => {}
            }
        }
    }

    let final_ssid = ssid?;
    let final_pass = password?;
    if final_ssid.len() > 32 || final_pass.len() > 64 {
        return None;
    }

    Some(WifiCredentials {
        ssid: final_ssid,
        password: final_pass,
    })
}

/// Parses the configuration parameters from JSON or URL-encoded form body and validates ranges.
fn parse_config_submit(body: &str) -> Option<DeviceConfig> {
    let trimmed = body.trim();
    let cfg = if trimmed.starts_with('{') {
        let parsed: ConfigSubmitPayload = serde_json::from_str(trimmed).ok()?;
        DeviceConfig {
            threshold: parsed.threshold,
            sensitivity: parsed.sensitivity,
            duration: parsed.duration,
            safety_off_min: parsed.safety_off_min,
            lamp_wattage_w: parsed.lamp_wattage_w.clamp(0, 5000) as u16,
        }
    } else {
        let mut threshold = None;
        let mut sensitivity = None;
        let mut duration = None;
        let mut safety_off_min = None;
        let mut lamp_wattage_w = 0u16;
        for pair in trimmed.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let val = url_decode(v);
                match k {
                    "threshold" => threshold = val.trim().parse::<u16>().ok(),
                    "sensitivity" => sensitivity = val.trim().parse::<u8>().ok(),
                    "duration" => duration = val.trim().parse::<u64>().ok(),
                    "safety_off_min" => safety_off_min = val.trim().parse::<u16>().ok(),
                    "lamp_wattage_w" => {
                        if let Ok(w) = val.trim().parse::<i32>() {
                            lamp_wattage_w = w.clamp(0, 5000) as u16;
                        }
                    }
                    _ => {}
                }
            }
        }
        DeviceConfig {
            threshold: threshold?,
            sensitivity: sensitivity?,
            duration: duration?,
            safety_off_min: safety_off_min?,
            lamp_wattage_w,
        }
    };

    if cfg.is_configured() {
        Some(cfg)
    } else {
        None
    }
}

/// Escapes HTML special characters to prevent XSS in generated portal pages.
fn html_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Writes a single HTTP/1.1 chunk directly to the TCP socket (zero heap allocation).
async fn write_http_chunk(socket: &mut TcpSocket<'_>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut hdr = FixedBuf::<24>::new();
    let _ = write!(hdr, "{:X}\r\n", data.len());
    let _ = socket.write_all(hdr.as_bytes()).await;
    let _ = socket.write_all(data).await;
    let _ = socket.write_all(b"\r\n").await;
}

/// Streams the fixed-height (`--app-h`, keyboard-safe, zero-scroll) two-view Hungarian Captive
/// Portal HTML/CSS/JS page directly in HTTP chunks so no ~11-20 KB `String`/`Vec` is allocated on heap.
async fn send_portal_html_chunked(
    socket: &mut TcpSocket<'_>,
    device_name: &str,
    ssids: &[String],
    initial_view: &str,
    last_wifi_error: bool,
    remaining_secs: Option<u64>,
    cfg: DeviceConfig,
    lamp_is_on: bool,
) {
    let safe_dev = html_escape(device_name);
    let (pre_th, pre_se, pre_du, pre_so, pre_lw) = if cfg.is_configured() {
        (
            cfg.threshold,
            cfg.sensitivity,
            cfg.duration,
            cfg.safety_off_min,
            cfg.lamp_wattage_w,
        )
    } else {
        (50, 50, 60, 0, cfg.lamp_wattage_w)
    };

    let _ = socket
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        )
        .await;

    let mut chunk = FixedBuf::<1024>::new();
    let _ = write!(
        chunk,
        "<!DOCTYPE html><html lang='hu'><head><meta charset='utf-8'>\
         <meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'>\
         <title>{dev} – Captive Portal</title><style>",
        dev = safe_dev
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    write_http_chunk(
        socket,
        b"*,*::before,*::after{box-sizing:border-box}\
          html,body{margin:0;padding:0;width:100%;height:var(--app-h,100vh);min-height:var(--app-h,100vh);overflow:hidden;\
          background:#0f172a;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;line-height:1.3}\
          button,select,input,a{-webkit-tap-highlight-color:transparent;touch-action:manipulation;flex-shrink:0}\
          .page{height:var(--app-h,100vh);min-height:var(--app-h,100vh);max-height:var(--app-h,100vh);overflow:hidden;\
          display:flex;flex-direction:column;padding:12px 14px;width:100%;max-width:480px;margin:0 auto}\
          .page-main{justify-content:space-between;gap:6px}\
          .page-config{justify-content:flex-start}\
          .page>*,.cfg-card>*,.cfg-form>*{flex-shrink:0}\
          .hidden{display:none!important}\
          .hdr{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-shrink:0}\
          .dev-title{font-size:19px;font-weight:800;color:#f8fafc;letter-spacing:-0.01em;text-align:left}\
          .dev-id{color:#38bdf8}\
          .link-btn{width:auto;height:36px;padding:0 12px;margin:0;background:transparent;border:1px solid #475569;\
          border-radius:8px;color:#93c5fd;font-size:14px;font-weight:600;cursor:pointer}\
          .warn{background:#78350f;border:1px solid #f59e0b;color:#fef3c7;border-radius:8px;\
          padding:8px 10px;font-size:13px;font-weight:600;line-height:1.3}\
          .grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px;flex-shrink:0}\
          .sec-lbl{font-size:16px;font-weight:700;color:#e2e8f0;text-align:left}",
    )
    .await;

    write_http_chunk(
        socket,
        b"select,input,button{width:100%;height:42px;padding:0 12px;margin:0;border-radius:8px;\
          border:1px solid #475569;background:#1e293b;color:#f8fafc;font-size:15px}\
          button{background:#2563eb;border:none;height:44px;font-size:15px;font-weight:700;cursor:pointer}\
          button:disabled{background:#334155;color:#94a3b8;cursor:not-allowed}\
          .btn-sec{background:#334155}\
          .btn-warn{background:#b45309;height:38px;font-size:14px}\
          .btn-danger{background:#b91c1c;height:38px;font-size:14px}\
          .btn-lamp-on{background:#16a34a}\
          .btn-lamp-off{background:#475569}\
          .err-slot{height:36px;min-height:36px;display:flex;align-items:center;justify-content:center;gap:8px;\
          text-align:center;font-size:13px;font-weight:600;line-height:1.3;flex-shrink:0}\
          .slot-err{color:#f87171}\
          .slot-info{color:#fbbf24}\
          .err-hidden{visibility:hidden}\
          .btn-icon{width:28px;height:28px;min-width:28px;padding:0;border-radius:6px;background:#2563eb;\
          color:#f8fafc;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}\
          .btn-icon svg{width:15px;height:15px;display:block}\
          .sys-sec{border-top:1px solid #334155;padding-top:8px;display:flex;flex-direction:column;gap:6px;flex-shrink:0}\
          .sys-lbl{font-size:13px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.03em}\
          .cfg-card{margin:auto 0;border:1px solid #334155;border-radius:12px;background:#1e293b;\
          padding:12px 14px;display:flex;flex-direction:column;gap:10px;flex-shrink:0}\
          .cfg-form{display:flex;flex-direction:column;gap:10px;flex-shrink:0}\
          .param-row{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-shrink:0}",
    )
    .await;

    write_http_chunk(
        socket,
        b".param-row label{font-size:15px;font-weight:600;color:#e2e8f0;text-align:left;flex:1}\
          .param-inp{width:88px;min-width:88px;max-width:88px;text-align:center;height:42px;padding:0 6px;\
          font-size:16px;font-weight:700;background:#0f172a;border:1px solid #475569}\
          .hint{font-size:12px;color:#94a3b8;line-height:1.3}\
          .modal-bg{position:fixed;inset:0;background:rgba(2,6,23,.78);display:flex;align-items:center;\
          justify-content:center;padding:14px;z-index:50}\
          .modal-card{width:100%;max-width:440px;background:#1e293b;border:1px solid #475569;\
          border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:12px}\
          .modal-hdr{display:flex;align-items:center;justify-content:space-between;gap:8px}\
          .modal-title{font-size:17px;font-weight:700;color:#f8fafc}\
          .modal-x{width:34px;height:34px;padding:0;border-radius:8px;background:#334155;color:#f8fafc;\
          font-size:15px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}\
          .modal-body{font-size:14px;color:#cbd5e1;line-height:1.45}\
          .modal-body ol{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:8px}\
          </style></head><body>",
    )
    .await;

    let view1_cls = if initial_view == "config" {
        "page page-main hidden"
    } else {
        "page page-main"
    };
    let view2_cls = if initial_view == "config" {
        "page page-config"
    } else {
        "page page-config hidden"
    };
    let lamp_text = if lamp_is_on { "Lámpa: BE" } else { "Lámpa: KI" };
    let lamp_cls = if lamp_is_on { "btn-lamp-on" } else { "btn-lamp-off" };

    chunk.clear();
    let _ = write!(
        chunk,
        "<div id='view-main' class='{v1}'>\
         <div class='hdr'><span class='dev-title'>Eszköz: <span class='dev-id'>{dev}</span></span><button type='button' class='link-btn' onclick=\"openModal('helpModal')\">Segítség</button></div>\
         <div class='warn'>FIGYELEM: Közvetlen eszköz beállítás és lámpa kapcsolás kizárólag a Wi-Fi hálózatra csatlakozás ELŐTT lehetséges. Utána csak Webapp-ból!</div>",
        v1 = view1_cls,
        dev = safe_dev,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div class='grid2'>\
           <button type='button' id='toggleLampBtn' class='{lcls}' onclick='toggleLamp()'>{ltxt}</button>\
           <button type='button' class='btn-sec' onclick=\"showView('config')\">Beállítások</button>\
         </div>\
         <div class='sec-lbl'>Wi-Fi hálózat beállítása</div>\
         <select name='ssid' id='ssid' onchange='validateWifiForm()'><option value=''>-- Válassz Wi-Fi hálózatot --</option>",
        lcls = lamp_cls,
        ltxt = lamp_text,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    for s in ssids {
        let safe_s = html_escape(s);
        chunk.clear();
        let _ = write!(chunk, "<option value='{0}'>{0}</option>", safe_s);
        write_http_chunk(socket, chunk.as_bytes()).await;
    }

    chunk.clear();
    let _ = write!(
        chunk,
        "</select>\
         <button type='button' id='scanBtn' class='btn-sec' onclick='scanWifi()'>Wi-Fi lista frissítése</button>\
         <input type='password' name='pass' id='pass' maxlength='64' autocomplete='new-password' placeholder='Wi-Fi jelszó' oninput='validateWifiForm()'>\
         <button type='button' id='connectBtn' onclick='openWifiConfirm()' disabled>Csatlakozás és Mentés</button>"
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let show_connect_now = !last_wifi_error && remaining_secs.is_some_and(|s| s > 0);
    if last_wifi_error {
        let _ = chunk.write_str(
            "<div id='wifi-err-slot' class='err-slot slot-err'><span id='wifi-msg'>Sikertelen Wi-Fi csatlakozás.</span>",
        );
    } else if let Some(secs) = remaining_secs {
        if secs > 0 {
            let _ = write!(
                chunk,
                "<div id='wifi-err-slot' class='err-slot slot-info'><span id='wifi-msg'>Mentett WiFi hálózatot találtam. Csatlakozás {:02}:{:02} múlva</span>",
                secs / 60,
                secs % 60
            );
        } else {
            let _ = chunk.write_str(
                "<div id='wifi-err-slot' class='err-slot slot-info'><span id='wifi-msg'>Csatlakozás...</span>",
            );
        }
    } else {
        let _ = chunk.write_str(
            "<div id='wifi-err-slot' class='err-slot err-hidden'><span id='wifi-msg'>\u{00a0}</span>",
        );
    }
    let btn_cls = if show_connect_now { "btn-icon" } else { "btn-icon hidden" };
    let _ = write!(
        chunk,
        "<button type='button' id='connectNowBtn' class='{bcls}' title='Azonnali csatlakozás' aria-label='Azonnali csatlakozás' onclick='connectSavedNow()'><svg viewBox='0 0 24 24' fill='currentColor' aria-hidden='true'><path d='M8 5v14l11-7z'/></svg></button></div>",
        bcls = btn_cls,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = chunk.write_str(
        "<div class='sys-sec'><div class='sys-lbl'>Rendszerműveletek</div><div class='grid2'>\
         <button type='button' id='clearWifiBtn' class='btn-warn' onclick='clearWifi()'>Wi-Fi adatok törlése</button>\
         <button type='button' id='restartBtn' class='btn-danger' onclick='restartDevice()'>Újraindítás</button>\
         </div></div></div>",
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div id='view-config' class='{v2}'>\
         <div class='hdr'><span class='dev-title'>Eszköz: <span class='dev-id'>{dev}</span></span><button type='button' class='link-btn' onclick=\"openModal('helpModal')\">Segítség</button></div>\
         <div class='cfg-card'><div class='sec-lbl'>Működési paraméterek beállítása</div><form id='cfgForm' class='cfg-form' onsubmit='saveConfig(event)'>",
        v2 = view2_cls,
        dev = safe_dev,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div class='param-row'><label for='threshold'>Fény érzékenység 1 - 100</label><input type='number' id='threshold' name='threshold' class='param-inp' min='1' max='100' value='{th}' required></div>\
         <div class='param-row'><label for='sensitivity'>Mozgás érzékenység 1 - 100</label><input type='number' id='sensitivity' name='sensitivity' class='param-inp' min='1' max='100' value='{se}' required></div>",
        th = pre_th,
        se = pre_se,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div class='param-row'><label for='duration'>Késleltetés (mp) 10 - 600</label><input type='number' id='duration' name='duration' class='param-inp' min='10' max='600' value='{du}' required></div>\
         <div class='param-row'><label for='safety_off_min'>Auto kikapcs (p)</label><input type='number' id='safety_off_min' name='safety_off_min' class='param-inp' min='0' max='1440' value='{so}' required></div>",
        du = pre_du,
        so = pre_so,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    write_http_chunk(
        socket,
        "<div class='hint'>Manuális lámpa kapcsolás biztonsági kikapcsolási időzítője. Hagyd nullán, hogy soha ne kapcsolja le!</div>".as_bytes(),
    )
    .await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div class='param-row'><label for='lamp_wattage_w'>Lámpa teljesítménye (W)</label><input type='number' id='lamp_wattage_w' name='lamp_wattage_w' class='param-inp' min='0' max='5000' step='1' placeholder='0' value='{lw}'></div>\
         <div class='hint'>0 = fogyasztásmérés kikapcsolva</div>\
         <button type='submit' id='saveCfgBtn'>Beállítások mentése</button>\
         </form></div>\
         <button type='button' class='btn-sec' onclick=\"showView('main')\">Vissza a Wi-Fi beállításokhoz</button>\
         </div>",
        lw = pre_lw,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    write_http_chunk(
        socket,
        "<div id='helpModal' class='modal-bg hidden' onclick=\"backdropClose(event,'helpModal')\">\
          <div class='modal-card' role='dialog' aria-modal='true'>\
            <div class='modal-hdr'>\
              <span class='modal-title'>Beüzemelési és Párosítási Útmutató</span>\
              <button type='button' class='modal-x' aria-label='Bezárás' onclick=\"closeModal('helpModal')\">X</button>\
            </div>\
            <div class='modal-body'><ol>\
              <li><strong>Működési paraméterek:</strong> A <em>Beállítások</em> gombra kattintva állítsd be a fényérzékenységet (1–100), mozgásérzékenységet (1–100), késleltetést (10–600 mp) és az opcionális manuális auto-kikapcsolást (perc, 0 = kikapcsolva), majd mentsd el.</li>\
              <li><strong>Helyi Wi-Fi csatlakozás:</strong> A főoldalon frissítsd a listát, válaszd ki az otthoni Wi-Fi hálózatot, írd be a jelszót, majd kattints a <em>Csatlakozás és Mentés</em> gombra.</li>".as_bytes(),
    )
    .await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<li><strong>Webapp párosítás:</strong> Sikeres Wi-Fi csatlakozás után az eszköz kilép AP módból. Nyisd meg a SmartLight Webappot, és párosítsd a(z) <strong>{dev}</strong> eszközt az eszközön található 10 karakteres biztonsági kóddal az 5 perces párosítási ablakban.</li>\
         </ol></div></div></div>",
        dev = safe_dev,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<div id='wifiConfirmModal' class='modal-bg hidden' onclick=\"backdropClose(event,'wifiConfirmModal')\">\
           <div class='modal-card' role='dialog' aria-modal='true'>\
             <div class='modal-hdr'>\
               <span class='modal-title'>Wi-Fi csatlakozás megerősítése</span>\
               <button type='button' class='modal-x' aria-label='Bezárás' onclick=\"closeModal('wifiConfirmModal')\">X</button>\
             </div>\
             <div class='modal-body'>A csatlakozás sikerességét jelzi, ha a telefon visszavált a helyi hálózatra és eltűnik a WiFi hálózatok listájáról az eszköz. Ekkor megkezdhető a Webappon a párosítás. Ha sikertelen a csatlakozás, ez a felület újra elérhetővé válik a(z) {dev} eszköz WiFi-jére csatlakozva és a 192.168.4.1 webcímen.</div>",
        dev = safe_dev,
    );
    write_http_chunk(socket, chunk.as_bytes()).await;

    write_http_chunk(
        socket,
        "<button type='button' id='confirmConnectBtn' onclick='confirmAndSubmitWifi()'>Csatlakozás indítása</button>\
           </div>\
         </div>".as_bytes(),
    )
    .await;

    chunk.clear();
    let _ = write!(
        chunk,
        "<script>\
         let initH=window.innerHeight;\
         function setAppH(h){{initH=h;document.documentElement.style.setProperty('--app-h',initH+'px');}}\
         setAppH(initH);\
         window.addEventListener('resize',()=>{{if(window.innerHeight>initH)setAppH(window.innerHeight);}});\
         window.addEventListener('orientationchange',()=>{{setTimeout(()=>{{setAppH(window.innerHeight);}},250);}});\
         let wifiErr={werr};let remSecs=",
        werr = last_wifi_error,
    );
    if let Some(s) = remaining_secs {
        let _ = write!(chunk, "{};", s);
    } else {
        let _ = chunk.write_str("null;");
    }
    write_http_chunk(socket, chunk.as_bytes()).await;

    write_http_chunk(
        socket,
        "let connectingNow=false;\
          function fmtMmSs(s){const m=Math.floor(s/60),sec=s%60;return String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');}\
          function renderRow9(){const el=document.getElementById('wifi-err-slot'),msg=document.getElementById('wifi-msg'),btn=document.getElementById('connectNowBtn');\
          if(connectingNow){el.className='err-slot slot-info';msg.textContent='Csatlakozás...';btn.classList.add('hidden');btn.disabled=true;}\
          else if(wifiErr){el.className='err-slot slot-err';msg.textContent='Sikertelen Wi-Fi csatlakozás.';btn.classList.add('hidden');}\
          else if(remSecs!==null&&remSecs>0){el.className='err-slot slot-info';msg.textContent='Mentett WiFi hálózatot találtam. Csatlakozás '+fmtMmSs(remSecs)+' múlva';btn.classList.remove('hidden');btn.disabled=false;}\
          else if(remSecs===0){el.className='err-slot slot-info';msg.textContent='Csatlakozás...';btn.classList.add('hidden');btn.disabled=true;}\
          else{el.className='err-slot err-hidden';msg.textContent='\\u00a0';btn.classList.add('hidden');}}\
          renderRow9();\
          setInterval(()=>{if(!wifiErr&&!connectingNow&&remSecs!==null&&remSecs>0){remSecs--;renderRow9();}},1000);\
          function showView(v){document.getElementById('view-main').classList.toggle('hidden',v!=='main');\
          document.getElementById('view-config').classList.toggle('hidden',v!=='config');}\
          function openModal(id){document.getElementById(id).classList.remove('hidden');}\
          function closeModal(id){document.getElementById(id).classList.add('hidden');}\
          function backdropClose(e,id){if(e.target&&e.target.id===id)closeModal(id);}\
          document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeModal('helpModal');closeModal('wifiConfirmModal');}});\
          function validateWifiForm(){const s=document.getElementById('ssid').value,p=document.getElementById('pass').value;\
          document.getElementById('connectBtn').disabled=!(s&&s.length>0&&p.length>0);}\
          function updateLampUi(on){const btn=document.getElementById('toggleLampBtn');\
          btn.textContent=on?'Lámpa: BE':'Lámpa: KI';btn.className=on?'btn-lamp-on':'btn-lamp-off';}".as_bytes(),
    )
    .await;

    write_http_chunk(
        socket,
        "async function syncStatus(init){try{const r=await fetch('/status');if(!r.ok)return;const d=await r.json();\
          updateLampUi(d.lamp_is_on);if(init&&typeof d.lamp_wattage_w==='number'){const lwEl=document.getElementById('lamp_wattage_w');if(lwEl&&document.activeElement!==lwEl)lwEl.value=d.lamp_wattage_w;}\
          if(!connectingNow){wifiErr=!!d.wifi_error;remSecs=(typeof d.remaining_secs==='number')?d.remaining_secs:null;renderRow9();}}catch(_){}}\
          syncStatus(true);setInterval(()=>syncStatus(false),5000);\
          async function connectSavedNow(){const btn=document.getElementById('connectNowBtn');if(!btn||connectingNow)return;\
          btn.disabled=true;connectingNow=true;renderRow9();\
          try{const r=await fetch('/connect-saved',{method:'POST'});if(!r.ok){connectingNow=false;renderRow9();}}catch(_){}}\
          async function scanWifi(){const btn=document.getElementById('scanBtn'),sel=document.getElementById('ssid');\
          btn.disabled=true;btn.textContent='Keresés...';\
          try{const r=await fetch('/scan?refresh=1');const arr=await r.json();const cur=sel.value;\
          sel.innerHTML=\"<option value=''>-- Válassz Wi-Fi hálózatot --</option>\";\
          arr.forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;if(s===cur)o.selected=true;sel.appendChild(o);});\
          validateWifiForm();}catch(_){}\
          btn.disabled=false;btn.textContent='Wi-Fi lista frissítése';}\
          function openWifiConfirm(){const s=document.getElementById('ssid').value,p=document.getElementById('pass').value;\
          if(!s||!p)return;openModal('wifiConfirmModal');}\
          async function confirmAndSubmitWifi(){const ssid=document.getElementById('ssid').value,pass=document.getElementById('pass').value;\
          if(!ssid||!pass)return;const cb=document.getElementById('confirmConnectBtn');cb.disabled=true;cb.textContent='Csatlakozás folyamatban...';\
          document.getElementById('connectBtn').disabled=true;wifiErr=false;connectingNow=false;remSecs=null;renderRow9();\
          try{await fetch('/connect-wifi',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid,pass})});}catch(_){}}\
          async function clearWifi(){const btn=document.getElementById('clearWifiBtn');btn.disabled=true;\
          try{const r=await fetch('/clear-wifi',{method:'POST'});if(r.ok){wifiErr=false;connectingNow=false;remSecs=null;renderRow9();btn.textContent='Törölve';\
          setTimeout(()=>{btn.textContent='Wi-Fi adatok törlése';btn.disabled=false;},1500);return;}}catch(_){}\
          btn.disabled=false;}".as_bytes(),
    )
    .await;

    write_http_chunk(
        socket,
        "async function restartDevice(){const btn=document.getElementById('restartBtn');btn.disabled=true;btn.textContent='Újraindítás...';\
          try{await fetch('/restart',{method:'POST'});}catch(_){}}\
          async function toggleLamp(){try{const r=await fetch('/toggle-lamp',{method:'POST'});const d=await r.json();\
          if(d.ok)updateLampUi(d.lamp_is_on);}catch(_){}}\
          async function saveConfig(e){e.preventDefault();const btn=document.getElementById('saveCfgBtn');\
          const lwEl=document.getElementById('lamp_wattage_w'),rawLw=Number(lwEl.value);\
          const lw=Number.isFinite(rawLw)?Math.min(5000,Math.max(0,Math.round(rawLw))):0;lwEl.value=lw;\
          const payload={threshold:+document.getElementById('threshold').value,sensitivity:+document.getElementById('sensitivity').value,\
          duration:+document.getElementById('duration').value,safety_off_min:+document.getElementById('safety_off_min').value,lamp_wattage_w:lw};\
          if(payload.threshold<1||payload.threshold>100||payload.sensitivity<1||payload.sensitivity>100||\
          payload.duration<10||payload.duration>600||payload.safety_off_min<0||payload.safety_off_min>1440){\
          btn.textContent='Érvénytelen értékek!';setTimeout(()=>{btn.textContent='Beállítások mentése';},1500);return;}\
          btn.disabled=true;try{const r=await fetch('/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});\
          const d=await r.json();btn.textContent=d.ok?'Mentve!':'Hiba a mentésnél!';}catch(_){btn.textContent='Hiba!';}\
          setTimeout(()=>{btn.textContent='Beállítások mentése';btn.disabled=false;},1500);}\
          </script></body></html>".as_bytes(),
    )
    .await;

    let _ = socket.write_all(b"0\r\n\r\n").await;
    let _ = socket.flush().await;
}

async fn send_http_response(
    socket: &mut TcpSocket<'_>,
    status: &str,
    content_type: &str,
    body: &str,
) {
    let mut hdr = String::new();
    let _ = write!(
        hdr,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    let _ = socket.write_all(hdr.as_bytes()).await;
    let _ = socket.write_all(body.as_bytes()).await;
    let _ = socket.flush().await;
}

/// Scans nearby Wi-Fi networks using the Wi-Fi controller in AP+STA mode.
async fn scan_nearby_ssids(controller: &mut WifiController<'_>) -> Vec<String> {
    let mut ssids: Vec<String> = Vec::new();
    for attempt in 0..2 {
        match with_timeout(
            Duration::from_secs(8),
            controller.scan_async(&ScanConfig::default().with_max(15)),
        )
        .await
        {
            Ok(Ok(results)) => {
                for ap in results {
                    let s = ap.ssid.as_str();
                    if !s.is_empty() && !ssids.iter().any(|x| x == s) {
                        ssids.push(String::from(s));
                    }
                }
                break;
            }
            _ if attempt == 0 => Timer::after(Duration::from_millis(250)).await,
            _ => {}
        }
    }
    ssids
}

/// HTTP server on port 80 serving the two-view Captive Portal and all provisioning/config endpoints.
async fn http_portal_server(
    stack: Stack<'_>,
    controller: &mut WifiController<'_>,
    device_name: &str,
    initial_ssids: Vec<String>,
    ap_deadline: &EmbassyMutex<CriticalSectionRawMutex, Option<Instant>>,
    last_wifi_error: &mut bool,
) -> WifiCredentials {
    let mut cached_ssids = initial_ssids;
    // Reuse idle SSE_SCRATCH TLS RX buffer (16.6 KB) during SoftAP portal mode so
    // ___embassy_main::POOL reserves zero permanent .bss for portal socket buffers.
    let mut portal_bufs = SSE_SCRATCH.lock().await;
    let (rx_buf, rest) = portal_bufs.tls_rx.split_at_mut(2048);
    let (tx_buf, rest) = rest.split_at_mut(4096);
    let (req_buf, _) = rest.split_at_mut(3072);

    loop {
        let mut socket = TcpSocket::new(stack, rx_buf, tx_buf);
        socket.set_timeout(Some(Duration::from_secs(10)));

        if socket.accept(80).await.is_err() {
            continue;
        }

        let mut total = 0usize;
        let mut payload_too_large = false;
        let mut parsed_content_len = 0usize;
        loop {
            match socket.read(&mut req_buf[total..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    if let Ok(s) = core::str::from_utf8(&req_buf[..total]) {
                        if let Some(hdr_end) = s.find("\r\n\r\n") {
                            let body_received = total - (hdr_end + 4);
                            parsed_content_len = s[..hdr_end]
                                .lines()
                                .find_map(|line| {
                                    let lower_eq = line
                                        .get(..15)
                                        .map(|p| p.eq_ignore_ascii_case("content-length:"))
                                        .unwrap_or(false);
                                    if lower_eq {
                                        line[15..].trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if parsed_content_len > MAX_POST_BODY_BYTES
                                || body_received > MAX_POST_BODY_BYTES
                            {
                                payload_too_large = true;
                                break;
                            }
                            if total >= hdr_end + 4 + parsed_content_len {
                                break;
                            }
                        }
                    }
                    if total >= req_buf.len() {
                        payload_too_large = true;
                        break;
                    }
                }
            }
        }

        if payload_too_large {
            println!(
                "HTTP payload exceeded {} bytes; dropping connection.",
                MAX_POST_BODY_BYTES
            );
            socket.close();
            continue;
        }

        if let Ok(req_str) = core::str::from_utf8(&req_buf[..total]) {
            let first_line = req_str.lines().next().unwrap_or("");
            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let raw_path = parts.next().unwrap_or("/");
            let path = raw_path.split('?').next().unwrap_or("/");
            let raw_body = req_str.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
            let body = if parsed_content_len > 0 && raw_body.len() >= parsed_content_len {
                &raw_body[..parsed_content_len]
            } else {
                raw_body
            };

            match (method, path) {
                ("GET", "/status") => {
                    let (has_saved_wifi, saved_ssid_opt) =
                        nvs_read_with(|nvs| (nvs.wifi.is_some(), nvs.wifi.as_ref().map(|w| w.ssid.clone()))).await;
                    let saved_ssid = saved_ssid_opt.as_deref().unwrap_or("");
                    let remaining_secs = {
                        let dl_opt = *ap_deadline.lock().await;
                        dl_opt.map(|dl| {
                            let now = Instant::now();
                            if dl > now {
                                dl.duration_since(now).as_secs()
                            } else {
                                0
                            }
                        })
                    };
                    let state = DEVICE_STATE.lock().await;
                    let status = PortalStatusJson {
                        device_name,
                        has_saved_wifi,
                        saved_ssid,
                        wifi_error: *last_wifi_error,
                        remaining_secs,
                        configured: state.is_configured(),
                        lamp_is_on: state.lamp_is_on,
                        remote_lamp_on: state.remote_lamp_on,
                        threshold: state.threshold,
                        sensitivity: state.sensitivity,
                        duration: state.duration,
                        safety_off_min: state.safety_off_min,
                        lamp_wattage_w: state.lamp_wattage_w,
                    };
                    drop(state);
                    let json = serde_json::to_string(&status).unwrap_or_else(|_| String::from("{}"));
                    send_http_response(&mut socket, "200 OK", "application/json", &json).await;
                }
                ("GET", "/scan") => {
                    let force_refresh = raw_path.contains("refresh=1");
                    if force_refresh || cached_ssids.is_empty() {
                        let fresh = scan_nearby_ssids(controller).await;
                        if !fresh.is_empty() {
                            cached_ssids = fresh;
                        }
                    }
                    let json =
                        serde_json::to_string(&cached_ssids).unwrap_or_else(|_| String::from("[]"));
                    send_http_response(&mut socket, "200 OK", "application/json", &json).await;
                }
                ("POST", "/connect-wifi") | ("POST", "/wifi") | ("POST", "/save") => {
                    if let Some(creds) = parse_wifi_submit(body) {
                        println!(
                            "PORTAL: Received candidate Wi-Fi '{}' (Verify-Before-Save, not written to NVS yet).",
                            creds.ssid
                        );
                        let resp = "{\"ok\":true,\"verifying\":true}";
                        send_http_response(&mut socket, "200 OK", "application/json", resp).await;
                        socket.close();
                        Timer::after(Duration::from_millis(350)).await;
                        return creds;
                    }
                    send_http_response(
                        &mut socket,
                        "400 Bad Request",
                        "application/json",
                        "{\"ok\":false,\"error\":\"Érvénytelen SSID vagy jelszó\"}",
                    )
                    .await;
                }
                ("POST", "/connect-saved") | ("POST", "/api/connect-saved") => {
                    let has_saved_wifi = nvs_read_with(|nvs| nvs.wifi.is_some()).await;
                    if has_saved_wifi {
                        println!(
                            "PORTAL: Immediate connect to saved Wi-Fi requested; expiring AP countdown."
                        );
                        *last_wifi_error = false;
                        send_http_response(
                            &mut socket,
                            "200 OK",
                            "application/json",
                            "{\"ok\":true,\"connecting\":true}",
                        )
                        .await;
                        socket.close();
                        Timer::after(Duration::from_millis(350)).await;
                        *ap_deadline.lock().await = Some(Instant::now());
                        continue;
                    }
                    send_http_response(
                        &mut socket,
                        "400 Bad Request",
                        "application/json",
                        "{\"ok\":false,\"error\":\"Nincs mentett Wi-Fi hálózat\"}",
                    )
                    .await;
                }
                ("POST", "/clear-wifi") => {
                    let cur_cfg = {
                        let state = DEVICE_STATE.lock().await;
                        state.to_config()
                    };
                    let _ = nvs_update(|nvs| {
                        nvs.config = cur_cfg;
                        nvs.wifi = None;
                        true
                    })
                    .await;
                    *last_wifi_error = false;
                    {
                        let mut dl = ap_deadline.lock().await;
                        *dl = None;
                    }
                    println!("PORTAL: Saved Wi-Fi cleared from NVS; switched AP to limitless mode.");
                    send_http_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        "{\"ok\":true,\"limitless\":true,\"remaining_secs\":null}",
                    )
                    .await;
                }
                ("POST", "/restart") => {
                    println!("PORTAL: Software reset requested by user.");
                    send_http_response(
                        &mut socket,
                        "200 OK",
                        "application/json",
                        "{\"ok\":true,\"restarting\":true}",
                    )
                    .await;
                    socket.close();
                    Timer::after(Duration::from_millis(300)).await;
                    esp_hal::system::software_reset();
                }
                ("POST", "/toggle-lamp") => {
                    let new_remote = {
                        let mut state = DEVICE_STATE.lock().await;
                        state.remote_lamp_on = !state.remote_lamp_on;
                        state.remote_lamp_on
                    };
                    // Allow 100ms relay_state_machine_task tick to apply P2 transition & safety timer.
                    Timer::after(Duration::from_millis(150)).await;
                    let lamp_is_on = {
                        let state = DEVICE_STATE.lock().await;
                        state.lamp_is_on
                    };
                    let resp = alloc::format!(
                        "{{\"ok\":true,\"lamp_is_on\":{},\"remote_lamp_on\":{}}}",
                        lamp_is_on, new_remote
                    );
                    send_http_response(&mut socket, "200 OK", "application/json", &resp).await;
                }
                ("POST", "/save-config") => {
                    if let Some(new_cfg) = parse_config_submit(body) {
                        let changed = {
                            let mut state = DEVICE_STATE.lock().await;
                            let prev = state.to_config();
                            state.threshold = new_cfg.threshold;
                            state.sensitivity = new_cfg.sensitivity;
                            state.duration = new_cfg.duration;
                            state.safety_off_min = new_cfg.safety_off_min;
                            state.lamp_wattage_w = new_cfg.lamp_wattage_w;
                            prev != new_cfg
                        };
                        if changed {
                            let _ = nvs_update(|nvs| {
                                nvs.config = new_cfg;
                                true
                            })
                            .await;
                            println!(
                                "PORTAL: Config updated and saved to NVS (threshold={}, sensitivity={}, duration={}s, safety_off_min={}m, lamp_wattage_w={}W).",
                                new_cfg.threshold, new_cfg.sensitivity, new_cfg.duration, new_cfg.safety_off_min, new_cfg.lamp_wattage_w
                            );
                        } else {
                            println!("PORTAL: Config unchanged; skipped NVS write.");
                        }
                        let resp = alloc::format!(
                            "{{\"ok\":true,\"saved_to_flash\":{},\"configured\":true}}",
                            changed
                        );
                        send_http_response(&mut socket, "200 OK", "application/json", &resp).await;
                    } else {
                        send_http_response(
                            &mut socket,
                            "400 Bad Request",
                            "application/json",
                            "{\"ok\":false,\"error\":\"Érvénytelen paraméter tartomány\"}",
                        )
                        .await;
                    }
                }
                _ => {
                    let remaining_secs = {
                        let dl_opt = *ap_deadline.lock().await;
                        dl_opt.map(|dl| {
                            let now = Instant::now();
                            if dl > now {
                                dl.duration_since(now).as_secs()
                            } else {
                                0
                            }
                        })
                    };
                    let (cfg, lamp_is_on) = {
                        let state = DEVICE_STATE.lock().await;
                        (state.to_config(), state.lamp_is_on)
                    };
                    let initial_view = if path == "/config" { "config" } else { "main" };
                    send_portal_html_chunked(
                        &mut socket,
                        device_name,
                        &cached_ssids,
                        initial_view,
                        *last_wifi_error,
                        remaining_secs,
                        cfg,
                        lamp_is_on,
                    )
                    .await;
                }
            }
        }
        socket.close();
    }
}

/// Builds a StationConfig from saved credentials.
fn station_config_from_creds(creds: &WifiCredentials) -> Option<Config> {
    let ssid: Ssid = creds.ssid.as_str().try_into().ok()?;
    let auth = if creds.password.is_empty() {
        AuthenticationMethodConfig::Open
    } else {
        AuthenticationMethodConfig::Wpa2Personal(creds.password.as_str().try_into().ok()?)
    };
    Some(Config::Station(
        StationConfig::default()
            .with_ssid(ssid)
            .with_authentication(auth),
    ))
}

/// Builds the dynamic device name `"SmartLight-XXXX"` from the last 2 bytes of the eFuse MAC.
fn build_device_name() -> String {
    let mac = esp_hal::efuse::base_mac_address();
    let bytes = mac.as_bytes();
    alloc::format!("SmartLight-{:02X}{:02X}", bytes[4], bytes[5])
}

/// Builds the full hardware MAC UID string in uppercase hex for cloud pairing (`espUid`).
fn build_esp_uid() -> String {
    let mac = esp_hal::efuse::base_mac_address();
    let bytes = mac.as_bytes();
    alloc::format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

static STA_NET_RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
static NTP_TIME: Mutex<RefCell<Option<NtpSyncState>>> = Mutex::new(RefCell::new(None));

const TLS_RX_BUF_LEN: usize = 16640;
const TLS_TX_BUF_LEN: usize = 16640;
const HTTP_RX_BUF_LEN: usize = 4608;
const NTP_SERVER: &str = "pool.ntp.org";
const NTP_PORT: u16 = 123;
const NTP_TO_UNIX_EPOCH: u64 = 2_208_988_800;
const NTP_RESYNC_INTERVAL_SECS: u64 = 12 * 60 * 60;
const NTP_RETRY_DELAY_SECS: u64 = 10;
const BH1750_ADDR_LOW: u8 = 0x23;
const BH1750_CMD_POWER_ON: u8 = 0x01;
const BH1750_CMD_CONT_HIGH_RES: u8 = 0x10;
const SENSOR_POLL_INTERVAL_SECS: u64 = 1;
const RELAY_TICK_MS: u64 = 100;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum LampOnSource {
    None,
    ManualP2,
    SensorP3,
}

#[derive(Copy, Clone)]
struct DeviceState {
    threshold: u16,
    sensitivity: u8,
    duration: u64,
    safety_off_min: u16,
    lamp_wattage_w: u16,
    remote_lamp_on: bool,
    lamp_is_on: bool,
    lamp_on_source: LampOnSource,
    p2_turned_on_at: Option<Instant>,
    lamp_on_started: Option<Instant>,
    last_movement_ts: Option<Instant>,
    current_lux: u16,
    simulated_pir: bool,
    pir_active: bool,
    pending_energy_sec: u32,
    pending_p1_off: bool,
}

impl DeviceState {
    /// Returns `true` when threshold (1..=100), sensitivity (1..=100), and duration (10..=600)
    /// are valid. `safety_off_min` is allowed to be `0` (disables P1 safety shutoff).
    fn is_configured(&self) -> bool {
        (1..=100).contains(&self.threshold)
            && (1..=100).contains(&self.sensitivity)
            && (10..=600).contains(&self.duration)
            && self.safety_off_min <= 1440
    }

    fn to_config(&self) -> DeviceConfig {
        DeviceConfig {
            threshold: self.threshold,
            sensitivity: self.sensitivity,
            duration: self.duration,
            safety_off_min: self.safety_off_min,
            lamp_wattage_w: self.lamp_wattage_w,
        }
    }
}

static DEVICE_STATE: EmbassyMutex<CriticalSectionRawMutex, DeviceState> =
    EmbassyMutex::new(DeviceState {
        threshold: 0,
        sensitivity: 0,
        duration: 0,
        safety_off_min: 0,
        lamp_wattage_w: 0,
        remote_lamp_on: false,
        lamp_is_on: false,
        lamp_on_source: LampOnSource::None,
        p2_turned_on_at: None,
        lamp_on_started: None,
        last_movement_ts: None,
        current_lux: 0,
        simulated_pir: false,
        pir_active: false,
        pending_energy_sec: 0,
        pending_p1_off: false,
    });

struct AuthState {
    id_token: FixedBuf<MAX_ID_TOKEN_LEN>,
    obtained_at: Option<Instant>,
    force_refresh: bool,
    consecutive_rtdb_auth_errors: u8,
}

impl AuthState {
    const fn new() -> Self {
        Self {
            id_token: FixedBuf::new(),
            obtained_at: None,
            force_refresh: false,
            consecutive_rtdb_auth_errors: 0,
        }
    }
}

static AUTH_STATE: EmbassyMutex<CriticalSectionRawMutex, AuthState> =
    EmbassyMutex::new(AuthState::new());
static AUTH_WAKE_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SSE_WAKE_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static REPORTER_STATE_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

static TLS_SEED_NONCE: AtomicU32 = AtomicU32::new(1);

fn next_tls_seed(base: u64) -> u64 {
    let n = TLS_SEED_NONCE.fetch_add(1, Ordering::Relaxed) as u64;
    base ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum HttpsExtraHeader {
    None,
    EspAuthToken,
    FormUrlEncoded,
}

struct HttpsJob {
    method: Method,
    extra_header: HttpsExtraHeader,
    json_content_type: bool,
    has_body: bool,
    timeout_ms: u32,
    status: u16,
    resp_len: usize,
    err: Option<&'static str>,
}

impl HttpsJob {
    const fn new() -> Self {
        Self {
            method: Method::GET,
            extra_header: HttpsExtraHeader::None,
            json_content_type: false,
            has_body: false,
            timeout_ms: 20_000,
            status: 0,
            resp_len: 0,
            err: None,
        }
    }
}

struct HttpsScratch {
    tcp_state: TcpClientState<1, 1536, 1536>,
    tls_rx: [u8; TLS_RX_BUF_LEN],
    tls_tx: [u8; TLS_TX_BUF_LEN],
    http_rx: [u8; HTTP_RX_BUF_LEN],
    url_buf: FixedBuf<1792>,
    req_buf: FixedBuf<1280>,
    job: HttpsJob,
}

impl HttpsScratch {
    const fn new() -> Self {
        Self {
            tcp_state: TcpClientState::new(),
            tls_rx: [0u8; TLS_RX_BUF_LEN],
            tls_tx: [0u8; TLS_TX_BUF_LEN],
            http_rx: [0u8; HTTP_RX_BUF_LEN],
            url_buf: FixedBuf::new(),
            req_buf: FixedBuf::new(),
            job: HttpsJob::new(),
        }
    }
}

static HTTPS_CALL_LOCK: EmbassyMutex<CriticalSectionRawMutex, ()> = EmbassyMutex::new(());
static HTTPS_GO_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static HTTPS_DONE_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static HTTPS_SCRATCH: EmbassyMutex<CriticalSectionRawMutex, HttpsScratch> =
    EmbassyMutex::new(HttpsScratch::new());

struct SseScratch {
    tcp_state: TcpClientState<1, 1536, 1024>,
    tls_rx: [u8; TLS_RX_BUF_LEN],
    tls_tx: [u8; 2048],
    http_rx: [u8; 1024],
    line_buf: [u8; 768],
    chunk_buf: [u8; 512],
    data_buf: FixedBuf<768>,
    url_buf: FixedBuf<1792>,
}

impl SseScratch {
    const fn new() -> Self {
        Self {
            tcp_state: TcpClientState::new(),
            tls_rx: [0u8; TLS_RX_BUF_LEN],
            tls_tx: [0u8; 2048],
            http_rx: [0u8; 1024],
            line_buf: [0u8; 768],
            chunk_buf: [0u8; 512],
            data_buf: FixedBuf::new(),
            url_buf: FixedBuf::new(),
        }
    }
}

static SSE_SCRATCH: EmbassyMutex<CriticalSectionRawMutex, SseScratch> =
    EmbassyMutex::new(SseScratch::new());

#[derive(Copy, Clone)]
struct NtpSyncState {
    unix_secs: u64,
    synced_at: Instant,
}

fn set_synced_unix_time(unix_secs: u64) {
    let synced_at = Instant::now();
    critical_section::with(|cs| {
        *NTP_TIME.borrow_ref_mut(cs) = Some(NtpSyncState {
            unix_secs,
            synced_at,
        });
    });
}

/// Returns the current UNIX timestamp in seconds by adding monotonic elapsed time since the
/// last NTP sync, or `None` if NTP has not synchronized yet.
#[allow(dead_code)]
fn current_unix_timestamp() -> Option<u64> {
    critical_section::with(|cs| {
        NTP_TIME.borrow_ref(cs).map(|state| {
            state
                .unix_secs
                .saturating_add(state.synced_at.elapsed().as_secs())
        })
    })
}

/// Single dedicated HTTPS worker task holding the `HttpClient::new_with_tls` async state machine
/// so caller tasks (`auth_task`, `rtdb_state_reporter_task`, `rtdb_sse_listener_task`) keep tiny `.bss` pools.
#[embassy_executor::task]
async fn https_worker_task(stack: Stack<'static>, seed: u64) -> ! {
    loop {
        HTTPS_GO_SIGNAL.wait().await;
        {
            let mut scratch = HTTPS_SCRATCH.lock().await;
            let HttpsScratch {
                tcp_state,
                tls_rx,
                tls_tx,
                http_rx,
                url_buf,
                req_buf,
                job,
            } = &mut *scratch;

            let fut = async {
                let tcp_client = TcpClient::new(stack, tcp_state);
                let dns_socket = DnsSocket::new(stack);
                let tls_config =
                    TlsConfig::new(next_tls_seed(seed), tls_rx, tls_tx, TlsVerify::None);
                let mut client = HttpClient::new_with_tls(&tcp_client, &dns_socket, tls_config);

                let mut req = client
                    .request(job.method, url_buf.as_str())
                    .await
                    .map_err(|_| "HTTP request init failed")?;

                let esp_hdr = [("X-Esp-Auth-Token", ESP_AUTH_TOKEN)];
                let form_hdr = [("Content-Type", "application/x-www-form-urlencoded")];
                match job.extra_header {
                    HttpsExtraHeader::None => {}
                    HttpsExtraHeader::EspAuthToken => req = req.headers(&esp_hdr),
                    HttpsExtraHeader::FormUrlEncoded => req = req.headers(&form_hdr),
                }
                if job.json_content_type {
                    req = req.content_type(ContentType::ApplicationJson);
                }

                if job.has_body {
                    let mut req = req.body(req_buf.as_bytes());
                    let resp = req
                        .send(http_rx)
                        .await
                        .map_err(|_| "HTTPS send failed")?;
                    let status = resp.status.0;
                    let resp_len = resp
                        .body()
                        .read_to_end()
                        .await
                        .map_err(|_| "HTTPS body read failed")?
                        .len();
                    Ok((status, resp_len))
                } else {
                    let resp = req
                        .send(http_rx)
                        .await
                        .map_err(|_| "HTTPS send failed")?;
                    let status = resp.status.0;
                    let resp_len = resp
                        .body()
                        .read_to_end()
                        .await
                        .map_err(|_| "HTTPS body read failed")?
                        .len();
                    Ok((status, resp_len))
                }
            };

            let timeout = Duration::from_millis(if job.timeout_ms > 0 {
                job.timeout_ms as u64
            } else {
                20_000
            });
            match with_timeout(timeout, fut).await {
                Ok(Ok((status, len))) => {
                    job.status = status;
                    job.resp_len = len;
                    job.err = None;
                }
                Ok(Err(e)) => {
                    job.status = 0;
                    job.resp_len = 0;
                    job.err = Some(e);
                }
                Err(_) => {
                    job.status = 0;
                    job.resp_len = 0;
                    job.err = Some("HTTPS request timed out");
                }
            }
        }
        HTTPS_DONE_SIGNAL.signal(());
    }
}

/// Dispatches a prepared request in `HTTPS_SCRATCH` to `https_worker_task` (caller holds `HTTPS_CALL_LOCK`).
async fn dispatch_https_job<R>(parse: impl FnOnce(u16, &[u8]) -> R) -> Result<R, &'static str> {
    HTTPS_DONE_SIGNAL.reset();
    HTTPS_GO_SIGNAL.signal(());
    HTTPS_DONE_SIGNAL.wait().await;
    let scratch = HTTPS_SCRATCH.lock().await;
    if let Some(e) = scratch.job.err {
        Err(e)
    } else {
        Ok(parse(
            scratch.job.status,
            &scratch.http_rx[..scratch.job.resp_len],
        ))
    }
}

async fn has_auth_id_token() -> bool {
    let auth = AUTH_STATE.lock().await;
    !auth.id_token.is_empty()
}

async fn set_auth_id_token(token: &str) -> bool {
    let mut auth = AUTH_STATE.lock().await;
    auth.id_token.clear();
    if !auth.id_token.push_bytes(token.as_bytes()) {
        auth.obtained_at = None;
        return false;
    }
    auth.obtained_at = Some(Instant::now());
    auth.force_refresh = false;
    true
}

async fn clear_auth_id_token() {
    let mut auth = AUTH_STATE.lock().await;
    auth.id_token.clear();
    auth.obtained_at = None;
}

async fn mark_rtdb_ok() {
    let mut auth = AUTH_STATE.lock().await;
    auth.consecutive_rtdb_auth_errors = 0;
}

async fn mark_rtdb_auth_error() {
    let mut auth = AUTH_STATE.lock().await;
    auth.id_token.clear();
    auth.obtained_at = None;
    auth.force_refresh = true;
    auth.consecutive_rtdb_auth_errors = auth.consecutive_rtdb_auth_errors.saturating_add(1);
}

#[derive(Deserialize)]
struct VerifyPairingResp {
    #[serde(rename = "customToken")]
    custom_token: Option<String>,
}

#[derive(Deserialize)]
struct CustomTokenExchangeResp {
    #[serde(rename = "idToken")]
    id_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct RefreshTokenResp {
    id_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct FirebaseErrDetail {
    message: Option<String>,
}

#[derive(Deserialize)]
struct FirebaseErrResp {
    error: Option<FirebaseErrDetail>,
}

fn is_revoked_refresh_error(msg: &str) -> bool {
    msg.contains("USER_NOT_FOUND")
        || msg.contains("INVALID_REFRESH_TOKEN")
        || msg.contains("TOKEN_EXPIRED")
        || msg.contains("USER_DISABLED")
}

/// Clears runtime `id_token` and NVS `refresh_token` while preserving Wi-Fi credentials and
/// sensor/wattage configuration so `auth_task` can re-run Zero-Touch registration.
async fn clear_auth_for_reregistration(reason: &str) {
    println!(
        "AUTH: {} -> clearing refresh_token/id_token for Zero-Touch re-registration.",
        reason
    );
    clear_auth_id_token().await;
    let _ = nvs_update(|nvs| {
        let had_rt = nvs.refresh_token_len > 0 || nvs.refresh_token.iter().any(|&b| b != 0);
        nvs.clear_refresh_token();
        had_rt
    })
    .await;
    {
        let mut auth = AUTH_STATE.lock().await;
        auth.consecutive_rtdb_auth_errors = 0;
        auth.force_refresh = false;
    }
    SSE_WAKE_SIGNAL.signal(());
}

/// Performs a single Zero-Touch registration POST to `VERIFY_PAIRING_URL` with `FACTORY_PASSKEY`
/// and returns the Firebase `customToken` on HTTP 200.
async fn register_device_once(
    stack: Stack<'static>,
    device_id: &str,
    esp_uid: &str,
) -> Option<String> {
    if !stack.is_config_up() {
        stack.wait_config_up().await;
    }

    println!(
        "AUTH: Sending Zero-Touch registration POST to {}",
        VERIFY_PAIRING_URL
    );
    let res = {
        let _call = HTTPS_CALL_LOCK.lock().await;
        {
            let mut scratch = HTTPS_SCRATCH.lock().await;
            scratch.url_buf.clear();
            let _ = scratch.url_buf.write_str(VERIFY_PAIRING_URL);
            scratch.req_buf.clear();
            let _ = write!(
                scratch.req_buf,
                r#"{{"deviceId":"{}","espUid":"{}","passkey":"{}","pin":"{}"}}"#,
                device_id, esp_uid, FACTORY_PASSKEY, FACTORY_PASSKEY
            );
            scratch.job = HttpsJob {
                method: Method::POST,
                extra_header: HttpsExtraHeader::EspAuthToken,
                json_content_type: true,
                has_body: true,
                ..HttpsJob::new()
            };
        }
        dispatch_https_job(|status, body| {
            let token = if status == 200 {
                serde_json::from_slice::<VerifyPairingResp>(body)
                    .ok()
                    .and_then(|r| r.custom_token)
            } else {
                None
            };
            (status, token)
        })
        .await
    };

    match res {
        Ok((200, Some(ct))) if !ct.is_empty() => {
            println!(
                "AUTH: Zero-Touch registration succeeded (HTTP 200) for {}; received customToken.",
                device_id
            );
            Some(ct)
        }
        Ok((200, _)) => {
            println!("AUTH: verifyPairing returned HTTP 200 without customToken.");
            None
        }
        Ok((code, _)) => {
            println!("AUTH: verifyPairing returned HTTP {}.", code);
            None
        }
        Err(e) => {
            println!("AUTH: verifyPairing request failed: {}", e);
            None
        }
    }
}

/// Exchanges a Firebase `customToken` for an `idToken` (RAM) and `refreshToken` (SLN3 NVS).
async fn exchange_custom_token(custom_token: &str) -> bool {
    let res = {
        let _call = HTTPS_CALL_LOCK.lock().await;
        let prep_ok = {
            let mut scratch = HTTPS_SCRATCH.lock().await;
            scratch.url_buf.clear();
            let _ = write!(
                scratch.url_buf,
                "{}{}",
                AUTH_CUSTOM_TOKEN_URL_BASE, FIREBASE_WEB_API_KEY
            );
            scratch.req_buf.clear();
            let ok = write!(
                scratch.req_buf,
                r#"{{"token":"{}","returnSecureToken":true}}"#,
                custom_token
            )
            .is_ok();
            scratch.job = HttpsJob {
                method: Method::POST,
                extra_header: HttpsExtraHeader::None,
                json_content_type: true,
                has_body: true,
                ..HttpsJob::new()
            };
            ok
        };
        if !prep_ok {
            Err("Custom token request overflow")
        } else {
            dispatch_https_job(|status, resp_body| {
                let parsed = if status == 200 {
                    serde_json::from_slice::<CustomTokenExchangeResp>(resp_body).ok()
                } else {
                    None
                };
                (status, parsed)
            })
            .await
        }
    };

    match res {
        Ok((200, Some(resp))) => {
            if let (Some(id_tok), Some(ref_tok)) = (resp.id_token, resp.refresh_token)
                && !id_tok.is_empty()
                && !ref_tok.is_empty()
            {
                let saved = nvs_update(|nvs| {
                    let ok = nvs.set_refresh_token(&ref_tok);
                    if !ok {
                        println!(
                            "AUTH: refreshToken length ({}) exceeds 320B NVS slot!",
                            ref_tok.len()
                        );
                    }
                    ok
                })
                .await
                .unwrap_or(false);
                if saved && set_auth_id_token(&id_tok).await {
                    let mut auth = AUTH_STATE.lock().await;
                    auth.consecutive_rtdb_auth_errors = 0;
                    drop(auth);
                    println!("AUTH: Exchanged customToken -> idToken in RAM + refreshToken saved to SLN3 NVS.");
                    SSE_WAKE_SIGNAL.signal(());
                    REPORTER_STATE_SIGNAL.signal(());
                    return true;
                }
            }
            println!("AUTH: signInWithCustomToken missing/oversized tokens.");
            false
        }
        Ok((status, _)) => {
            println!("AUTH: signInWithCustomToken failed with HTTP {}", status);
            false
        }
        Err(e) => {
            println!("AUTH: signInWithCustomToken error: {}", e);
            false
        }
    }
}

enum RefreshOutcome {
    Ok,
    Revoked,
    TransientError,
}

/// Exchanges the NVS `refresh_token` for a fresh `id_token` (and updates rotated `refresh_token`).
async fn refresh_id_token_via_nvs() -> RefreshOutcome {
    let res = {
        let _call = HTTPS_CALL_LOCK.lock().await;
        let has_rt = {
            let mut scratch = HTTPS_SCRATCH.lock().await;
            scratch.url_buf.clear();
            let _ = write!(
                scratch.url_buf,
                "{}{}",
                AUTH_REFRESH_TOKEN_URL_BASE, FIREBASE_WEB_API_KEY
            );
            scratch.req_buf.clear();
            let ok = nvs_read_with(|nvs| {
                if let Some(rt) = nvs.refresh_token_str() {
                    write!(scratch.req_buf, "grant_type=refresh_token&refresh_token={}", rt).is_ok()
                } else {
                    false
                }
            })
            .await;
            scratch.job = HttpsJob {
                method: Method::POST,
                extra_header: HttpsExtraHeader::FormUrlEncoded,
                json_content_type: false,
                has_body: true,
                ..HttpsJob::new()
            };
            ok
        };

        if !has_rt {
            return RefreshOutcome::Revoked;
        }

        dispatch_https_job(|status, resp_body| {
            let parsed = if status == 200 {
                serde_json::from_slice::<RefreshTokenResp>(resp_body).ok()
            } else {
                None
            };
            let err_msg = if status == 400 || status == 401 || status == 403 {
                serde_json::from_slice::<FirebaseErrResp>(resp_body)
                    .ok()
                    .and_then(|e| e.error)
                    .and_then(|d| d.message)
                    .or_else(|| {
                        core::str::from_utf8(resp_body)
                            .ok()
                            .map(|s| s.chars().take(160).collect())
                    })
            } else {
                None
            };
            (status, parsed, err_msg)
        })
        .await
    };

    match res {
        Ok((200, Some(resp), _)) => {
            if let Some(id_tok) = resp.id_token
                && !id_tok.is_empty()
            {
                let still_paired = nvs_read_with(|nvs| nvs.refresh_token_len > 0).await;
                if !still_paired {
                    println!("AUTH: Unpaired while refresh was in flight; discarding refreshed token.");
                    return RefreshOutcome::Revoked;
                }
                if let Some(new_rt) = resp.refresh_token
                    && !new_rt.is_empty()
                {
                    let _ = nvs_update(|nvs| {
                        if nvs.refresh_token_len > 0
                            && nvs.refresh_token_str() != Some(new_rt.as_str())
                        {
                            nvs.set_refresh_token(&new_rt)
                        } else {
                            false
                        }
                    })
                    .await;
                }
                if set_auth_id_token(&id_tok).await {
                    println!("AUTH: Refreshed id_token in RAM (valid 45m refresh cycle).");
                    SSE_WAKE_SIGNAL.signal(());
                    REPORTER_STATE_SIGNAL.signal(());
                    return RefreshOutcome::Ok;
                }
            }
            RefreshOutcome::TransientError
        }
        Ok((400, _, err_opt)) => {
            let msg = err_opt.as_deref().unwrap_or("");
            if is_revoked_refresh_error(msg) {
                println!(
                    "AUTH: securetoken rejected refresh_token (HTTP 400: {}); clearing SLN3 refresh_token.",
                    msg
                );
                RefreshOutcome::Revoked
            } else {
                println!(
                    "AUTH: securetoken returned HTTP 400 ({}); retrying...",
                    msg
                );
                RefreshOutcome::TransientError
            }
        }
        Ok((code @ (401 | 403), _, err_opt)) => {
            println!(
                "AUTH: Refresh token rejected/revoked (HTTP {}: {}); clearing SLN3 refresh_token.",
                code,
                err_opt.as_deref().unwrap_or("")
            );
            RefreshOutcome::Revoked
        }
        Ok((status, _, _)) => {
            println!("AUTH: securetoken returned HTTP {}", status);
            RefreshOutcome::TransientError
        }
        Err(e) => {
            println!("AUTH: securetoken request failed: {}", e);
            RefreshOutcome::TransientError
        }
    }
}

/// Manages Zero-Touch registration (`verifyPairing`), Custom Token exchange, and 45-min `id_token` refresh lifecycle.
#[embassy_executor::task]
async fn auth_task(stack: Stack<'static>) -> ! {
    stack.wait_config_up().await;

    let device_id = build_device_name();
    let esp_uid = build_esp_uid();
    let mut backoff_secs: u64 = 5;
    let reg_backoff_steps = [5u64, 15, 30, 60];
    let mut reg_backoff_idx: usize = 0;

    loop {
        if !stack.is_config_up() {
            clear_auth_id_token().await;
            println!("AUTH: Network offline; waiting for Wi-Fi + DHCP recovery...");
            stack.wait_config_up().await;
            let mut auth = AUTH_STATE.lock().await;
            auth.force_refresh = true;
            println!("AUTH: Network restored; triggering immediate id_token refresh.");
        }

        let has_refresh_token = nvs_read_with(|nvs| nvs.refresh_token_len > 0).await;
        if has_refresh_token {
            let (need_refresh, rtdb_errors) = {
                let auth = AUTH_STATE.lock().await;
                let expired = auth.id_token.is_empty()
                    || auth.force_refresh
                    || auth
                        .obtained_at
                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(TOKEN_REFRESH_INTERVAL_SECS));
                (expired, auth.consecutive_rtdb_auth_errors)
            };

            if rtdb_errors >= 2 {
                clear_auth_for_reregistration("Repeated RTDB 401/403 after fresh token").await;
                reg_backoff_idx = 0;
                continue;
            }

            if need_refresh {
                match refresh_id_token_via_nvs().await {
                    RefreshOutcome::Ok => {
                        backoff_secs = 5;
                    }
                    RefreshOutcome::Revoked => {
                        clear_auth_for_reregistration("Refresh token rejected/revoked").await;
                        reg_backoff_idx = 0;
                        continue;
                    }
                    RefreshOutcome::TransientError => {
                        let wait = Duration::from_secs(backoff_secs);
                        backoff_secs = (backoff_secs * 2).min(30);
                        let _ = select(Timer::after(wait), AUTH_WAKE_SIGNAL.wait()).await;
                        continue;
                    }
                }
            }

            // Online & token valid: wake every 2s to check link drop or 45-min renewal, or wake early on signal.
            let _ = select(Timer::after(Duration::from_secs(2)), AUTH_WAKE_SIGNAL.wait()).await;
        } else {
            clear_auth_id_token().await;
            AUTH_WAKE_SIGNAL.reset();
            if let Some(custom_token) =
                register_device_once(stack, &device_id, &esp_uid).await
                && exchange_custom_token(&custom_token).await
            {
                reg_backoff_idx = 0;
                backoff_secs = 5;
            } else {
                let wait = Duration::from_secs(reg_backoff_steps[reg_backoff_idx]);
                if reg_backoff_idx + 1 < reg_backoff_steps.len() {
                    reg_backoff_idx += 1;
                }
                println!(
                    "AUTH: Zero-Touch registration retry in {}s...",
                    wait.as_secs()
                );
                let _ = select(Timer::after(wait), AUTH_WAKE_SIGNAL.wait()).await;
            }
        }
    }
}

struct CmdUpdate {
    lamp: Option<bool>,
    restart: Option<bool>,
    thr: Option<u16>,
    sens: Option<u8>,
    dur: Option<u64>,
    safe: Option<u16>,
    wattage: Option<u16>,
}

fn parse_cmd_update_from_sse(json_str: &str) -> Option<CmdUpdate> {
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let path = val.get("path")?.as_str()?;
    let data = val.get("data")?;
    if data.is_null() {
        return None;
    }

    let mut upd = CmdUpdate {
        lamp: None,
        restart: None,
        thr: None,
        sens: None,
        dur: None,
        safe: None,
        wattage: None,
    };

    let parse_thr = |v: &serde_json::Value| {
        v.as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| (1..=100).contains(n))
    };
    let parse_sens = |v: &serde_json::Value| {
        v.as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .filter(|n| (1..=100).contains(n))
    };
    let parse_dur = |v: &serde_json::Value| v.as_u64().filter(|n| (10..=600).contains(n));
    let parse_safe = |v: &serde_json::Value| {
        v.as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n <= 1440)
    };
    let parse_wattage = |v: &serde_json::Value| {
        v.as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n <= 5000)
    };

    match path {
        "/" => {
            let obj = data.as_object()?;
            upd.lamp = obj.get("lamp").and_then(|v| v.as_bool());
            upd.restart = obj.get("restart").and_then(|v| v.as_bool());
            upd.thr = obj.get("thr").and_then(parse_thr);
            upd.sens = obj.get("sens").and_then(parse_sens);
            upd.dur = obj.get("dur").and_then(parse_dur);
            upd.safe = obj.get("safe").and_then(parse_safe);
            upd.wattage = obj
                .get("wattage")
                .or_else(|| obj.get("lamp_wattage_w"))
                .and_then(parse_wattage);
        }
        "/lamp" => upd.lamp = data.as_bool(),
        "/restart" => upd.restart = data.as_bool(),
        "/thr" => upd.thr = parse_thr(data),
        "/sens" => upd.sens = parse_sens(data),
        "/dur" => upd.dur = parse_dur(data),
        "/safe" => upd.safe = parse_safe(data),
        "/wattage" | "/lamp_wattage_w" => upd.wattage = parse_wattage(data),
        _ => return None,
    }

    Some(upd)
}

enum RestartOutcome {
    NotRequested,
    AuthError,
    Failed,
}

async fn apply_cmd_update(device_id: &str, upd: CmdUpdate) -> RestartOutcome {
    let (new_cfg, wattage_changed) = {
        let mut state = DEVICE_STATE.lock().await;
        if let Some(lamp_on) = upd.lamp {
            if state.remote_lamp_on != lamp_on {
                state.remote_lamp_on = lamp_on;
                println!("SSE: Applied remote lamp command -> {}", lamp_on);
            }
        }
        if let Some(v) = upd.thr {
            state.threshold = v;
        }
        if let Some(v) = upd.sens {
            state.sensitivity = v;
        }
        if let Some(v) = upd.dur {
            state.duration = v;
        }
        if let Some(v) = upd.safe {
            state.safety_off_min = v;
        }
        let mut wattage_changed = false;
        if let Some(v) = upd.wattage
            && state.lamp_wattage_w != v
        {
            state.lamp_wattage_w = v;
            wattage_changed = true;
        }
        (state.to_config(), wattage_changed)
    };

    if wattage_changed {
        REPORTER_STATE_SIGNAL.signal(());
    }

    if upd.thr.is_some()
        || upd.sens.is_some()
        || upd.dur.is_some()
        || upd.safe.is_some()
        || upd.wattage.is_some()
    {
        let saved = nvs_update(|nvs| {
            let mut candidate = nvs.config;
            if let Some(v) = upd.thr {
                candidate.threshold = v;
            }
            if let Some(v) = upd.sens {
                candidate.sensitivity = v;
            }
            if let Some(v) = upd.dur {
                candidate.duration = v;
            }
            if let Some(v) = upd.safe {
                candidate.safety_off_min = v;
            }
            if let Some(v) = upd.wattage {
                candidate.lamp_wattage_w = v;
            }
            if candidate != nvs.config && candidate.is_configured() {
                nvs.config = candidate;
                true
            } else {
                false
            }
        })
        .await
        .unwrap_or(false);

        if saved {
            println!(
                "SSE: Config changed -> saved to SLN3 NVS (thr={}, sens={}, dur={}s, safe={}m, wattage={}W).",
                new_cfg.threshold,
                new_cfg.sensitivity,
                new_cfg.duration,
                new_cfg.safety_off_min,
                new_cfg.lamp_wattage_w
            );
        }
    }

    if upd.restart == Some(true) {
        println!("SSE: Remote restart requested! Clearing cmd/restart=false in RTDB before reboot...");
        let ack_res = {
            let _call = HTTPS_CALL_LOCK.lock().await;
            let has_token = {
                let mut scratch = HTTPS_SCRATCH.lock().await;
                scratch.url_buf.clear();
                let ok = {
                    let auth = AUTH_STATE.lock().await;
                    if auth.id_token.is_empty() {
                        false
                    } else {
                        write!(
                            scratch.url_buf,
                            "https://{}/live/{}/cmd.json?auth={}",
                            RTDB_HOST,
                            device_id,
                            auth.id_token.as_str()
                        )
                        .is_ok()
                    }
                };
                scratch.req_buf.clear();
                let _ = scratch.req_buf.write_str(r#"{"restart":false}"#);
                scratch.job = HttpsJob {
                    method: Method::PATCH,
                    extra_header: HttpsExtraHeader::None,
                    json_content_type: true,
                    has_body: true,
                    timeout_ms: 3_500,
                    ..HttpsJob::new()
                };
                ok
            };
            if has_token {
                dispatch_https_job(|status, _| status).await
            } else {
                Ok(401u16)
            }
        };

        match ack_res {
            Ok(status) if (200..=299).contains(&status) => {
                mark_rtdb_ok().await;
                println!(
                    "RESTART: Cleared cmd/restart=false in RTDB (HTTP {}); rebooting now...",
                    status
                );
                Timer::after(Duration::from_millis(250)).await;
                esp_hal::system::software_reset();
            }
            Ok(status @ (401 | 403)) => {
                println!(
                    "RESTART: Failed to clear cmd/restart=false (HTTP {}); aborting reboot.",
                    status
                );
                return RestartOutcome::AuthError;
            }
            Ok(status) => {
                println!(
                    "RESTART: Failed to clear cmd/restart=false (HTTP {}); aborting reboot.",
                    status
                );
                return RestartOutcome::Failed;
            }
            Err(e) => {
                println!(
                    "RESTART: Failed to clear cmd/restart=false ({}); aborting reboot.",
                    e
                );
                return RestartOutcome::Failed;
            }
        }
    }

    RestartOutcome::NotRequested
}

/// Listens to `/live/<deviceId>/cmd.json` via Firebase RTDB Server-Sent Events (SSE).
#[embassy_executor::task]
async fn rtdb_sse_listener_task(stack: Stack<'static>, seed: u64) -> ! {
    let device_id = build_device_name();
    let backoff_steps = [2u64, 5, 10, 20, 30];
    let mut backoff_idx: usize = 0;

    loop {
        if !stack.is_config_up() {
            stack.wait_config_up().await;
        }

        SSE_WAKE_SIGNAL.reset();
        if !has_auth_id_token().await {
            let _ = select(
                Timer::after(Duration::from_secs(5)),
                SSE_WAKE_SIGNAL.wait(),
            )
            .await;
            continue;
        }

        enum SseStopReason {
            AuthError,
            TokenRotated,
            Reconnect,
            ApplyRestart,
        }

        let mut pending_restart_upd: Option<CmdUpdate> = None;

        let stop_reason = {
            let mut scratch = SSE_SCRATCH.lock().await;
            let SseScratch {
                tcp_state,
                tls_rx,
                tls_tx,
                http_rx,
                line_buf,
                chunk_buf,
                data_buf,
                url_buf,
            } = &mut *scratch;

            url_buf.clear();
            let has_url = {
                let auth = AUTH_STATE.lock().await;
                if auth.id_token.is_empty() {
                    false
                } else {
                    write!(
                        url_buf,
                        "https://{}/live/{}/cmd.json?auth={}",
                        RTDB_HOST,
                        device_id,
                        auth.id_token.as_str()
                    )
                    .is_ok()
                }
            };
            if !has_url {
                SseStopReason::TokenRotated
            } else {
                let tcp_client = TcpClient::new(stack, tcp_state);
                let dns_socket = DnsSocket::new(stack);
                let tls_config =
                    TlsConfig::new(next_tls_seed(seed), tls_rx, tls_tx, TlsVerify::None);
                let mut client = HttpClient::new_with_tls(&tcp_client, &dns_socket, tls_config);

                let sse_headers = [("Accept", "text/event-stream"), ("Connection", "keep-alive")];
                let req_res = with_timeout(
                    Duration::from_secs(20),
                    client.request(Method::GET, url_buf.as_str()),
                )
                .await;

                match req_res {
                    Ok(Ok(req_handle)) => {
                        let mut req = req_handle.headers(&sse_headers);
                        let send_res =
                            with_timeout(Duration::from_secs(20), req.send(http_rx)).await;
                        match send_res {
                            Ok(Ok(resp)) => {
                                let status = resp.status.0;
                                if status == 401 || status == 403 {
                                    println!("SSE: RTDB rejected connection with HTTP {}", status);
                                    SseStopReason::AuthError
                                } else if status != 200 {
                                    println!("SSE: Unexpected HTTP status {}", status);
                                    SseStopReason::Reconnect
                                } else {
                                    println!("SSE: Connected to /live/{}/cmd.json", device_id);
                                    backoff_idx = 0;
                                    mark_rtdb_ok().await;

                                    let mut reader = resp.body().reader();
                                    let mut line_len: usize = 0;
                                    let mut line_overflow = false;
                                    let mut current_event = FixedBuf::<32>::new();
                                    data_buf.clear();

                                    loop {
                                        let read_sel = select(
                                            with_timeout(
                                                Duration::from_secs(SSE_READ_TIMEOUT_SECS),
                                                reader.read(chunk_buf),
                                            ),
                                            SSE_WAKE_SIGNAL.wait(),
                                        )
                                        .await;

                                        let n = match read_sel {
                                            Either::Second(()) => {
                                                println!("SSE: Woken for token update; reconnecting cleanly.");
                                                break SseStopReason::TokenRotated;
                                            }
                                            Either::First(Err(_)) => {
                                                println!("SSE: Stream read timed out; reconnecting...");
                                                break SseStopReason::Reconnect;
                                            }
                                            Either::First(Ok(Err(_))) => {
                                                println!("SSE: Stream read error; reconnecting...");
                                                break SseStopReason::Reconnect;
                                            }
                                            Either::First(Ok(Ok(0))) => {
                                                println!("SSE: Stream closed by server; reconnecting...");
                                                break SseStopReason::Reconnect;
                                            }
                                            Either::First(Ok(Ok(n))) => n,
                                        };

                                        let mut frame_action: Option<SseStopReason> = None;

                                        for &b in &chunk_buf[..n] {
                                            if b == b'\r' {
                                                continue;
                                            }
                                            if b == b'\n' {
                                                if line_overflow {
                                                    line_len = 0;
                                                    line_overflow = false;
                                                    current_event.clear();
                                                    data_buf.clear();
                                                    continue;
                                                }

                                                let line =
                                                    core::str::from_utf8(&line_buf[..line_len])
                                                        .unwrap_or("");
                                                line_len = 0;

                                                if line.is_empty() {
                                                    let ev = current_event.as_str();
                                                    if ev == "auth_revoked" || ev == "cancel" {
                                                        println!("SSE: Received '{}' event; refreshing auth token.", ev);
                                                        frame_action = Some(SseStopReason::AuthError);
                                                        break;
                                                    } else if (ev == "put" || ev == "patch")
                                                        && !data_buf.is_empty()
                                                    {
                                                        if let Some(upd) =
                                                            parse_cmd_update_from_sse(
                                                                data_buf.as_str(),
                                                            )
                                                        {
                                                            if upd.restart == Some(true) {
                                                                pending_restart_upd = Some(upd);
                                                                frame_action = Some(
                                                                    SseStopReason::ApplyRestart,
                                                                );
                                                                break;
                                                            } else {
                                                                let _ = apply_cmd_update(&device_id, upd)
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                    current_event.clear();
                                                    data_buf.clear();
                                                } else if let Some(ev) = line.strip_prefix("event:") {
                                                    current_event.clear();
                                                    let _ = write!(current_event, "{}", ev.trim());
                                                } else if let Some(d) = line.strip_prefix("data:") {
                                                    let payload = d.strip_prefix(' ').unwrap_or(d);
                                                    if !data_buf.is_empty() {
                                                        let _ = data_buf.push_bytes(b"\n");
                                                    }
                                                    let _ = data_buf.push_bytes(payload.as_bytes());
                                                }
                                            } else if !line_overflow {
                                                if line_len < line_buf.len() {
                                                    line_buf[line_len] = b;
                                                    line_len += 1;
                                                } else {
                                                    line_overflow = true;
                                                }
                                            }
                                        }

                                        if let Some(action) = frame_action {
                                            break action;
                                        }
                                    }
                                }
                            }
                            Ok(Err(_)) => {
                                println!("SSE: HTTP send failed; reconnecting...");
                                SseStopReason::Reconnect
                            }
                            Err(_) => {
                                println!("SSE: HTTP send timed out; reconnecting...");
                                SseStopReason::Reconnect
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        println!("SSE: TCP/TLS connect failed; reconnecting...");
                        SseStopReason::Reconnect
                    }
                    Err(_) => {
                        println!("SSE: Connect/handshake timed out; reconnecting...");
                        SseStopReason::Reconnect
                    }
                }
            }
        };

        // SSE_SCRATCH & TLS socket are cleanly dropped/closed here before any restart PATCH or backoff.
        match stop_reason {
            SseStopReason::ApplyRestart => {
                if let Some(upd) = pending_restart_upd.take() {
                    match apply_cmd_update(&device_id, upd).await {
                        RestartOutcome::AuthError => {
                            mark_rtdb_auth_error().await;
                            AUTH_WAKE_SIGNAL.signal(());
                            let _ = select(
                                Timer::after(Duration::from_secs(5)),
                                SSE_WAKE_SIGNAL.wait(),
                            )
                            .await;
                        }
                        RestartOutcome::Failed => {
                            let delay = backoff_steps[backoff_idx];
                            if backoff_idx + 1 < backoff_steps.len() {
                                backoff_idx += 1;
                            }
                            let _ = select(
                                Timer::after(Duration::from_secs(delay)),
                                SSE_WAKE_SIGNAL.wait(),
                            )
                            .await;
                        }
                        RestartOutcome::NotRequested => {}
                    }
                }
            }
            SseStopReason::TokenRotated => {
                continue;
            }
            SseStopReason::AuthError => {
                mark_rtdb_auth_error().await;
                AUTH_WAKE_SIGNAL.signal(());
                let _ = select(
                    Timer::after(Duration::from_secs(5)),
                    SSE_WAKE_SIGNAL.wait(),
                )
                .await;
            }
            SseStopReason::Reconnect => {
                let delay = backoff_steps[backoff_idx];
                if backoff_idx + 1 < backoff_steps.len() {
                    backoff_idx += 1;
                }
                let _ = select(
                    Timer::after(Duration::from_secs(delay)),
                    SSE_WAKE_SIGNAL.wait(),
                )
                .await;
            }
        }
    }
}

/// Reports device state & energy delta (`PATCH /live/<deviceId>/state.json`) on state changes or 20s heartbeat.
#[embassy_executor::task]
async fn rtdb_state_reporter_task(stack: Stack<'static>) -> ! {
    let device_id = build_device_name();

    loop {
        if !stack.is_config_up() {
            stack.wait_config_up().await;
        }

        if !has_auth_id_token().await {
            let _ = select(
                Timer::after(Duration::from_secs(5)),
                REPORTER_STATE_SIGNAL.wait(),
            )
            .await;
            continue;
        }

        let (lamp_on, auto_on, lux, mot, energy_delta, p1_off, wattage) = {
            let state = DEVICE_STATE.lock().await;
            (
                state.lamp_is_on,
                state.lamp_on_source == LampOnSource::SensorP3,
                state.current_lux,
                state.pir_active,
                state.pending_energy_sec.min(86400),
                state.pending_p1_off,
                state.lamp_wattage_w.min(5000),
            )
        };

        let patch_res = {
            let _call = HTTPS_CALL_LOCK.lock().await;
            let has_url = {
                let mut scratch = HTTPS_SCRATCH.lock().await;
                scratch.url_buf.clear();
                let ok = {
                    let auth = AUTH_STATE.lock().await;
                    if auth.id_token.is_empty() {
                        false
                    } else {
                        write!(
                            scratch.url_buf,
                            "https://{}/live/{}/state.json?auth={}",
                            RTDB_HOST,
                            device_id,
                            auth.id_token.as_str()
                        )
                        .is_ok()
                    }
                };
                scratch.req_buf.clear();
                let _ = write!(
                    scratch.req_buf,
                    r#"{{"on":{},"auto":{},"lux":{},"mot":{},"ts":{{".sv":"timestamp"}},"energy_delta_sec":{},"p1_off":{},"wattage":{}}}"#,
                    lamp_on, auto_on, lux, mot, energy_delta, p1_off, wattage
                );
                scratch.job = HttpsJob {
                    method: Method::PATCH,
                    extra_header: HttpsExtraHeader::None,
                    json_content_type: true,
                    has_body: true,
                    ..HttpsJob::new()
                };
                ok
            };
            if !has_url {
                Ok(401u16)
            } else {
                dispatch_https_job(|status, _| status).await
            }
        };

        match patch_res {
            Ok(200) => {
                mark_rtdb_ok().await;
                let mut remaining_energy = false;
                {
                    let mut state = DEVICE_STATE.lock().await;
                    state.pending_energy_sec =
                        state.pending_energy_sec.saturating_sub(energy_delta);
                    if p1_off {
                        state.pending_p1_off = false;
                    }
                    if state.pending_energy_sec > 0 {
                        remaining_energy = true;
                    }
                }
                if remaining_energy {
                    REPORTER_STATE_SIGNAL.signal(());
                }
            }
            Ok(code @ (401 | 403)) => {
                println!(
                    "RTDB STATE: Rejected with HTTP {}; triggering token refresh/check.",
                    code
                );
                mark_rtdb_auth_error().await;
                AUTH_WAKE_SIGNAL.signal(());
                Timer::after(Duration::from_secs(2)).await;
                continue;
            }
            Ok(status) => {
                println!("RTDB STATE: PATCH returned HTTP {}", status);
            }
            Err(e) => {
                println!("RTDB STATE: PATCH failed ({}); keeping pending energy/p1_off.", e);
            }
        }

        let _ = select(
            Timer::after(Duration::from_secs(RTDB_HEARTBEAT_INTERVAL_SECS)),
            REPORTER_STATE_SIGNAL.wait(),
        )
        .await;
    }
}

/// Reads ambient light (in lux) from the BH1750 sensor over async I2C and updates `DEVICE_STATE`.
/// When `i2c_opt` is `None`, waits idly until physical I2C pins are wired in a future revision.
#[embassy_executor::task]
async fn sensor_task(i2c_opt: Option<I2c<'static, Async>>) -> ! {
    let Some(mut i2c) = i2c_opt else {
        loop {
            Timer::after(Duration::from_secs(3600)).await;
        }
    };
    let mut initialized = false;

    loop {
        if !initialized {
            let init_ok = i2c
                .write_async(BH1750_ADDR_LOW, &[BH1750_CMD_POWER_ON])
                .await
                .is_ok()
                && i2c
                    .write_async(BH1750_ADDR_LOW, &[BH1750_CMD_CONT_HIGH_RES])
                    .await
                    .is_ok();
            if init_ok {
                initialized = true;
                // BH1750 high-res measurement takes up to 180 ms after mode selection.
                Timer::after(Duration::from_millis(180)).await;
            } else {
                println!("BH1750: I2C init failed; falling back to 0 lux.");
                {
                    let mut state = DEVICE_STATE.lock().await;
                    state.current_lux = 0;
                }
                Timer::after(Duration::from_secs(SENSOR_POLL_INTERVAL_SECS)).await;
                continue;
            }
        }

        let mut buf = [0u8; 2];
        let lux = match i2c.read_async(BH1750_ADDR_LOW, &mut buf).await {
            Ok(()) => {
                let raw = u16::from_be_bytes(buf);
                ((raw as u32 * 10) / 12) as u16
            }
            Err(_) => {
                println!("BH1750: I2C read failed; falling back to 0 lux.");
                initialized = false;
                0
            }
        };

        {
            let mut state = DEVICE_STATE.lock().await;
            state.current_lux = lux;
        }

        Timer::after(Duration::from_secs(SENSOR_POLL_INTERVAL_SECS)).await;
    }
}

/// Deterministically exercises all P1/P2/P3 switching priorities, boot gate, and timers.
#[allow(dead_code)]
#[embassy_executor::task]
async fn simulation_stimulus_task() -> ! {
    // Allow initial startup logs to settle before beginning the verification sequence.
    Timer::after(Duration::from_secs(1)).await;

    // Step 0: Unconfigured Boot Gate Test (threshold == 0 -> relay must stay OFF)
    println!("[SIM STEP 0] Unconfigured Boot Gate Test: threshold=0, lux=10, pir=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.threshold = 0;
        state.sensitivity = 50;
        state.duration = 10;
        state.safety_off_min = 1;
        state.remote_lamp_on = false;
        state.current_lux = 10;
        state.simulated_pir = true;
    }
    Timer::after(Duration::from_secs(1)).await;
    {
        let mut state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 0] FAIL: Relay turned ON while unconfigured"
        );
        state.simulated_pir = false;
    }
    println!("[SIM STEP 0] PASS: Relay stayed OFF while device is unconfigured.");

    // Step 1: Configured + Daylight Motion Blocked (lux >= threshold * 10)
    println!("[SIM STEP 1] Configured + Daylight Motion Blocked: threshold=10 (100 lux), lux=250, pir=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.threshold = 10;
        state.sensitivity = 50;
        state.duration = 10;
        state.safety_off_min = 1;
        state.current_lux = 250;
        state.simulated_pir = true;
    }
    Timer::after(Duration::from_secs(2)).await;
    {
        let mut state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 1] FAIL: Relay turned ON in daylight (lux >= threshold)"
        );
        state.simulated_pir = false;
    }
    println!("[SIM STEP 1] PASS: Relay stayed OFF in daylight.");

    // Step 2: P3 Dark + PIR Motion -> Duration Auto-OFF
    println!("[SIM STEP 2] P3 Dark + PIR Motion -> Duration Auto-OFF: lux=30, pir=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.current_lux = 30;
        state.simulated_pir = true;
    }
    Timer::after(Duration::from_secs(1)).await;
    {
        let mut state = DEVICE_STATE.lock().await;
        assert!(
            state.lamp_is_on && state.lamp_on_source == LampOnSource::SensorP3,
            "[SIM STEP 2] FAIL: P3 did not turn relay ON in dark with PIR motion"
        );
        state.simulated_pir = false;
    }
    println!("[SIM STEP 2] Relay ON (SensorP3); PIR cleared, waiting 5s for duration=4s auto-OFF...");
    Timer::after(Duration::from_secs(5)).await;
    {
        let state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 2] FAIL: P3 did not turn relay OFF after duration elapsed"
        );
    }
    println!("[SIM STEP 2] PASS: P3 turned relay OFF automatically after duration.");

    // Step 3: P2 Manual Lamp ON Overrides Daylight & Duration
    println!("[SIM STEP 3] P2 Manual Lamp ON Overrides Daylight & Duration: lux=300, remote_lamp_on=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.current_lux = 300;
        state.simulated_pir = false;
        state.remote_lamp_on = true;
    }
    Timer::after(Duration::from_secs(5)).await;
    {
        let state = DEVICE_STATE.lock().await;
        assert!(
            state.lamp_is_on && state.lamp_on_source == LampOnSource::ManualP2,
            "[SIM STEP 3] FAIL: P2 manual ON did not override daylight/duration"
        );
    }
    println!("[SIM STEP 3] PASS: Relay stayed ON for 5s (> duration=4s) in daylight via P2.");

    // Step 4: P2 Manual Lamp OFF
    println!("[SIM STEP 4] P2 Manual Lamp OFF: remote_lamp_on=false");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.remote_lamp_on = false;
    }
    Timer::after(Duration::from_secs(1)).await;
    {
        let state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 4] FAIL: P2 manual OFF did not turn relay OFF immediately"
        );
    }
    println!("[SIM STEP 4] PASS: Relay turned OFF immediately via P2.");

    // Step 5: P2 Manual Lamp ON -> P1 SAFETY_OFF_SEC Forced Shutoff
    println!("[SIM STEP 5] P2 Manual Lamp ON -> P1 SAFETY_OFF_SEC (6s) Forced Shutoff");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.remote_lamp_on = true;
    }
    Timer::after(Duration::from_secs(7)).await;
    {
        let state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on
                && !state.remote_lamp_on
                && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 5] FAIL: P1 SAFETY_OFF_SEC did not force relay OFF and reset remote_lamp_on"
        );
    }
    println!("[SIM STEP 5] PASS: P1 forced relay OFF and reset remote_lamp_on=false.");

    // Step 6: P3 Sensor Recovery After P1 Safety Off
    println!("[SIM STEP 6] P3 Sensor Recovery After P1 Safety Off: lux=25, pir=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.current_lux = 25;
        state.simulated_pir = true;
    }
    Timer::after(Duration::from_secs(1)).await;
    {
        let mut state = DEVICE_STATE.lock().await;
        assert!(
            state.lamp_is_on && state.lamp_on_source == LampOnSource::SensorP3,
            "[SIM STEP 6] FAIL: P3 did not recover after P1 safety off"
        );
        state.simulated_pir = false;
    }
    Timer::after(Duration::from_secs(5)).await;
    {
        let state = DEVICE_STATE.lock().await;
        assert!(
            !state.lamp_is_on && state.lamp_on_source == LampOnSource::None,
            "[SIM STEP 6] FAIL: P3 did not turn OFF after duration in recovery step"
        );
    }
    println!("[SIM STEP 6] PASS: P3 sensor automation recovered and turned OFF after duration.");
    println!("[SIMULATION COMPLETE] All P1/P2/P3 switching scenarios verified!");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}

fn set_relay_output(
    pir_relay_opt: &mut Option<(Input<'static>, Output<'static>)>,
    state: &mut DeviceState,
    on: bool,
    now: Instant,
) {
    let _ = pir_relay_opt;
    let prev_on = state.lamp_is_on;
    state.lamp_is_on = on;
    if !prev_on && on {
        state.lamp_on_started = Some(now);
    } else if prev_on && !on
        && let Some(started) = state.lamp_on_started.take()
    {
        let elapsed_secs = now.duration_since(started).as_secs();
        if elapsed_secs >= 1 {
            state.pending_energy_sec = state
                .pending_energy_sec
                .saturating_add(elapsed_secs.min(u32::MAX as u64) as u32);
        }
    }
}

fn step_relay_state_machine(
    pir_relay_opt: &mut Option<(Input<'static>, Output<'static>)>,
    state: &mut DeviceState,
    prev_pir_active: &mut bool,
    now: Instant,
) {
    let pir_active = if let Some((pir, _)) = pir_relay_opt.as_ref() {
        pir.is_high()
    } else {
        state.simulated_pir
    };
    state.pir_active = pir_active;

    // [P1: Safety Timeout] ONLY applies when the lamp is ON due to P2 (remote_lamp_on == true)
    // and safety_off_min > 0 (safety_off_min == 0 disables P1 shutoff).
    // Evaluated independently of is_configured() so manual switching always works.
    if state.remote_lamp_on
        && state.lamp_on_source == LampOnSource::ManualP2
        && state.safety_off_min > 0
        && let Some(p2_ts) = state.p2_turned_on_at
        && now.duration_since(p2_ts) >= Duration::from_secs((state.safety_off_min as u64) * 60)
    {
        set_relay_output(pir_relay_opt, state, false, now);
        state.remote_lamp_on = false;
        state.p2_turned_on_at = None;
        state.lamp_on_source = LampOnSource::None;
        state.last_movement_ts = None;
        state.pending_p1_off = true;
        println!(
            "[P1 SAFETY OFF] Manual lamp ON exceeded {} min -> Forced OFF",
            state.safety_off_min
        );
        *prev_pir_active = pir_active;
        return;
    }

    // [P2: PWA / Captive Portal Manual Switch]
    // Evaluated independently of is_configured() so clicking "Lámpa BE/KI" always works.
    if state.remote_lamp_on {
        if !state.lamp_is_on || state.lamp_on_source != LampOnSource::ManualP2 {
            set_relay_output(pir_relay_opt, state, true, now);
            state.lamp_on_source = LampOnSource::ManualP2;
            state.p2_turned_on_at = Some(now);
            println!("[P2 MANUAL ON] Lamp turned ON via PWA/Portal switch");
        }
        *prev_pir_active = pir_active;
        return;
    } else if state.lamp_on_source == LampOnSource::ManualP2 {
        set_relay_output(pir_relay_opt, state, false, now);
        state.p2_turned_on_at = None;
        state.lamp_on_source = LampOnSource::None;
        state.last_movement_ts = None;
        println!("[P2 MANUAL OFF] Lamp turned OFF via PWA/Portal switch");
        *prev_pir_active = pir_active;
        return;
    }

    // Gate check ONLY for P3 (PIR + BH1750 Lux sensor automation).
    if !state.is_configured() {
        if state.lamp_is_on && state.lamp_on_source == LampOnSource::SensorP3 {
            set_relay_output(pir_relay_opt, state, false, now);
            state.lamp_on_source = LampOnSource::None;
        }
        state.last_movement_ts = None;
        *prev_pir_active = pir_active;
        return;
    }

    // [P3: PIR + BH1750 Lux Automation] (only evaluated when configured && remote_lamp_on == false)
    if pir_active {
        if !state.lamp_is_on {
            let lux_limit = state.threshold.saturating_mul(10);
            if state.current_lux < lux_limit {
                set_relay_output(pir_relay_opt, state, true, now);
                state.lamp_on_source = LampOnSource::SensorP3;
                state.last_movement_ts = Some(now);
                println!(
                    "[P3 SENSOR ON] PIR active & lux ({}) < limit ({}) -> Lamp ON",
                    state.current_lux, lux_limit
                );
            }
        } else if state.lamp_on_source == LampOnSource::SensorP3 {
            state.last_movement_ts = Some(now);
            if !*prev_pir_active {
                println!("[P3 MOTION] PIR active while Lamp ON -> duration timer refreshed");
            }
        }
    } else if state.lamp_is_on
        && state.lamp_on_source == LampOnSource::SensorP3
        && state
            .last_movement_ts
            .is_none_or(|ts| now.duration_since(ts) >= Duration::from_secs(state.duration))
    {
        set_relay_output(pir_relay_opt, state, false, now);
        state.last_movement_ts = None;
        state.lamp_on_source = LampOnSource::None;
        println!(
            "[P3 DURATION OFF] No PIR motion for {}s -> Lamp OFF",
            state.duration
        );
    }

    *prev_pir_active = pir_active;
}

/// Non-blocking 100 ms offline-resilient state machine enforcing P1/P2/P3 relay priorities.
#[embassy_executor::task]
async fn relay_state_machine_task(
    mut pir_relay_opt: Option<(Input<'static>, Output<'static>)>,
) -> ! {
    let mut prev_pir_active = false;

    loop {
        Timer::after(Duration::from_millis(RELAY_TICK_MS)).await;

        let now = Instant::now();
        let should_notify = {
            let mut state = DEVICE_STATE.lock().await;
            let prev_on = state.lamp_is_on;
            let prev_auto = state.lamp_on_source == LampOnSource::SensorP3;
            let prev_energy = state.pending_energy_sec;
            let prev_p1_off = state.pending_p1_off;

            step_relay_state_machine(&mut pir_relay_opt, &mut state, &mut prev_pir_active, now);

            let cur_on = state.lamp_is_on;
            let cur_auto = state.lamp_on_source == LampOnSource::SensorP3;
            let cur_energy = state.pending_energy_sec;
            let cur_p1_off = state.pending_p1_off;

            cur_on != prev_on
                || cur_auto != prev_auto
                || (cur_energy > 0 && cur_energy != prev_energy)
                || (cur_p1_off && !prev_p1_off)
        };

        if should_notify {
            REPORTER_STATE_SIGNAL.signal(());
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface>) -> ! {
    runner.run().await
}

/// Performs a single SNTP query against `pool.ntp.org:123` and returns the UNIX timestamp in seconds.
async fn sync_ntp_once(stack: Stack<'static>) -> Result<u64, &'static str> {
    let addrs = with_timeout(
        Duration::from_secs(10),
        stack.dns_query(NTP_SERVER, DnsQueryType::A),
    )
    .await
    .map_err(|_| "DNS lookup timed out")?
    .map_err(|_| "DNS lookup failed")?;

    let server_ip = addrs.first().copied().ok_or("DNS returned no addresses")?;

    let mut rx_meta = [PacketMetadata::EMPTY; 1];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut rx_buf = [0u8; 64];
    let mut tx_buf = [0u8; 64];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    socket.bind(0).map_err(|_| "UDP bind failed")?;

    let mut req = [0u8; 48];
    req[0] = 0x1B; // LI = 0, VN = 3, Mode = 3 (client)

    let endpoint = IpEndpoint::new(server_ip, NTP_PORT);
    with_timeout(Duration::from_secs(5), socket.send_to(&req, endpoint))
        .await
        .map_err(|_| "UDP send timed out")?
        .map_err(|_| "UDP send failed")?;

    let mut resp = [0u8; 48];
    let (len, _) = with_timeout(Duration::from_secs(5), socket.recv_from(&mut resp))
        .await
        .map_err(|_| "UDP recv timed out")?
        .map_err(|_| "UDP recv failed")?;

    if len < 48 {
        return Err("SNTP response too short");
    }
    if (resp[0] & 0x07) != 4 || resp[1] == 0 {
        return Err("Invalid SNTP server response");
    }

    let ntp_secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]) as u64;
    if ntp_secs < NTP_TO_UNIX_EPOCH {
        return Err("NTP timestamp before UNIX epoch");
    }

    Ok(ntp_secs - NTP_TO_UNIX_EPOCH)
}

/// Synchronizes system time via SNTP on startup and resynchronizes every 12 hours.
#[embassy_executor::task]
async fn ntp_task(stack: Stack<'static>) -> ! {
    loop {
        stack.wait_config_up().await;

        match sync_ntp_once(stack).await {
            Ok(unix_secs) => {
                set_synced_unix_time(unix_secs);
                println!("NTP: synchronized UNIX timestamp = {}", unix_secs);
                Timer::after(Duration::from_secs(NTP_RESYNC_INTERVAL_SECS)).await;
            }
            Err(e) => {
                println!(
                    "NTP: sync failed ({}); retrying in {}s...",
                    e, NTP_RETRY_DELAY_SECS
                );
                Timer::after(Duration::from_secs(NTP_RETRY_DELAY_SECS)).await;
            }
        }
    }
}

/// Attempts to connect as Station and acquire a DHCPv4 IP address within ~15-20s.
/// Returns `true` only if both Wi-Fi association and DHCP IP acquisition succeed.
async fn connect_sta_with_timeout(
    stack: Stack<'static>,
    controller: &mut WifiController<'_>,
    creds: &WifiCredentials,
) -> bool {
    let Some(sta_cfg) = station_config_from_creds(creds) else {
        println!("Invalid Wi-Fi credentials format.");
        return false;
    };

    if controller.set_config(&sta_cfg).is_err() {
        println!("Failed to apply STA config.");
        return false;
    }

    println!("Connecting to Wi-Fi SSID '{}'...", creds.ssid);
    let mut connected = false;
    for attempt in 1..=2 {
        match with_timeout(Duration::from_secs(6), controller.connect_async()).await {
            Ok(Ok(_)) => {
                connected = true;
                break;
            }
            Ok(Err(e)) => println!("Connect attempt {} failed: {:?}", attempt, e),
            Err(_) => println!("Connect attempt {} timed out.", attempt),
        }
        Timer::after(Duration::from_millis(250)).await;
    }

    if !connected {
        let _ = controller.disconnect_async().await;
        return false;
    }

    println!("Wi-Fi associated! Waiting for DHCP lease...");

    if with_timeout(Duration::from_secs(6), stack.wait_config_up())
        .await
        .is_err()
    {
        println!("DHCP timed out.");
        let _ = controller.disconnect_async().await;
        return false;
    }

    if let Some(cfg) = stack.config_v4() {
        println!("Acquired IP address: {}", cfg.address.address());
    }
    true
}

/// Runs periodic gateway ICMP keep-alive pings and auto-reconnects STA if Wi-Fi link drops.
async fn sta_online_keepalive(stack: Stack<'static>, controller: &mut WifiController<'_>) -> ! {
    let mut icmp_rx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_tx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_rx_buf = [0u8; 128];
    let mut icmp_tx_buf = [0u8; 128];

    loop {
        Timer::after(Duration::from_secs(KEEPALIVE_INTERVAL_SECS)).await;

        if !stack.is_link_up() {
            println!("Wi-Fi link down; attempting STA reconnect...");
            let _ = with_timeout(Duration::from_secs(8), controller.connect_async()).await;
            continue;
        }

        let gateway = stack.config_v4().and_then(|cfg| cfg.gateway);
        if let Some(gw) = gateway {
            let mut ping_mgr = PingManager::new(
                stack,
                &mut icmp_rx_meta,
                &mut icmp_rx_buf,
                &mut icmp_tx_meta,
                &mut icmp_tx_buf,
            );
            let mut params = PingParams::new(gw);
            params.set_count(1);
            params.set_timeout(Duration::from_secs(2));
            match ping_mgr.ping(&params).await {
                Ok(rtt) => println!(
                    "Keep-alive: ping reply from {} ({} ms).",
                    gw,
                    rtt.as_millis()
                ),
                Err(e) => println!("Keep-alive: ping to {} failed: {:?}", gw, e),
            }
        }
    }
}

/// Polls until the optional AP deadline expires (or waits forever if `None` / limitless).
async fn wait_ap_deadline(
    ap_deadline: &EmbassyMutex<CriticalSectionRawMutex, Option<Instant>>,
) {
    loop {
        if let Some(dl) = *ap_deadline.lock().await
            && Instant::now() >= dl
        {
            return;
        }
        Timer::after(Duration::from_millis(250)).await;
    }
}

/// Runs WPA2-protected SoftAP + STA scan coex with Scan-Before-Countdown boot check.
async fn run_captive_portal(
    controller: &mut WifiController<'_>,
    device_name: &str,
    seed: u64,
    allow_auto_countdown: bool,
    last_wifi_error: &mut bool,
) -> PortalOutcome {
    let ap_cfg = AccessPointConfig::default()
        .with_ssid(device_name.try_into().expect("valid AP SSID"))
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            FACTORY_PASSKEY.try_into().expect("valid AP password"),
        ));
    controller
        .set_config(&Config::AccessPointStation(
            StationConfig::default(),
            ap_cfg,
        ))
        .expect("Failed to start SoftAP");

    // Perform initial Wi-Fi scan right as AccessPointStation mode starts and cache results.
    let scanned_ssids = scan_nearby_ssids(controller).await;
    println!(
        "Found {} Wi-Fi networks for portal list.",
        scanned_ssids.len()
    );

    let (cfg_is_configured, saved_wifi_ssid) =
        nvs_read_with(|nvs| (nvs.config.is_configured(), nvs.wifi.as_ref().map(|w| w.ssid.clone())))
            .await;
    let saved_ssid_visible = saved_wifi_ssid
        .as_ref()
        .is_some_and(|ssid| scanned_ssids.iter().any(|s| s == ssid));

    let timeout = if allow_auto_countdown
        && !*last_wifi_error
        && cfg_is_configured
        && saved_ssid_visible
    {
        println!(
            "Scan-Before-Countdown: saved SSID '{}' reachable -> starting {}s AP countdown.",
            saved_wifi_ssid.as_deref().unwrap_or(""),
            AP_BOOT_WINDOW_SECS
        );
        Some(Duration::from_secs(AP_BOOT_WINDOW_SECS))
    } else {
        if cfg_is_configured
            && let Some(ref ssid) = saved_wifi_ssid
            && !saved_ssid_visible
        {
            println!(
                "Scan-Before-Countdown: saved SSID '{}' NOT reachable -> limitless AP (no auto-connect).",
                ssid
            );
        } else {
            println!("AP mode: limitless (no auto-countdown).");
        }
        None
    };

    let ap_iface = Interface::access_point();
    let mut resources = StackResources::<6>::new();
    let net_cfg = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(AP_IP, 24),
        gateway: Some(AP_IP),
        dns_servers: Default::default(),
    });
    let (stack, mut runner) = embassy_net::new(ap_iface, net_cfg, &mut resources, seed);

    println!(
        "SoftAP '{}' (WPA2 pass: '{}') active at http://{}/ (timeout: {:?})",
        device_name, FACTORY_PASSKEY, AP_IP, timeout
    );

    let ap_deadline = EmbassyMutex::new(timeout.map(|d| Instant::now() + d));
    let portal_future = select4(
        runner.run(),
        dhcp_server(stack),
        dns_server(stack),
        http_portal_server(
            stack,
            controller,
            device_name,
            scanned_ssids,
            &ap_deadline,
            last_wifi_error,
        ),
    );

    match select(portal_future, wait_ap_deadline(&ap_deadline)).await {
        Either::First(Either4::Fourth(creds)) => PortalOutcome::ConnectWifi(creds),
        _ => PortalOutcome::TimeoutExpired,
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_alloc::heap_allocator!(size: 128 * 1024);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let flash = FlashStorage::new(peripherals.FLASH);
    {
        let mut nvs_state = NVS_FLASH.lock().await;
        nvs_state.flash = Some(flash);
    }
    let (boot_cfg, has_saved_wifi) = nvs_read_with(|d| (d.config, d.wifi.is_some())).await;
    {
        let mut state = DEVICE_STATE.lock().await;
        state.threshold = boot_cfg.threshold;
        state.sensitivity = boot_cfg.sensitivity;
        state.duration = boot_cfg.duration;
        state.safety_off_min = boot_cfg.safety_off_min;
        state.lamp_wattage_w = boot_cfg.lamp_wattage_w;
    }

    // Hardware Safety: do not drive physical relay/sensor GPIO pins yet; only WS2812 mirrors lamp_is_on.
    // simulation_stimulus_task is intentionally not spawned so real Captive Portal & state machine interactions run undisturbed.
    spawner.spawn(led_task(peripherals.RMT, peripherals.GPIO48).expect("led_task spawn"));
    spawner.spawn(sensor_task(None).expect("sensor_task spawn"));
    spawner.spawn(relay_state_machine_task(None).expect("relay_state_machine_task spawn"));

    let rng = Rng::new();
    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);

    let device_name = build_device_name();
    println!("Device identity: {}", device_name);

    let mut controller =
        WifiController::new(peripherals.WIFI, Default::default()).expect("Wi-Fi init failed");

    let sta_resources = STA_NET_RESOURCES.init(StackResources::<8>::new());
    let mut dhcp_cfg = DhcpConfig::default();
    dhcp_cfg.hostname = Some(device_name.as_str().try_into().expect("valid hostname"));
    let (sta_stack, sta_runner) = embassy_net::new(
        Interface::station(),
        embassy_net::Config::dhcpv4(dhcp_cfg),
        sta_resources,
        seed,
    );
    spawner.spawn(net_task(sta_runner).expect("net_task spawn"));
    spawner.spawn(ntp_task(sta_stack).expect("ntp_task spawn"));
    spawner.spawn(https_worker_task(sta_stack, seed).expect("https_worker_task spawn"));
    spawner.spawn(auth_task(sta_stack).expect("auth_task spawn"));
    spawner.spawn(rtdb_sse_listener_task(sta_stack, seed).expect("rtdb_sse_listener_task spawn"));
    spawner.spawn(rtdb_state_reporter_task(sta_stack).expect("rtdb_state_reporter_task spawn"));

    if boot_cfg.is_configured() && has_saved_wifi {
        println!(
            "BOOT Case 3 (Configured + Saved Wi-Fi): Checking saved SSID reachability via initial scan..."
        );
    } else if !boot_cfg.is_configured() {
        println!("BOOT Case 1 (Virgin / Unconfigured): P3 automation inactive (P2 manual active); starting limitless AP.");
    } else {
        println!("BOOT Case 2 (Configured, no Wi-Fi): Automation active; starting limitless AP.");
    }

    let mut allow_auto_countdown = true;
    let mut last_wifi_error = false;

    loop {
        let outcome = run_captive_portal(
            &mut controller,
            &device_name,
            seed,
            allow_auto_countdown,
            &mut last_wifi_error,
        )
        .await;

        match outcome {
            PortalOutcome::ConnectWifi(candidate_creds) => {
                if connect_sta_with_timeout(sta_stack, &mut controller, &candidate_creds).await {
                    let cur_cfg = {
                        let state = DEVICE_STATE.lock().await;
                        state.to_config()
                    };
                    let save_res = nvs_update(|nvs| {
                        nvs.config = cur_cfg;
                        nvs.wifi = Some(candidate_creds);
                        true
                    })
                    .await;
                    if save_res.is_ok() {
                        println!("Verify-Before-Save: Wi-Fi verified and saved to NVS.");
                    } else {
                        println!("Verify-Before-Save: Wi-Fi connected, but NVS write failed.");
                    }
                    sta_online_keepalive(sta_stack, &mut controller).await;
                } else {
                    println!(
                        "Verify-Before-Save: Wi-Fi connection failed; NVS untouched. Returning to limitless AP."
                    );
                    last_wifi_error = true;
                    allow_auto_countdown = false;
                }
            }
            PortalOutcome::TimeoutExpired => {
                let saved_wifi = nvs_read_with(|d| d.wifi.clone()).await;
                if let Some(saved_creds) = saved_wifi {
                    println!(
                        "{}s AP window expired; connecting to saved Wi-Fi...",
                        AP_BOOT_WINDOW_SECS
                    );
                    if connect_sta_with_timeout(sta_stack, &mut controller, &saved_creds).await {
                        sta_online_keepalive(sta_stack, &mut controller).await;
                    } else {
                        println!("Saved Wi-Fi connection failed; falling back to limitless AP.");
                        last_wifi_error = true;
                        allow_auto_countdown = false;
                    }
                } else {
                    allow_auto_countdown = false;
                }
            }
        }
    }
}
