#![no_std]
#![no_main]

extern crate alloc;

#[path = "../secrets.rs"]
#[allow(dead_code)]
mod secrets;

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::{
    cell::RefCell,
    fmt::Write as _,
    sync::atomic::{AtomicU8, Ordering},
};
use critical_section::Mutex;
use embassy_executor::Spawner;
use embassy_futures::select::{Either4, select4};
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
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex as EmbassyMutex};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions::{
    DataPartitionSubType, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
use esp_hal::{
    Async,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    i2c::master::{Config as I2cConfig, I2c},
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
use smart_leds::{RGB8, SmartLedsWrite, brightness};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const NVS_FALLBACK_OFFSET: u32 = 0x9000;
const CRED_MAGIC: [u8; 4] = *b"SLWC";
const CRED_VERSION: u8 = 1;
const CRED_RECORD_LEN: usize = 108;

const AP_PASSWORD: &str = "A1B2C3D4";
const AP_IP: Ipv4Address = Ipv4Address::new(192, 168, 4, 1);
const AP_BOOT_WINDOW_SECS: u64 = 60;
const MAX_POST_BODY_BYTES: usize = 256;
const KEEPALIVE_INTERVAL_SECS: u64 = 15;

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
enum LedState {
    ApMode = 0,
    Connecting = 1,
    Connected = 2,
    Error = 3,
    Off = 4,
}

impl LedState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::ApMode,
            1 => Self::Connecting,
            2 => Self::Connected,
            3 => Self::Error,
            _ => Self::Off,
        }
    }
}

static LED_STATE: AtomicU8 = AtomicU8::new(LedState::ApMode as u8);

fn set_led_state(state: LedState) {
    LED_STATE.store(state as u8, Ordering::Relaxed);
}

#[derive(Clone)]
struct WifiCredentials {
    ssid: String,
    password: String,
}

/// Background task driving the onboard WS2812 status LED based on `LED_STATE`.
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

    let mut blink_on = false;

    loop {
        let state = LedState::from_u8(LED_STATE.load(Ordering::Relaxed));

        match state {
            LedState::ApMode => {
                blink_on = !blink_on;
                let color = if blink_on {
                    RGB8::new(0, 0, 255)
                } else {
                    RGB8::new(0, 0, 0)
                };
                let _ = led.write(brightness(core::iter::once(color), 30));
                Timer::after(Duration::from_millis(300)).await;
            }
            LedState::Connecting => {
                blink_on = !blink_on;
                let color = if blink_on {
                    RGB8::new(255, 180, 0)
                } else {
                    RGB8::new(0, 0, 0)
                };
                let _ = led.write(brightness(core::iter::once(color), 30));
                Timer::after(Duration::from_millis(200)).await;
            }
            LedState::Connected => {
                if SIMULATE_HARDWARE {
                    let mut last_relay_on: Option<bool> = None;
                    while LED_STATE.load(Ordering::Relaxed) == LedState::Connected as u8 {
                        let relay_on = {
                            let state = DEVICE_STATE.lock().await;
                            state.relay_on
                        };
                        if last_relay_on != Some(relay_on) {
                            let color = if relay_on {
                                RGB8::new(50, 50, 50)
                            } else {
                                RGB8::new(0, 0, 0)
                            };
                            let _ = led.write(core::iter::once(color));
                            last_relay_on = Some(relay_on);
                        }
                        Timer::after(Duration::from_millis(100)).await;
                    }
                } else {
                    let _ = led.write(brightness(core::iter::once(RGB8::new(255, 0, 0)), 30));
                    Timer::after(Duration::from_millis(500)).await;
                    let _ = led.write(brightness(core::iter::once(RGB8::new(0, 0, 0)), 0));
                    for _ in 0..120 {
                        if LED_STATE.load(Ordering::Relaxed) != LedState::Connected as u8 {
                            break;
                        }
                        Timer::after(Duration::from_millis(250)).await;
                    }
                }
            }
            LedState::Error => {
                blink_on = !blink_on;
                let color = if blink_on {
                    RGB8::new(255, 0, 0)
                } else {
                    RGB8::new(0, 0, 0)
                };
                let _ = led.write(brightness(core::iter::once(color), 30));
                Timer::after(Duration::from_millis(250)).await;
            }
            LedState::Off => {
                let _ = led.write(brightness(core::iter::once(RGB8::new(0, 0, 0)), 0));
                Timer::after(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Computes a 32-bit FNV-1a checksum for credential integrity verification.
fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Resolves the NVS partition offset from the ESP-IDF partition table, or falls back to 0x9000.
fn nvs_partition_offset(flash: &mut FlashStorage<'_>) -> u32 {
    let mut pt_mem = [0u8; PARTITION_TABLE_MAX_LEN];
    if let Ok(pt) = read_partition_table(flash, &mut pt_mem) {
        if let Ok(Some(nvs)) = pt.find_partition(PartitionType::Data(DataPartitionSubType::Nvs)) {
            return nvs.offset();
        }
    }
    NVS_FALLBACK_OFFSET
}

/// Reads and validates saved Wi-Fi credentials from flash.
fn load_credentials(flash: &mut FlashStorage<'_>) -> Option<WifiCredentials> {
    let offset = nvs_partition_offset(flash);
    let mut buf = [0u8; CRED_RECORD_LEN];
    if flash.read(offset, &mut buf).is_err() {
        return None;
    }

    if buf[0..4] != CRED_MAGIC || buf[4] != CRED_VERSION {
        return None;
    }

    let ssid_len = buf[5] as usize;
    let pass_len = buf[6] as usize;
    if ssid_len == 0 || ssid_len > 32 || pass_len > 64 {
        return None;
    }

    let expected_crc = u32::from_le_bytes([buf[104], buf[105], buf[106], buf[107]]);
    if fnv1a_32(&buf[0..104]) != expected_crc {
        return None;
    }

    let ssid = core::str::from_utf8(&buf[8..8 + ssid_len]).ok()?;
    let password = core::str::from_utf8(&buf[40..40 + pass_len]).ok()?;

    Some(WifiCredentials {
        ssid: String::from(ssid),
        password: String::from(password),
    })
}

/// Serializes and writes Wi-Fi credentials with a checksum to the NVS flash region.
fn save_credentials(flash: &mut FlashStorage<'_>, creds: &WifiCredentials) -> Result<(), ()> {
    let ssid_bytes = creds.ssid.as_bytes();
    let pass_bytes = creds.password.as_bytes();
    if ssid_bytes.is_empty() || ssid_bytes.len() > 32 || pass_bytes.len() > 64 {
        return Err(());
    }

    let mut buf = [0u8; CRED_RECORD_LEN];
    buf[0..4].copy_from_slice(&CRED_MAGIC);
    buf[4] = CRED_VERSION;
    buf[5] = ssid_bytes.len() as u8;
    buf[6] = pass_bytes.len() as u8;
    buf[8..8 + ssid_bytes.len()].copy_from_slice(ssid_bytes);
    buf[40..40 + pass_bytes.len()].copy_from_slice(pass_bytes);

    let crc = fnv1a_32(&buf[0..104]);
    buf[104..108].copy_from_slice(&crc.to_le_bytes());

    let offset = nvs_partition_offset(flash);
    flash.write(offset, &buf).map_err(|_| ())
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

/// Extracts `ssid` and `password` from a URL-encoded form body.
fn parse_credentials_form(body: &str) -> Option<WifiCredentials> {
    let mut ssid = None;
    let mut manual_ssid = None;
    let mut password = String::new();

    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let val = url_decode(v);
            match k {
                "ssid" if !val.is_empty() => ssid = Some(val),
                "manual_ssid" if !val.is_empty() => manual_ssid = Some(val),
                "password" => password = val,
                _ => {}
            }
        }
    }

    let final_ssid = manual_ssid.or(ssid)?;
    if final_ssid.is_empty() || final_ssid.len() > 32 || password.len() > 64 {
        return None;
    }

    Some(WifiCredentials {
        ssid: final_ssid,
        password,
    })
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

/// Builds the captive portal HTML page with scanned SSIDs and manual entry fallback.
fn build_portal_html(ssids: &[String]) -> String {
    let mut html = String::from(
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>\
         <title>SmartLight Wi-Fi Setup</title><style>\
         body{font-family:sans-serif;max-width:420px;margin:2rem auto;padding:0 1rem;background:#111;color:#eee}\
         input,select,button{width:100%;padding:.6rem;margin:.4rem 0 1rem;box-sizing:border-box;border-radius:6px;border:1px solid #444;background:#222;color:#fff}\
         button{background:#2563eb;border:none;font-weight:bold;cursor:pointer}\
         </style></head><body><h2>SmartLight Wi-Fi Setup</h2><form method='POST' action='/save'>",
    );

    if !ssids.is_empty() {
        html.push_str("<label>Available Networks</label><select name='ssid'><option value=''>-- Select network --</option>");
        for s in ssids {
            let safe_ssid = html_escape(s);
            let _ = write!(html, "<option value='{0}'>{0}</option>", safe_ssid);
        }
        html.push_str("</select>");
    }

    html.push_str(
        "<label>Or Enter SSID Manually</label><input type='text' name='manual_ssid' maxlength='32' placeholder='Wi-Fi SSID'>\
         <label>Password</label><input type='password' name='password' maxlength='64' placeholder='Leave blank if open'>\
         <button type='submit'>Save & Connect</button></form></body></html>",
    );
    html
}

/// HTTP server on port 80 that serves the portal and returns once valid credentials are saved.
async fn http_portal_server(
    stack: Stack<'_>,
    flash: &mut FlashStorage<'_>,
    portal_html: &str,
) -> WifiCredentials {
    let mut rx_buf = [0u8; 2048];
    let mut tx_buf = [0u8; 2048];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
        socket.set_timeout(Some(Duration::from_secs(10)));

        if socket.accept(80).await.is_err() {
            continue;
        }

        let mut req_buf = [0u8; 1536];
        let mut total = 0usize;
        let mut payload_too_large = false;
        loop {
            match socket.read(&mut req_buf[total..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    if let Ok(s) = core::str::from_utf8(&req_buf[..total]) {
                        if let Some(hdr_end) = s.find("\r\n\r\n") {
                            let body_received = total - (hdr_end + 4);
                            let content_len = s[..hdr_end]
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
                            if content_len > MAX_POST_BODY_BYTES
                                || body_received > MAX_POST_BODY_BYTES
                            {
                                payload_too_large = true;
                                break;
                            }
                            if total >= hdr_end + 4 + content_len {
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

        if payload_too_large {
            println!(
                "HTTP payload exceeded {} bytes; dropping connection.",
                MAX_POST_BODY_BYTES
            );
            socket.close();
            continue;
        }

        if let Ok(req_str) = core::str::from_utf8(&req_buf[..total]) {
            if req_str.starts_with("POST ") {
                let body = req_str.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
                if body.len() > MAX_POST_BODY_BYTES {
                    socket.close();
                    continue;
                }
                if let Some(creds) = parse_credentials_form(body) {
                    println!("Saving credentials for SSID '{}'...", creds.ssid);
                    if save_credentials(flash, &creds).is_ok() {
                        let resp_body = "<!DOCTYPE html><html><body><h2>Saved!</h2><p>Connecting to Wi-Fi...</p></body></html>";
                        let mut hdr = String::new();
                        let _ = write!(
                            hdr,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            resp_body.len()
                        );
                        let _ = socket.write_all(hdr.as_bytes()).await;
                        let _ = socket.write_all(resp_body.as_bytes()).await;
                        let _ = socket.flush().await;
                        socket.close();
                        Timer::after(Duration::from_millis(300)).await;
                        return creds;
                    }
                }
                let err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 19\r\nConnection: close\r\n\r\nInvalid credentials";
                let _ = socket.write_all(err_resp.as_bytes()).await;
            } else {
                let mut hdr = String::new();
                let _ = write!(
                    hdr,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    portal_html.len()
                );
                let _ = socket.write_all(hdr.as_bytes()).await;
                let _ = socket.write_all(portal_html.as_bytes()).await;
            }
            let _ = socket.flush().await;
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

static STA_NET_RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
static NTP_TIME: Mutex<RefCell<Option<NtpSyncState>>> = Mutex::new(RefCell::new(None));

const TLS_RX_BUF_LEN: usize = 16640;
const TLS_TX_BUF_LEN: usize = 16640;
const HTTP_RX_BUF_LEN: usize = 8192;
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
const SAFETY_OFF_SEC: u64 = 3600;
const LUX_THRESHOLD: u16 = 50;
const PIR_DURATION_SEC: u64 = 60;
const SIMULATE_HARDWARE: bool = true;

#[derive(Copy, Clone)]
struct DeviceState {
    pwa_lamp_on: bool,
    relay_on: bool,
    lamp_turned_on_ts: Option<Instant>,
    last_movement_ts: Option<Instant>,
    current_lux: u16,
    simulated_pir: bool,
}

static DEVICE_STATE: EmbassyMutex<CriticalSectionRawMutex, DeviceState> =
    EmbassyMutex::new(DeviceState {
        pwa_lamp_on: false,
        relay_on: false,
        lamp_turned_on_ts: None,
        last_movement_ts: None,
        current_lux: 0,
        simulated_pir: false,
    });

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

/// Executes an async HTTPS request over `embassy_net` using `reqwless` + `embedded-tls`.
#[allow(dead_code)]
async fn https_request(
    stack: Stack<'static>,
    seed: u64,
    method: Method,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), &'static str> {
    let tcp_state = Box::new(TcpClientState::<1, 4096, 4096>::new());
    let tcp_client = TcpClient::new(stack, &tcp_state);
    let dns_socket = DnsSocket::new(stack);

    let mut tls_rx = vec![0u8; TLS_RX_BUF_LEN];
    let mut tls_tx = vec![0u8; TLS_TX_BUF_LEN];
    let tls_config = TlsConfig::new(seed, &mut tls_rx, &mut tls_tx, TlsVerify::None);
    let mut client = HttpClient::new_with_tls(&tcp_client, &dns_socket, tls_config);

    let auth_header = bearer_token.map(|t| format!("Bearer {}", t));
    let mut extra_headers: [(&str, &str); 1] = [("", "")];

    let mut req = client
        .request(method, url)
        .await
        .map_err(|_| "HTTP request init failed")?;

    if let Some(ref auth) = auth_header {
        extra_headers[0] = ("Authorization", auth.as_str());
        req = req.headers(&extra_headers);
    }

    let mut rx_buf = vec![0u8; HTTP_RX_BUF_LEN];
    if let Some(payload) = body {
        let mut req = req.content_type(ContentType::ApplicationJson).body(payload);
        let resp = req
            .send(&mut rx_buf)
            .await
            .map_err(|_| "HTTPS send failed")?;
        let status = resp.status.0;
        let resp_bytes = resp
            .body()
            .read_to_end()
            .await
            .map_err(|_| "HTTPS body read failed")?;
        Ok((status, resp_bytes.to_vec()))
    } else {
        let resp = req
            .send(&mut rx_buf)
            .await
            .map_err(|_| "HTTPS send failed")?;
        let status = resp.status.0;
        let resp_bytes = resp
            .body()
            .read_to_end()
            .await
            .map_err(|_| "HTTPS body read failed")?;
        Ok((status, resp_bytes.to_vec()))
    }
}

/// Reads ambient light (in lux) from the BH1750 sensor over async I2C and updates `DEVICE_STATE`,
/// or alternates simulated lux values between 20 and 200 every 15s when `SIMULATE_HARDWARE` is true.
#[embassy_executor::task]
async fn sensor_task(i2c_opt: Option<I2c<'static, Async>>) -> ! {
    if SIMULATE_HARDWARE {
        let _ = i2c_opt;
        let mut dark = true;
        loop {
            let lux = if dark { 20 } else { 200 };
            {
                let mut state = DEVICE_STATE.lock().await;
                state.current_lux = lux;
            }
            println!("SIMULATOR: Lux set to {}", lux);
            dark = !dark;
            Timer::after(Duration::from_secs(15)).await;
        }
    }

    let mut i2c = i2c_opt.expect("I2C must be initialized when SIMULATE_HARDWARE is false");
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

/// Programmatically toggles `DEVICE_STATE.simulated_pir` to exercise auto-mode transitions.
#[allow(dead_code)]
#[embassy_executor::task]
async fn simulation_stimulus_task() -> ! {
    loop {
        {
            let mut state = DEVICE_STATE.lock().await;
            state.simulated_pir = true;
        }
        println!("SIMULATOR: Stimulus toggled PIR to true (active for 5s)");
        Timer::after(Duration::from_secs(5)).await;

        {
            let mut state = DEVICE_STATE.lock().await;
            state.simulated_pir = false;
        }
        println!("SIMULATOR: Stimulus toggled PIR to false (idle for 20s)");
        Timer::after(Duration::from_secs(20)).await;
    }
}

fn set_relay_output(
    pir_relay_opt: &mut Option<(Input<'static>, Output<'static>)>,
    state: &mut DeviceState,
    on: bool,
) {
    state.relay_on = on;
    if !SIMULATE_HARDWARE && let Some((_, relay)) = pir_relay_opt.as_mut() {
        if on {
            relay.set_high();
        } else {
            relay.set_low();
        }
    }
}

/// Non-blocking 100 ms state machine controlling the relay from PIR, lux, and PWA state.
#[embassy_executor::task]
async fn relay_state_machine_task(
    mut pir_relay_opt: Option<(Input<'static>, Output<'static>)>,
) -> ! {
    let mut tick_count: u32 = 0;
    let mut prev_pir_active = false;

    loop {
        Timer::after(Duration::from_millis(RELAY_TICK_MS)).await;

        let now = Instant::now();
        let mut state = DEVICE_STATE.lock().await;

        let (pir_active, relay_is_on) = if SIMULATE_HARDWARE {
            (state.simulated_pir, state.relay_on)
        } else {
            let (pir, relay) = pir_relay_opt
                .as_ref()
                .expect("PIR and Relay GPIOs must be initialized when SIMULATE_HARDWARE is false");
            (pir.is_high(), relay.is_set_high())
        };

        tick_count = tick_count.wrapping_add(1);
        if SIMULATE_HARDWARE && tick_count.is_multiple_of(20) {
            let on_elapsed = state
                .lamp_turned_on_ts
                .map_or(0, |ts| ts.elapsed().as_secs());
            let idle_elapsed = state
                .last_movement_ts
                .map_or(0, |ts| ts.elapsed().as_secs());
            println!(
                "SIMULATOR: status | lux={} | pir={} | relay={} | pwa={} | on_elapsed={}s | idle_elapsed={}s",
                state.current_lux,
                pir_active,
                relay_is_on,
                state.pwa_lamp_on,
                on_elapsed,
                idle_elapsed
            );
        }

        // [P1: Safety Override]
        if relay_is_on
            && state.pwa_lamp_on
            && let Some(turned_on_ts) = state.lamp_turned_on_ts
            && turned_on_ts.elapsed().as_secs() > SAFETY_OFF_SEC
        {
            set_relay_output(&mut pir_relay_opt, &mut state, false);
            state.pwa_lamp_on = false;
            state.lamp_turned_on_ts = None;
            println!(
                "SIMULATOR: Safety timeout ({}s) reached -> Relay OFF",
                SAFETY_OFF_SEC
            );
            prev_pir_active = pir_active;
            continue;
        }

        // [P2: PWA Override]
        if state.pwa_lamp_on {
            if !relay_is_on {
                set_relay_output(&mut pir_relay_opt, &mut state, true);
                state.lamp_turned_on_ts = Some(now);
                println!("SIMULATOR: PWA override active -> Relay ON");
            }
            prev_pir_active = pir_active;
            continue;
        }

        // [P3: Auto Mode]
        if !relay_is_on {
            if pir_active && state.current_lux < LUX_THRESHOLD {
                set_relay_output(&mut pir_relay_opt, &mut state, true);
                state.last_movement_ts = Some(now);
                state.lamp_turned_on_ts = Some(now);
                println!(
                    "SIMULATOR: PIR active & Lux ({}) < threshold ({}) -> Relay ON",
                    state.current_lux, LUX_THRESHOLD
                );
            }
        } else if pir_active {
            state.last_movement_ts = Some(now);
            if SIMULATE_HARDWARE && !prev_pir_active {
                println!("SIMULATOR: PIR active while Relay ON -> movement timer reset");
            }
        } else if state
            .last_movement_ts
            .is_none_or(|ts| ts.elapsed().as_secs() > PIR_DURATION_SEC)
        {
            set_relay_output(&mut pir_relay_opt, &mut state, false);
            state.lamp_turned_on_ts = None;
            println!(
                "SIMULATOR: PIR timeout ({}s) reached -> Relay OFF",
                PIR_DURATION_SEC
            );
        }

        prev_pir_active = pir_active;
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

/// Attempts to connect as Station and acquire a DHCPv4 IP address with configured hostname.
async fn try_connect_sta(
    stack: Stack<'static>,
    controller: &mut WifiController<'_>,
    creds: &WifiCredentials,
) -> bool {
    let Some(sta_cfg) = station_config_from_creds(creds) else {
        println!("Invalid stored Wi-Fi credentials format.");
        return false;
    };

    if controller.set_config(&sta_cfg).is_err() {
        println!("Failed to apply STA config.");
        return false;
    }

    println!("Connecting to Wi-Fi SSID '{}'...", creds.ssid);
    let mut connected = false;
    for attempt in 1..=3 {
        match with_timeout(Duration::from_secs(12), controller.connect_async()).await {
            Ok(Ok(_)) => {
                connected = true;
                break;
            }
            Ok(Err(e)) => println!("Connect attempt {} failed: {:?}", attempt, e),
            Err(_) => println!("Connect attempt {} timed out.", attempt),
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    if !connected {
        return false;
    }

    println!("Wi-Fi associated! Waiting for DHCP lease...");

    if with_timeout(Duration::from_secs(15), stack.wait_config_up())
        .await
        .is_err()
    {
        println!("DHCP timed out.");
        return false;
    }

    let gateway = if let Some(cfg) = stack.config_v4() {
        println!("Acquired IP address: {}", cfg.address.address());
        cfg.gateway
    } else {
        None
    };
    set_led_state(LedState::Connected);

    let mut icmp_rx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_tx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_rx_buf = [0u8; 128];
    let mut icmp_tx_buf = [0u8; 128];

    loop {
        println!(
            "Keep-alive: starting {}s timer before next gateway ping...",
            KEEPALIVE_INTERVAL_SECS
        );
        Timer::after(Duration::from_secs(KEEPALIVE_INTERVAL_SECS)).await;
        if let Some(gw) = gateway {
            println!("Keep-alive: sending ICMP ping to gateway {}...", gw);
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

/// Runs WPA2-protected SoftAP mode with optional timeout; returns submitted credentials if any.
async fn run_captive_portal(
    controller: &mut WifiController<'_>,
    flash: &mut FlashStorage<'_>,
    device_name: &str,
    seed: u64,
    timeout: Option<Duration>,
) -> Option<WifiCredentials> {
    set_led_state(LedState::ApMode);

    let mut scanned_ssids: Vec<String> = Vec::new();
    if controller
        .set_config(&Config::Station(StationConfig::default()))
        .is_ok()
    {
        if let Ok(results) = controller
            .scan_async(&ScanConfig::default().with_max(12))
            .await
        {
            for ap in results {
                let s = ap.ssid.as_str();
                if !s.is_empty() && !scanned_ssids.iter().any(|x| x == s) {
                    scanned_ssids.push(String::from(s));
                }
            }
        }
    }
    println!(
        "Found {} Wi-Fi networks for portal list.",
        scanned_ssids.len()
    );

    let ap_cfg = AccessPointConfig::default()
        .with_ssid(device_name.try_into().expect("valid AP SSID"))
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            AP_PASSWORD.try_into().expect("valid AP password"),
        ));
    controller
        .set_config(&Config::AccessPoint(ap_cfg))
        .expect("Failed to start SoftAP");

    let ap_iface = Interface::access_point();
    let mut resources = StackResources::<6>::new();
    let net_cfg = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(AP_IP, 24),
        gateway: Some(AP_IP),
        dns_servers: Default::default(),
    });
    let (stack, mut runner) = embassy_net::new(ap_iface, net_cfg, &mut resources, seed);

    println!(
        "SoftAP '{}' (WPA2 pass: '{}') active at http://{}/",
        device_name, AP_PASSWORD, AP_IP
    );

    let portal_html = build_portal_html(&scanned_ssids);

    let portal_future = select4(
        runner.run(),
        dhcp_server(stack),
        dns_server(stack),
        http_portal_server(stack, flash, &portal_html),
    );

    match timeout {
        Some(dur) => match with_timeout(dur, portal_future).await {
            Ok(Either4::Fourth(creds)) => Some(creds),
            _ => None,
        },
        None => match portal_future.await {
            Either4::Fourth(creds) => Some(creds),
            _ => None,
        },
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_alloc::heap_allocator!(size: 128 * 1024);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    spawner.spawn(led_task(peripherals.RMT, peripherals.GPIO48).expect("led_task spawn"));

    let (i2c_opt, pir_relay_opt) = if SIMULATE_HARDWARE {
        spawner.spawn(simulation_stimulus_task().expect("simulation_stimulus_task spawn"));
        (None, None)
    } else {
        let pir = Input::new(
            peripherals.GPIO4,
            InputConfig::default().with_pull(Pull::Down),
        );
        let relay = Output::new(peripherals.GPIO5, Level::Low, OutputConfig::default());
        let i2c = I2c::new(peripherals.I2C0, I2cConfig::default())
            .expect("I2C0 init failed")
            .with_sda(peripherals.GPIO8)
            .with_scl(peripherals.GPIO9)
            .into_async();
        (Some(i2c), Some((pir, relay)))
    };
    spawner.spawn(sensor_task(i2c_opt).expect("sensor_task spawn"));
    spawner.spawn(relay_state_machine_task(pir_relay_opt).expect("relay_state_machine_task spawn"));

    let rng = Rng::new();
    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);

    let device_name = build_device_name();
    println!("Device identity: {}", device_name);

    let mut flash = FlashStorage::new(peripherals.FLASH);
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

    println!(
        "Starting {}-second SoftAP configuration window...",
        AP_BOOT_WINDOW_SECS
    );
    let mut active_creds = run_captive_portal(
        &mut controller,
        &mut flash,
        &device_name,
        seed,
        Some(Duration::from_secs(AP_BOOT_WINDOW_SECS)),
    )
    .await;

    if active_creds.is_none() {
        println!("60s AP window expired; checking NVS for saved credentials...");
        active_creds = load_credentials(&mut flash);
    }

    loop {
        if let Some(creds) = active_creds.take() {
            set_led_state(LedState::Connecting);
            if !try_connect_sta(sta_stack, &mut controller, &creds).await {
                println!("STA connection failed; falling back to SoftAP provisioning.");
                set_led_state(LedState::Error);
                Timer::after(Duration::from_secs(2)).await;
            }
        } else {
            println!("No valid Wi-Fi credentials; starting SoftAP provisioning indefinitely.");
        }

        active_creds =
            run_captive_portal(&mut controller, &mut flash, &device_name, seed, None).await;
    }
}
