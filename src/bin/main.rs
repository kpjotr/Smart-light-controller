#![no_std]
#![no_main]

extern crate alloc;

#[path = "../secrets.rs"]
#[allow(dead_code)]
mod secrets;

use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{cell::RefCell, fmt::Write as _};
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
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex as EmbassyMutex};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions::{
    DataPartitionSubType, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
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
const NVS_MAGIC: [u8; 4] = *b"SLN2";
const NVS_VERSION: u8 = 2;
const NVS_RECORD_LEN: usize = 128;

const FACTORY_PASSKEY: &str = "K7M9P2X4R8";
const AP_IP: Ipv4Address = Ipv4Address::new(192, 168, 4, 1);
const AP_BOOT_WINDOW_SECS: u64 = 300;
const PAIRING_WINDOW_SECS: u64 = 300;
const PAIRING_RETRY_INTERVAL_SECS: u64 = 10;
const MAX_POST_BODY_BYTES: usize = 512;
const KEEPALIVE_INTERVAL_SECS: u64 = 15;
const CLOUD_FUNC_URL: &str = "https://verifypairing-lfmgd4eena-uc.a.run.app";
const ESP_AUTH_TOKEN: &str = "ESP32_SECRET_TOKEN_998877";

#[derive(Clone, Eq, PartialEq)]
struct WifiCredentials {
    ssid: String,
    password: String,
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
struct DeviceConfig {
    threshold: u16,
    duration: u64,
    sensitivity: u8,
    delay: u16,
}

impl DeviceConfig {
    fn is_configured(&self) -> bool {
        self.threshold != 0 && self.duration != 0 && self.sensitivity != 0 && self.delay != 0
    }
}

#[derive(Clone, Default)]
struct NvsData {
    config: DeviceConfig,
    wifi: Option<WifiCredentials>,
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

/// Computes a 32-bit FNV-1a checksum for NVS integrity verification.
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

/// Reads and validates the 4 core config parameters and single Wi-Fi credential slot from NVS.
fn load_nvs_data(flash: &mut FlashStorage<'_>) -> NvsData {
    let offset = nvs_partition_offset(flash);
    let mut buf = [0u8; NVS_RECORD_LEN];
    if flash.read(offset, &mut buf).is_err() {
        return NvsData::default();
    }

    if buf[0..4] != NVS_MAGIC || buf[4] != NVS_VERSION {
        return NvsData::default();
    }

    let expected_crc = u32::from_le_bytes([buf[124], buf[125], buf[126], buf[127]]);
    if fnv1a_32(&buf[0..124]) != expected_crc {
        return NvsData::default();
    }

    let config = DeviceConfig {
        threshold: u16::from_le_bytes([buf[8], buf[9]]),
        duration: u64::from_le_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]),
        sensitivity: buf[18],
        delay: u16::from_le_bytes([buf[19], buf[20]]),
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

    NvsData { config, wifi }
}

/// Serializes and writes the 4 core config parameters and single Wi-Fi credential slot to NVS.
fn save_nvs_data(flash: &mut FlashStorage<'_>, data: &NvsData) -> Result<(), ()> {
    let mut buf = [0u8; NVS_RECORD_LEN];
    buf[0..4].copy_from_slice(&NVS_MAGIC);
    buf[4] = NVS_VERSION;

    buf[8..10].copy_from_slice(&data.config.threshold.to_le_bytes());
    buf[10..18].copy_from_slice(&data.config.duration.to_le_bytes());
    buf[18] = data.config.sensitivity;
    buf[19..21].copy_from_slice(&data.config.delay.to_le_bytes());

    if let Some(creds) = &data.wifi {
        let ssid_bytes = creds.ssid.as_bytes();
        let pass_bytes = creds.password.as_bytes();
        if ssid_bytes.is_empty() || ssid_bytes.len() > 32 || pass_bytes.len() > 64 {
            return Err(());
        }
        buf[5] = 1;
        buf[6] = ssid_bytes.len() as u8;
        buf[7] = pass_bytes.len() as u8;
        buf[28..28 + ssid_bytes.len()].copy_from_slice(ssid_bytes);
        buf[60..60 + pass_bytes.len()].copy_from_slice(pass_bytes);
    }

    let crc = fnv1a_32(&buf[0..124]);
    buf[124..128].copy_from_slice(&crc.to_le_bytes());

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

#[derive(Deserialize)]
struct WifiSubmitPayload {
    ssid: String,
    pass: String,
}

#[derive(Deserialize)]
struct ConfigSubmitPayload {
    threshold: u16,
    duration: u64,
    sensitivity: u8,
    delay: u16,
}

#[derive(Serialize)]
struct PortalStatusJson<'a> {
    device_name: &'a str,
    limitless: bool,
    remaining_secs: Option<u64>,
    has_saved_wifi: bool,
    saved_ssid: &'a str,
    last_wifi_error: bool,
    configured: bool,
    lamp_is_on: bool,
    remote_lamp_on: bool,
    threshold: u16,
    duration: u64,
    sensitivity: u8,
    delay: u16,
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

/// Parses the 4 configuration parameters from JSON or URL-encoded form body and ensures all are non-zero.
fn parse_config_submit(body: &str) -> Option<DeviceConfig> {
    let trimmed = body.trim();
    let cfg = if trimmed.starts_with('{') {
        let parsed: ConfigSubmitPayload = serde_json::from_str(trimmed).ok()?;
        DeviceConfig {
            threshold: parsed.threshold,
            duration: parsed.duration,
            sensitivity: parsed.sensitivity,
            delay: parsed.delay,
        }
    } else {
        let mut threshold = None;
        let mut duration = None;
        let mut sensitivity = None;
        let mut delay = None;
        for pair in trimmed.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let val = url_decode(v);
                match k {
                    "threshold" => threshold = val.trim().parse::<u16>().ok(),
                    "duration" => duration = val.trim().parse::<u64>().ok(),
                    "sensitivity" => sensitivity = val.trim().parse::<u8>().ok(),
                    "delay" => delay = val.trim().parse::<u16>().ok(),
                    _ => {}
                }
            }
        }
        DeviceConfig {
            threshold: threshold?,
            duration: duration?,
            sensitivity: sensitivity?,
            delay: delay?,
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

/// Builds the responsive two-view Hungarian Captive Portal HTML/CSS/JS page.
fn build_portal_html(
    device_name: &str,
    ssids: &[String],
    initial_view: &str,
    remaining_secs: Option<u64>,
    last_wifi_error: bool,
    cfg: DeviceConfig,
    lamp_is_on: bool,
    saved_ssid: Option<&str>,
) -> String {
    let safe_dev = html_escape(device_name);
    let mut html = String::with_capacity(8192);
    let _ = write!(
        html,
        "<!DOCTYPE html><html lang='hu'><head><meta charset='utf-8'>\
         <meta name='viewport' content='width=device-width,initial-scale=1'>\
         <title>{dev} – Captive Portal</title><style>\
         *{{box-sizing:border-box}}\
         body{{font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:1rem;background:#0f172a;color:#f1f5f9;line-height:1.45}}\
         .card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem;margin-bottom:1rem}}\
         .warn{{background:#78350f;border:1px solid #f59e0b;color:#fef3c7;border-radius:8px;padding:.85rem;margin-bottom:1rem;font-size:.92rem;font-weight:600}}\
         .err{{background:#7f1d1d;border:1px solid #ef4444;color:#fee2e2;border-radius:8px;padding:.85rem;margin-bottom:1rem;font-size:.9rem}}\
         .ok{{background:#14532d;border:1px solid #22c55e;color:#dcfce7;border-radius:8px;padding:.75rem;margin-bottom:1rem;font-size:.9rem;display:none}}\
         .timer{{background:#0b1220;border:1px solid #38bdf8;color:#bae6fd;border-radius:8px;padding:.75rem;text-align:center;font-weight:700;margin-bottom:1rem}}\
         h1{{font-size:1.25rem;margin:0 0 .25rem}}\
         h2{{font-size:1.05rem;margin:0 0 .75rem;color:#93c5fd}}\
         p,li{{font-size:.9rem;color:#cbd5e1}}\
         ol{{padding-left:1.25rem;margin:.5rem 0}}\
         label{{display:block;font-size:.88rem;color:#cbd5e1;margin-top:.65rem;font-weight:600}}\
         input,select,button{{width:100%;padding:.68rem;margin:.35rem 0 .6rem;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#f8fafc;font-size:.95rem}}\
         button{{background:#2563eb;border:none;font-weight:700;cursor:pointer}}\
         button:disabled{{background:#475569;color:#94a3b8;cursor:not-allowed}}\
         .btn-sec{{background:#334155}}\
         .btn-warn{{background:#b45309}}\
         .btn-danger{{background:#b91c1c}}\
         .btn-lamp-on{{background:#16a34a}}\
         .btn-lamp-off{{background:#475569}}\
         .row{{display:flex;gap:.5rem}}\
         .hidden{{display:none}}\
         .status-pill{{padding:.6rem;border-radius:8px;text-align:center;font-weight:700;margin-bottom:.75rem;background:#0f172a;border:1px solid #475569}}\
         </style></head><body>\
         <div class='warn'>FIGYELEM: A vezérlési paraméterek (Config) beállítására és a helyi kézi kapcsolásra kizárólag a Wi-Fi hálózatra történő csatlakozás ELŐTT (AP módban) van lehetőség!</div>",
        dev = safe_dev
    );

    if last_wifi_error {
        html.push_str(
            "<div id='wifi-error-banner' class='err'><strong>Sikertelen Wi-Fi csatlakozás!</strong> A megadott hálózathoz nem sikerült csatlakozni (hibás jelszó vagy nem elérhető hálózat). A korábbi NVS adatok változatlanok maradtak, az AP időkorlát nélkül fut.</div>",
        );
    } else {
        html.push_str("<div id='wifi-error-banner' class='err hidden'></div>");
    }
    html.push_str("<div id='msg-banner' class='ok'></div>");

    // View 1: Main View (Wi-Fi Provisioning, Onboarding & System Actions)
    let view1_cls = if initial_view == "config" { "hidden" } else { "" };
    let view2_cls = if initial_view == "config" { "" } else { "hidden" };

    let _ = write!(
        html,
        "<div id='view-main' class='{v1}'>\
         <div class='card'><h1>{dev}</h1><p>Helyi AP felület és Wi-Fi beállítás</p>",
        v1 = view1_cls,
        dev = safe_dev
    );

    match remaining_secs {
        Some(secs) => {
            let mm = secs / 60;
            let ss = secs % 60;
            let _ = write!(
                html,
                "<div id='countdown-box' class='timer'>Hátralévő idő a Wi-Fi csatlakozásig: {:02}:{:02}</div>",
                mm, ss
            );
        }
        None => {
            html.push_str(
                "<div id='countdown-box' class='timer'>Időkorlát nélküli helyi AP üzemmód</div>",
            );
        }
    }

    if let Some(s) = saved_ssid {
        let _ = write!(
            html,
            "<p id='saved-wifi-info'>Mentett Wi-Fi hálózat: <strong>{}</strong></p>",
            html_escape(s)
        );
    } else {
        html.push_str("<p id='saved-wifi-info'>Nincs mentett Wi-Fi hálózat az NVS memóriában.</p>");
    }

    html.push_str(
        "<button type='button' class='btn-sec' onclick=\"showView('config')\">⚙️ Konfiguráció és Kézi Kapcsolás (Config)</button></div>\
         <div class='card'><h2>Beüzemelési és Párosítási Útmutató</h2><ol>\
         <li><strong>Konfigurálás (opcionális):</strong> A fenti <em>Config</em> gombbal állítsd be a 4 szenzor/időzítő paramétert és tesztelheted a lámpa kézi kapcsolását.</li>\
         <li><strong>Wi-Fi csatlakozás:</strong> Válaszd ki az otthoni Wi-Fi hálózatot a listából, add meg a jelszót, majd nyomd meg a <em>Csatlakozás és Mentés</em> gombot.</li>",
    );
    let _ = write!(
        html,
        "<li><strong>PWA párosítás:</strong> Sikeres Wi-Fi csatlakozás után nyisd meg a SmartLight PWA alkalmazást, és párosítsd az eszközt (<strong>{dev}</strong>) az eszközön található 10 karakteres biztonsági kóddal a 5 perces párosítási ablakon belül.</li></ol></div>",
        dev = safe_dev
    );

    html.push_str(
        "<div class='card'><h2>Wi-Fi Hálózat Beállítása (Verify-Before-Save)</h2>\
         <form id='wifiForm' onsubmit='submitWifi(event)'>\
         <label for='ssid'>Elérhető Wi-Fi hálózatok (kizárólag listából)</label>\
         <select name='ssid' id='ssid' onchange='validateWifiForm()'><option value=''>-- Válassz Wi-Fi hálózatot --</option>",
    );
    for s in ssids {
        let safe_s = html_escape(s);
        let _ = write!(html, "<option value='{0}'>{0}</option>", safe_s);
    }
    html.push_str(
        "</select>\
         <button type='button' class='btn-sec' id='scanBtn' onclick='scanWifi()'>🔄 Wi-Fi lista frissítése</button>\
         <label for='pass'>Wi-Fi Jelszó (csak írásra)</label>\
         <input type='password' name='pass' id='pass' maxlength='64' autocomplete='new-password' placeholder='Add meg a Wi-Fi jelszót' oninput='validateWifiForm()'>\
         <button type='submit' id='connectBtn' disabled>Csatlakozás és Mentés</button>\
         </form></div>\
         <div class='card'><h2>Rendszerműveletek</h2>\
         <button type='button' class='btn-warn' onclick='clearWifi()'>🗑️ Mentett Wi-Fi adatok törlése</button>\
         <button type='button' class='btn-danger' onclick='restartDevice()'>🔄 Eszköz Újraindítása (Restart)</button>\
         </div></div>",
    );

    // View 2: Config View (Local Parameters & Lamp Switch)
    let lamp_text = if lamp_is_on {
        "Lámpa állapota: BEKAPCSOLVA"
    } else {
        "Lámpa állapota: KIKAPCSOLVA"
    };
    let lamp_cls = if lamp_is_on {
        "btn-lamp-on"
    } else {
        "btn-lamp-off"
    };
    let _ = write!(
        html,
        "<div id='view-config' class='{v2}'>\
         <div class='card'><h2>Helyi Kézi Kapcsolás (P2)</h2>\
         <div id='lamp-status' class='status-pill'>{ltxt}</div>\
         <button type='button' id='toggleLampBtn' class='{lcls}' onclick='toggleLamp()'>💡 Lámpa BE / KI kapcsolása</button></div>\
         <div class='card'><h2>Vezérlési Paraméterek (Config)</h2>\
         <p>Minden paraméternek 0-tól különbözőnek kell lennie az automatika aktiválásához.</p>\
         <form id='cfgForm' onsubmit='saveConfig(event)'>\
         <label for='threshold'>Lux küszöb (threshold)</label>\
         <input type='number' id='threshold' name='threshold' min='1' max='65535' value='{th}' required>\
         <label for='duration'>Világítási idő mozgás után – mp (duration)</label>\
         <input type='number' id='duration' name='duration' min='1' max='86400' value='{du}' required>\
         <label for='sensitivity'>Érzékenység – 1..255 (sensitivity)</label>\
         <input type='number' id='sensitivity' name='sensitivity' min='1' max='255' value='{se}' required>\
         <label for='delay'>Késleltetés (delay)</label>\
         <input type='number' id='delay' name='delay' min='1' max='65535' value='{de}' required>\
         <button type='submit'>💾 Konfiguráció Mentése</button>\
         </form>\
         <button type='button' class='btn-sec' onclick=\"showView('main')\">⬅️ Vissza a Wi-Fi beállításokhoz</button>\
         </div></div>",
        v2 = view2_cls,
        ltxt = lamp_text,
        lcls = lamp_cls,
        th = cfg.threshold,
        du = cfg.duration,
        se = cfg.sensitivity,
        de = cfg.delay,
    );

    let init_rem_js = match remaining_secs {
        Some(s) => alloc::format!("{}", s),
        None => String::from("null"),
    };
    let _ = write!(
        html,
        "<script>\
         let remSecs={rem};\
         function showMsg(txt,isErr){{const m=document.getElementById('msg-banner'),e=document.getElementById('wifi-error-banner');\
         if(isErr){{e.textContent=txt;e.classList.remove('hidden');m.style.display='none';}}\
         else{{m.textContent=txt;m.style.display='block';e.classList.add('hidden');}}}}\
         function showView(v){{document.getElementById('view-main').classList.toggle('hidden',v!=='main');\
         document.getElementById('view-config').classList.toggle('hidden',v!=='config');}}\
         function validateWifiForm(){{const s=document.getElementById('ssid').value,p=document.getElementById('pass').value;\
         document.getElementById('connectBtn').disabled=!(s&&s.length>0&&p.length>0);}}\
         function renderTimer(){{const b=document.getElementById('countdown-box');\
         if(remSecs===null){{b.textContent='Időkorlát nélküli helyi AP üzemmód';}}\
         else{{const m=String(Math.floor(remSecs/60)).padStart(2,'0'),s=String(remSecs%60).padStart(2,'0');\
         b.textContent='Hátralévő idő a Wi-Fi csatlakozásig: '+m+':'+s;}}}}\
         setInterval(()=>{{if(remSecs!==null&&remSecs>0){{remSecs--;renderTimer();}}}},1000);\
         setInterval(async()=>{{try{{const r=await fetch('/status');if(!r.ok)return;const d=await r.json();\
         remSecs=d.limitless?null:d.remaining_secs;renderTimer();updateLampUi(d.lamp_is_on);}}catch(_){{}}}},5000);\
         function updateLampUi(on){{const ls=document.getElementById('lamp-status'),btn=document.getElementById('toggleLampBtn');\
         ls.textContent=on?'Lámpa állapota: BEKAPCSOLVA':'Lámpa állapota: KIKAPCSOLVA';\
         btn.className=on?'btn-lamp-on':'btn-lamp-off';}}\
         async function scanWifi(){{const btn=document.getElementById('scanBtn'),sel=document.getElementById('ssid');\
         btn.disabled=true;btn.textContent='Keresés...';\
         try{{const r=await fetch('/scan');const arr=await r.json();const cur=sel.value;\
         sel.innerHTML=\"<option value=''>-- Válassz Wi-Fi hálózatot --</option>\";\
         arr.forEach(s=>{{const o=document.createElement('option');o.value=s;o.textContent=s;if(s===cur)o.selected=true;sel.appendChild(o);}});\
         validateWifiForm();showMsg('Wi-Fi lista frissítve ('+arr.length+' hálózat).',false);}}catch(_){{showMsg('Hiba a Wi-Fi keresés során.',true);}}\
         btn.disabled=false;btn.textContent='🔄 Wi-Fi lista frissítése';}}\
         async function submitWifi(e){{e.preventDefault();const ssid=document.getElementById('ssid').value,pass=document.getElementById('pass').value;\
         if(!ssid||!pass)return;document.getElementById('connectBtn').disabled=true;\
         showMsg('Csatlakozás és ellenőrzés folyamatban ('+ssid+')... Ha sikertelen, az AP újraindul.',false);\
         try{{await fetch('/connect-wifi',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{ssid,pass}})}});}}catch(_){{}}}}\
         async function clearWifi(){{if(!confirm('Biztosan törlöd a mentett Wi-Fi adatokat?'))return;\
         const r=await fetch('/clear-wifi',{{method:'POST'}});if(r.ok){{remSecs=null;renderTimer();\
         document.getElementById('saved-wifi-info').textContent='Nincs mentett Wi-Fi hálózat az NVS memóriában.';\
         showMsg('Mentett Wi-Fi adatok törölve. Az eszköz időkorlát nélküli AP módban marad.',false);}}}}\
         async function restartDevice(){{if(!confirm('Biztosan újraindítod az eszközt?'))return;\
         showMsg('Eszköz újraindítása...',false);try{{await fetch('/restart',{{method:'POST'}});}}catch(_){{}}}}\
         async function toggleLamp(){{const r=await fetch('/toggle-lamp',{{method:'POST'}});const d=await r.json();\
         if(d.ok){{updateLampUi(d.lamp_is_on);showMsg(d.lamp_is_on?'Lámpa BEKAPCSOLVA (P2).':'Lámpa KIKAPCSOLVA.',false);}}\
         else{{showMsg(d.error||'Előbb mentsd el a 4 konfigurációs paramétert!',true);}}}}\
         async function saveConfig(e){{e.preventDefault();\
         const payload={{threshold:+document.getElementById('threshold').value,duration:+document.getElementById('duration').value,\
         sensitivity:+document.getElementById('sensitivity').value,delay:+document.getElementById('delay').value}};\
         if(!payload.threshold||!payload.duration||!payload.sensitivity||!payload.delay){{showMsg('Minden paraméternek 0-tól különbözőnek kell lennie!',true);return;}}\
         const r=await fetch('/save-config',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(payload)}});\
         const d=await r.json();if(d.ok){{showMsg(d.saved_to_flash?'Konfiguráció mentve az NVS memóriába.':'Konfiguráció változatlan (NVS írás kihagyva).',false);}}\
         else{{showMsg('Érvénytelen konfigurációs értékek!',true);}}}}\
         </script></body></html>",
        rem = init_rem_js
    );

    html
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

async fn remaining_ap_secs(
    ap_deadline: &EmbassyMutex<CriticalSectionRawMutex, Option<Instant>>,
) -> Option<u64> {
    let dl_opt = *ap_deadline.lock().await;
    dl_opt.map(|dl| {
        let now = Instant::now();
        if dl > now {
            dl.duration_since(now).as_secs()
        } else {
            0
        }
    })
}

/// Scans nearby Wi-Fi networks using the Wi-Fi controller in AP+STA mode.
async fn scan_nearby_ssids(controller: &mut WifiController<'_>) -> Vec<String> {
    let mut ssids: Vec<String> = Vec::new();
    if let Ok(Ok(results)) = with_timeout(
        Duration::from_secs(8),
        controller.scan_async(&ScanConfig::default().with_max(15)),
    )
    .await
    {
        for ap in results {
            let s = ap.ssid.as_str();
            if !s.is_empty() && !ssids.iter().any(|x| x == s) {
                ssids.push(String::from(s));
            }
        }
    }
    ssids
}

/// HTTP server on port 80 serving the two-view Captive Portal and all provisioning/config endpoints.
async fn http_portal_server(
    stack: Stack<'_>,
    controller: &mut WifiController<'_>,
    flash: &mut FlashStorage<'_>,
    device_name: &str,
    initial_ssids: Vec<String>,
    ap_deadline: &EmbassyMutex<CriticalSectionRawMutex, Option<Instant>>,
    last_wifi_error: &mut bool,
) -> WifiCredentials {
    let mut rx_buf = [0u8; 2048];
    let mut tx_buf = [0u8; 4096];
    let mut cached_ssids = initial_ssids;

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);
        socket.set_timeout(Some(Duration::from_secs(10)));

        if socket.accept(80).await.is_err() {
            continue;
        }

        let mut req_buf = [0u8; 2048];
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

        if let Ok(req_str) = core::str::from_utf8(&req_buf[..total]) {
            let first_line = req_str.lines().next().unwrap_or("");
            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let raw_path = parts.next().unwrap_or("/");
            let path = raw_path.split('?').next().unwrap_or("/");
            let body = req_str.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");

            match (method, path) {
                ("GET", "/status") => {
                    let rem = remaining_ap_secs(ap_deadline).await;
                    let nvs = load_nvs_data(flash);
                    let saved_ssid = nvs.wifi.as_ref().map(|w| w.ssid.as_str()).unwrap_or("");
                    let state = DEVICE_STATE.lock().await;
                    let status = PortalStatusJson {
                        device_name,
                        limitless: rem.is_none(),
                        remaining_secs: rem,
                        has_saved_wifi: nvs.wifi.is_some(),
                        saved_ssid,
                        last_wifi_error: *last_wifi_error,
                        configured: state.is_configured(),
                        lamp_is_on: state.lamp_is_on,
                        remote_lamp_on: state.remote_lamp_on,
                        threshold: state.threshold,
                        duration: state.duration,
                        sensitivity: state.sensitivity,
                        delay: state.delay,
                    };
                    drop(state);
                    let json = serde_json::to_string(&status).unwrap_or_else(|_| String::from("{}"));
                    send_http_response(&mut socket, "200 OK", "application/json", &json).await;
                }
                ("GET", "/scan") => {
                    let fresh = scan_nearby_ssids(controller).await;
                    if !fresh.is_empty() {
                        cached_ssids = fresh;
                    }
                    let json =
                        serde_json::to_string(&cached_ssids).unwrap_or_else(|_| String::from("[]"));
                    send_http_response(&mut socket, "200 OK", "application/json", &json).await;
                }
                ("POST", "/connect-wifi") | ("POST", "/save") => {
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
                ("POST", "/clear-wifi") => {
                    let mut nvs = load_nvs_data(flash);
                    {
                        let state = DEVICE_STATE.lock().await;
                        nvs.config = DeviceConfig {
                            threshold: state.threshold,
                            duration: state.duration,
                            sensitivity: state.sensitivity,
                            delay: state.delay,
                        };
                    }
                    nvs.wifi = None;
                    let _ = save_nvs_data(flash, &nvs);
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
                        "{\"ok\":true,\"limitless\":true}",
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
                    let (configured, new_remote) = {
                        let mut state = DEVICE_STATE.lock().await;
                        if !state.is_configured() {
                            (false, false)
                        } else {
                            state.remote_lamp_on = !state.remote_lamp_on;
                            (true, state.remote_lamp_on)
                        }
                    };
                    if !configured {
                        send_http_response(
                            &mut socket,
                            "400 Bad Request",
                            "application/json",
                            "{\"ok\":false,\"lamp_is_on\":false,\"error\":\"Előbb állítsd be és mentsd el a 4 konfigurációs paramétert (nem 0 értékekkel)!\"}",
                        )
                        .await;
                    } else {
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
                }
                ("POST", "/save-config") => {
                    if let Some(new_cfg) = parse_config_submit(body) {
                        let changed = {
                            let mut state = DEVICE_STATE.lock().await;
                            let prev = DeviceConfig {
                                threshold: state.threshold,
                                duration: state.duration,
                                sensitivity: state.sensitivity,
                                delay: state.delay,
                            };
                            state.threshold = new_cfg.threshold;
                            state.duration = new_cfg.duration;
                            state.sensitivity = new_cfg.sensitivity;
                            state.delay = new_cfg.delay;
                            prev != new_cfg
                        };
                        if changed {
                            let mut nvs = load_nvs_data(flash);
                            nvs.config = new_cfg;
                            let _ = save_nvs_data(flash, &nvs);
                            println!(
                                "PORTAL: Config updated and saved to NVS (threshold={}, duration={}, sensitivity={}, delay={}).",
                                new_cfg.threshold, new_cfg.duration, new_cfg.sensitivity, new_cfg.delay
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
                            "{\"ok\":false,\"error\":\"Minden paraméternek 0-tól különböző érvényes számnak kell lennie\"}",
                        )
                        .await;
                    }
                }
                _ => {
                    let rem = remaining_ap_secs(ap_deadline).await;
                    let nvs = load_nvs_data(flash);
                    let (cfg, lamp_is_on) = {
                        let state = DEVICE_STATE.lock().await;
                        (
                            DeviceConfig {
                                threshold: state.threshold,
                                duration: state.duration,
                                sensitivity: state.sensitivity,
                                delay: state.delay,
                            },
                            state.lamp_is_on,
                        )
                    };
                    let initial_view = if path == "/config" { "config" } else { "main" };
                    let html = build_portal_html(
                        device_name,
                        &cached_ssids,
                        initial_view,
                        rem,
                        *last_wifi_error,
                        cfg,
                        lamp_is_on,
                        nvs.wifi.as_ref().map(|w| w.ssid.as_str()),
                    );
                    send_http_response(
                        &mut socket,
                        "200 OK",
                        "text/html; charset=utf-8",
                        &html,
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

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum LampOnSource {
    None,
    ManualP2,
    SensorP3,
}

#[derive(Copy, Clone)]
struct DeviceState {
    threshold: u16,
    duration: u64,
    sensitivity: u8,
    delay: u16,
    safety_off_sec: u64,
    remote_lamp_on: bool,
    lamp_is_on: bool,
    lamp_on_source: LampOnSource,
    p2_turned_on_at: Option<Instant>,
    last_movement_ts: Option<Instant>,
    current_lux: u16,
    simulated_pir: bool,
}

impl DeviceState {
    /// Returns `true` only when all four core configuration parameters are non-zero.
    fn is_configured(&self) -> bool {
        self.threshold != 0 && self.duration != 0 && self.sensitivity != 0 && self.delay != 0
    }
}

static DEVICE_STATE: EmbassyMutex<CriticalSectionRawMutex, DeviceState> =
    EmbassyMutex::new(DeviceState {
        threshold: 0,
        duration: 0,
        sensitivity: 0,
        delay: 0,
        safety_off_sec: SAFETY_OFF_SEC,
        remote_lamp_on: false,
        lamp_is_on: false,
        lamp_on_source: LampOnSource::None,
        p2_turned_on_at: None,
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
async fn https_request(
    stack: Stack<'static>,
    seed: u64,
    method: Method,
    url: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), &'static str> {
    let tcp_state = Box::new(TcpClientState::<1, 4096, 4096>::new());
    let tcp_client = TcpClient::new(stack, &tcp_state);
    let dns_socket = DnsSocket::new(stack);

    let mut tls_rx = vec![0u8; TLS_RX_BUF_LEN];
    let mut tls_tx = vec![0u8; TLS_TX_BUF_LEN];
    let tls_config = TlsConfig::new(seed, &mut tls_rx, &mut tls_tx, TlsVerify::None);
    let mut client = HttpClient::new_with_tls(&tcp_client, &dns_socket, tls_config);

    let mut req = client
        .request(method, url)
        .await
        .map_err(|_| "HTTP request init failed")?;

    if !extra_headers.is_empty() {
        req = req.headers(extra_headers);
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

/// Attempts cloud pairing against `CLOUD_FUNC_URL` for up to 5 minutes after Wi-Fi is connected.
#[embassy_executor::task]
async fn pairing_test_task(stack: Stack<'static>, seed: u64) {
    stack.wait_config_up().await;

    let window_start = Instant::now();
    let window_duration = Duration::from_secs(PAIRING_WINDOW_SECS);
    let device_id = build_device_name();
    let esp_uid = build_esp_uid();
    let headers = [("X-Esp-Auth-Token", ESP_AUTH_TOKEN)];
    let payload = alloc::format!(
        r#"{{"deviceId": "{}", "pin": "{}", "espUid": "{}"}}"#,
        device_id, FACTORY_PASSKEY, esp_uid
    );

    println!(
        "PAIRING: 5-minute pairing window opened for {} (espUid={})",
        device_id, esp_uid
    );

    loop {
        let elapsed = window_start.elapsed();
        if elapsed >= window_duration {
            break;
        }

        println!("PAIRING: Sending verifyPairing POST to {}", CLOUD_FUNC_URL);
        match https_request(
            stack,
            seed,
            Method::POST,
            CLOUD_FUNC_URL,
            &headers,
            Some(payload.as_bytes()),
        )
        .await
        {
            Ok((200, _)) => {
                println!(
                    "PAIRING: Pairing successful (HTTP 200) for {}; closing pairing window.",
                    device_id
                );
                return;
            }
            Ok((code @ (400 | 401 | 403 | 404), _)) => {
                println!("PAIRING: verifyPairing returned status: {}", code);
            }
            Ok((code, _)) => {
                println!("PAIRING: verifyPairing returned unexpected status: {}", code);
            }
            Err(e) => {
                println!("PAIRING: verifyPairing request failed: {}", e);
            }
        }

        let Some(remaining) = window_duration.checked_sub(window_start.elapsed()) else {
            break;
        };
        if remaining.as_millis() == 0 {
            break;
        }
        let retry_delay = Duration::from_secs(PAIRING_RETRY_INTERVAL_SECS);
        Timer::after(if remaining < retry_delay {
            remaining
        } else {
            retry_delay
        })
        .await;
    }

    println!(
        "PAIRING: 5-minute pairing window closed for {} without HTTP 200 (re-open via Hard Reset or PWA/Portal Restart).",
        device_id
    );
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
        state.duration = 4;
        state.sensitivity = 50;
        state.delay = 10;
        state.safety_off_sec = 6;
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

    // Step 1: Configured + Daylight Motion Blocked (lux >= threshold)
    println!("[SIM STEP 1] Configured + Daylight Motion Blocked: threshold=100, lux=250, pir=true");
    {
        let mut state = DEVICE_STATE.lock().await;
        state.threshold = 100;
        state.duration = 4;
        state.sensitivity = 50;
        state.delay = 10;
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
) {
    let _ = pir_relay_opt;
    state.lamp_is_on = on;
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
        let mut state = DEVICE_STATE.lock().await;

        let pir_active = if let Some((pir, _)) = pir_relay_opt.as_ref() {
            pir.is_high()
        } else {
            state.simulated_pir
        };

        // Gate check: do not run P1/P2/P3 automation while any core parameter is 0.
        if !state.is_configured() {
            if state.lamp_is_on {
                set_relay_output(&mut pir_relay_opt, &mut state, false);
            }
            state.lamp_on_source = LampOnSource::None;
            state.p2_turned_on_at = None;
            state.last_movement_ts = None;
            prev_pir_active = pir_active;
            continue;
        }

        // [P1: Safety Timeout] ONLY applies when the lamp is ON due to P2 (remote_lamp_on == true).
        if state.remote_lamp_on
            && state.lamp_on_source == LampOnSource::ManualP2
            && let Some(p2_ts) = state.p2_turned_on_at
            && now.duration_since(p2_ts) >= Duration::from_secs(state.safety_off_sec)
        {
            set_relay_output(&mut pir_relay_opt, &mut state, false);
            state.remote_lamp_on = false;
            state.p2_turned_on_at = None;
            state.lamp_on_source = LampOnSource::None;
            state.last_movement_ts = None;
            println!(
                "[P1 SAFETY OFF] Manual lamp ON exceeded SAFETY_OFF_SEC ({}s) -> Forced OFF",
                state.safety_off_sec
            );
            prev_pir_active = pir_active;
            continue;
        }

        // [P2: PWA / Captive Portal Manual Switch]
        if state.remote_lamp_on {
            if !state.lamp_is_on || state.lamp_on_source != LampOnSource::ManualP2 {
                set_relay_output(&mut pir_relay_opt, &mut state, true);
                state.lamp_on_source = LampOnSource::ManualP2;
                state.p2_turned_on_at = Some(now);
                println!("[P2 MANUAL ON] Lamp turned ON via PWA/Portal switch");
            }
            prev_pir_active = pir_active;
            continue;
        } else if state.lamp_on_source == LampOnSource::ManualP2 {
            set_relay_output(&mut pir_relay_opt, &mut state, false);
            state.p2_turned_on_at = None;
            state.lamp_on_source = LampOnSource::None;
            state.last_movement_ts = None;
            println!("[P2 MANUAL OFF] Lamp turned OFF via PWA/Portal switch");
            prev_pir_active = pir_active;
            continue;
        }

        // [P3: PIR + BH1750 Lux Automation] (only evaluated when remote_lamp_on == false)
        if pir_active {
            if !state.lamp_is_on {
                if state.current_lux < state.threshold {
                    set_relay_output(&mut pir_relay_opt, &mut state, true);
                    state.lamp_on_source = LampOnSource::SensorP3;
                    state.last_movement_ts = Some(now);
                    println!(
                        "[P3 SENSOR ON] PIR active & lux ({}) < threshold ({}) -> Lamp ON",
                        state.current_lux, state.threshold
                    );
                }
            } else if state.lamp_on_source == LampOnSource::SensorP3 {
                state.last_movement_ts = Some(now);
                if !prev_pir_active {
                    println!("[P3 MOTION] PIR active while Lamp ON -> duration timer refreshed");
                }
            }
        } else if state.lamp_is_on
            && state.lamp_on_source == LampOnSource::SensorP3
            && state
                .last_movement_ts
                .is_none_or(|ts| now.duration_since(ts) >= Duration::from_secs(state.duration))
        {
            set_relay_output(&mut pir_relay_opt, &mut state, false);
            state.last_movement_ts = None;
            state.lamp_on_source = LampOnSource::None;
            println!(
                "[P3 DURATION OFF] No PIR motion for {}s -> Lamp OFF",
                state.duration
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
        match with_timeout(Duration::from_secs(7), controller.connect_async()).await {
            Ok(Ok(_)) => {
                connected = true;
                break;
            }
            Ok(Err(e)) => println!("Connect attempt {} failed: {:?}", attempt, e),
            Err(_) => println!("Connect attempt {} timed out.", attempt),
        }
        Timer::after(Duration::from_millis(300)).await;
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

/// Runs periodic gateway ICMP keep-alive pings in Normal Online Mode.
async fn sta_online_keepalive(stack: Stack<'static>) -> ! {
    let gateway = stack.config_v4().and_then(|cfg| cfg.gateway);

    let mut icmp_rx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_tx_meta = [IcmpPacketMetadata::EMPTY; 1];
    let mut icmp_rx_buf = [0u8; 128];
    let mut icmp_tx_buf = [0u8; 128];

    loop {
        Timer::after(Duration::from_secs(KEEPALIVE_INTERVAL_SECS)).await;
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

/// Runs WPA2-protected SoftAP + STA scan coex with optional dynamic countdown timeout.
async fn run_captive_portal(
    controller: &mut WifiController<'_>,
    flash: &mut FlashStorage<'_>,
    device_name: &str,
    seed: u64,
    timeout: Option<Duration>,
    last_wifi_error: &mut bool,
) -> PortalOutcome {
    let mut scanned_ssids: Vec<String> = Vec::new();
    if controller
        .set_config(&Config::Station(StationConfig::default()))
        .is_ok()
    {
        scanned_ssids = scan_nearby_ssids(controller).await;
    }
    println!(
        "Found {} Wi-Fi networks for portal list.",
        scanned_ssids.len()
    );

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
            flash,
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

    let mut flash = FlashStorage::new(peripherals.FLASH);
    let nvs_data = load_nvs_data(&mut flash);
    {
        let mut state = DEVICE_STATE.lock().await;
        state.threshold = nvs_data.config.threshold;
        state.duration = nvs_data.config.duration;
        state.sensitivity = nvs_data.config.sensitivity;
        state.delay = nvs_data.config.delay;
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
    spawner.spawn(pairing_test_task(sta_stack, seed).expect("pairing_test_task spawn"));

    let mut ap_timeout = if nvs_data.config.is_configured() && nvs_data.wifi.is_some() {
        println!(
            "BOOT Case 3 (Configured + Saved Wi-Fi): Starting {}-second timed AP window.",
            AP_BOOT_WINDOW_SECS
        );
        Some(Duration::from_secs(AP_BOOT_WINDOW_SECS))
    } else if !nvs_data.config.is_configured() {
        println!("BOOT Case 1 (Virgin / Unconfigured): Relay inactive; starting limitless AP.");
        None
    } else {
        println!("BOOT Case 2 (Configured, no Wi-Fi): Relay active; starting limitless AP.");
        None
    };

    let mut last_wifi_error = false;

    loop {
        let outcome = run_captive_portal(
            &mut controller,
            &mut flash,
            &device_name,
            seed,
            ap_timeout,
            &mut last_wifi_error,
        )
        .await;

        match outcome {
            PortalOutcome::ConnectWifi(candidate_creds) => {
                if connect_sta_with_timeout(sta_stack, &mut controller, &candidate_creds).await {
                    let cur_cfg = {
                        let state = DEVICE_STATE.lock().await;
                        DeviceConfig {
                            threshold: state.threshold,
                            duration: state.duration,
                            sensitivity: state.sensitivity,
                            delay: state.delay,
                        }
                    };
                    let updated = NvsData {
                        config: cur_cfg,
                        wifi: Some(candidate_creds),
                    };
                    if save_nvs_data(&mut flash, &updated).is_ok() {
                        println!("Verify-Before-Save: Wi-Fi verified and saved to NVS.");
                    } else {
                        println!("Verify-Before-Save: Wi-Fi connected, but NVS write failed.");
                    }
                    sta_online_keepalive(sta_stack).await;
                } else {
                    println!(
                        "Verify-Before-Save: Wi-Fi connection failed; NVS untouched. Returning to limitless AP."
                    );
                    last_wifi_error = true;
                    ap_timeout = None;
                }
            }
            PortalOutcome::TimeoutExpired => {
                let latest_nvs = load_nvs_data(&mut flash);
                if let Some(saved_creds) = latest_nvs.wifi {
                    println!("300s AP window expired; connecting to saved Wi-Fi...");
                    if connect_sta_with_timeout(sta_stack, &mut controller, &saved_creds).await {
                        sta_online_keepalive(sta_stack).await;
                    } else {
                        println!("Saved Wi-Fi connection failed; falling back to limitless AP.");
                        last_wifi_error = true;
                        ap_timeout = None;
                    }
                } else {
                    ap_timeout = None;
                }
            }
        }
    }
}
