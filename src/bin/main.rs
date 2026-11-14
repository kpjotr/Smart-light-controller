#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    fmt::Write as _,
    sync::atomic::{AtomicU8, Ordering},
};
use embassy_executor::Spawner;
use embassy_futures::select::{Either4, select, select4};
use embassy_net::{
    DhcpConfig, IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources,
    StaticConfigV4,
    icmp::{
        PacketMetadata as IcmpPacketMetadata,
        ping::{PingManager, PingParams},
    },
    tcp::TcpSocket,
    udp::{PacketMetadata, UdpSocket},
};
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions::{
    DataPartitionSubType, PARTITION_TABLE_MAX_LEN, PartitionType, read_partition_table,
};
use esp_hal::{
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
use smart_leds::{RGB8, SmartLedsWrite, brightness};

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

/// Attempts to connect as Station and acquire a DHCPv4 IP address with configured hostname.
async fn try_connect_sta(
    controller: &mut WifiController<'_>,
    creds: &WifiCredentials,
    device_name: &str,
    seed: u64,
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

    println!(
        "Wi-Fi associated! Starting DHCP client (hostname: {})...",
        device_name
    );
    let sta_iface = Interface::station();
    let mut resources = StackResources::<4>::new();
    let mut dhcp_cfg = DhcpConfig::default();
    dhcp_cfg.hostname = Some(device_name.try_into().expect("valid hostname"));

    let (stack, mut runner) = embassy_net::new(
        sta_iface,
        embassy_net::Config::dhcpv4(dhcp_cfg),
        &mut resources,
        seed,
    );

    let sta_task = async {
        if with_timeout(Duration::from_secs(15), stack.wait_config_up())
            .await
            .is_err()
        {
            println!("DHCP timed out.");
            return;
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
    };

    select(runner.run(), sta_task).await;
    false
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
    esp_alloc::heap_allocator!(size: 96 * 1024);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    spawner.spawn(led_task(peripherals.RMT, peripherals.GPIO48).expect("led_task spawn"));

    let rng = Rng::new();
    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);

    let device_name = build_device_name();
    println!("Device identity: {}", device_name);

    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut controller =
        WifiController::new(peripherals.WIFI, Default::default()).expect("Wi-Fi init failed");

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
            if !try_connect_sta(&mut controller, &creds, &device_name, seed).await {
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
