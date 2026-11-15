# Smart Light Controller – ESP32-S3 Firmware (Rust `no_std` + Embassy)

Ipari megbízhatóságú, **100%-ban offline-tűrő (offline-resilient)** okos világításvezérlő firmware **ESP32-S3** mikrokontrollerre, **Rust (`no_std`)** nyelven, `esp-hal` + `esp-rtos` + aszinkron **Embassy** keretrendszerre építve.

> **Kapcsolódó Webalkalmazás (PWA & Cloud Functions):**  
> A rendszerhez tartozó Firebase PWA vezérlőpult és a Cloud Functions v2 backend külön tárolóban érhető el:  
> 👉 **[https://github.com/kpjotr/smart-light-controller-PWA](https://github.com/kpjotr/smart-light-controller-PWA)**

---

## Projekt Áttekintés & Architektúra

- **Offline-Resilient Működés:** Minden belső állapotgép- és biztonsági időzítő (`embassy_time::Instant` és `Duration`) kizárólag hardveres monotonic órára épül; a lámpavezérlés és a szenzoros automatika teljesen független a Wi-Fi-től és az NTP időszinkrontól.
- **Könnyűsúlyú Felhő Kommunikáció:** A memóriaintenzív Firebase Auth/Firestore kliens SDK helyett az ESP32 közvetlen **HTTPS POST** kérésekkel (`reqwless` + `embedded-tls`, `TLS_RX_BUF_LEN = 16640`, `TLS_TX_BUF_LEN = 16640`) kommunikál a Cloud Functions v2 végpontokkal.

---

## Hardver & Perifériák (Jelenlegi Fejlesztői Állapot)

- **Mikrokontroller:** ESP32-S3 (`xtensa-esp32s3-none-elf`, `esp-hal` + `esp-rtos` + `embassy-executor` / `embassy-net`)
- **Fényérzékelő:** BH1750 digitális környezeti fényerő-szenzor (I2C)
- **Mozgásérzékelő:** PIR mozgásérzékelő szenzor
- **Beavatkozó:** Relé kimenet
- **Státusz kijelzés:** Fedélzeti WS2812 RGB LED (`GPIO48` / RMT)
- **Fontos fejlesztői megjegyzés (Hardverbiztonság):**
  - **Fizikai fali kapcsoló NINCS** használatban; a kézi vezérlés kizárólag a Captive Portalról (Wi-Fi csatlakozás előtt) vagy a PWA-ból (Wi-Fi csatlakozás után) történik.
  - A jelenlegi fejlesztői fázisban a fizikai relé és a külső szenzor GPIO kimenetek **passzívak** maradnak (a firmware nem hajt fizikai relé lábat a biztonság érdekében). A relékimenet közvetlen vizuális helyettesítőjeként kizárólag a fedélzeti **WS2812 RGB LED** működik: **folyamatos FEHÉR fény** (`255, 255, 255`) ha a lámpa BE van kapcsolva (`lamp_is_on == true`), és **KI** (`0, 0, 0`) ha a lámpa KI van kapcsolva (`lamp_is_on == false`).

---

## Hardveres Azonosítás & Egységes Kriptográfiai Kulcs (`FACTORY_PASSKEY`)

- **Dinamikus Eszközazonosítók:** Az eszköz neve / SoftAP SSID-ja (`SmartLight-XXXX`, az utolsó két MAC bájt alapján) valamint a teljes hexadecimális hardveres UID (`espUid`) futásidőben, az eFuse MAC címből (`esp_hal::efuse::base_mac_address()`) generálódik.
- **Egységes 10 karakteres biztonsági kód (`FACTORY_PASSKEY`):** Minden eszköz gyárilag egy 10 karakteres alfanumerikus biztonsági kulccsal (pl. `K7M9P2X4R8`) rendelkezik, amely **egyszerre** szolgál:
  1. a helyi SoftAP **WPA2-PSK jelszavaként**, valamint
  2. a felhős párosítás (`verifyPairing`) **párosítási kulcsaként (`pin`)**.

---

## Vezérlési és Prioritási Logika (P1 / P2 / P3 Relé Állapotgép)

Az állapotgép (`relay_state_machine_task`) három prioritási szinten vezérli a lámpa kimenetét:

1. **P2 – Kézi Lámpa BE/KI kapcsolás (`remote_lamp_on`):**
   - Wi-Fi csatlakozás előtt a Captive Portalról, Wi-Fi csatlakozás után pedig a PWA-ból vezérelhető.
   - **Teljesen független** attól, hogy a működési paraméterek be vannak-e állítva (`is_configured()`): a `Lámpa: BE / KI` gomb azonnal fel- és lekapcsolja a lámpát (és a fehér WS2812 LED-et) még konfigurálatlan ("szűz") eszközön is.
   - Felülbírálja a P3 szenzoros automatikát (`ManualP2` forrás).
2. **P1 – Biztonsági lekapcsolás (`safety_off_min` / Auto kikapcs):**
   - **KIZÁRÓLAG** a kézzel (P2 módban, `ManualP2`) felkapcsolt lámpára vonatkozik.
   - Percben adható meg (`0..=1440`, alapértelmezett: `0`). Ha az értéke **`0`**, a biztonsági időzítő **ki van kapcsolva** (a kézzel felkapcsolt lámpa addig marad BE állapotban, amíg manuálisan le nem kapcsolják). Ha `> 0`, a beállított perc elteltével automatikusan lekapcsolja a lámpát.
3. **P3 – Szenzoros automatika (PIR + BH1750 Lux):**
   - Kizárólag akkor aktív, ha `is_configured() == true` **és** `remote_lamp_on == false`.
   - Ha a PIR mozgást észlel és a környezeti fényerő a beállított küszöbérték alatt van (`threshold: 1..=100`, összehasonlítás: `current_lux < threshold * 10`), felkapcsolja a lámpát (`SensorP3` forrás).
   - A mozgás megszűnése után szigorúan a beállított késleltetési idő (**`duration`: `10..=600` másodperc**) letelte után kapcsolja ki a lámpát.

---

## Boot Életciklus, Scan-Before-Countdown & Verify-Before-Save NVS (`SLN2`)

- **CRC-védett NVS rekord (`SLN2`):** Az NVS partíció 128 bájtos, FNV-1a ellenőrzőösszeggel védett (`SLN2`, `v3`) rekordjában tárolódik a 4 működési paraméter (`threshold`, `sensitivity`, `duration`, `safety_off_min`) és legfeljebb **1 db** Wi-Fi hitelesítő adatpár (`wifi_ssid`, `wifi_pass`; új mentése felülírja a korábbit).
- **Boot Életciklus és Scan-Before-Countdown:**
  - **Konfigurálatlan (`!is_configured()`) vagy mentett Wi-Fi nélküli állapot:** A P3 automatika inaktív (szűz állapotban, de a P2 kézi lámpakapcsolás ekkor is működik!), a WPA2-védett SoftAP + Captive Portal **időkorlát nélkül (limitless)** fut.
  - **Konfigurált (`is_configured() == true`) és van mentett `wifi_ssid` az NVS-ben:** Induláskor az ESP32 `AccessPointStation` módban azonnal végez egy kezdeti Wi-Fi környezeti keresést (`scan_nearby_ssids`), és ellenőrzi, hogy a mentett SSID valóban elérhető-e (`saved_ssid_visible`).
    - **Csak ha `saved_ssid_visible == true`:** Elindul az 5 perces (`AP_BOOT_WINDOW_SECS = 300`) visszaszámláló, amelynek végén az ESP32 kikapcsolja az AP-t és csatlakozik a mentett Wi-Fi hálózatra.
    - **Ha `saved_ssid_visible == false`:** Az AP **időkorlát nélkül (limitless)** fut (`remaining_secs = null`), nem próbál automatikusan csatlakozni, és nem jelenít meg visszaszámlálót.
- **Verify-Before-Save Wi-Fi Tárolás:**
  - A Captive Portalról beküldött új SSID + jelszó páros **először kizárólag a RAM-ban** kerül tesztelésre (élő WPA2 kézfogás + DHCP IP-cím kérés).
  - Az adatok **kizárólag sikeres csatlakozás után** íródnak be az NVS flash memóriába, majd az eszköz átlép *Normál Online Üzemmódba* (és elindítja az 5 perces felhő párosítási ablakot).
  - Hibás jelszó vagy sikertelen csatlakozás esetén az NVS érintetlen marad, a SoftAP azonnal újraindul időkorlát nélküli módban, és a 9. sorban megjelenik a `"Sikertelen Wi-Fi csatlakozás."` hibaüzenet.

---

## Kétnézetes Captive Portal (`192.168.4.1`) & UX/UI Felépítés

A Captive Portal a WPA2-védett `SmartLight-XXXX` hálózatra csatlakozva a `http://192.168.4.1` címen érhető el. Mobilra optimalizált, görgetésmentes, fix magasságú (`--app-h` + `flex-shrink: 0`) elrendezést használ, így a virtuális billentyűzet felugrásakor sem nyomja össze a felület elemeit.

### 1. Főoldal (Main View)
1. **Fejléc (1. sor):** Kiemelt `Eszköz: SmartLight-XXXX` azonosító bal oldalon, `Segítség` modális útmutató gomb jobb oldalon.
2. **Figyelmeztető sáv (2. sor):** Tajékoztatás arról, hogy közvetlen beállítás és helyi lámpakapcsolás kizárólag a Wi-Fi hálózatra csatlakozás előtt lehetséges.
3. **Gyorsvezérlés (3. sor):** Egymás mellett a `Lámpa: BE / KI` (P2 kézi kapcsoló) és a `Beállítások` navigációs gomb.
4. **Wi-Fi szekció (4–8. sor):** `Wi-Fi hálózat beállítása` cím, kizárólag a beolvasott hálózatokat kínáló `<select>` lista (gyorsítótárazott induló találatokkal), `Wi-Fi lista frissítése` gomb, write-only jelszómező, valamint a megerősítő ablakot (`#wifiConfirmModal`) nyitó `Csatlakozás és Mentés` gomb.
5. **Fix magasságú státusz/hiba sáv (9. sor — Zero Layout Shift):**
   - Csatlakozási hiba esetén piros színnel: `"Sikertelen Wi-Fi csatlakozás."`
   - Elérhető mentett hálózat és aktív visszaszámlálás esetén: `"Mentett WiFi hálózatot találtam. Csatlakozás [mm:ss] múlva"` (másodpercenként frissülő élő visszaszámlálóval).
   - Alaphelyzetben vagy Wi-Fi adatok törlése után rejtett (`visibility: hidden`), elmozdulás nélkül.
6. **Rendszerműveletek:** `Wi-Fi adatok törlése` (törli a mentett Wi-Fi-t, leállítja a visszaszámlálót, elrejti a 9. soros üzenetet) és `Újraindítás`.

### 2. Config Oldal (Beállítások)
Három függőleges zónából áll: felső eszközfejléc (`Eszköz: SmartLight-XXXX` + `Segítség`), középre igazított keretezett kártya a 4 paraméterrel (egyenlő, `88px` széles jobb oldali beviteli mezőkkel) + magyarázó szöveg + `Beállítások mentése` gomb, valamint alul a `Vissza a Wi-Fi beállításokhoz` gomb.

Konfigurálatlan eszköz esetén az alábbi alapértelmezett értékekkel tölti fel a mezőket:
1. `Fény érzékenység 1 - 100` — alapértelmezett: **`50`**
2. `Mozgás érzékenység 1 - 100` — alapértelmezett: **`50`**
3. `Késleltetés (mp) 10 - 600` — alapértelmezett: **`60`**
4. `Auto kikapcs (p)` (`0..=1440`) — alapértelmezett: **`0`** *(manuális lámpakapcsolás auto-kikapcsolása kikapcsolva)*

---

## 5 Perces Felhő Párosítási Ablak (`verifyPairing`)

- Sikeres Wi-Fi csatlakozás és DHCP IP-cím szerzése után az ESP32 megnyit egy **5 perces (`PAIRING_WINDOW_SECS = 300`)** párosítási ablakot, és periodikusan (`10s` időközönként) POST kérést küld a `verifyPairing` Cloud Function végpontra a `deviceId`, `pin` (`FACTORY_PASSKEY`) és `espUid` adatokkal.
- **Sikeres párosítás (`HTTP 200`):** A párosítási folyamat azonnal leáll.
- **Többfiókos (Multi-Account) támogatás:** Egy **Hard Reset** vagy **Újraindítás (`Restart`)** végrehajtásával az 5 perces párosítási ablak bármikor újra megnyitható újabb felhasználói fiók hozzárendeléséhez.

---

## Fejlesztői Környezet és Fordítás

- **Célplatform:** `xtensa-esp32s3-none-elf` (`#![no_std]`, `#![no_main]`)
- **Fő függőségek:** `esp-hal`, `esp-rtos`, `esp-radio`, `esp-storage`, `esp-alloc`, `embassy-executor`, `embassy-time`, `embassy-net`, `reqwless`, `embedded-tls` (`TLS_RX_BUF_LEN = 16640`, `TLS_TX_BUF_LEN = 16640`).

```bash
# Fordítás ellenőrzése
cargo check

# Fordítás és flashelés (ESP32-S3)
cargo run --release
```
