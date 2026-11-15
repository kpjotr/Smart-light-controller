# Smart Light Controller – ESP32-S3 Firmware (Rust `no_std` + Embassy)

Ipari megbízhatóságú, **100%-ban offline-tűrő (offline-resilient)** okos világításvezérlő firmware **ESP32-S3** mikrokontrollerre, **Rust (`no_std`)** nyelven, az aszinkron **Embassy** keretrendszerre építve.

> **Kapcsolódó Webalkalmazás (PWA & Cloud Functions):**  
> A rendszerhez tartozó Firebase PWA vezérlőpult és a Cloud Functions v2 backend külön tárolóban érhető el:  
> 👉 **[kpjotr/smart-light-controller-PWA](https://github.com/kpjotr/smart-light-controller-PWA)**

---

## Főbb Jellemzők & Architektúra ("First-Principles")

- **100% Offline-Resilient Alapműködés:** Az eszköz a tápfeszültség ráadása után – érvényes NVS konfiguráció esetén – **Wi-Fi kapcsolat és NTP időszinkron nélkül is azonnal működik**. A belső állapotgép időzítései (`embassy_time::Instant`) teljesen függetlenek a hálózati állapottól.
- **Wi-Fi Nélküli (Lokális) Üzemmód:** Olyan helyszíneken, ahol nincs internet/Wi-Fi lefedettség, az eszköz saját **Captive Portal (AP)** felületén keresztül is teljes körűen konfigurálható és kézzel kapcsolható.
- **Könnyűsúlyú Felhő Kommunikáció:** A memóriazabáló kliensoldali Firebase Auth és Firestore REST API hívások helyett az ESP32 biztonságos, minimális lábnyomú **HTTPS POST** kérésekkel (`reqwless` + `embedded-tls`) kommunikál a Firebase Cloud Functions v2 végpontokkal.
- **Többfiókos (Multi-Account) Párosítás:** A 3-szoros védelemmel (Pre-Shared Key + 5 perces TTL + 3-Strike Brute-Force Lockout) ellátott párosítási folyamat bármikor megismételhető egy újraindítással (Hard Reset vagy távoli PWA Restart), így több felhasználói fiók is hozzárendelhető ugyanazon eszközhöz.

---

## Hardver & Perifériák

- **Mikrokontroller:** ESP32-S3 (`esp-hal` + `esp-rtos` + `embassy`)
- **Fényérzékelő:** BH1750 digitális környezeti fényerő-szenzor (I2C)
- **Mozgásérzékelő:** PIR szenzor (konfigurálható `sensitivity` és `delay` paraméterekkel)
- **Beavatkozó:** Relé kimenet (világítás kapcsolása)
- **Státusz kijelzés:** WS2812 címezhető RGB LED (vizuális állapot- és hibajelzés)
- **Fizikai fali kapcsoló:** Nincs (a kézi vezérlés a PWA-ból és a Captive Portalról történik).

---

## Vezérlési és Prioritási Logika (Relé Állapotgép)

Az állapotgép (`relay_state_machine_task`) három prioritási szinten kezeli a lámpa állapotát:

1. **P1 – Biztonsági Lekapcsolás (`SAFETY_OFF_SEC`):**
   - **Kizárólag** a kézi (PWA vagy Captive Portal **Lamp ON**) parancs hatására felkapcsolt lámpánál számol!
   - Ha a felhasználó felkapcsolva felejti a lámpát, a biztonsági időkorlát letelte után a vezérlő automatikusan lekapcsolja.
2. **P2 – Kézi Kapcsoló (`Lamp ON / OFF`) & Távoli Vezérlés:**
   - A PWA-ban (Firestore-ba írt és az ESP32 által ciklikusan olvasott) vagy a helyi Captive Portalon kiadott fel-/lekapcsolási parancs.
   - Felülbírálja a P3 szenzoros automatikát.
3. **P3 – Szenzoros Automatika (PIR + BH1750 Lux):**
   - Ha a mért környezeti fényerő a beállított küszöbérték (`threshold`) alatt van, és a PIR szenzor mozgást érzékel (a `sensitivity` és `delay` figyelembevételével), a relé behúz.
   - A lámpa a mozgás megszűnése után kizárólag a beállított **`duration` (`PIR_DURATION_SEC`)** időzítő szerint kapcsol le (nem a `SAFETY_OFF_SEC` alapján).

---

## Boot Életciklus és Hálózati Folyamat

Az ESP32 induláskor (boot) kiolvassa az NVS flash memóriából a négy alapvető vezérlési változót (**`threshold`, `duration`, `sensitivity`, `delay`**) és a Wi-Fi adatokat:

| Boot Állapot (NVS) | Relé Állapotgép | Captive Portal (AP) és Wi-Fi Csatlakozás |
| :--- | :--- | :--- |
| **1. Konfigurálatlan (Szűz) állapot**<br>Bármelyik alapváltozó (`threshold`, `duration`, `sensitivity`, `delay`) értéke `0` | **Inaktív** (vár az első érvényes konfigurációra) | **AP + Captive Portal elindul időkorlát nélkül (limitless)**, várva a felhasználói beállításra. |
| **2. Konfigurált állapot (Nincs Wi-Fi / Sikertelen Wi-Fi)**<br>Minden alapváltozó `!= 0`, de nincs mentett Wi-Fi vagy a csatlakozás meghiúsul | **Azonnal elindul** és önállóan vezérli a lámpát | **AP + Captive Portal időkorlát nélkül (limitless) fut**, biztosítva a Wi-Fi nélküli lokális konfigurálást és kézi kapcsolást. |
| **3. Konfigurált állapot (Van mentett Wi-Fi)**<br>Minden alapváltozó `!= 0` és van mentett Wi-Fi credential | **Azonnal elindul** és önállóan vezérli a lámpát | 1. **AP + Captive Portal elindul 5 perces időzítővel** (visszaszámlálóval a felületen).<br>2. **5 perc után AP OFF** -> átvált STA módba és csatlakozik a Wi-Fi-re.<br>3. **Sikeres csatlakozás:** Belép *Normál Online Üzemmódba*.<br>4. **Sikertelen csatlakozás:** Visszakapcsol *AP + Captive Portal* módba időkorlát nélkül. |

---

## Captive Portal Funkciók

Amikor az ESP32 Access Point (AP) módban sugároz (`SmartLight-XXXX`), a beépített webes Captive Portal az alábbi funkciókat nyújtja:
- **Beüzemelési és párosítási útmutató:** Pontos tájékoztató üzenet a beállítás és a PWA párosítás műveleti sorrendjéről.
- **Visszaszámláló (Countdown Timer):** Ha az eszköz rendelkezik mentett konfigurációval és Wi-Fi-vel, vizuálisan mutatja az AP kikapcsolásáig (Wi-Fi csatlakozásig) hátralévő időt az 5 percből.
- **Helyi Vezérlés & Konfiguráció (Offline használathoz is):**
  - `threshold` (Lux küszöb), `duration` (égési idő mozgás után), `sensitivity` és `delay` beállítása.
  - Közvetlen **Lamp ON / OFF** kapcsoló.
- **Hálózati & Párosítási Beállítások:** Wi-Fi SSID, jelszó és a 6 jegyű párosítási PIN kód megadása.

---

## Felhő Párosítás (5 perces ablak) és Szinkronizáció

1. **5 perces Párosítási Figyelés (`verifyPairing`):**
   - Sikeres Wi-Fi csatlakozás után az ESP32 **maximum 5 percig** figyeli/próbálja a párosítást a megadott 6 jegyű PIN kóddal a `verifyPairing` Cloud Function végponton keresztül (ez szinkronban van a Firestore `pairing_requests` 5 perces lejárati idejével).
   - **Sikeres párosítás (`HTTP 200`) esetén:** A párosítási figyelés azonnal leáll, és az eszköz átlép a normál ciklikus szinkronizációba.
   - **Újabb fiók (Account) hozzáadása:** Ha a felhasználó egy további fiókhoz is párosítani szeretné az eszközt, egy **Hard Reset** (tápfeszültség megszakítása) vagy a PWA-ból küldött **Restart** parancs után – a Wi-Fi-re való felcsatlakozást követően – az 5 perces párosítási ablak újra megnyílik.
2. **Normál Ciklikus Üzem (`syncDevice` / Firestore szinkron):**
   - **Olvasás:** Az ESP32 ciklikusan lekéri a Firestore-ban tárolt vezérlési parancsokat (PWA **P2 Lamp ON/OFF** kapcsoló, távoli **Restart** kérés, módosított `threshold`, `duration`, `sensitivity`, `delay` értékek).
   - **Írás (Telemetria & Naplózás):** Beküldi az aktuális állapotot (relé állapota, mért lux érték, utolsó mozgás, valamint a lámpa égési ideje / fogyasztási adatok).

---

## Fejlesztői Környezet és Fordítás

- **Célplatform:** `xtensa-esp32s3-none-elf`
- **Fő függőségek:** `esp-hal`, `esp-rtos`, `esp-wifi`, `embassy-executor`, `embassy-time`, `embassy-net`, `reqwless`, `embedded-tls` (`TLS_RX_BUF_LEN = 16640`, `TLS_TX_BUF_LEN = 16640`).

```bash
# Fordítás és flashelés (ESP32-S3)
cargo run --release