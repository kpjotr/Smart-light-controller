# Smart Light Controller – ESP32-S3 Firmware (Rust `no_std` + Embassy)

Ipari megbízhatóságú, **100%-ban offline-tűrő (offline-resilient)** okos világításvezérlő firmware **ESP32-S3** mikrokontrollerre, **Rust (`no_std`)** nyelven, az aszinkron **Embassy** keretrendszerre építve.

> **Kapcsolódó Webalkalmazás (PWA & Cloud Functions):**  
> A rendszerhez tartozó Firebase PWA vezérlőpult és a Cloud Functions v2 backend külön tárolóban érhető el:  
> 👉 **[kpjotr/smart-light-controller-PWA](https://github.com/kpjotr/smart-light-controller-PWA)**

---

## Főbb Jellemzők & Architektúra ("First-Principles")

- **100% Offline-Resilient Alapműködés:** Az eszköz a tápfeszültség ráadása után – érvényes NVS konfiguráció esetén – **Wi-Fi kapcsolat és NTP időszinkron nélkül is azonnal működik**. A belső állapotgép időzítései (`embassy_time::Instant`) teljesen függetlenek a hálózati állapottól.
- **Hardveres Azonosítás & Egységes Kriptográfiai Kulcs:**
  - Az eszköz neve és Access Point (AP) SSID-ja automatikusan az ESP32 egyedi hardveres **MAC címéből** generálódik (`SmartLight-XXXX`).
  - Gyártáskor minden eszköz egy kriptográfiailag biztonságos, egyedi, fix hosszúságú **Biztonsági Kódot (Passkey)** kap, amely egyszerre szolgál az **AP WPA2-PSK jelszavaként** és a **PWA felhős párosítási kódjaként**.
  - A Captive Portal kizárólag a WPA2-védett AP-hoz történő csatlakozás után érhető el.
- **Verify-Before-Save Wi-Fi Tárolás:** A megadott helyi Wi-Fi adatokat (maximum 1 db SSID + PW páros, az új mindig felülírja a régit) a vezérlő **kizárólag sikeres Wi-Fi csatlakozás után** menti el az NVS flash memóriába, így kizárt a hibás/elgépelt hálózati adatok rögzítése.
- **Könnyűsúlyú Felhő Kommunikáció:** A memóriazabáló kliensoldali Firebase Auth és Firestore REST API hívások helyett az ESP32 biztonságos **HTTPS POST** kérésekkel (`reqwless` + `embedded-tls`) kommunikál a Firebase Cloud Functions v2 végpontokkal.
- **Többfiókos (Multi-Account) Párosítás:** A 3-szoros védelemmel (Pre-Shared Key + 5 perces TTL + 3-Strike Brute-Force Lockout) ellátott párosítási folyamat bármikor megismételhető egy újraindítással (Hard Reset, Captive Portal Restart vagy távoli PWA Restart), így több felhasználói fiók is hozzárendelhető ugyanazon eszközhöz.

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

Az ESP32 induláskor (boot) kiolvassa az NVS flash memóriából a négy alapvető vezérlési változót (**`threshold`, `duration`, `sensitivity`, `delay`**) és az 1 db mentett Wi-Fi credentialt:

| Boot Állapot (NVS) | Relé Állapotgép | Captive Portal (AP) és Wi-Fi Csatlakozás |
| :--- | :--- | :--- |
| **1. Konfigurálatlan (Szűz) állapot**<br>Bármelyik alapváltozó (`threshold`, `duration`, `sensitivity`, `delay`) értéke `0` | **Inaktív** (vár az első érvényes konfigurációra) | **WPA2-védett AP + Captive Portal elindul időkorlát nélkül (limitless)**, várva a felhasználói beállításra. |
| **2. Konfigurált állapot (Nincs mentett Wi-Fi)**<br>Minden alapváltozó `!= 0`, de nincs mentett Wi-Fi (vagy törölve lett) | **Azonnal elindul** és önállóan vezérli a lámpát | **WPA2-védett AP + Captive Portal időkorlát nélkül (limitless) fut**, biztosítva a Wi-Fi nélküli lokális konfigurálást és kézi kapcsolást. |
| **3. Konfigurált állapot (Van mentett Wi-Fi)**<br>Minden alapváltozó `!= 0` és van mentett Wi-Fi credential | **Azonnal elindul** és önállóan vezérli a lámpát | 1. **AP + Captive Portal elindul 5 perces időzítővel** (élő visszaszámlálóval a felületen).<br>2. **5 perc után AP OFF** -> átvált STA módba és csatlakozik a mentett Wi-Fi-re.<br>3. **Sikeres csatlakozás:** Belép *Normál Online Üzemmódba* (5 perces párosítási ablakkal).<br>4. **Sikertelen csatlakozás:** Visszakapcsol *AP + Captive Portal* módba és időkorlát nélkül fut. |

---

## Captive Portal Felépítése és Funkciói

A Captive Portal felülete **kizárólag az eszköz WPA2-védett AP hálózatához (`SmartLight-XXXX`) csatlakozva érhető el**, és két elkülönített nézetből áll:

### 1. Főnézet: Tájékoztató, Státusz és Wi-Fi Csatlakozás
- **Figyelmeztetés:** Kiemelt tájékoztató jelzi, hogy a helyi konfigurálásra (Config) kizárólag a Wi-Fi-re történő csatlakozás előtt (AP módban) van lehetőség.
- **Beüzemelési és Párosítási Útmutató:** Lépésről lépésre ismerteti a beüzemelés és a PWA párosítás pontos sorrendjét.
- **Élő Visszaszámláló (Countdown Timer):** Amennyiben az AP 5 perces időzített módban fut, másodperces pontossággal mutatja a Wi-Fi csatlakozásig (AP lekapcsolásáig) hátralévő időt.
- **Helyi Wi-Fi Csatlakozás (Verify-Before-Save):**
  - **SSID kiválasztása kizárólag listából:** Az ESP32 által észlelt Wi-Fi hálózatok legördülő listája (`<select>`).
  - **Jelszó (PW) mező:** Write-only beviteli mező.
  - **Inaktív Mentés Gomb:** A *Csatlakozás és Mentés* gomb mindaddig inaktív (`disabled`), amíg nincs kiválasztva SSID és megadva érvényes jelszó.
  - **Mentés csak sikeres csatlakozás után:** Az új SSID + PW páros (amely mindig felülírja a korábbi egyetlen mentett párost) **kizárólag akkor kerül mentésre az NVS-be, ha a Wi-Fi csatlakozás ténylegesen sikerült**. Sikertelen csatlakozás esetén az adat nem mentődik el, és az AP aktív marad.
- **Rendszerműveletek:**
  - **Wi-Fi adatok törlése gomb:** Törli az NVS-ből a mentett Wi-Fi hálózatot (átállítva az eszközt állandó helyi/offline AP üzemmódba).
  - **Restart gomb:** Az eszköz szoftveres újraindítása.
  - **Navigációs gomb:** Átlépés a különálló *Config* felületre.

### 2. Config Nézet: Vezérlési Paraméterek és Helyi Kapcsoló
- **Kézi Kapcsolás:** Azonnali **Lamp ON / OFF** gomb a lámpa helyi (P2 prioritású) fel- és lekapcsolásához.
- **Szenzor és Időzítési Változók:** A `threshold` (Lux küszöb), `duration` (PIR utáni világítási idő), `sensitivity` (PIR érzékenység) és `delay` paraméterek beállítása és NVS-be mentése.

---

## Felhő Párosítás (5 perces ablak) és Ciklikus Szinkronizáció

1. **5 perces Párosítási Figyelés (`verifyPairing`):**
   - Sikeres Wi-Fi csatlakozás után az ESP32 **maximum 5 percig** figyeli/próbálja a párosítást a gyártási biztonsági kóddal a `verifyPairing` Cloud Function végponton keresztül (szinkronban a Firestore `pairing_requests` 5 perces TTL idejével).
   - **Sikeres párosítás (`HTTP 200`) esetén:** A párosítási figyelés azonnal leáll, és az eszköz átlép a normál ciklikus szinkronizációba.
   - **Újabb fiók (Account) hozzáadása:** Egy **Hard Reset**, Captive Portal **Restart** vagy PWA-ból küldött **Restart** parancs után – a Wi-Fi csatlakozást követően – az 5 perces párosítási ablak újra megnyílik.
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