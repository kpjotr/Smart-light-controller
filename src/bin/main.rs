#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_hal::{
    gpio::{Level, Output, OutputConfig},
    peripherals::Peripherals,
    prelude::*,
};
use esp_backtrace as _;

[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // 1. Perifériák inicializálása az esp-hal segítségével
    let peripherals = Peripherals::take();
    
    // ESP32-S3 DevKit-en a GPIO 2 (vagy fedélzeti LED) kimenetként konfigurálása
    // (Ha más lábra kötöd a LED-et, itt átírhatod, pl. GPIO4)
    let mut led = Output::new(peripherals.GPIO2, Level::Low, OutputConfig::default());

    // 2. Végtelen aszinkron ciklus (Embassy task)
    loop {
        led.set_high();
        Timer::after(Duration::from_millis(500)).await;
        
        led.set_low();
        Timer::after(Duration::from_millis(500)).await;
    }
}