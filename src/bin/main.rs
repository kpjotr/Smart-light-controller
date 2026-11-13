#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::{
    rmt::Rmt,
    time::Rate,
    timer::timg::TimerGroup,
};
use esp_hal_smartled::{RmtSmartLeds, WS2812_TIMING, buffer_size, color_order};
use esp_println::println;
use smart_leds::{RGB8, SmartLedsWrite, brightness};

esp_bootloader_esp_idf::esp_app_desc!();

/// Converts a 0..=255 color-wheel phase into an RGB8 color.
fn color_wheel(mut pos: u8) -> RGB8 {
    pos = 255 - pos;
    if pos < 85 {
        RGB8::new(255 - pos * 3, 0, pos * 3)
    } else if pos < 170 {
        pos -= 85;
        RGB8::new(0, pos * 3, 255 - pos * 3)
    } else {
        pos -= 170;
        RGB8::new(pos * 3, 255 - pos * 3, 0)
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let rmt_freq = Rate::from_mhz(80);
    let rmt = Rmt::new(peripherals.RMT, rmt_freq).unwrap();
    let mut led = RmtSmartLeds::<{ buffer_size::<RGB8>(1) }, _, RGB8, color_order::Grb>::new(
        WS2812_TIMING,
        rmt.channel0,
        peripherals.GPIO48,
        rmt_freq,
    )
    .unwrap();

    println!("Rainbow showcase started!");

    let mut phase: u8 = 0;
    loop {
        led.write(brightness(core::iter::once(color_wheel(phase)), 30))
            .unwrap();
        phase = phase.wrapping_add(1);
        Timer::after(Duration::from_millis(15)).await;
    }
}
