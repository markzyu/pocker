// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use std::io::Write;
use std::time::{Duration, Instant};

/// Reasons that can cause the finite state machine to transition between states
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TrafficLightYieldReason {
    /// Timer ticks by 500ms with other updates
    TimerTick,
    /// Lane sensors decide that this light can be green
    SensorAcquire,
    /// Lane sensors decide taht this light can stop being green
    SensorRelease,
}

type TrafficLightYieldResponse = ();

type AsyncRuntime = krsm::AsyncRuntime<TrafficLightYieldReason, TrafficLightYieldResponse>;

/// This is a state machine that is written in the exact same way as its transitions
/// Note: The start state is hardcoded to be Green light.
struct TrafficLight<'a> {
    runtime: &'a AsyncRuntime,
    start_time: Instant,
}

const GREEN_LIGHT_DURATION: Duration = Duration::from_secs(7);
const YELLOW_LIGHT_DURATION: Duration = Duration::from_secs(3);
const RED_LIGHT_DURATION: Duration = Duration::from_secs(5);

/// How long to wait before fulfilling a sensor request for light to be green
const SENSOR_ACQUIRE_DURATION: Duration = Duration::from_secs(1);
const SENSOR_RELEASE_DURATION: Duration = Duration::from_secs(1);

type TResult<T> = Result<T, krsm::AsyncRuntimeError>;

impl<'a> TrafficLight<'a> {
    fn new(runtime: &'a AsyncRuntime) -> Self {
        Self {
            runtime,
            start_time: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    async fn _sleep_and_print(&self, light: &'static str, duration: Duration) -> TResult<()> {
        let start = self.elapsed();
        loop {
            // print the countdown (+1 to round up)
            print!("{}{}", light, (start + duration - self.elapsed()).as_secs() + 1);
            self.runtime
                .new_pending_future(TrafficLightYieldReason::TimerTick)
                .await?;
            if self.elapsed() - start > duration {
                break;
            }
        }
        Ok(())
    }

    async fn _green_light(&self) -> TResult<()> {
        futures_lite::future::or(
            async {
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::SensorRelease)
                    .await?;
                self._sleep_and_print("🟢", SENSOR_RELEASE_DURATION).await?;

                Ok(())
            },
            // Note: the ordering matters here. if the async
            // block from above is placed at the end instead,
            // then the wait for sensor release never.gets unblocked.
            self._sleep_and_print("🟢", GREEN_LIGHT_DURATION),
        )
        .await?;

        self._yellow_light().await
    }

    async fn _yellow_light(&self) -> TResult<()> {
        self._sleep_and_print("🟡", YELLOW_LIGHT_DURATION).await?;
        self._red_light().await
    }

    async fn _red_light(&self) -> TResult<()> {
        futures_lite::future::or(
            async {
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::SensorAcquire)
                    .await?;

                self._sleep_and_print("🔴", SENSOR_ACQUIRE_DURATION).await?;
                Ok(())
            },
            self._sleep_and_print("🔴", RED_LIGHT_DURATION),
        )
        .await?;

        // To avoid infinite recusrion, we return to green light by resetting to start state
        Ok(())
    }

    async fn run_loop(&self) -> TResult<()> {
        loop {
            // Do one round of (Green -> Yellow -> Red) transitions
            self._green_light().await?;
        }
    }
}

fn main() -> std::io::Result<()> {
    let runtime = AsyncRuntime::new().unwrap();
    let traffic_light = TrafficLight::new(&runtime);
    let mut future = traffic_light.run_loop();
    let mut stdout = std::io::stdout();

    println!(
        "Traffic light state machine. Press y to simulate lane sensor. Press n to simulate no car in lane."
    );
    crossterm::terminal::enable_raw_mode()?;

    loop {
        let result = unsafe { runtime.run_async_step(&mut future) }.unwrap();
        if let Some(_) = result {
            break;
        }

        // Async step finished. Flush stdout to ensure any output is shown
        stdout.flush()?;

        let mut is_sensor = false;
        // check user input with a 500ms timeout
        if crossterm::event::poll(Duration::from_millis(500))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                let has_ctrl = key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL);
                if key.code == crossterm::event::KeyCode::Char('c') && has_ctrl {
                    crossterm::terminal::disable_raw_mode()?;
                    println!("");
                    println!("Exiting...");
                    return Ok(());
                }
                if key.code == crossterm::event::KeyCode::Char('y') {
                    runtime
                        .unblock_futures(TrafficLightYieldReason::SensorAcquire, ())
                        .unwrap();
                    is_sensor = true;
                }
                if key.code == crossterm::event::KeyCode::Char('n') {
                    runtime
                        .unblock_futures(TrafficLightYieldReason::SensorRelease, ())
                        .unwrap();
                    is_sensor = true;
                }
            }
        }

        if !is_sensor {
            // no keyboard input, do a timer tick
            runtime
                .unblock_futures(TrafficLightYieldReason::TimerTick, ())
                .unwrap();

            // Reset terminal output so we don't keep creating more lines/outputs
            crossterm::execute!(
                stdout,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
            )?;
        }
    }
    println!("Unexpected early exit");
    Ok(())
}
