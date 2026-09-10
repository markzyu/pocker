// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use std::io::Write;
use std::time::{Duration, Instant};

/// Reasons that can cause the finite state machine to transition between states
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TrafficLightYieldReason {
    /// It's time for the light to change
    Timer(Duration),
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

    async fn _green_light(&self) -> TResult<()> {
        print!("🟢");

        let timer = GREEN_LIGHT_DURATION + self.start_time.elapsed();
        futures_lite::future::or(
            self.runtime
                .new_pending_future(TrafficLightYieldReason::Timer(timer)),
            async {
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::SensorRelease)
                    .await?;

                let new_timer = SENSOR_RELEASE_DURATION + self.start_time.elapsed();
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::Timer(new_timer))
                    .await?;
                Ok(())
            },
        )
        .await?;

        self._yellow_light().await
    }

    async fn _yellow_light(&self) -> TResult<()> {
        print!("🟡");

        let timer = YELLOW_LIGHT_DURATION + self.start_time.elapsed();
        self.runtime
            .new_pending_future(TrafficLightYieldReason::Timer(timer))
            .await?;

        self._red_light().await
    }

    async fn _red_light(&self) -> TResult<()> {
        print!("🔴");

        let timer = RED_LIGHT_DURATION + self.start_time.elapsed();
        futures_lite::future::or(
            self.runtime
                .new_pending_future(TrafficLightYieldReason::Timer(timer)),
            async {
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::SensorAcquire)
                    .await?;

                let new_timer = SENSOR_ACQUIRE_DURATION + self.start_time.elapsed();
                self.runtime
                    .new_pending_future(TrafficLightYieldReason::Timer(new_timer))
                    .await?;
                Ok(())
            },
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

        // Create a subloop to wait for a valid timer or a user input
        // This subloop should not be blocking for more than 1 second at a time.
        let mut should_clear_stdout = true;
        loop {
            // Call runtime.check_pending_reasons to see whether we've hit a timer
            let hit_timer = runtime
                .check_pending_reasons(|reason| match reason {
                    Some(TrafficLightYieldReason::Timer(timer)) => true,
                    _ => false,
                })
                .unwrap();

            if let Some(TrafficLightYieldReason::Timer(timer)) = hit_timer {
                let now = traffic_light.elapsed();
                if now >= timer {
                    runtime
                        .unblock_futures(TrafficLightYieldReason::Timer(timer), ())
                        .unwrap();
                    break;
                } else {
                    // Show a countdown next to the light
                    print!("{}", (timer - now).as_secs());
                    stdout.flush()?;
                }
            }

            // Otherwise, check user input with a 500ms timeout
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

                        // The state machine will still wait for SENSOR_ACQUIRE_DURATION
                        // So, we don't clear stdout for now
                        should_clear_stdout = false;
                        break;
                    }
                    if key.code == crossterm::event::KeyCode::Char('n') {
                        runtime
                            .unblock_futures(TrafficLightYieldReason::SensorRelease, ())
                            .unwrap();

                        // The state machine will still wait for SENSOR_RELEASE_DURATION
                        // So, we don't clear stdout for now
                        should_clear_stdout = false;
                        break;
                    }
                }
            }
        }

        // Reset terminal output so we don't keep creating more lines/outputs
        if should_clear_stdout {
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
