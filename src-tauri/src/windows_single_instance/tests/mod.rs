use super::*;

#[test]
fn second_thread_cannot_cross_the_startup_gap() {
    let identifier = format!(
        "com.polaris.test.{}.{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("gate")
    );
    let first = StartupGate::acquire_with_timeout(&identifier, Duration::from_secs(1))
        .expect("first owner");
    let contender_id = identifier.clone();
    let contender = std::thread::spawn(move || {
        StartupGate::acquire_with_timeout(&contender_id, Duration::from_millis(40))
            .expect_err("second thread must not enter while the first owns the gate")
            .kind()
    });
    assert_eq!(
        contender.join().expect("contender thread"),
        io::ErrorKind::TimedOut
    );

    drop(first);
    StartupGate::acquire_with_timeout(&identifier, Duration::from_secs(1))
        .expect("released gate must be acquirable");
}
