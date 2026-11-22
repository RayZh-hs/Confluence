use confluence_core::lease::LeaseHandle;
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

fn main() {
    const CHECKS: usize = 250_000;
    for threads in [1, 2, 4, 8] {
        let start = Arc::new(Barrier::new(threads + 1));
        let lease = Arc::new(LeaseHandle::new(Duration::from_secs(30)).unwrap());
        let elapsed = std::thread::scope(|pool| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    let (lease, start) = (lease.clone(), start.clone());
                    pool.spawn(move || {
                        start.wait();
                        for _ in 0..CHECKS {
                            black_box(lease.is_active());
                        }
                    })
                })
                .collect();
            let timer = Instant::now();
            start.wait();
            for worker in workers {
                worker.join().unwrap();
            }
            timer.elapsed()
        });
        println!(
            "{threads} thread(s) · {:.0} checks/s",
            (threads * CHECKS) as f64 / elapsed.as_secs_f64()
        );
    }
}
