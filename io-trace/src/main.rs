use aya::programs::{ KProbe, FExit };
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use std::collections::HashMap;
use clap::Parser;
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};

use io_trace_common::*;

#[derive(Parser)]
struct Args {
    /// Target process ID (TGID) to trace. Omit to trace all processes (VFS layer disabled).
    #[arg(short = 'p', long = "pid")]
    pid: Option<u32>,

    /// Stop tracing after this duration (e.g. 1s, 30s, 1m, 1h)
    #[arg(short = 't', long = "time")]
    time: Option<String>,
}

fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    if let Some(n) = s.strip_suffix('h') {
        Ok(std::time::Duration::from_secs(n.parse::<u64>()? * 3600))
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(std::time::Duration::from_secs(n.parse::<u64>()? * 60))
    } else if let Some(n) = s.strip_suffix('s') {
        Ok(std::time::Duration::from_secs(n.parse()?))
    } else {
        anyhow::bail!("invalid duration '{}': expected format like 1s, 30s, 1m, 1h", s)
    }
}

struct IoTracker {
    // Page Cache: (tgid, pid) → timestamp
    vfs_start: HashMap<(u32, u32), u64>,

    // BIO: bio_ptr → (timestamp, dev, sector)
    bio_submit: HashMap<u64, (u64, u32, u64)>,

    // NvmeQueue: request_ptr → (timestamp, dev, sector)
    nvme_requests: HashMap<u64, (u64, u32, u64)>,
    // NvmeQueueExit: request_ptr → exit_timestamp
    nvme_device_start: HashMap<u64, u64>,

    stats: IoStats,
}

#[derive(Default, Debug)]
struct IoStats {
    vfs_latency: Vec<u64>,         // generic_perform_write → vfs_write ret
    block_layer_latency: Vec<u64>, // submit_bio → nvme_queue_rq
    driver_latency: Vec<u64>,      // nvme_queue_rq → nvme_queue_rq_exit
    nvme_latency: Vec<u64>,        // nvme_queue_rq_exit → nvme_complete
}

impl IoTracker {
    fn new() -> Self {
        Self {
            vfs_start: HashMap::new(),
            bio_submit: HashMap::new(),
            nvme_requests: HashMap::new(),
            nvme_device_start: HashMap::new(),
            stats: IoStats::default(),
        }
    }

    fn handle_event(&mut self, event: IoEvent) {
        match event.event_type {
            EventType::VfsWrite => {
                self.vfs_start.insert((event.tgid, event.pid), event.timestamp);
                let (maj, min) = dev_to_maj_min(event.dev);
                println!(
                    "[{:>12}] vfs_write: tgid: {}, dev: ({}, {}), inode: {}",
                    event.timestamp, event.tgid, maj, min, event.inode
                );
            }

            EventType::GenericPerformWrite => {
                if let Some(start_time) = self.vfs_start.remove(&(event.tgid, event.pid)) {
                    let latency = event.timestamp - start_time;
                    self.stats.vfs_latency.push(latency);
                    let (maj, min) = dev_to_maj_min(event.dev);
                    println!(
                        "[{:>12}] generic_perform_write: tgid: {}, pid: {}, dev: ({}, {}), inode: {}, latency {} ns",
                        event.timestamp, event.tgid, event.pid, maj, min, event.inode, latency
                    );
                } else {
                    println!(
                        "[{:>12}] generic_perform_write: tgid: {}, pid: {}, inode: {} (no matching start)",
                        event.timestamp, event.tgid, event.pid, event.inode
                    );
                }
            }

            EventType::VfsWriteRet => {
                println!(
                    "[{:>12}] vfs_write_ret: tgid: {}, pid: {}",
                    event.timestamp, event.tgid, event.pid
                );
            }

            EventType::BioSubmit => {
                let bio_ptr = event.request_ptr; // submit_bio stores bio ptr in request_ptr
                self.bio_submit.insert(bio_ptr, (event.timestamp, event.dev, event.sector));
                let (maj, min) = dev_to_maj_min(event.dev);
                println!(
                    "[{:>12}] BIO Submit: tgid: {}, dev: ({},{}), sector: {}, size: {}, bio_ptr: {:#x}",
                    event.timestamp, event.tgid, maj, min, event.sector, event.size, bio_ptr
                );
            }

            EventType::BioComplete => {
                let (maj, min) = dev_to_maj_min(event.dev);
                println!(
                    "[{:>12}] BIO Complete: tgid: {}, dev: ({},{}), sector: {}",
                    event.timestamp, event.tgid, maj, min, event.sector
                );
            }

            EventType::BlkMqStartRequest => {
                let bio_ptr = event.inode; // bio_ptr stored in inode field
                if bio_ptr != 0 {
                    if let Some((submit_time, dev, sector)) = self.bio_submit.remove(&bio_ptr) {
                        let latency = event.timestamp - submit_time;
                        let (maj, min) = dev_to_maj_min(dev);
                        println!(
                            "[{:12}] blk_mq_start: tgid: {}, request_ptr: {:#x}, tag: {}, bio_ptr: {:#x}, dev: ({}, {}), sector: {}, submit_bio->blk_mq: {} ns",
                            event.timestamp, event.tgid, event.request_ptr, event.tag, bio_ptr, maj, min, sector, latency
                        );
                    }
                }
            }

            EventType::NvmeQueue => {
                let bio_ptr = event.inode;
                if bio_ptr != 0 {
                    if let Some(&(submit_time, dev, sector)) = self.bio_submit.get(&bio_ptr) {
                        let block_latency = event.timestamp - submit_time;
                        self.stats.block_layer_latency.push(block_latency);
                        self.nvme_requests.insert(event.request_ptr, (event.timestamp, dev, sector));
                        let (maj, min) = dev_to_maj_min(dev);
                        println!(
                            "[{:>12}] NVMe Queue: request_ptr: {:#x}, tag: {}, tgid: {}, dev: ({},{}), sector: {}, block_layer_latency: {} ns",
                            event.timestamp, event.request_ptr, event.tag, event.tgid, maj, min, sector, block_latency
                        );
                    }
                }
            }

            EventType::NvmeQueueExit => {
                if let Some(&(queue_time, dev, sector)) = self.nvme_requests.get(&event.request_ptr) {
                    self.nvme_device_start.insert(event.request_ptr, event.timestamp);
                    let driver_latency = event.timestamp - queue_time;
                    self.stats.driver_latency.push(driver_latency);
                    let (maj, min) = dev_to_maj_min(dev);
                    println!(
                        "[{:>12}] NVMe Queue Exit: request_ptr: {:#x}, tgid: {}, dev: ({},{}), sector: {}, driver_latency: {} ns",
                        event.timestamp, event.request_ptr, event.tgid, maj, min, sector, driver_latency
                    );
                }
            }

            EventType::NvmeCompleteBatch => {
                if let Some((_, dev, sector)) = self.nvme_requests.remove(&event.request_ptr) {
                    if let Some(device_start) = self.nvme_device_start.remove(&event.request_ptr) {
                        let device_latency = event.timestamp - device_start;
                        self.stats.nvme_latency.push(device_latency);
                        let (maj, min) = dev_to_maj_min(dev);
                        println!(
                            "[{:>12}] NVMe Complete(batch): request_ptr: {:#x}, dev: ({},{}), sector: {}, device_latency: {} ns",
                            event.timestamp, event.request_ptr, maj, min, sector, device_latency
                        );
                    }
                }
            }

            EventType::NvmeComplete => {
                if let Some((_, dev, sector)) = self.nvme_requests.remove(&event.request_ptr) {
                    if let Some(device_start) = self.nvme_device_start.remove(&event.request_ptr) {
                        let device_latency = event.timestamp - device_start;
                        self.stats.nvme_latency.push(device_latency);
                        let (maj, min) = dev_to_maj_min(dev);
                        println!(
                            "[{:>12}] NVMe Complete: request_ptr: {:#x}, dev: ({},{}), sector: {}, device_latency: {} ns",
                            event.timestamp, event.request_ptr, maj, min, sector, device_latency
                        );
                    }
                }
            }
        }
    }

    fn print_avg(name: &str, data: &[u64]) {
        if !data.is_empty() {
            let avg = data.iter().sum::<u64>() / data.len() as u64;
            println!("{name} avg latency: {avg} ns ({} samples)", data.len());
        }
    }

    fn print_stats(&self) {
        println!("\n=== I/O Latency Statistics ===");
        Self::print_avg("Page Cache (generic_perform_write → vfs_write ret)", &self.stats.vfs_latency);
        Self::print_avg("Block Layer (submit_bio → nvme_queue_rq)", &self.stats.block_layer_latency);
        Self::print_avg("NVMe Driver (nvme_queue_rq → nvme_queue_rq_exit)", &self.stats.driver_latency);
        Self::print_avg("NVMe Device (nvme_queue_rq_exit → nvme_complete)", &self.stats.nvme_latency);
    }
}

fn attach_kprobe(ebpf: &mut aya::Ebpf, prog: &str, fn_name: &str) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut(prog).unwrap().try_into()?;
    program.load()?;
    program.attach(fn_name, 0)?;
    Ok(())
}

fn attach_fexit(ebpf: &mut aya::Ebpf, prog: &str, fn_name: &str) -> anyhow::Result<()> {
    let btf = aya::Btf::from_sys_fs()?;
    let program: &mut FExit = ebpf.program_mut(prog).unwrap().try_into()?;
    program.load(fn_name, &btf)?;
    program.attach()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // CLI 인자 파싱
    let args = Args::parse();
    let target_pid = args.pid.unwrap_or(0);
    let duration = args.time.as_deref().map(parse_duration).transpose()?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/io-trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    // eBPF Probe Initialization
    // VFS 계층은 PID가 지정된 경우에만 attach
    if target_pid != 0 {
        let _ = attach_kprobe(&mut ebpf, "vfs_vfs_write", "vfs_write");
        let _ = attach_kprobe(&mut ebpf, "fs_generic_perform_write", "generic_perform_write");
        if let Err(_) = attach_kprobe(&mut ebpf, "fs_iomap_file_buffered_write", "iomap_file_buffered_write") {
            warn!("Failed to init: iomap_file_buffered_write");
        }
        let _ = attach_kprobe(&mut ebpf, "vfs_vfs_write_ret", "vfs_write");
    }
    if let Err(e) = attach_kprobe(&mut ebpf, "fs_do_writepages", "do_writepages") {
            warn!("Failed to init: do_writepages: {e:#}");
        }

    if let Err(e) = attach_fexit(&mut ebpf, "fs_ext4_map_blocks", "ext4_map_blocks") {
            warn!("Failed to init: ext4_map_blocks: {e:#}");
        }

    let _ = attach_kprobe(&mut ebpf, "bio_submit_bio", "submit_bio");
    let _ = attach_kprobe(&mut ebpf, "bio_bio_endio", "bio_endio");
    
    if let Err(e) = attach_kprobe(&mut ebpf, "dev_nvme_queue_rq_exit", "nvme_queue_rq") {
        warn!("Failed to init: nvme_queue_rq fexit, {}", e.to_string());
    }

    let _ = attach_kprobe(&mut ebpf, "dev_nvme_queue_rq", "nvme_queue_rq");
    //if let Err(e) = attach_kprobe(&mut ebpf, "dev_nvme_queue_rq_raw", "nvme_queue_rq") {
    //    warn!("Failed to init: nvme_queue_rq_raw");
    //}
    let _ = attach_kprobe(&mut ebpf, "dev_nvme_complete_batch_req", "nvme_complete_batch_req");
    let _ = attach_kprobe(&mut ebpf, "dev_nvme_complete_rq", "nvme_complete_rq");
        
    let _ = attach_kprobe(&mut ebpf, "bio_blk_mq_start_request", "blk_mq_start_request");

    // Target PID를 eBPF Map에 설정
    let mut pid_map: aya::maps::Array<_, u32> =
        aya::maps::Array::try_from(ebpf.map_mut("TARGET_PID_MAP").unwrap())?;
    pid_map.set(0, target_pid, 0)?;

    // Load user-space tracker
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut tracker = Arc::new(Mutex::new(IoTracker::new()));

    for cpu_id in online_cpus().map_err(|(_msg, err)| err)? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tracker_clone = Arc::clone(&tracker);
        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<IoEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter().take(events.read) {
                    let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const IoEvent) };
                    tracker_clone.lock().unwrap().handle_event(event);
                }
            }
        });
    }

    if target_pid != 0 {
        println!("All probes attached, tracing TGID: {}", target_pid);
    } else {
        println!("All probes attached, tracing all processes (VFS layer disabled)");
    }
    match &duration {
        Some(d) => println!("Will stop after {:?}. Press Ctrl-C to stop early.", d),
        None => println!("Press Ctrl-C to stop."),
    }

    tokio::select! {
        _ = signal::ctrl_c() => {}
        _ = async {
            match duration {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            }
        } => {
            println!("Time limit reached.");
        }
    }
    tracker.lock().unwrap().print_stats();
    println!("Exiting...");

    Ok(())
}
