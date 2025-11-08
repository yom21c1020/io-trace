use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use std::collections::HashMap;
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use std::sync::{Arc, Mutex};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct IoEvent {
    event_type: u32,
    timestamp: u64,
    tgid: u32,
    pid: u32,

    dev: u32,
    sector: u64,
    inode: u64,
    request_ptr: u64,
    tag: i32,

    size: u32,
    flags: u32,
}

// 이벤트 타입
const EVENT_BTREE_WRITEPAGES:      u32 = 0;
const EVENT_BTRFS_WRITEPAGES:      u32 = 1;
const EVENT_BIO_SUBMIT:            u32 = 2;
const EVENT_BIO_COMPLETE:          u32 = 3;
const EVENT_NVME_QUEUE:            u32 = 4;
const EVENT_NVME_COMPLETE:         u32 = 5;
const EVENT_BLK_MQ_START_REQUEST:  u32 = 6;

const TARGET_TGID: u32 = 979834;

struct IoTracker {
    // FS 레이어: tgid -> (inode, start_time)
    btree_requests: HashMap<u32, (u64, u64)>,
    btrfs_requests: HashMap<u32, (u64, u64)>,

    // BIO 레이어: (tgid, dev, sector) -> (submit_time, request_ptr)
    bio_requests: HashMap<(u32, u32, u64), (u64, u64)>,

    // NVMe 레이어: request_ptr -> (queue_time, bio_info)
    nvme_requests: HashMap<u64, (u64, u32, u64)>, // ptr -> (time, dev, sector)
    nvme_req_tgid: HashMap<(u64, i32), (u32, u64)>, // (ptr, tag) -> (dev, sector)

    // 통계
    stats: IoStats,
}

#[derive(Default, Debug)]
struct IoStats {
    fs_to_bio_latency: Vec<u64>,
    bio_latency: Vec<u64>,
    nvme_latency: Vec<u64>,
    total_latency: Vec<u64>,
}

impl IoTracker {
    fn new() -> Self {
        Self {
            btree_requests: HashMap::new(),
            btrfs_requests: HashMap::new(),
            bio_requests: HashMap::new(),
            nvme_requests: HashMap::new(),
            nvme_req_tgid: HashMap::new(),
            stats: IoStats::default(),
        }
    }

    fn handle_event(&mut self, event: IoEvent) {
        match event.event_type {
            EVENT_BTREE_WRITEPAGES => {
                self.btree_requests
                    .insert(event.tgid, (event.inode, event.timestamp));
                println!(
                    "[{:>12}] btrfs Layer  : btree_writepages started - tgid: {}, inode: {}",
                    event.timestamp, event.tgid, event.inode
                );
            }

            EVENT_BTRFS_WRITEPAGES => {
                self.btrfs_requests
                    .insert(event.tgid, (event.inode, event.timestamp));
                println!(
                    "[{:>12}] btrfs Layer  : writepages started - tgid: {}, inode: {}",
                    event.timestamp, event.tgid, event.inode
                );
            }

            EVENT_BIO_SUBMIT => {
                // FS -> BIO 레이턴시 계산
                if let Some((inode, fs_time)) = self.btrfs_requests.get(&event.tgid) {
                    let fs_to_bio = event.timestamp - fs_time;
                    self.stats.fs_to_bio_latency.push(fs_to_bio);
                    println!(
                        "[{:>12}] FS->BIO   : tgid: {}, inode: {}, dev: ({},{}), sector: {}, latency: {} ns",
                        event.timestamp,
                        event.tgid,
                        "-",
                        event.dev >> 20,
                        event.dev & ((1 << 20) - 1),
                        event.sector,
                        fs_to_bio
                    );
                }

                self.bio_requests.insert(
                    (event.tgid, event.dev, event.sector),
                    (event.timestamp, event.request_ptr),
                );

                println!(
                    "[{:>12}] BIO Submit: tgid: {}, dev: ({},{}), sector: {}, size: {}",
                    event.timestamp,
                    event.tgid,
                    event.dev >> 20,
                    event.dev & ((1 << 20) - 1),
                    event.sector,
                    event.size
                );
            }

            EVENT_BIO_COMPLETE => {
                if let Some((submit_time, _)) = self.bio_requests.remove(&(event.tgid, event.dev, event.sector))
                {
                    let bio_latency = event.timestamp - submit_time;
                    self.stats.bio_latency.push(bio_latency);

                    println!(
                        "[{:>12}] BIO Complete: tgid: {}, dev: ({},{}), sector: {}, latency: {} ns",
                        event.timestamp,
                        event.tgid,
                        event.dev >> 20,
                        event.dev & ((1 << 20) - 1),
                        event.sector,
                        bio_latency
                    );

                    // FS 요청 정리
                    self.btrfs_requests.remove(&event.tgid);
                }
            }

            EVENT_BLK_MQ_START_REQUEST => {
                //if event.tgid == TARGET_TGID {
                //    self.nvme_req_tgid.insert((event.request_ptr, event.tag), (event.dev, event.sector));
                //
                    println!(
                        "[{:>12}] blk_mq start: tgid: {}, ptr: {:#x}, tag: {}",
                        event.timestamp, event.tgid, event.request_ptr, event.tag
                    );
                // }
            }

            EVENT_NVME_QUEUE => {
                if let Some((dev, sector)) = self.nvme_req_tgid.remove(&(event.request_ptr, event.tag)) {
                    self.nvme_requests.insert(
                        event.request_ptr,
                        (event.timestamp, event.dev, event.sector),
                    );
                
                    println!(
                        "[{:>12}] NVMe Queue: request_ptr: {:#x}, tag: {}, tgid: {}, dev: ({},{}), sector: {}",
                        event.timestamp,
                        event.request_ptr,
                        event.tag,
                        event.tgid,
                        event.dev >> 20,
                        event.dev & ((1 << 20) - 1),
                        event.sector
                    );
                } else {
                    println!(
                        "[{:>12}] NO MATCH// NVMe Queue: request_ptr: {:#x}, tag: {}, tgid: {}, dev: ({},{}), sector: {}",
                        event.timestamp,
                        event.request_ptr,
                        event.tag,
                        event.tgid,
                        event.dev >> 20,
                        event.dev & ((1 << 20) - 1),
                        event.sector
                    );
                }
            }

            EVENT_NVME_COMPLETE => {
                if let Some((queue_time, dev, sector)) =
                    self.nvme_requests.remove(&event.request_ptr)
                {
                    let nvme_latency = event.timestamp - queue_time;
                    self.stats.nvme_latency.push(nvme_latency);

                    println!(
                        "[{:>12}] NVMe Complete: request_ptr: {:#x}, dev: ({},{}), sector: {}, latency: {} ns",
                        event.timestamp,
                        event.request_ptr,
                        dev >> 20,
                        dev & ((1 << 20) - 1),
                        sector,
                        nvme_latency
                    );
                }
            }

            _ => {}
        }
    }

    fn print_stats(&self) {
        println!("\n=== I/O Statistics ===");

        if !self.stats.fs_to_bio_latency.is_empty() {
            let avg: u64 = self.stats.fs_to_bio_latency.iter().sum::<u64>()
                / self.stats.fs_to_bio_latency.len() as u64;
            println!("FS->BIO avg latency: {} ns", avg);
        }

        if !self.stats.bio_latency.is_empty() {
            let avg: u64 =
                self.stats.bio_latency.iter().sum::<u64>() / self.stats.bio_latency.len() as u64;
            println!("BIO avg latency: {} ns", avg);
        }

        if !self.stats.nvme_latency.is_empty() {
            let avg: u64 =
                self.stats.nvme_latency.iter().sum::<u64>() / self.stats.nvme_latency.len() as u64;
            println!("NVMe avg latency: {} ns", avg);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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
    let program_bio_submit_bio: &mut KProbe =
        ebpf.program_mut("bio_submit_bio").unwrap().try_into()?;
    program_bio_submit_bio.load()?;
    program_bio_submit_bio.attach("submit_bio", 0)?;

    let program_bio_bio_endio: &mut KProbe =
        ebpf.program_mut("bio_bio_endio").unwrap().try_into()?;
    program_bio_bio_endio.load()?;
    program_bio_bio_endio.attach("bio_endio", 0)?;

    let program_dev_nvme_queue_rq: &mut KProbe =
        ebpf.program_mut("dev_nvme_queue_rq").unwrap().try_into()?;
    program_dev_nvme_queue_rq.load()?;
    program_dev_nvme_queue_rq.attach("nvme_queue_rq", 0)?;

    let program_dev_nvme_complete_batch_req: &mut KProbe = ebpf
        .program_mut("dev_nvme_complete_batch_req")
        .unwrap()
        .try_into()?;
    program_dev_nvme_complete_batch_req.load()?;
    program_dev_nvme_complete_batch_req.attach("nvme_complete_batch_req", 0)?;

    let program_fs_btree_writepages: &mut KProbe = ebpf
        .program_mut("fs_btree_writepages")
        .unwrap()
        .try_into()?;
    program_fs_btree_writepages.load()?;
    program_fs_btree_writepages.attach("btree_writepages", 0)?;

    let program_fs_btrfs_writepages: &mut KProbe = ebpf
        .program_mut("fs_btrfs_writepages")
        .unwrap()
        .try_into()?;
    program_fs_btrfs_writepages.load()?;
    program_fs_btrfs_writepages.attach("btrfs_writepages", 0)?;

    let program_bio_blk_mq_start_request: &mut KProbe = ebpf
        .program_mut("bio_blk_mq_start_request")
        .unwrap()
        .try_into()?;
    program_bio_blk_mq_start_request.load()?;
    program_bio_blk_mq_start_request.attach("blk_mq_start_request", 0)?;

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

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    tracker.lock().unwrap().print_stats();
    println!("Exiting...");

    Ok(())
}
