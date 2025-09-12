#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, tracepoint}, programs::{ProbeContext, TracePointContext}};
use aya_log_ebpf::info;
use aya_ebpf::helpers;
use aya_ebpf::macros::map;

#[map]
static BIO_REQUESTS: aya_ebpf::maps::HashMap::<RequestKey, u64> = aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    dev: u32,
    sector: u64,
}

/* legacy
#[allow(dead_code)]
#[repr(C, packed)]
struct BlockRqIssueArgs {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    dev: u32,
    _pad: u32,
    sector: u64,
    nr_sector: u32,
    bytes: u32,
    ioprio: u16,
    rwbs: [u8; 9],
    comm: [u8; 16],
}

#[allow(dead_code)]
#[repr(C, packed)]
struct BlockRqCompleteArgs {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    dev: u32,
    _pad1: u32,
    sector: u64,
    nr_sector: u32,
    error: i32,
    ioprio: u16,
    rwbs: [u8; 9],
    _pad2: u8,
    cmd: [u8; 16],
}
*/

fn dev_to_maj_min(dev: u32) -> (u32, u32) {
    let maj: u32 = dev >> 20;
    let min: u32 = dev & ((1 << 20) - 1);
    (maj, min)
}

#[kprobe]
pub fn io_trace_submit_bio(ctx: ProbeContext) -> u32 {
    match try_io_trace_submit_bio(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_io_trace_submit_bio(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let req_ptr: u64 = ctx.arg(0).ok_or(1u32)?;     // pointer
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();
        
        let bi_bdev: u64 = helpers::bpf_probe_read_kernel((req_ptr + 8) as *const u64).map_err(|_| 1u32)?; //
        if bi_bdev == 0 { return Ok(0); }
        
        // u64 + u64 + 8byte + 8byte + 8byte + 8byte(ulong) + 4byte = 64 + 64 + 64 + 64 = 256 + 64 + 64 = 384 + 32 = 416bits == 52bytes
        let bd_dev: u32 = helpers::bpf_probe_read_kernel((bi_bdev + 52) as *const u32).map_err(|_| 1u32)?;
        let (maj, min) = dev_to_maj_min(bd_dev);

        // u64 + u64 + blk_opf_t(__u32) + u16 + u16 + enum rw_hint(8) + u8 + blk_status_t(u8) + atomic_t(i32)
        // 8 + 8 + 4 + 2 + 2 + 1 + 1 + 1 + 4 == 24 + 7 == 31bytes => align to 32b
        let bi_sector: u64 = helpers::bpf_probe_read_kernel((req_ptr + 32) as *const u64).map_err(|_| 1u32)?;

        let key: RequestKey = RequestKey { dev: bd_dev, sector: bi_sector };
        BIO_REQUESTS.insert(&key, &time, 0).map_err(|_| 1u32)?;
        info!(&ctx, "insert request (kprobe): dev {} ({}, {}), sector {}, time {}", key.dev, maj, min, key.sector, time);

    }
    //info!(&ctx, "kprobe block_rq_issue called");
    Ok(0)
}

#[tracepoint]
pub fn io_trace_issue(ctx: TracePointContext) -> u32 {
    match try_io_trace_issue(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_io_trace_issue(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let dev: u32 = ctx.read_at(8).map_err(|_| 1u32)?;
        let sector: u64 = ctx.read_at(16).map_err(|_| 1u32)?;

        let key: RequestKey = RequestKey { dev, sector };
        BIO_REQUESTS.insert(&key, &time, 0).map_err(|_| 1u32)?;
        info!(&ctx, "insert request: dev {}, sector {}, time {}", key.dev, key.sector, time);
    }
    //info!(&ctx, "tracepoint block_rq_issue called");
    Ok(0)
}

#[tracepoint]
pub fn io_trace(ctx: TracePointContext) -> u32 {
    match try_io_trace(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_io_trace(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let time: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let dev: u32 = ctx.read_at(8).map_err(|_| 1u32)?;
        let sector: u64 = ctx.read_at(16).map_err(|_| 1u32)?;

        let key: RequestKey = RequestKey { dev, sector };

        if let Some(issued_time) = BIO_REQUESTS.get(&key) {
            let latency = time - *issued_time;
            info!(&ctx, "request completed: dev {}, sector {}, latency {}", key.dev, key.sector, latency);
            BIO_REQUESTS.remove(&key);
        } else {
            info!(&ctx, "request completed but not found: dev {}, sector {}", key.dev, key.sector);
        }
    }
    //info!(&ctx, "tracepoint block_rq_complete called");
    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
