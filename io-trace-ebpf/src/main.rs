#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, EbpfContext};
use aya_log_ebpf::info;
use aya_ebpf::helpers;
use aya_ebpf::macros::map;

#[map]
static REQUESTS: aya_ebpf::maps::HashMap::<RequestKey, u64> = aya_ebpf::maps::HashMap::<RequestKey, u64>::with_max_entries(10240, 0);

#[derive(Clone, Copy)]
#[repr(C)]
struct RequestKey {
    dev: u32,
    sector: u64,
}

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
        let args = &*(ctx.as_ptr() as *const BlockRqIssueArgs);

        let key: RequestKey = RequestKey {
            dev: args.dev,
            sector: args.sector,
        };
        REQUESTS.insert(&key, &time, 0);
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
        let args = &*(ctx.as_ptr() as *const BlockRqCompleteArgs);
        let key: RequestKey = RequestKey {
            dev: args.dev,
            sector: args.sector,
        };

        if let Some(issued_time) = REQUESTS.get(&key) {
            let latency = time - *issued_time;
            info!(&ctx, "request completed: dev {}, sector {}, latency {}", key.dev, key.sector, latency);
            REQUESTS.remove(&key);
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
