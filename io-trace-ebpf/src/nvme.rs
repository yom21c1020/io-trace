use aya_ebpf::EbpfContext;
use aya_ebpf::helpers;
use aya_ebpf::macros::{kprobe, kretprobe};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_log_ebpf::debug;

use io_trace_common::{EventType, IoEvent};

use crate::btf::nvme::{blk_mq_hw_ctx, nvme_queue};
use crate::btf::vmlinux::{bio, blk_mq_queue_data, request};
use crate::define_probe;
use crate::helpers::ERR_CODE;
use crate::maps::{BIO_MAP, ENTRY_MAP, EVENTS, EntryData, IN_NVME_QUEUE_RQ, NVME_DEVICE_MAP};
use crate::{ptr_field_is_null, read_field, read_ptr_field};

define_probe!(#[kprobe] dev_nvme_queue_rq, ProbeContext, try_dev_nvme_queue_rq);
fn try_dev_nvme_queue_rq(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        let pid: u32 = ctx.pid();
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let hctx_ptr: *const blk_mq_hw_ctx = ctx.arg(0).ok_or(ERR_CODE)?;
        let bd_ptr: *const blk_mq_queue_data = ctx.arg(1).ok_or(ERR_CODE)?;

        if let Some(flag) = IN_NVME_QUEUE_RQ.get_ptr_mut(0) {
            *flag = 1;
        }

        if ptr_field_is_null!(bd_ptr, blk_mq_queue_data, rq, request) {
            debug!(&ctx, "nvme_queue_rq //// pid {}, req_ptr null, ", pid);
            return Err(0);
        }

        let req_ptr: *const request =
            read_ptr_field!(bd_ptr, blk_mq_queue_data, rq, request).map_err(|_| ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        let nvmeq_ptr: *const nvme_queue =
            read_ptr_field!(hctx_ptr, blk_mq_hw_ctx, driver_data, nvme_queue)
                .map_err(|_| ERR_CODE)?;

        let mut bio_ptr_val: u64 = 0;
        let bio_ptr: *const bio =
            read_ptr_field!(req_ptr, request, bio, bio).map_err(|_| ERR_CODE)?;
        if bio_ptr != core::ptr::null() {
            bio_ptr_val = bio_ptr as u64;
        }

        debug!(
            &ctx,
            "nvme_queue_rq hit ////// pid {}, req_ptr {:x}, tag {}, bio_ptr {:x}",
            pid, req_ptr as u64, tag, bio_ptr as u64
        );

        // driver latency 측정을 위해 ENTRY_MAP은 항상 저장 (kprobe/kretprobe 동일 컨텍스트)
        let data = EntryData {
            req_ptr: req_ptr as u64,
            ts_entry: timestamp,
        };
        ENTRY_MAP.insert(&pid, &data, 0).ok();

        if let Some(&entry_ts) = BIO_MAP.get(&(bio_ptr_val)) {
            BIO_MAP.remove(&(bio_ptr as u64)).ok();
            debug!(
                &ctx,
                "nvme_queue_rq hit with pid {}, bio_ptr {:x}, elapsed {} ns",
                pid, bio_ptr as u64, timestamp - entry_ts
            );

            let event = IoEvent {
                event_type: EventType::NvmeQueue,
                timestamp,
                tgid,
                pid,
                inode: bio_ptr_val,
                dev: 0,
                sector: 0,
                request_ptr: req_ptr as u64,
                tag,
                size: 0,
                flags: 0,
            };

            EVENTS.output(&ctx, &event, 0);
        }

        Ok(0)
    }
}

define_probe!(#[kretprobe] dev_nvme_queue_rq_exit, RetProbeContext, try_dev_nvme_queue_rq_exit);
fn try_dev_nvme_queue_rq_exit(ctx: RetProbeContext) -> Result<u32, u32> {
    unsafe {
        let ret: u32 = ctx.ret().unwrap_or(1);
        if ret != 0 {
            return Err(0);
        }
        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();

        let tgid = ctx.tgid();
        let pid = ctx.pid();

        if let Some(flag) = IN_NVME_QUEUE_RQ.get_ptr_mut(0) {
            *flag = 0;
        }

        if let Some(&data) = ENTRY_MAP.get(&pid) {
            debug!(
                &ctx,
                "nvme_queue_rq ret: pid {}, req_ptr {:x}, driver_latency {} ns",
                pid, data.req_ptr, (timestamp - data.ts_entry)
            );
            ENTRY_MAP.remove(&pid).ok();

            // device latency 측정 시작점: request_ptr → exit timestamp
            NVME_DEVICE_MAP.insert(&data.req_ptr, &timestamp, 0).ok();

            let event = IoEvent {
                event_type: EventType::NvmeQueueExit,
                timestamp,
                tgid,
                pid,
                inode: 0,
                dev: 0,
                sector: 0,
                request_ptr: data.req_ptr as u64,
                tag: 0,
                size: 0,
                flags: 0,
            };
            EVENTS.output(&ctx, &event, 0);
        }

        Ok(0)
    }
}

define_probe!(#[kprobe] dev_nvme_complete_batch_req, ProbeContext, try_dev_nvme_complete_batch_req);
fn try_dev_nvme_complete_batch_req(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        // if !check_tgid(tgid) {
        //     return Ok(0);
        // }

        let pid: u32 = ctx.pid();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        let event = IoEvent {
            event_type: EventType::NvmeCompleteBatch,
            timestamp: helpers::r#gen::bpf_ktime_get_ns(),
            tgid,
            pid,
            inode: 0,
            dev: 0,
            sector: 0,
            request_ptr: req_ptr as u64,
            tag,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }
    Ok(0)
}

define_probe!(#[kprobe] dev_nvme_complete_rq, ProbeContext, try_dev_nvme_complete_rq);
fn try_dev_nvme_complete_rq(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tgid: u32 = ctx.tgid();
        // if !check_tgid(tgid) {
        //     return Ok(0);
        // }

        let pid: u32 = ctx.pid();

        let timestamp: u64 = helpers::r#gen::bpf_ktime_get_ns();
        let req_ptr: *const request = ctx.arg(0).ok_or(ERR_CODE)?;
        let tag: i32 = read_field!(req_ptr, request, tag, i32).map_err(|_| ERR_CODE)?;

        let event = IoEvent {
            event_type: EventType::NvmeComplete,
            timestamp,
            tgid,
            pid,
            inode: 0,
            dev: 0,
            sector: 0,
            request_ptr: req_ptr as u64,
            tag,
            size: 0,
            flags: 0,
        };
        EVENTS.output(&ctx, &event, 0);
    }
    Ok(0)
}
