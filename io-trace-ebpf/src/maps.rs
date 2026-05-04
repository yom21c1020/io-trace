use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerfEventArray};

use io_trace_common::IoEvent;

#[map]
pub(crate) static EVENTS: PerfEventArray<IoEvent> = PerfEventArray::new(0);

#[map]
pub(crate) static TARGET_PID_MAP: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub(crate) static IN_NVME_QUEUE_RQ: PerCpuArray<u8> = PerCpuArray::with_max_entries(1, 0);

#[derive(Clone, Copy)]
pub(crate) struct EntryData {
    pub(crate) req_ptr: u64,
    pub(crate) ts_entry: u64,
}

#[map]
pub(crate) static ENTRY_MAP: HashMap<u32, EntryData> = HashMap::with_max_entries(1024, 0);

#[map]
pub(crate) static BIO_MAP: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

#[map]
pub(crate) static NVME_DEVICE_MAP: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);
