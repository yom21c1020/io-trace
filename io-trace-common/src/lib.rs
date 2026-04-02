#![no_std]

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    VfsWrite = 0,
    GenericPerformWrite = 1,
    VfsWriteRet = 2,
    BioSubmit = 3,
    BioComplete = 4,
    BlkMqStartRequest = 5,
    NvmeQueue = 6,
    NvmeQueueExit = 7,
    NvmeCompleteBatch = 8,
    NvmeComplete = 9,
    NvmeQueueRaw = 10,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoEvent {
    pub event_type: EventType,
    pub timestamp: u64,
    pub tgid: u32,
    pub pid: u32,

    pub dev: u32,
    pub sector: u64,
    pub inode: u64,
    pub request_ptr: u64,
    pub tag: i32,

    pub size: u32,
    pub flags: u32,
}

pub fn dev_to_maj_min(dev: u32) -> (u32, u32) {
    let maj: u32 = dev >> 20;
    let min: u32 = dev & ((1 << 20) - 1);
    (maj, min)
}
