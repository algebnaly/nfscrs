use std::sync::Mutex;

// cureently, we did not support multi slot concurrent.
pub struct SlotTable {
    slots: Vec<Mutex<u32>>,
}

impl SlotTable {}
