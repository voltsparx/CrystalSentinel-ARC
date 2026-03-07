#![forbid(unsafe_code)]

use std::collections::HashMap;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub source: String,
    pub destination: String,
    pub protocol: String,
}

#[derive(Clone, Debug, Default)]
pub struct FlowRecord {
    pub event_count: usize,
}

#[derive(Default)]
pub struct FlowTracker {
    records: HashMap<FlowKey, FlowRecord>,
}

impl FlowTracker {
    pub fn observe(&mut self, key: FlowKey) -> usize {
        let record = self.records.entry(key).or_default();
        record.event_count += 1;
        record.event_count
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

