#![forbid(unsafe_code)]

use sentinel_common::ThreatAssessment;
use sentinel_forensics::InvestigationRecord;

#[derive(Default)]
pub struct MemoryStore {
    assessments: Vec<ThreatAssessment>,
    records: Vec<InvestigationRecord>,
}

impl MemoryStore {
    pub fn store_assessment(&mut self, assessment: ThreatAssessment) {
        self.assessments.push(assessment);
    }

    pub fn store_record(&mut self, record: InvestigationRecord) {
        self.records.push(record);
    }

    pub fn assessment_count(&self) -> usize {
        self.assessments.len()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

