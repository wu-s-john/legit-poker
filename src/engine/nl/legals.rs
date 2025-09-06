use super::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalActions {
    pub may_fold: bool,
    pub may_check: bool,
    pub call_amount: Option<Chips>,
    pub bet_to_range: Option<std::ops::RangeInclusive<Chips>>,
    pub raise_to_range: Option<std::ops::RangeInclusive<Chips>>,
}

impl Default for LegalActions {
    fn default() -> Self {
        Self {
            may_fold: false,
            may_check: false,
            call_amount: None,
            bet_to_range: None,
            raise_to_range: None,
        }
    }
}
