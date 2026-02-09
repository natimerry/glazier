use crate::ExpError;

pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

pub enum PatternScanOption {
    Begin,
    End,
}

impl Pattern {
    pub fn from(pattern: impl ToString) -> Result<Self, ExpError> {
        let pattern = pattern.to_string();

        let parts = pattern.split_whitespace().collect::<Vec<&str>>();

        let mut bytes = vec![];
        let mut mask = vec![];

        for part in parts {
            if part == "?" || part == "??" || part == "*" {
                bytes.push(0);
            } else {
                bytes
                    .push(u8::from_str_radix(part, 16).map_err(|_| ExpError::InvalidPatternError)?);
                mask.push(true);
            }
        }

        Ok(Pattern { bytes, mask })
    }

    pub fn scan(
        &mut self,
        base: *const u8,
        size: usize,
        opt: PatternScanOption,
    ) -> Option<Vec<*const u8>> {
        let mut matches = vec![];
        let data = unsafe { std::slice::from_raw_parts(base, size) };

        let n = self.bytes.len();
        if size < n {
            return None;
        }
        for i in 0..=(size - n) {
            let mut found = true;

            for j in 0..n {
                if self.mask[j] && data[i + j] != self.bytes[j] {
                    found = false;
                    break;
                }
            }

            if found {
                unsafe {
                    match opt {
                        PatternScanOption::Begin => matches.push(base.add(i)),
                        PatternScanOption::End => matches.push(base.add(i + n)),
                    }
                }
            }
        }

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }
}
