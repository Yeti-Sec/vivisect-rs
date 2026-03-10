//! Register context abstraction.

use crate::error::VivResult;
use std::collections::HashMap;

/// Register information.
#[derive(Clone, Debug)]
pub struct RegisterInfo {
    /// Register name.
    pub name: String,
    /// Register index.
    pub index: usize,
    /// Size in bits.
    pub size: usize,
    /// Parent register index (for sub-registers like AL/AH/AX/EAX/RAX).
    pub parent: Option<usize>,
    /// Bit offset within parent.
    pub parent_offset: usize,
}

/// Snapshot of register state.
#[derive(Clone, Debug, Default)]
pub struct RegisterSnapshot {
    pub values: HashMap<usize, u64>,
}

/// Trait for register context management.
pub trait RegisterContext: Send + Sync {
    /// Get a register value by name.
    fn get_register(&self, name: &str) -> VivResult<u64>;

    /// Set a register value by name.
    fn set_register(&mut self, name: &str, value: u64) -> VivResult<()>;

    /// Get a register value by index.
    fn get_register_by_index(&self, index: usize) -> VivResult<u64>;

    /// Set a register value by index.
    fn set_register_by_index(&mut self, index: usize, value: u64) -> VivResult<()>;

    /// Get all register names.
    fn get_register_names(&self) -> Vec<String>;

    /// Get register info by name.
    fn get_register_info(&self, name: &str) -> Option<RegisterInfo>;

    /// Get register info by index.
    fn get_register_info_by_index(&self, index: usize) -> Option<RegisterInfo>;

    /// Get the program counter register name.
    fn get_pc_name(&self) -> &str;

    /// Get the stack pointer register name.
    fn get_sp_name(&self) -> &str;

    /// Get program counter value.
    fn get_program_counter(&self) -> u64 {
        self.get_register(self.get_pc_name()).unwrap_or(0)
    }

    /// Set program counter value.
    fn set_program_counter(&mut self, value: u64) -> VivResult<()> {
        let pc_name = self.get_pc_name().to_string();
        self.set_register(&pc_name, value)
    }

    /// Get stack pointer value.
    fn get_stack_pointer(&self) -> u64 {
        self.get_register(self.get_sp_name()).unwrap_or(0)
    }

    /// Set stack pointer value.
    fn set_stack_pointer(&mut self, value: u64) -> VivResult<()> {
        let sp_name = self.get_sp_name().to_string();
        self.set_register(&sp_name, value)
    }

    /// Take a snapshot of current register state.
    fn snapshot(&self) -> RegisterSnapshot;

    /// Restore from a register snapshot.
    fn restore(&mut self, snapshot: &RegisterSnapshot) -> VivResult<()>;
}

/// A basic register context implementation.
#[derive(Clone, Debug)]
pub struct BasicRegisterContext {
    /// Register values by index.
    values: Vec<u64>,
    /// Register info by name.
    by_name: HashMap<String, usize>,
    /// Register info by index.
    info: Vec<RegisterInfo>,
    /// Program counter register index.
    pc_index: usize,
    /// Stack pointer register index.
    sp_index: usize,
}

impl BasicRegisterContext {
    /// Create a new register context.
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            by_name: HashMap::new(),
            info: Vec::new(),
            pc_index: 0,
            sp_index: 0,
        }
    }

    /// Add a register definition.
    pub fn add_register(&mut self, name: &str, size: usize) -> usize {
        let index = self.info.len();
        self.info.push(RegisterInfo {
            name: name.to_string(),
            index,
            size,
            parent: None,
            parent_offset: 0,
        });
        self.by_name.insert(name.to_string(), index);
        self.values.push(0);
        index
    }

    /// Add a sub-register.
    pub fn add_sub_register(&mut self, name: &str, parent: usize, offset: usize, size: usize) -> usize {
        let index = self.info.len();
        self.info.push(RegisterInfo {
            name: name.to_string(),
            index,
            size,
            parent: Some(parent),
            parent_offset: offset,
        });
        self.by_name.insert(name.to_string(), index);
        self.values.push(0);
        index
    }

    /// Set the program counter register.
    pub fn set_pc_register(&mut self, index: usize) {
        self.pc_index = index;
    }

    /// Set the stack pointer register.
    pub fn set_sp_register(&mut self, index: usize) {
        self.sp_index = index;
    }
}

impl Default for BasicRegisterContext {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterContext for BasicRegisterContext {
    fn get_register(&self, name: &str) -> VivResult<u64> {
        let index = self.by_name.get(name).ok_or_else(|| {
            crate::error::VivError::InvalidRegister {
                name: name.to_string(),
            }
        })?;
        self.get_register_by_index(*index)
    }

    fn set_register(&mut self, name: &str, value: u64) -> VivResult<()> {
        let index = self.by_name.get(name).ok_or_else(|| {
            crate::error::VivError::InvalidRegister {
                name: name.to_string(),
            }
        })?;
        self.set_register_by_index(*index, value)
    }

    fn get_register_by_index(&self, index: usize) -> VivResult<u64> {
        let info = self.info.get(index).ok_or_else(|| {
            crate::error::VivError::InvalidRegister {
                name: format!("index {}", index),
            }
        })?;

        if let Some(parent) = info.parent {
            // Sub-register: extract bits from parent
            let parent_val = self.values.get(parent).copied().unwrap_or(0);
            let mask = (1u64 << info.size) - 1;
            Ok((parent_val >> info.parent_offset) & mask)
        } else {
            Ok(self.values.get(index).copied().unwrap_or(0))
        }
    }

    fn set_register_by_index(&mut self, index: usize, value: u64) -> VivResult<()> {
        let info = self.info.get(index).ok_or_else(|| {
            crate::error::VivError::InvalidRegister {
                name: format!("index {}", index),
            }
        })?.clone();

        if let Some(parent) = info.parent {
            // Sub-register: modify bits in parent
            if let Some(parent_val) = self.values.get_mut(parent) {
                let mask = (1u64 << info.size) - 1;
                let clear_mask = !(mask << info.parent_offset);
                *parent_val = (*parent_val & clear_mask) | ((value & mask) << info.parent_offset);
            }
        } else if let Some(val) = self.values.get_mut(index) {
            let mask = (1u64 << info.size) - 1;
            *val = value & mask;
        }

        Ok(())
    }

    fn get_register_names(&self) -> Vec<String> {
        self.by_name.keys().cloned().collect()
    }

    fn get_register_info(&self, name: &str) -> Option<RegisterInfo> {
        let index = self.by_name.get(name)?;
        self.info.get(*index).cloned()
    }

    fn get_register_info_by_index(&self, index: usize) -> Option<RegisterInfo> {
        self.info.get(index).cloned()
    }

    fn get_pc_name(&self) -> &str {
        self.info
            .get(self.pc_index)
            .map(|i| i.name.as_str())
            .unwrap_or("pc")
    }

    fn get_sp_name(&self) -> &str {
        self.info
            .get(self.sp_index)
            .map(|i| i.name.as_str())
            .unwrap_or("sp")
    }

    fn snapshot(&self) -> RegisterSnapshot {
        let mut values = HashMap::new();
        for (i, &v) in self.values.iter().enumerate() {
            values.insert(i, v);
        }
        RegisterSnapshot { values }
    }

    fn restore(&mut self, snapshot: &RegisterSnapshot) -> VivResult<()> {
        for (&index, &value) in &snapshot.values {
            if let Some(val) = self.values.get_mut(index) {
                *val = value;
            }
        }
        Ok(())
    }
}
