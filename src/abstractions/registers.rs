//! Register context abstraction.

use crate::error::VivResult;
use std::collections::HashMap;

/// Compute a bitmask for the given bit width (0..=64).
/// For size == 64 returns u64::MAX; for size < 64 returns (1u64 << size) - 1.
#[inline]
fn bit_mask(size: usize) -> u64 {
    if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    }
}

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

// RegisterSnapshot Default is derived above

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
            let mask = bit_mask(info.size);
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
                let mask = bit_mask(info.size);
                let clear_mask = !(mask << info.parent_offset);
                *parent_val = (*parent_val & clear_mask) | ((value & mask) << info.parent_offset);
            }
        } else if let Some(val) = self.values.get_mut(index) {
            let mask = bit_mask(info.size);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_x86_context() -> BasicRegisterContext {
        let mut ctx = BasicRegisterContext::new();
        let rax = ctx.add_register("rax", 64);
        let _rbx = ctx.add_register("rbx", 64);
        let _rcx = ctx.add_register("rcx", 64);
        let rsp = ctx.add_register("rsp", 64);
        let rip = ctx.add_register("rip", 64);
        // Add sub-register: eax is lower 32 bits of rax
        let _eax = ctx.add_sub_register("eax", rax, 0, 32);
        // Add sub-register: ax is lower 16 bits of rax
        let _ax = ctx.add_sub_register("ax", rax, 0, 16);
        // Add sub-register: al is lower 8 bits of rax
        let _al = ctx.add_sub_register("al", rax, 0, 8);
        // Add sub-register: ah is bits 8-15 of rax
        let _ah = ctx.add_sub_register("ah", rax, 8, 8);
        ctx.set_pc_register(rip);
        ctx.set_sp_register(rsp);
        ctx
    }

    #[test]
    fn test_basic_register_context_new() {
        let ctx = BasicRegisterContext::new();
        assert!(ctx.get_register_names().is_empty());
    }

    #[test]
    fn test_basic_register_context_default() {
        let ctx = BasicRegisterContext::default();
        assert!(ctx.get_register_names().is_empty());
    }

    #[test]
    fn test_add_register() {
        let mut ctx = BasicRegisterContext::new();
        let idx = ctx.add_register("rax", 64);
        assert_eq!(idx, 0);
        let idx2 = ctx.add_register("rbx", 64);
        assert_eq!(idx2, 1);
    }

    #[test]
    fn test_get_set_register_by_name() {
        let mut ctx = make_x86_context();
        ctx.set_register("rax", 0xDEADBEEF).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_get_set_register_by_index() {
        let mut ctx = make_x86_context();
        ctx.set_register_by_index(0, 0x12345678).unwrap();
        assert_eq!(ctx.get_register_by_index(0).unwrap(), 0x12345678);
    }

    #[test]
    fn test_invalid_register_name() {
        let ctx = make_x86_context();
        assert!(ctx.get_register("nonexistent").is_err());
    }

    #[test]
    fn test_invalid_register_index() {
        let ctx = make_x86_context();
        assert!(ctx.get_register_by_index(999).is_err());
    }

    #[test]
    fn test_sub_register_read() {
        let mut ctx = make_x86_context();
        // Set rax to a known value (within 63-bit range)
        ctx.set_register("rax", 0x0122334455667788).unwrap();
        // eax should be lower 32 bits
        let eax = ctx.get_register("eax").unwrap();
        assert_eq!(eax, 0x55667788);
        // ax should be lower 16 bits
        let ax = ctx.get_register("ax").unwrap();
        assert_eq!(ax, 0x7788);
        // al should be lower 8 bits
        let al = ctx.get_register("al").unwrap();
        assert_eq!(al, 0x88);
        // ah should be bits 8-15
        let ah = ctx.get_register("ah").unwrap();
        assert_eq!(ah, 0x77);
    }

    #[test]
    fn test_sub_register_write() {
        let mut ctx = make_x86_context();
        ctx.set_register("rax", 0xFFFFFFFFFFFFFFFF).unwrap();
        // Write to al (lower 8 bits)
        ctx.set_register("al", 0x42).unwrap();
        let rax = ctx.get_register("rax").unwrap();
        // Lower 8 bits should be 0x42, rest unchanged
        assert_eq!(rax & 0xFF, 0x42);
        assert_eq!((rax >> 8) & 0xFF, 0xFF); // ah unchanged
    }

    #[test]
    fn test_sub_register_write_ah() {
        let mut ctx = make_x86_context();
        ctx.set_register("rax", 0).unwrap();
        ctx.set_register("ah", 0xAB).unwrap();
        let rax = ctx.get_register("rax").unwrap();
        assert_eq!(rax & 0xFF, 0x00); // al should be 0
        assert_eq!((rax >> 8) & 0xFF, 0xAB); // ah should be 0xAB
    }

    #[test]
    fn test_pc_sp_names() {
        let ctx = make_x86_context();
        assert_eq!(ctx.get_pc_name(), "rip");
        assert_eq!(ctx.get_sp_name(), "rsp");
    }

    #[test]
    fn test_program_counter() {
        let mut ctx = make_x86_context();
        ctx.set_program_counter(0x401000).unwrap();
        assert_eq!(ctx.get_program_counter(), 0x401000);
    }

    #[test]
    fn test_stack_pointer() {
        let mut ctx = make_x86_context();
        ctx.set_stack_pointer(0x7FFE0000).unwrap();
        assert_eq!(ctx.get_stack_pointer(), 0x7FFE0000);
    }

    #[test]
    fn test_get_register_names() {
        let ctx = make_x86_context();
        let names = ctx.get_register_names();
        assert!(names.contains(&"rax".to_string()));
        assert!(names.contains(&"rbx".to_string()));
        assert!(names.contains(&"rsp".to_string()));
        assert!(names.contains(&"rip".to_string()));
        assert!(names.contains(&"eax".to_string()));
        assert!(names.contains(&"al".to_string()));
        assert!(names.contains(&"ah".to_string()));
    }

    #[test]
    fn test_get_register_info_by_name() {
        let ctx = make_x86_context();
        let info = ctx.get_register_info("rax").unwrap();
        assert_eq!(info.name, "rax");
        assert_eq!(info.size, 64);
        assert!(info.parent.is_none());
    }

    #[test]
    fn test_get_register_info_sub_register() {
        let ctx = make_x86_context();
        let info = ctx.get_register_info("eax").unwrap();
        assert_eq!(info.name, "eax");
        assert_eq!(info.size, 32);
        assert!(info.parent.is_some());
        assert_eq!(info.parent_offset, 0);
    }

    #[test]
    fn test_get_register_info_nonexistent() {
        let ctx = make_x86_context();
        assert!(ctx.get_register_info("nonexistent").is_none());
    }

    #[test]
    fn test_snapshot_and_restore() {
        let mut ctx = make_x86_context();
        ctx.set_register("rax", 0xAAAA).unwrap();
        ctx.set_register("rbx", 0xBBBB).unwrap();
        ctx.set_register("rsp", 0x7FFE0000).unwrap();

        let snapshot = ctx.snapshot();

        // Modify registers
        ctx.set_register("rax", 0).unwrap();
        ctx.set_register("rbx", 0).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), 0);

        // Restore
        ctx.restore(&snapshot).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), 0xAAAA);
        assert_eq!(ctx.get_register("rbx").unwrap(), 0xBBBB);
        assert_eq!(ctx.get_register("rsp").unwrap(), 0x7FFE0000);
    }

    #[test]
    fn test_register_info_construction() {
        let info = RegisterInfo {
            name: "test_reg".to_string(),
            index: 5,
            size: 32,
            parent: Some(2),
            parent_offset: 16,
        };
        assert_eq!(info.name, "test_reg");
        assert_eq!(info.index, 5);
        assert_eq!(info.size, 32);
        assert_eq!(info.parent, Some(2));
        assert_eq!(info.parent_offset, 16);
    }

    #[test]
    fn test_register_snapshot_default() {
        let snapshot = RegisterSnapshot::default();
        assert!(snapshot.values.is_empty());
    }

    #[test]
    fn test_register_value_masking() {
        // Registers should mask values to their declared size
        let mut ctx = BasicRegisterContext::new();
        ctx.add_register("r8", 8);
        // Setting a value larger than 8 bits should be masked
        ctx.set_register("r8", 0x1FF).unwrap(); // 9 bits
        assert_eq!(ctx.get_register("r8").unwrap(), 0xFF); // Only 8 bits kept
    }

    #[test]
    fn test_64bit_register_full_range() {
        // Verify 64-bit registers can store and retrieve the full u64 range
        let mut ctx = BasicRegisterContext::new();
        ctx.add_register("rax", 64);

        ctx.set_register("rax", u64::MAX).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), u64::MAX);

        ctx.set_register("rax", 0x8000_0000_0000_0000).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), 0x8000_0000_0000_0000);

        ctx.set_register("rax", 0).unwrap();
        assert_eq!(ctx.get_register("rax").unwrap(), 0);
    }

    #[test]
    fn test_bit_mask_helper() {
        assert_eq!(bit_mask(0), 0);
        assert_eq!(bit_mask(1), 1);
        assert_eq!(bit_mask(8), 0xFF);
        assert_eq!(bit_mask(16), 0xFFFF);
        assert_eq!(bit_mask(32), 0xFFFF_FFFF);
        assert_eq!(bit_mask(64), u64::MAX);
    }
}
