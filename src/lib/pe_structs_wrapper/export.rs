use crate::data_source::{DataSource, DataSourceExt};
use crate::pe::ParseError;
use crate::pe_structs::IMAGE_EXPORT_DIRECTORY;

#[derive(Debug)]
pub struct Export {
    //_export_desc: IMAGE_EXPORT_DIRECTORY,
    name_table: Vec<(String, u16)>,
    function_addr_table: Vec<u64>,
    ordinal_base: u16,
}

impl Export {
    pub fn parse<T: DataSource + ?Sized>(
        data_source: &T,
        rva_to_foa: &dyn Fn(u32) -> u32,
        export_desc: IMAGE_EXPORT_DIRECTORY,
        _is_pe32p: bool,
    ) -> Result<Self, ParseError> {
        let num_of_name = export_desc.NumberOfNames;
        let mut names_offset = rva_to_foa(export_desc.AddressOfNames);
        let mut ordinals_offset = rva_to_foa(export_desc.AddressOfNameOrdinals);
        let ordinal_base = export_desc.Base as u16;

        let mut name_table: Vec<(String, u16)> = Vec::with_capacity(num_of_name as usize);
        for _ in 0..num_of_name {
            let name_rva = data_source.read_u32(names_offset as u64)?;
            names_offset += std::mem::size_of::<u32>() as u32;
            let ordinal = data_source.read_u16(ordinals_offset as u64)?;
            ordinals_offset += std::mem::size_of::<u16>() as u32;

            let name_offset = if data_source.is_file_aligned() {
                rva_to_foa(name_rva)
            } else {
                name_rva
            };

            let name = data_source.read_ascii(name_offset as u64, 256)?;
            name_table.push((name, ordinal));
        }

        let num_of_functions = export_desc.NumberOfFunctions;
        // 函数表本身的偏移也按 file_aligned 选择 RVA/FOA——之前无条件 rva_to_foa
        // 在 non-file-aligned 路径下会读错位置
        let function_offset = if data_source.is_file_aligned() {
            rva_to_foa(export_desc.AddressOfFunctions)
        } else {
            export_desc.AddressOfFunctions
        };
        // 用真实循环上界预分配容量
        let mut function_addr_table: Vec<u64> = Vec::with_capacity(num_of_functions as usize);
        for i in 0..num_of_functions {
            let function_virtual_address = data_source
                .read_u32((function_offset + i * std::mem::size_of::<u32>() as u32) as u64)?;
            if data_source.is_file_aligned() {
                function_addr_table.push(rva_to_foa(function_virtual_address) as u64);
            } else {
                function_addr_table
                    .push(data_source.image_base() + function_virtual_address as u64);
            }
        }

        // TODO(forwarder): 当某个函数 RVA 落在导出目录自身范围内
        // ([export_dir_rva, export_dir_rva + export_dir_size)) 时，它是
        // "dll_name.function_name" 形式的 forwarder 字符串，Windows loader
        // 会据此把调用重定向到别的 DLL。当前实现会把 forwarder 错当成普通
        // 函数地址返回。后续支持 forwarder 时需要：
        //   1. Export::parse 接收 export_dir_rva / export_dir_size
        //   2. 增加 is_forwarder_by_* / forwarder_by_* 查询方法
        //   3. function_address_by_* 在 forwarder 情形返回 None
        Ok(Self {
            name_table,
            function_addr_table,
            ordinal_base,
        })
    }

    pub fn function_address_by_name(&self, function_name: &str) -> Option<u64> {
        let potion_index = self
            .name_table
            .iter()
            .position(|item| item.0 == function_name);
        if let Some(index) = potion_index {
            debug_assert!(index < self.function_addr_table.len());
            self.function_addr_table.get(index).cloned()
        } else {
            None
        }
    }

    pub fn function_address_by_ordinal(&self, function_ordinal: u16) -> Option<u64> {
        // 防止 u16 减法下溢 (debug 模式 panic / release 环绕)
        if function_ordinal < self.ordinal_base {
            return None;
        }
        let index = (function_ordinal - self.ordinal_base) as usize;
        if index < self.function_addr_table.len() {
            self.function_addr_table.get(index).cloned()
        } else {
            None
        }
    }
}
