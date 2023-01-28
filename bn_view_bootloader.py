'''
File:      bn_view_bootloader.py
Author(s): @SpecterDev
Purpose:   Implements the bootloader binary view for binja
'''

import binaryninja as bn
from .psp_file import PSPFile
from .psp_types import *

# Note: These came from reversing various firmwares. Some versions may differ where things are loaded in SRAM.
LOAD_ADDR_BOOTLOADER = 0

class BootloaderView(bn.BinaryView):
    name = "AMD-SP Bootloader"
    long_name = "AMD-SP Bootloader"

    def log(self, msg, error=False):
        msg = f"[AMD-SP Bootloader Loader] {msg}"
        if not error:
            bn.log_info(msg)
        else:
            bn.log_error(msg)

    def __init__(self, data):
        bn.BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data
        self.psp_file = PSPFile(data)

    def define_header_struct(self):
        header_struct = create_header_struct_type()
        self.define_user_data_var(self.load_address, header_struct, 'psp_file_header')

    @classmethod
    def is_valid_for_data(self, data):
        self.psp_file = PSPFile(data)
        return self.psp_file.is_bootloader()

    def on_complete(self):
        # Define structs
        self.define_header_struct()

    def init(self):
        # PSP binaries are always armv7 (and userspace at least will likely switch to thumb2)
        self.arch = bn.Architecture["armv7"]
        self.platform = self.arch.standalone_platform

        # Load the binary. Data is mixed with code, and so it should be RWX.
        self.load_address = LOAD_ADDR_BOOTLOADER

        self.log("Detected AMD-SP/PSP Bootloader binary")

        # Header segment
        header_segment_offset = self.load_address
        header_segment_size   = 0x100
        self.add_auto_segment(
            header_segment_offset,
            header_segment_size,
            0,
            header_segment_size,
            bn.SegmentFlag.SegmentReadable
        )

        self.add_user_section("header", header_segment_offset, header_segment_size,
            bn.SectionSemantics.ReadOnlyDataSectionSemantics)

        # Code/data segment
        code_segment_offset = self.load_address + header_segment_size
        code_segment_size = len(self.parent_view) - 0x100

        self.add_auto_segment(
            code_segment_offset,
            code_segment_size,
            header_segment_size,
            code_segment_size,
            bn.SegmentFlag.SegmentReadable | bn.SegmentFlag.SegmentWritable | bn.SegmentFlag.SegmentExecutable
        )

        self.add_user_section("code", code_segment_offset, code_segment_size,
            bn.SectionSemantics.ReadOnlyCodeSectionSemantics)

        # Add the entrypoint, which is always immediately after the header at 0x100
        self.add_entry_point(code_segment_offset)

        self.define_auto_symbol_and_var_or_function(
            bn.Symbol(bn.SymbolType.FunctionSymbol, code_segment_offset, '_start'),
            bn.Type.function(bn.Type.void(), []),
            bn.Architecture["armv7"].standalone_platform
        )

        self.update_analysis()

        # Register a completion event to create structs
        bn.AnalysisCompletionEvent(self, self.on_complete)
        return True
