'''
File:      bn_view_abl.py
Author(s): @SpecterDev
Purpose:   Implements the ABL binary view for binja
'''

import binaryninja as bn
import json
import os
from .psp_file import PSPFile
from .psp_types import *
from .svc_annotate import annotate

# Note: These came from reversing various firmwares. Some versions may differ where things are loaded in SRAM.
# TODO: There might be a better way to do this, such as parsing instructions to determine the location?
LOAD_ADDR_ABL0 = 0x15100
LOAD_ADDR_ABLN = 0x16200

class ABLView(bn.BinaryView):
    name = "AMD-SP ABL"
    long_name = "AMD-SP ABL"
    do_annotation = False

    def __init__(self, data):
        bn.BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data
        self.psp_file = PSPFile(data)

        # Prompt the user if they want annotation if theres no existing database
        if not self.has_database:
            do_annotate = bn.get_choice_input('Do you want syscalls annotated?', 'Annotate syscalls?', ['Yes', 'No'])

            if do_annotate == 0:
                self.db = self.load_syscall_db()
                self.do_annotation = True

    def log(self, msg, error=False):
        msg = f"[AMD-SP ABL Loader] {msg}"
        if not error:
            bn.log_info(msg)
        else:
            bn.log_error(msg)

    def load_syscall_db(self):
        current_file_path = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(current_file_path, 'data', 'syscalls.json')
        db_file = open(db_path, 'r')
        return json.load(db_file)

    def define_header_struct(self):
        header_struct = create_header_struct_type()
        self.define_user_data_var(self.load_address, header_struct, 'psp_file_header')

    @classmethod
    def is_valid_for_data(self, data):
        self.psp_file = PSPFile(data)

        if self.psp_file.is_abl() and self.psp_file.get_abl_num() >= 0:
            return True
        return False

    def on_complete(self):
        # Define structs
        self.define_header_struct()

        # Annotate syscalls (if the user has specified to do so)
        if self.do_annotation:
            self.log("Annotating syscalls...")
            funcs = self.functions
            annotate(funcs, self.db, self)
        else:
            self.log("Skipping syscall annotation")

    def init(self):
        # PSP binaries are always armv7 (and userspace at least will likely switch to thumb2)
        self.arch = bn.Architecture["armv7"]
        self.platform = self.arch.standalone_platform

        # Load the binary. Data is mixed with code, and so it should be RWX.
        abl_num = self.psp_file.get_abl_num()
        if abl_num == 0:
            self.load_address = LOAD_ADDR_ABL0
        else:
            self.load_address = LOAD_ADDR_ABLN

        self.log("Detected AMD-SP/PSP ABL binary (abl={:d})".format(abl_num))

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
        
        # Register a completion event to annotate syscalls
        bn.AnalysisCompletionEvent(self, self.on_complete)
        return True
