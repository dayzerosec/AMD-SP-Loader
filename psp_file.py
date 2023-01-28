'''
File:      psp_file.py
Author(s): @SpecterDev, github.com/PSPReverse
Purpose:   Contains PSPFile helper class to parse AMD-SP/PSP file headers.
Note:      Much of the info here is undocumented and therefore reversed and not complete (and may not be accurate).
           A lot of it came from PSPReverse and their PSPTool. Check their repositories for more details.
'''
import struct

# PSP Magic constants + masks
PSP_MAGIC_GENERIC               = 0x24505331 # "$PS1"

# PSP Magic Variant A (seen on ABL version <= 19.7.8.30)
PSP_MAGIC_ABL_VARIANT_A         = 0x00424157 # "[N]BAW"
PSP_MAGIC_ABL_VARIANT_A_MASK    = 0xFF000000
PSP_MAGIC_ABL_VARIANT_A_SHIFT   = 24

# PSP Magic Variant B (seen on 19.8.12.0 <= ABL version <= 20.10.19.0)
PSP_MAGIC_ABL_VARIANT_B         = 0x41570042 # "AW[N]B"
PSP_MAGIC_ABL_VARIANT_B_MASK    = 0x0000FF00
PSP_MAGIC_ABL_VARIANT_B_SHIFT   = 8

# PSP Directory Entry Types
PSP_FW_BOOT_LOADER          = 0x01
PSP_FW_TRUSTED_OS           = 0x02
PSP_FW_RECOVERY_BOOT_LOADER = 0x03
PSP_FW_BOOT_TIME_TRUSTLETS  = 0x0C

def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

class PSPFile:
    '''
    Layout of the PSP file header. Contributions to unknown fields + corrections would be appreciated.

    struct psp_file_header {
        char _unk_00h[0x10];            // 0x00
        char magic[0x4];                // 0x10
        uint32_t size_signed;           // 0x14
        uint32_t is_encrypted;          // 0x18
        char _unk_1Ch[0x4];             // 0x1C
        char aes_cbc_iv[0x10];          // 0x20
        uint32_t is_signed;             // 0x30
        char _unk_34h[0x4];             // 0x34
        char signature_footprint[0x10]; // 0x38
        uint32_t is_compressed;         // 0x48
        char _unk_4Ch[0x4];             // 0x4C
        uint32_t size_uncompressed;     // 0x50
        uint32_t size_zlib;             // 0x54
        char _unk_58h[0x8];             // 0x58
        uint32_t version;               // 0x60
        char _unk_64h[0x4];             // 0x64
        uint32_t load_addr;             // 0x68
        uint32_t rom_size;              // 0x6C
        char _unk_70h[0x0C];            // 0x70
        uint32_t entry_type;            // 0x7C - matches directory table entry types
        char wrapped_ikek[0x10];        // 0x80
        char _unk_90h[0x10];            // 0x90
        uint32_t metadata;              // 0xA0
        char _unk_A4h[0x5C];            // 0xA4
    } // Size: 0x100
    '''

    def __init__(self, f):
        # 0x10-0x1C
        (self.magic, self.size_signed, self.is_encrypted) = struct.unpack("<III", f.read(0x10, 0x0C))
        self.magic = swap32(self.magic)
        
        # 0x20-0x4C
        (self.iv, self.is_signed, self.pad1, self.signature_footprint, self.is_compressed) = struct.unpack(
            "<16sI4s16sI", f.read(0x20, 0x2C))
        
        # 0x50-0x58
        (self.size_uncompressed, self.size_zlib) = struct.unpack("<II", f.read(0x50, 0x08))
        
        # 0x60-0x70
        (self.version, self.pad, self.load_addr, self.rom_size) = struct.unpack("<I4sII", f.read(0x60, 0x10))

        # 0x7C
        self.entry_type = struct.unpack("<I", f.read(0x7C, 0x04))[0]
        
        # 0x80-0x90
        self.wrapped_key = struct.unpack("<16s", f.read(0x80, 0x10))[0]

        # 0xA0-0xA4
        self.metadata = struct.unpack("<I", f.read(0xA0, 0x04))[0]
        self.metadata = swap32(self.metadata)

    def is_abl(self):
        # If the magic is an ABL magic, we can safely assume it's an ABL binary
        if (self.magic & ~PSP_MAGIC_ABL_VARIANT_A_MASK) == PSP_MAGIC_ABL_VARIANT_A:
            return True
        
        if (self.magic & ~PSP_MAGIC_ABL_VARIANT_B_MASK) == PSP_MAGIC_ABL_VARIANT_B:
            return True
        
        # If the magic is generic we need to check a few locations
        if self.magic == PSP_MAGIC_GENERIC:
            # First, check if the entry type is an ABL type
            if self.entry_type >= 0x30 and self.entry_type <= 0x37:
                return True
            
            # Fallback on metadata, if it's non-zero bytes, we can also probably assume it's an ABL binary
            if self.metadata != 0:
                return True
        
        return False

    def is_bootloader(self):
        if self.entry_type == PSP_FW_BOOT_LOADER or self.entry_type == PSP_FW_RECOVERY_BOOT_LOADER:
            return True
        return False

    def is_trusted_os(self):
        return self.entry_type == PSP_FW_TRUSTED_OS

    def is_boot_time_trustlets(self):
        return self.entry_type == PSP_FW_BOOT_TIME_TRUSTLETS

    def get_abl_num(self):
        # Sanity check
        if not self.is_abl():
            return -1

        # Get via type field
        return self.entry_type - 0x30
