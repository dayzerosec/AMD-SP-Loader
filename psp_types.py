'''
File:      psp_types.py
Author(s): @SpecterDev, github.com/PSPReverse
Purpose:   Type library for PSP stuff
Note:      Much of the info here is undocumented and therefore reversed and not complete (and may not be accurate).
           A lot of it came from PSPReverse and their PSPTool. Check their repositories for more details.
'''
import binaryninja as bn

def create_header_struct_type():
    struct_type = bn.types.StructureBuilder.create()

    struct_type.append(bn.Type.array(bn.Type.int(1), 0x10), '_unk_00h')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), 'magic')
    struct_type.append(bn.Type.int(4, False), 'size_signed')
    struct_type.append(bn.Type.int(4), 'is_encrypted')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), '_unk_1Ch')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x10), 'aes_cbc_iv')
    struct_type.append(bn.Type.int(4), 'is_signed')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), '_unk_34h')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x10), 'signature_footprint')
    struct_type.append(bn.Type.int(4), 'is_compressed')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), 'unk_4Ch')
    struct_type.append(bn.Type.int(4, False), 'size_uncompressed')
    struct_type.append(bn.Type.int(4, False), 'size_zlib')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x8), 'unk_58h')
    struct_type.append(bn.Type.int(4, False), 'version')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x4), 'unk_64h')
    struct_type.append(bn.Type.int(4, False), 'load_addr')
    struct_type.append(bn.Type.int(4, False), 'rom_size')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0xC), 'unk_70h')
    struct_type.append(bn.Type.int(4, False), 'entry_type')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x10), 'wrapped_ikek')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x10), 'unk_90h')
    struct_type.append(bn.Type.int(4, False), 'metadata')
    struct_type.append(bn.Type.array(bn.Type.int(1), 0x5C), 'unk_A4h')

    return struct_type

