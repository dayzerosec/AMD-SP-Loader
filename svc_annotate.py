'''
File:      svc_annotate.py
Author(s): @SpecterDev
Purpose:   Implement svc annotation of functions post-analysis
'''
import binaryninja as bn

# Blue
HIGHLIGHT_COLOR = [0, 115, 255]

def annotate(funcs, db, bv):
    for fun in funcs:
        for bb in fun.basic_blocks:
            for txt in bb.get_disassembly_text():
                if txt.tokens[0].text == "svc":
                    # Highlight syscall lines because they're important
                    color = bn.highlight.HighlightColor(
                        red=HIGHLIGHT_COLOR[0],
                        green=HIGHLIGHT_COLOR[1],
                        blue=HIGHLIGHT_COLOR[2]
                    )

                    fun.set_auto_instr_highlight(txt.address, color)
                    svc_num = txt.tokens[-1].value

                    # Lookup svc # in the database and comment
                    if str(svc_num) in db:
                        # Get svc info
                        svc = db[str(svc_num)]
                        svc_name = svc['name']
                        svc_args = svc['args']

                        # Build up comment and set
                        comment_str = svc_name + '('

                        if len(svc['args']) > 0:
                            last_arg = svc['args'][-1]
                            for arg in svc['args']:
                                comment_str += arg['type'] + ' ' + arg['name']
                                if arg != last_arg:
                                    comment_str += ', '
                        
                        comment_str += ')'
                        bv.set_comment_at(txt.address, comment_str)
                    else:
                        if svc_num > 0 and svc_num < 255:
                            bn.log_warn(f"[AMD-SP ABL Loader] Don't have SVC #{svc_num} defined in dictionary (addr=0x{txt.address:08x}).")