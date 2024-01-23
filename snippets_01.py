import idautils, ida_funcs, idaapi, idc


def get_basic_block():
    textseg = idaapi.get_segm_by_name(".text")
    for fn in idautils.Functions(textseg.start_ea, textseg.end_ea):
        fname = ida_funcs.get_func_name(fn)
        # print(f"function name: {fname}")
        f = ida_funcs.get_func(fn)
        # skip lib
        if f.flags & idaapi.FUNC_LIB:
            continue
        # get basic block
        for bb in idaapi.FlowChart(f):
            disasm = idc.GetDisasm(bb.start_ea)
            ins_len = idc.create_insn(bb.start_ea)
            ins_opcode = idaapi.get_bytes(bb.start_ea, ins_len)
            yield bb.start_ea, ins_opcode.hex(), disasm

def get_all_disasm():
    textseg = idaapi.get_segm_by_name(".text")
    for ea in idautils.Functions(textseg.start_ea, textseg.end_ea):
        for insnea in idautils.FuncItems(ea):
            disasm = idc.GetDisasm(insnea)
            yield insnea, disasm

def test():
    # for ea, opcode, disasm in get_basic_block():
    #     print(f"0x{ea:x} {bytes.fromhex(opcode)} {disasm}")
    for ea, disasm in get_all_disasm():
        print(f"0x{ea:x} {disasm}")


if __name__ == "__main__":
    test()
