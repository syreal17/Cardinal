#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: bb.py
#
# The class for a basic block in our procedure boundary analysis
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------

class BasicBlock(object):
    def __init__(self, index, start_addr, end_addr, next_addr, fall_block,
                 jump_block):
        self.index = index
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.next_addr = next_addr
        self.fall_block = fall_block
        self.jump_block = jump_block

    def debug_print(self):
        index = self.index
        start_addr = self.start_addr
        end_addr = self.end_addr
        next_addr = self.next_addr
        if self.fall_block != None:
            fall_block = self.fall_block.index
        else:
            fall_block = None
        if self.jump_block != None:
            jump_block = self.jump_block.index
        else:
            jump_block = None

        if index == None:
            index = -1
        if start_addr == None:
            start_addr = -1
        if end_addr == None:
            end_addr = -1
        if next_addr == None:
            next_addr = -1
        if fall_block == None:
            fall_block = -1
        if jump_block == None:
            jump_block = -1

        print("%d: %x %x %x, fall:%d, jump:%d" % (index, start_addr, end_addr,
            next_addr, fall_block, jump_block))
