#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: bb.py
#
# The class for a basic block in our procedure boundary analysis
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# The MIT License (MIT)
# Copyright (c) 2016 Chthonian Cyber Services
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
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
        self.addrs = list()

    def split(self,tgt_addr):
        #print("tgt_addr: %x" % tgt_addr)
        new_bb = BasicBlock(float(self.index)+0.001, tgt_addr, self.end_addr,
                self.next_addr, self.fall_block, self.jump_block)

        addr = None
        while addr != tgt_addr:
            #print("pop")
            addr = self.addrs.pop()
            new_bb.addrs.append(addr)
        new_bb.addrs.reverse()

        self.end_addr = self.addrs[len(self.addrs)-1]
        self.next_addr = tgt_addr
        self.fall_block = new_bb
        self.jump_block = None
        return new_bb

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

        print("%.3f: %x %x %x, fall:%.3f, jump:%.3f" % (index, start_addr, end_addr,
            next_addr, fall_block, jump_block))

    def debug_print_addrs(self):
        index = self.index
        start_addr = self.start_addr
        end_addr = self.end_addr
        next_addr = self.next_addr
        if self.fall_block != None:
            fall_block = self.fall_block.start_addr
        else:
            fall_block = None
        if self.jump_block != None:
            jump_block = self.jump_block.start_addr
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

        print("%d: %x %x %x, fall:%x, jump:%x" % (index, start_addr, end_addr,
            next_addr, fall_block, jump_block))
