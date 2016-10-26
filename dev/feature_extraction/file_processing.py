#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: file_processing.py
#
# This is code common between feature extraction algorithms. Processing the 
# header for points of interest mainly
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
from __future__ import print_function

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class ELFInfo(object):
    def __init__(self):
        self.code = b""
        self.entry_point = 0
        self.entry_end = 0
        self.addr_to_sym = dict()

    def find_section_by_addr(self, elffile, fstream, addr):
        """ Finds a section by its base address and returns the index
        """
        # Try to find the entry section
        for i in range(elffile['e_shnum']):
            section_offset = elffile['e_shoff'] + i * elffile['e_shentsize']
            # Parse the section header using structs.Elf_Shdr
            fstream.seek(section_offset)
            section_header = elffile.structs.Elf_Shdr.parse_stream(fstream)

            if section_header['sh_addr'] == addr:
                return i
        else:
            print('find_section_by_addr: Address not found in sections')

    def process_file(self, filename):
        #print('Processing file: ', filename)
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)

            #Find the entry point
            #print('Entry Point: ', elffile.header.e_entry)
            #self.entry_point = elffile.header.e_entry

            #lt:this fails on gcc o2&3. Entry point and text section don't
            #don't match
            #Find the section associated with the entry point
            #entry_section_i = self.find_section_by_addr(elffile, f,
            #                                            self.entry_point)

            #if not entry_section_i:
            #    print('Entry section not found. Perhaps the sample is obfuscated?')
            #    return
            #entry_section = elffile.get_section(entry_section_i)
            entry_section = elffile.get_section_by_name('.text')
            #print('Entry section found: ', entry_section.name)
            self.entry_point = entry_section['sh_addr']
            self.entry_end = self.entry_point + entry_section['sh_size']

            #Find the PLT section
            #plt_section = elffile.get_section_by_name('.plt')
            #if not plt_section:
            #    pass
            #    #print('PLT section not found. Jump reasoning degraded')
            #else:
            #    pass
            #    #print('PLT section found.')

            #find symtab and create address to symbol dictionary
            symtab_section = elffile.get_section_by_name('.symtab')

            if not symtab_section:
                print('No symbol table found. Perhaps binary stripped')
            if isinstance(symtab_section, SymbolTableSection):
                num_symbols = symtab_section.num_symbols()
                for s in range(1,num_symbols):
                    sym = symtab_section.get_symbol(s)
                    self.addr_to_sym[sym['st_value']] = sym.name

            #copy out the entry section
            f.seek(entry_section['sh_offset'])
            self.code = f.read(entry_section['sh_size'])
