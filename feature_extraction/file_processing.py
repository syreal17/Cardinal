#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: file_processing.py
#
# This is code common between feature extraction algorithms. Processing the 
# header for points of interest mainly
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------
from __future__ import print_function

from elftools.elf.elffile import ELFFile

class ELFInfo(object):
    def __init__(self):
        self.code = b""
        self.entry_point = 0
        self.entry_end = 0

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
            self.entry_point = elffile.header.e_entry

            #Find the section associated with the entry point
            entry_section_i = self.find_section_by_addr(elffile, f,
                                                        self.entry_point)
            if not entry_section_i:
                print('Entry section not found. Perhaps the sample is obfuscated?')
                return
            entry_section = elffile.get_section(entry_section_i)
            #print('Entry section found: ', entry_section.name)
            self.entry_end = self.entry_point + entry_section['sh_size']

            #Find the PLT section
            #plt_section = elffile.get_section_by_name('.plt')
            #if not plt_section:
            #    pass
            #    #print('PLT section not found. Jump reasoning degraded')
            #else:
            #    pass
            #    #print('PLT section found.')

            #copy out the entry section
            f.seek(entry_section['sh_offset'])
            self.code = f.read(entry_section['sh_size'])
