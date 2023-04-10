#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dll_extractor.py

Utility to extract all functions from a shared library

Created by Chris Mason on 04/07/2023
"""

import clr
import os
import pefile
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def extract_dll(path: str):
    """
    Prints all functions contained in a PE-format dynamic library (aka a .dll)
    Currently, it chokes on managed DLLs.
    :param path: the DLL to load
    :return: None
    """
    # Load the DLL file
    pe = pefile.PE(path)

    # If we have the export attribute, we're unmanaged
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        # Find the export directory
        export_directory = pe.DIRECTORY_ENTRY_EXPORT

        # Get the address of the exported names
        names_rva = pe.get_rva_from_offset(export_directory.struct.AddressOfNames)

        # Iterate through the exported names
        for i in range(export_directory.struct.NumberOfNames):
            name_rva_offset = pe.get_offset_from_rva(names_rva + i * 4)
            name_rva = pe.get_dword_at_rva(name_rva_offset)
            function_name = pe.get_string_at_rva(name_rva)
            print(f"{function_name.decode('utf-8')}")

    # Else we're managed
    else:
        dir_name = os.path.dirname(path)
        if dir_name == '':
            dir_name = '.'
        sys.path.append(dir_name)

        # Load the managed DLL.  Needs to be the library name without the extension or directory
        clr.AddReference(os.path.basename(path).split('.')[0])

        # Import the Assembly class from System.Reflection
        from System.Reflection import Assembly

        # Load the assembly from the DLL
        assembly = Assembly.LoadFrom(path)

        # Iterate through the types in the assembly
        for t in assembly.GetTypes():
            print(f"Type: {t.FullName}")

            # Iterate through the methods of the type
            for method in t.GetMethods():
                # Get the parameter types
                param_types = [p.ParameterType for p in method.GetParameters()]
                param_types_str = ', '.join([str(pt) for pt in param_types])

                # Get the return type
                return_type = method.ReturnType

                print(f"  Method: {method.Name}({param_types_str}) -> {return_type}")


def extract_elf(path: str):
    """
    Prints all functions contained in an ELF-format dynamic library
    :param path: string path to the ELF file to parse
    :return: None
    """
    with open(path, 'rb') as file:
        # Load the ELF file
        elffile = ELFFile(file)

        # Iterate through all the sections in the DLL file
        for section in elffile.iter_sections():

            # Check if the section is a symbol table
            if isinstance(section, SymbolTableSection):

                # Iterate through all the symbols in the symbol table
                for symbol in section.iter_symbols():

                    # Check if the symbol is a function
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        print(f"{symbol.name}")


# TODO: use argparse
if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("Usage: dll_extractor <path to file>")
        exit(-1)

    in_path = sys.argv[1]
    if ".dll" in in_path:
        extract_dll(in_path)
    else:
        extract_elf(in_path)
