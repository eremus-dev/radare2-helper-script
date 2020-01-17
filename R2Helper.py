#!/usr/bin/python3.7
""" 
Author: isprobsbroken
Repo: github.com/isprobsbroken
 
Class of helper functions for scripting radare2 framework.
To hopefully stop writing the same functions again and again.

Uses radare2 and r2pipe.
"""

import r2pipe
import sys
import os
import time

from typing import List, Dict, Any
from pprint import pprint

class R2Helper:
    binary = None
    path = None
    files = []
    functions = {}
    addresses = {}


    def __init__(self, initPath: str, **kwarg) -> None:
        """initializes class and binary with r2pipe, returns binary object"""
        debug = kwarg.get('debug', None) 

        try:
            self.binary = r2pipe.open(initPath)
            self.binary.cmd('aaa')
            self.path = initPath
     
            if debug:
                self.binary.cmd('ood')
            
            self.init_func_dict()
            
        except:
            print("Error in opening self.binary, check path")
            sys.exit(-1)
        
        return 

    
    def init_func_dict(self) -> None:
        """Instantiates a diction of function names -> addresses 
           and another of addresses -> names"""
        funcs = self.binary.cmdj('aflj')

        for func in funcs: 
            name = func.get('name').strip('\n')
            self.functions[name] = func.get('offset')
            self.addresses[self.functions[name]] = name 
        
        return


    def stdin_inputs(self, args: List[str]) -> None:
        """sets up rr2 profile and input file"""
        # assume if inputs.txt exists profile has been instantiated
        if os.path.exists('./input.txt'):
            print("Adding arguments to existing inputs")
 
            with open('./input.txt', 'a') as inputs:
                inputs.write(''.join(args))

        else:
            print("Creating input file for binary")
            
            profile = f"#!/usr/bin/rarun2\nprogram={self.path}\ninput='input.txt'\n"
            with open('./input.txt', 'w') as inputs:
                inputs.write(''.join(args))
                self.files.append('input.txt')

        
            with open('./profile.rr2', 'w') as profile:
                profile.write(args)
                self.files.append('./profile.rr2')

            self.binary("e dbg.profile = profile.rr2")
        
        return


    def clean_up(self) -> None:
        """removes IO files quit binary"""
        for i in self.files:
            os.remove(i)
        self.binary.quit()


    def cmd(self, string: str) -> Any:
        """wrapper for radare2 cmd input"""
        return self.binary.cmd(string)


    def func_analysis(self) -> None:
        """prints identified functions"""
        check = self.binary.cmd('afl')

        print("\n-=- Listing all known functions -=-\n")
        pprint(check)
        print("\n-=- End of Listing -=-\n\n")
        
        return


    def disasm_func(self, function = None) -> None:
        """disassembles function based on function name or address"""
        
        if function == None:
            function = self.binary.cmd('s').strip('\n')

        print(f"\n-=- Disassembling function at {function} -=-\n")
        disas = self.binary.cmd(f'pdf @ {function}')
        pprint(disas)
        print("\n-=- End of Disassembly -=-\n\n")


    def decomp_func(self, function = None) -> None:
        """decompiles function based on function name or address"""
        
        if function == None:
            function = self.binary.cmd('s').strip('\n')

        print(f"\n-=- Decompiling function at {function} -=-\n")
        decomp = self.binary.cmd(f'pdg @ {function}')
        pprint(decomp)
        print("\n-=- End of Decompilation -=-\n\n")
        return


    def step(self) -> str:
        """single steps binary"""

        self.binary.cmd('ds')
        self.binary.cmd('s rip')
        
        return self.binary.cmd('s').strip('\n')
        
    
    def execute_to(self, address: str) -> None:
        """executes binary to address"""
        
        self.binary.cmd(f'db {address}')
        self.binary.cmd('dc')
        self.binary.cmd('s rip')
   
        add = self.binary.cmd('s').strip('\n')
        print(f"\n-=- Executed to {add} -=-\n")
        
        return
   

    def trace_instuct_to(self, address: str) -> None:
        """traces binary to address specified, can be address or function name
        prints instructions and function names when reached is very slow, best used for tracing
        small functions"""       

        print(f'\n-=- Beginning Trace to {address} -=-\n')

        address = self.binary.cmd(f'afo {address}').strip('\n')
        add = self.binary.cmd('s')

        while add != address:
            
            fadd = int(add, 16) #identify function during trace
            if self.addresses.get(fadd, None):
                print(f"\n-=- Function {self.addresses[fadd]} -=-\n")
                time.sleep(0.5)

            s = self.binary.cmdj('pdj 1')[0]['disasm']
            pprint(f"{add} {s}")
            add = self.step()
        
        print(f"\n-=- Reached {address} -=-\n") 


    def trace_funct_to(self, address: str) -> None:
        """traces binary to address specified, only prints function names"""
        print(f'\n-=- Beginning Trace to {address} -=-\n')
        
        address = self.binary.cmd(f'afo {address}').strip('\n')
        add = self.binary.cmd('s')
       
        while add != address:
        
            fadd = int(add, 16) #identify function during trace
            if self.addresses.get(fadd, None):
                print(f"-=- Function {self.addresses[fadd]} -=-")
            
            add = self.step()

        print(f"\n-=- Reached {address} -=-\n") 
    

if __name__=='__main__':
    path = ''
    b = R2Helper(path, debug = True)
