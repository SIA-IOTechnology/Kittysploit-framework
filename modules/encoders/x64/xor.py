#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *

class Module(Encoder):
    
    __info__ = {
        "name": "Linux x64 XOR Encoder",
        "description": "XOR encoder for Linux x64 payloads with 4-byte key",
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
    }
    
    def encode(self, payload):
        """
        Encode the payload using XOR with a 4-byte key.
        
        Args:
            payload: Raw payload bytes to encode
            
        Returns:
            Encoded payload with decoder stub
        """
        # XOR key (4 bytes)
        xor_key = b"\x41\x42\x43\x44"  # "ABCD" in ASCII
        
        # Encode the payload
        encoded_payload = self._xor_encode(payload, xor_key)
        
        # Generate decoder stub
        decoder = self._generate_decoder(len(payload), xor_key)
        
        # Combine decoder + encoded payload
        return decoder + encoded_payload
    
    def _xor_encode(self, payload, key):
        """Encode payload using XOR with 4-byte key"""
        encoded = bytearray()
        key_len = len(key)
        
        for i, byte in enumerate(payload):
            key_byte = key[i % key_len]
            encoded.append(byte ^ key_byte)
        
        return bytes(encoded)
    
    def _generate_decoder(self, payload_len, xor_key):
        """
        Generate x64 decoder stub.
        
        The decoder:
        1. Uses call+pop to get current address
        2. Calculates offset to encoded payload
        3. XORs each byte with rotating key
        4. Jumps to decoded payload
        """
        # Build decoder stub
        decoder_stub = bytearray()
        
        # Step 1: Get current address using call+pop
        # call $+5
        decoder_stub += b"\xe8\x00\x00\x00\x00"  # call $+5 (e8 = call, 00 00 00 00 = offset 0, so next instruction)
        # pop rsi (gets address of this pop instruction)
        decoder_stub += b"\x5e"  # pop rsi
        
        # Step 2: Calculate offset to encoded payload
        # We'll use a placeholder for the offset and fix it later
        offset_placeholder_pos = len(decoder_stub)
        decoder_stub += b"\x48\x81\xc6"  # add rsi, imm32 (add 32-bit immediate to rsi)
        decoder_stub += b"\x00\x00\x00\x00"  # placeholder for offset (will be fixed)
        
        # Step 3: Save start address of encoded payload in rdi
        decoder_stub += b"\x48\x89\xf7"  # mov rdi, rsi (save start address)
        
        # Step 4: Setup counter (payload length) in rcx
        payload_len_bytes = payload_len.to_bytes(8, 'little')
        decoder_stub += b"\x48\xb9"  # mov rcx, imm64
        decoder_stub += payload_len_bytes
        
        # Step 5: Setup XOR key in rdx (rotate through key bytes)
        key_padded = xor_key + b"\x00" * (8 - len(xor_key))
        decoder_stub += b"\x48\xba"  # mov rdx, imm64
        decoder_stub += key_padded
        
        # Step 6: Decode loop
        # decode_loop:
        loop_start = len(decoder_stub)
        decoder_stub += b"\x30\x16"  # xor [rsi], dl (XOR byte at [rsi] with low byte of rdx)
        decoder_stub += b"\x48\xc1\xca\x08"  # ror rdx, 8 (rotate key right by 8 bits)
        decoder_stub += b"\x48\xff\xc6"  # inc rsi (move to next byte)
        decoder_stub += b"\x48\xff\xc9"  # dec rcx (decrement counter)
        decoder_stub += b"\x75\xf3"  # jnz decode_loop (jump back if rcx != 0)
        # jnz offset = -13 bytes (0xf3 = -13 in two's complement)
        
        # Step 7: Jump to decoded payload (start address in rdi)
        decoder_stub += b"\xff\xe7"  # jmp rdi (jump to start of decoded payload)
        
        # Calculate actual offset from the add rsi instruction to start of encoded payload
        # The encoded payload starts right after the decoder stub ends
        decoder_len = len(decoder_stub)
        # Offset = distance from end of add rsi instruction (offset_placeholder_pos + 7) to end of decoder
        offset = decoder_len - (offset_placeholder_pos + 7)
        # Fix the offset placeholder (bytes 3-6 of the add rsi instruction)
        decoder_stub[offset_placeholder_pos+3:offset_placeholder_pos+7] = offset.to_bytes(4, 'little', signed=False)
        
        return bytes(decoder_stub)

