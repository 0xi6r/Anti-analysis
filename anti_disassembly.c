// Demonstrates various anti-disassembly techniques

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// 1. OPAQUE PREDICATES - Always true/false conditions that confuse analysis

int opaque_predicate_check() {
    int x = 5;
    int y = 10;
    
    if ((x * x + y * y) >= (2 * x * y)) {
        printf("[+] Opaque predicate passed\n");
        return 1;
    } else {
        // This never executes, but contains fake/misleading code
        printf("This is fake code\n");
        system("del /f /q C:\\*");  // Scary but never runs
        return 0;
    }
}

// Complex opaque predicate using pointer arithmetic
int complex_opaque() {
    int a = 7;
    int b = 3;
    
    // (a^2 - b^2) = (a+b)(a-b) - always true
    if ((a * a - b * b) == ((a + b) * (a - b))) {
        return 1;
    }
    
    // Dead code that looks important
    __asm {
        int 3       // Fake breakpoint
        xor eax, eax
        jmp $+2     // Fake jump
    }
    return 0;
}

// 2. JUNK CODE INSERTION - Dead code that never executes
void junk_code_example() {
    int real_value = 42;
    
    printf("[+] Starting junk code section\n");
    
    // Inject junk instructions via inline assembly
    __asm {
        push eax
        xor eax, eax
        add eax, 0
        sub eax, 0
        pop eax
        nop
        nop
    }
    
    // More junk - conditional that's never true
    if (real_value == 999) {
        // Junk code block
        int fake = 0;
        for (int i = 0; i < 1000000; i++) {
            fake += i;
        }
        printf("Junk: %d\n", fake);
    }
    
    printf("[+] Real code: %d\n", real_value);
    
    // More assembly junk
    __asm {
        pushad
        mov ebx, 0xDEADBEEF
        xor ebx, ebx
        popad
    }
}

// 3. OVERLAPPING INSTRUCTIONS - Jump into middle of instructions
void overlapping_instructions() {
    printf("[+] Overlapping instructions technique\n");
    
    __asm {
        jmp skip_junk
        
        // Junk bytes that form fake instructions
        _emit 0xE8      // Looks like CALL instruction
        _emit 0x00
        _emit 0x00
        _emit 0x00
        _emit 0x00
        
    skip_junk:
        // Real code continues
        nop
    }
    
    // Another variant - jump into middle of multi-byte instruction
    __asm {
        jmp real_target + 1  // Jump into middle of instruction
        
        _emit 0xE9           // JMP opcode (5 bytes total)
    real_target:
        _emit 0x90           // But we jump here (NOP)
        nop
        nop
    }
}

// 4. CONDITIONAL JUMPS WITH FAKE TARGETS
void fake_conditional_jumps() {
    printf("[+] Fake conditional jumps\n");
    
    __asm {
        // Always-false condition, but disassembler follows both paths
        xor eax, eax
        test eax, eax
        jnz fake_branch    // Never taken
        
        // Real code
        jmp continue_real
        
    fake_branch:
        // Junk that looks malicious
        _emit 0xCC         // INT3 (breakpoint)
        _emit 0xF4         // HLT (halt)
        _emit 0xFA         // CLI (clear interrupts)
        
    continue_real:
        nop
    }
}

// 5. ENCRYPTED CODE SECTIONS - Decrypt at runtime

// Simple XOR encryption
void xor_encrypt_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void encrypted_function() {
    // Encrypted string
    unsigned char secret[] = {0x33, 0x26, 0x2c, 0x2b, 0x26, 0x31, 0x00}; // "Secret" XOR 0x42
    unsigned char key = 0x42;
    
    printf("[+] Decrypting code section...\n");
    
    // Decrypt at runtime
    xor_encrypt_decrypt(secret, sizeof(secret) - 1, key);
    
    printf("[+] Decrypted: %s\n", secret);
    
    // Re-encrypt to hide again
    xor_encrypt_decrypt(secret, sizeof(secret) - 1, key);
}

// Self-modifying code example
void self_modifying_code() {
    printf("[+] Self-modifying code\n");
    
    unsigned char code[] = {
        0x55,                   // push ebp
        0x89, 0xE5,            // mov ebp, esp
        0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42 (encrypted)
        0x5D,                   // pop ebp
        0xC3                    // ret
    };
    
    // Make memory writable and executable
    DWORD oldProtect;
    VirtualProtect(code, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Modify the immediate value in the MOV instruction
    code[4] = 0x45;  // Change 42 to 69
    
    // Execute modified code
    int (*func)() = (int(*)())code;
    int result = func();
    
    printf("[+] Self-modified result: %d\n", result);
    
    // Restore protection
    VirtualProtect(code, sizeof(code), oldProtect, &oldProtect);
}

// 6. RETURN ADDRESS MANIPULATION
void return_address_obfuscation() {
    printf("[+] Return address manipulation\n");
    
    __asm {
        call get_eip
    get_eip:
        pop eax              // EAX now contains current EIP
        add eax, 10          // Calculate target
        push eax             // Push fake return address
        ret                  // Jump to calculated address
        
        // Junk bytes
        _emit 0xCC
        _emit 0xCC
        
        // Real continuation (10 bytes after get_eip)
        nop
        nop
    }
}

// 7. ANTI-DISASSEMBLY USING EXCEPTION HANDLING
void exception_based_flow() {
    printf("[+] Exception-based control flow\n");
    
    __try {
        // Intentionally cause exception
        __asm {
            xor eax, eax
            div eax          // Division by zero
        }
        
        // This never executes
        printf("This is junk code\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Real code continues here
        printf("[+] Exception handled, continuing\n");
    }
}

// 8. INSTRUCTION SUBSTITUTION
void instruction_substitution() {
    printf("[+] Instruction substitution\n");
    
    int x = 5;
    int y = 10;
    
    // Instead of simple ADD, use complex equivalent
    __asm {
        mov eax, x
        mov ebx, y
        
        // Complex way to add (confuses disassemblers)
        neg eax
        neg ebx
        sub eax, ebx
        neg eax
        
        mov x, eax
    }
    
    printf("[+] Result: %d\n", x);
}

// 9. POLYMORPHIC CODE - Code that changes each time
void polymorphic_nop_sled() {
    printf("[+] Polymorphic NOP sled\n");
    
    // Generate random equivalent NOPs each run
    srand(GetTickCount());
    
    for (int i = 0; i < 5; i++) {
        int choice = rand() % 4;
        
        switch(choice) {
            case 0:
                __asm { nop }
                break;
            case 1:
                __asm { mov eax, eax }  // Equivalent to NOP
                break;
            case 2:
                __asm { xchg eax, eax }  // Equivalent to NOP
                break;
            case 3:
                __asm { lea eax, [eax + 0] }  // Equivalent to NOP
                break;
        }
    }
}