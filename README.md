# Anti-Analysis Techniques

A collection of anti-analysis techniques implemented in C to make reverse engineering more challenging.

## 🛡️ Techniques Implemented

### 1. Anti-Debugging (`anti_debugging.c`)
- `IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()`
- Hardware breakpoint detection (debug registers)
- Timing-based detection
- Exception-based detection
- Parent process analysis
- `NtQueryInformationProcess` checks
- Debugger window detection
- PEB (Process Environment Block) inspection

### 2. Anti-Disassembly (`anti_disassembly.c`)
- Opaque predicates (always-true/false conditions)
- Junk code insertion
- Overlapping instructions
- Fake conditional jumps
- Encrypted code sections
- Self-modifying code
- Return address manipulation
- Exception-based control flow
- Polymorphic code generation

### 3. Integrity Checks (`integrity_checks.c`)
- CRC32 checksum verification
- Function hash verification
- Inline integrity checks
- Memory checksum validation
- PE header verification
- Import table validation
- Timing-based integrity checks
- Continuous monitoring thread
- Stack canary implementation

#### These techniques are for learning about software protection and reverse engineering

# Run
./anti_debug.exe
./anti_disasm.exe
./integrity.exe
