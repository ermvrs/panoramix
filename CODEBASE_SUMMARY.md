# Panoramix Codebase Summary

Panoramix is an Ethereum Virtual Machine (EVM) decompiler that converts EVM bytecode back into human-readable code. This document provides a comprehensive overview of all files and their functionalities.

## Project Overview

**Main Purpose:** EVM bytecode decompiler that analyzes smart contracts and converts them to readable format  
**Language:** Python  
**Architecture:** Modular decompiler with symbolic execution, AST manipulation, and code prettification

---

## Core Entry Points

### `/panoramix/__main__.py`
**Main application entry point**
- Command-line argument parsing
- Handles multiple addresses/bytecode inputs
- Profiling support
- Integrates with `decompiler.py` for main functionality
- Supports both address-based and bytecode-based decompilation

### `/panoramix/__init__.py`
**Package initialization** (currently empty)

---

## Core Decompilation Engine

### `/panoramix/decompiler.py`
**Main decompilation orchestrator**
- `decompile_address()` and `decompile_bytecode()` - main entry functions
- Coordinates the entire decompilation pipeline:
  1. Load bytecode via `Loader`
  2. Find functions using light VM execution
  3. Decompile each function using symbolic VM
  4. Apply AST transformations (`make_whiles`)
  5. Post-process via `Contract` class
- Handles timeouts and error recovery
- Returns `Decompilation` objects with text, ASM, and JSON representations

### `/panoramix/vm.py`
**Symbolic EVM implementation**
- `VM` class: Core symbolic execution engine
- `Node` class: Represents execution states with stack, condition, and trace
- Implements loop detection and simplification algorithms
- Handles EVM opcodes symbolically rather than concretely
- Complex jump analysis and control flow reconstruction
- Stack manipulation and symbolic expression building
- **Key Features:**
  - Symbolic stack operations
  - Jump destination analysis
  - Loop detection via graph analysis
  - Timeout handling during execution

### `/panoramix/contract.py`
**Contract-level analysis and organization**
- `Contract` class: Container for all functions in a contract
- Post-processing pipeline for the entire contract
- Storage structure analysis (`stor_defs`)
- Function organization (constants, regular functions)
- AST creation and manipulation
- Type inference and cleanup
- Cross-function analysis for better decompilation

---

## Function and Code Analysis

### `/panoramix/function.py`
**Individual function analysis**
- `Function` class: Represents a single contract function
- Parameter type inference from usage patterns
- Function categorization (const, payable, read-only)
- Name generation for unknown functions
- Mask cleanup and type analysis
- Function priority sorting for output

### `/panoramix/loader.py`
**Bytecode loading and initial analysis**
- `Loader` class: Handles bytecode input from various sources
- Web3 integration for fetching on-chain bytecode
- Bytecode disassembly using opcode dictionary
- Function discovery via symbolic execution
- Jump destination identification
- Signature database integration

---

## Code Transformation Pipeline

### `/panoramix/whiles.py`
**Control flow reconstruction**
- Converts goto-based control flow to while loops
- `make_whiles()`: Main transformation function
- Label and jump destination analysis
- Loop condition extraction
- Integrates with simplification pipeline

### `/panoramix/simplify.py`
**Expression and code simplification**
- `simplify_trace()`: Main simplification loop with 40+ iterations
- Expression simplification and algebraic reductions
- Variable cleanup and inlining
- Memory operation cleanup
- Condition optimization
- Loop-to-setmem conversions
- Storage access pattern analysis
- **Complex transformations:**
  - Memory size calculations
  - Storage pattern recognition
  - Loop variable propagation

### `/panoramix/folder.py`
**AST folding and path merging**
- Converts execution paths into concise if-else structures  
- `fold()`: Main folding algorithm
- Path extraction and merging
- Condition deduplication
- Code structure optimization for human readability

---

## Post-processing and Output

### `/panoramix/prettify.py`
**Human-readable code generation**
- `prettify()`: Main prettification function
- Expression formatting and operator precedence
- Color coding support
- Storage name resolution
- Memory access pattern formatting
- Panic code interpretation
- Type-aware formatting
- **Output formats:**
  - Human-readable text
  - Colored terminal output
  - HTML-compatible output

### `/panoramix/postprocess.py`
**Final cleanup operations**
- `cleanup_mul_1()`: Removes unnecessary operations
- Mask simplification for storage operations
- Boolean expression cleanup
- String literal extraction

### `/panoramix/rewriter.py`
**Code rewriting heuristics**  
- String storage pattern recognition
- Array access pattern cleanup
- Memory copy operation detection
- Contract-specific optimizations (some mathematically imprecise but practically useful)

---

## Storage and Memory Analysis

### `/panoramix/sparser.py`
**Storage structure analysis**
- `rewrite_functions()`: Main storage analysis entry point
- Storage location analysis and naming
- Array and mapping detection
- Storage type inference
- Cross-function storage pattern analysis
- **Complex analysis:**
  - SHA3-based storage mapping detection
  - Dynamic array identification
  - Storage field extraction

### `/panoramix/stack.py`
**Stack simulation and analysis**
- `Stack` class: Symbolic EVM stack implementation
- Stack folding for loop variable detection
- Expression simplification during stack operations
- Jump destination tracking
- Variable unification across execution paths

---

## Utility and Helper Modules

### `/panoramix/matcher.py`
**Pattern matching framework**
- `match()`: Main pattern matching function
- Support for wildcards (`Any`, `_`)
- Variable binding in patterns
- Recursive pattern matching
- `replace()`: Pattern-based replacement

### `/panoramix/utils/helpers.py`
**General utility functions**
- Color terminal output support
- Expression manipulation utilities
- Trace rewriting functions
- Caching decorators
- File path utilities
- **Key utilities:**
  - `rewrite_trace()` family of functions
  - `find_f()` and `find_f_list()` for expression searching
  - `replace_f()` for expression replacement

### `/panoramix/utils/opcode_dict.py`
**EVM opcode definitions**
- Complete EVM opcode mapping
- Stack effect definitions for opcodes
- Used by loader for disassembly

### `/panoramix/utils/signatures.py`
**Function signature management**
- ABI (Application Binary Interface) handling
- Function name resolution
- Parameter type and name management
- Integration with signature databases

### `/panoramix/utils/supplement.py`
**External signature database**
- Function signature lookup from compressed database
- Caching system for signature resolution
- Integration with 4byte.directory-like databases

---

## Core Algorithm Modules

### `/panoramix/core/algebra.py`
**Symbolic algebra operations**
- Expression simplification and comparison
- Arithmetic operation handling
- Mask operations for EVM word manipulation
- Maximum/minimum calculations
- Comparison operations with uncertainty handling
- **Complex operations:**
  - `apply_mask()`: Bit manipulation operations
  - `max_op()`, `min_op()`: Symbolic extrema
  - Algebraic simplification rules

### `/panoramix/core/arithmetic.py`
**EVM arithmetic implementation**
- All EVM arithmetic opcodes
- Signed/unsigned number handling
- Boolean expression evaluation
- Overflow/underflow handling
- Originally based on py-evm but heavily modified

### `/panoramix/core/masks.py`
**Bit manipulation and masking**
- EVM word masking operations
- Type inference from masks
- Bit extraction and manipulation

### `/panoramix/core/memloc.py`
**Memory location analysis**
- Memory range operations
- Memory overlap detection
- Memory operation splitting and merging

### `/panoramix/core/variants.py`
**Expression variant generation**
- Generates different forms of the same expression
- Used for comprehensive algebraic analysis

---

## Configuration and Data

### `/pyproject.toml`
**Project configuration**
- Poetry-based dependency management
- Package metadata and entry points
- Build system configuration

### `/panoramix/data/abi_dump.xz`
**Compressed signature database**
- Pre-compiled function signatures
- Used by supplement system for function identification

---

## Documentation

### `/README.md`
**Main project documentation**
- Installation and usage instructions
- Examples and caveats
- Project history and goals

### `/TODO.md`
**Development todo list**
- Planned features and fixes

### `/OPCODES.md`
**Opcode documentation**
- Mask operation documentation
- Bit manipulation examples

---

## Architecture Summary

**Decompilation Pipeline:**
1. **Load** → Fetch bytecode and disassemble
2. **Analyze** → Find functions and control flow  
3. **Execute** → Symbolic execution with VM
4. **Transform** → Convert to structured code (whiles, simplify)
5. **Analyze** → Contract-level analysis and storage
6. **Format** → Generate human-readable output

**Key Design Patterns:**
- **Symbolic Execution**: VM operates on symbolic expressions rather than concrete values
- **Iterative Refinement**: Multiple passes of simplification and cleanup
- **Pattern Matching**: Extensive use of pattern matching for code recognition
- **Modular Pipeline**: Each stage is independent and can be modified separately

**Complexity Notes:**
- Loop detection algorithm is particularly complex
- Storage analysis requires cross-function reasoning  
- Expression simplification uses algebraic rules with caching
- The codebase acknowledges its complexity and technical debt in several places

This codebase represents a sophisticated approach to reverse engineering EVM bytecode, with multiple layers of analysis and transformation to produce readable decompiled output. 