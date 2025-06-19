import cProfile
import logging
import argparse
import sys
import json
import os
from datetime import datetime

import coloredlogs

from panoramix.decompiler import decompile_address, decompile_bytecode

logger = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(description="EVM decompiler.")
    parser.add_argument(
        "-v",
        default=str(logging.INFO),
        help="log level (INFO, DEBUG...)",
        metavar="LOG_LEVEL",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        default=False,
        help="Enable profiling of the application. "
        "Dumps the profile data to a 'panoramix.prof' file.",
    )
    parser.add_argument(
        "address_or_bytecode",
        help="An ethereum address, a comma-separated list of ethereum addresses, or `-` to read bytecode from stdin.",
    )
    parser.add_argument(
        "--function",
        default="",
        help="Function name to decompile only this one.",
        required=False,
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument(
        "--json",
        nargs="?",
        const="",
        help="Save decompilation result as JSON to a file. Optionally specify filename (default: auto-generated).",
        metavar="FILENAME",
    )
    parser.add_argument(
        "--statements",
        action="store_true",
        help="Extract function return flows with require statements and storage changes as JSON output.",
    )

    return parser.parse_args(args)


def generate_json_filename(address):
    """Generate a filename for JSON output based on address and timestamp."""
    # Clean the address for filename (remove special characters)
    clean_addr = address.replace(",", "_").replace("-", "stdin")[:20]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"decompilation_{clean_addr}_{timestamp}.json"


def print_decompilation(this_addr, args, addr_index=0, total_addrs=1):
    function_name = args.function or None

    if this_addr == "-":
        this_addr = sys.stdin.read().strip()

    if len(this_addr) == 42:
        decompilation = decompile_address(this_addr, function_name)
    else:
        decompilation = decompile_bytecode(this_addr, function_name)

    # Handle --statements argument
    if args.statements:
        statements_data = extract_function_statements(decompilation)
        print(json.dumps(statements_data, indent=2))
        return

    if args.json is not None:
        # Output as JSON to file
        output_data = {
            "address": this_addr,
            "decompilation": decompilation.json,
            "asm": decompilation.asm
        }
        
        # Determine filename
        if args.json:  # User provided a filename
            if total_addrs > 1:
                # For multiple addresses with user-specified filename, add index
                base, ext = os.path.splitext(args.json)
                filename = f"{base}_{addr_index + 1}{ext}" if ext else f"{args.json}_{addr_index + 1}.json"
            else:
                filename = args.json if args.json.endswith('.json') else f"{args.json}.json"
        else:  # Auto-generate filename
            filename = generate_json_filename(this_addr)
        
        # Write JSON to file
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"JSON output saved to: {filename}")
    else:
        # Output as text (default behavior)
        print(decompilation.text)


def extract_function_statements(decompilation):
    """
    Extract function return flows with require statements and storage changes.
    Returns a list of dictionaries with function analysis.
    """
    from panoramix.utils.helpers import find_f_list, opcode
    from panoramix.matcher import match
    from panoramix.prettify import prettify
    
    result = []
    
    if not decompilation.json or 'functions' not in decompilation.json:
        return result
    
    for func_data in decompilation.json['functions']:
        func_name = func_data.get('name', 'unknown')
        func_hash = func_data.get('hash', '')
        func_trace = func_data.get('trace', [])
        
        # Extract function parameters
        func_params = extract_function_parameters(func_data)
        
        # Extract return flows
        return_flows = extract_return_flows(func_trace)
        
        # Extract all statements (requires, stores) even without return flows
        all_statements = extract_all_statements(func_trace)
        
        # Include function if it has return flows OR other statements (requires/stores)
        if return_flows or all_statements['requires'] or all_statements['stores']:
            result.append({
                'function_name': func_name,
                'function_hash': func_hash,
                'parameters': func_params,
                'return_flows': return_flows,
                'all_statements': all_statements
            })
    
    return result


def extract_function_parameters(func_data):
    """
    Extract function parameters with their types from function data.
    """
    parameters = []
    
    # Check various possible parameter fields
    param_sources = ['params', 'parameters', 'arguments', 'inputs', 'args']
    
    for source in param_sources:
        if source in func_data and func_data[source]:
            param_data = func_data[source]
            break
    else:
        param_data = []
    
    # If param_data is a list of parameter objects
    if isinstance(param_data, list):
        for i, param in enumerate(param_data):
            if isinstance(param, dict):
                # Standard ABI-style parameter with name and type
                param_info = {
                    'name': param.get('name', f'param_{i}'),
                    'type': param.get('type', 'unknown'),
                    'index': i
                }
                # Add additional fields if available
                if 'indexed' in param:
                    param_info['indexed'] = param['indexed']
                if 'internalType' in param:
                    param_info['internal_type'] = param['internalType']
                    
                parameters.append(param_info)
            else:
                # Simple parameter (just type or name)
                parameters.append({
                    'name': f'param_{i}',
                    'type': str(param) if param else 'unknown',
                    'index': i
                })
    
    # If param_data is a dictionary with parameter info
    elif isinstance(param_data, dict):
        for key, value in param_data.items():
            if isinstance(value, dict) and 'type' in value:
                param_info = {
                    'name': key,
                    'type': value['type'],
                    'index': len(parameters)
                }
                if 'indexed' in value:
                    param_info['indexed'] = value['indexed']
                if 'internalType' in value:
                    param_info['internal_type'] = value['internalType']
                    
                parameters.append(param_info)
            else:
                parameters.append({
                    'name': key,
                    'type': str(value) if value else 'unknown',
                    'index': len(parameters)
                })
    
    # Try to extract parameter info from function signature if available
    if not parameters and 'signature' in func_data:
        signature = func_data['signature']
        parameters = parse_signature_parameters(signature)
    
    # Try to extract from function name if it contains parameter info
    if not parameters and 'name' in func_data:
        func_name = func_data['name']
        if '(' in func_name and ')' in func_name:
            parameters = parse_signature_parameters(func_name)
    
    return parameters


def parse_signature_parameters(signature):
    """
    Parse function parameters from a function signature string.
    Example: "transfer(address,uint256)" -> [{'name': 'param_0', 'type': 'address'}, ...]
    """
    parameters = []
    
    try:
        # Extract parameter part from signature
        if '(' in signature and ')' in signature:
            param_part = signature[signature.find('(') + 1:signature.rfind(')')]
            
            if param_part.strip():
                param_types = [p.strip() for p in param_part.split(',')]
                
                for i, param_type in enumerate(param_types):
                    # Handle array types, mappings, etc.
                    clean_type = param_type.strip()
                    
                    parameters.append({
                        'name': f'param_{i}',
                        'type': clean_type,
                        'index': i
                    })
    except Exception:
        # If parsing fails, return empty list
        pass
    
    return parameters


def extract_all_statements(trace):
    """
    Extract all require statements and storage changes from a function trace,
    regardless of return flows.
    """
    from panoramix.prettify import prettify
    from panoramix.core.arithmetic import is_zero
    
    requires = []
    stores = []
    current_idx = [0]
    
    def format_condition(condition):
        """Format a condition using the prettify function for readable output"""
        try:
            return prettify(condition, add_color=False, parentheses=False, rem_bool=True)
        except:
            return str(condition)
    
    def format_storage_location(location):
        """Format storage location for readable output"""
        try:
            return prettify(location, add_color=False, parentheses=False)
        except:
            return str(location)
    
    def extract_statements_recursive(trace_part):
        """Recursively extract all statements from trace"""
        nonlocal requires, stores, current_idx
        
        for line in trace_part:
            if not isinstance(line, (list, tuple)) or len(line) == 0:
                continue
                
            op = line[0] if isinstance(line[0], str) else str(line[0])
            
            # Handle require statements  
            if op == 'require':
                if len(line) > 1:
                    current_idx[0] += 1
                    requires.append({
                        'condition': format_condition(line[1]),
                        'idx': current_idx[0]
                    })
                    
            # Handle storage changes
            elif op in ('store', 'set'):
                if len(line) >= 3:
                    current_idx[0] += 1
                    store_info = {
                        'operation': op,
                        'location': format_storage_location(line[1]) if len(line) > 1 else 'unknown',
                        'value': format_condition(line[2]) if len(line) > 2 else 'unknown',
                        'idx': current_idx[0]
                    }
                    # For 'store' operations, we might have more parameters
                    if op == 'store' and len(line) >= 5:
                        store_info.update({
                            'size': str(line[1]) if len(line) > 1 else 'unknown',
                            'offset': str(line[2]) if len(line) > 2 else 'unknown', 
                            'location': format_storage_location(line[3]) if len(line) > 3 else 'unknown',
                            'value': format_condition(line[4]) if len(line) > 4 else 'unknown'
                        })
                    stores.append(store_info)
                    
            # Handle if statements (branches) - recurse into both branches
            elif op == 'if':
                if len(line) >= 3:
                    # Process if-true branch
                    if isinstance(line[2], list):
                        extract_statements_recursive(line[2])
                    
                    # Process if-false branch (else)
                    if len(line) >= 4 and isinstance(line[3], list):
                        extract_statements_recursive(line[3])
                        
            # Handle while loops
            elif op == 'while':
                if len(line) >= 3:
                    if len(line) > 1:
                        current_idx[0] += 1
                        requires.append({
                            'condition': f"while {format_condition(line[1])}",
                            'idx': current_idx[0]
                        })
                    if isinstance(line[2], list):
                        extract_statements_recursive(line[2])
            
            # Recurse into nested structures
            elif isinstance(line, list):
                extract_statements_recursive([line])
    
    extract_statements_recursive(trace)
    
    return {
        'requires': requires,
        'stores': stores
    }


def extract_return_flows(trace):
    """
    Extract all successful return flows from a function trace.
    Each flow contains require statements and storage changes leading to a return.
    """
    from panoramix.prettify import prettify
    from panoramix.utils.helpers import opcode
    from panoramix.core.arithmetic import is_zero
    
    flows = []
    
    def format_condition(condition):
        """Format a condition using the prettify function for readable output"""
        try:
            # Use prettify to format the condition nicely
            return prettify(condition, add_color=False, parentheses=False, rem_bool=True)
        except:
            # Fallback to string representation if prettify fails
            return str(condition)
    
    def format_storage_location(location):
        """Format storage location for readable output"""
        try:
            return prettify(location, add_color=False, parentheses=False)
        except:
            return str(location)
    
    def extract_paths_to_returns(trace_part, current_requires=None, current_stores=None, current_idx=None):
        """Recursively extract paths that lead to return statements"""
        if current_requires is None:
            current_requires = []
        if current_stores is None:
            current_stores = []
        if current_idx is None:
            current_idx = [0]  # Use list to maintain reference across recursive calls
            
        nonlocal flows
        
        for i, line in enumerate(trace_part):
            if not isinstance(line, (list, tuple)) or len(line) == 0:
                continue
                
            op = line[0] if isinstance(line[0], str) else str(line[0])
            
            # Handle return statements
            if op == 'return':
                # Extract return value(s) if present
                return_value = None
                if len(line) > 1:
                    if len(line) == 2:
                        # Single return value
                        return_value = format_condition(line[1])
                    else:
                        # Multiple return values
                        return_value = [format_condition(val) for val in line[1:]]
                
                flows.append({
                    'requires': current_requires.copy(),
                    'stores': current_stores.copy(),
                    'return_value': return_value
                })
                continue
                
            # Handle require statements  
            elif op == 'require':
                if len(line) > 1:
                    current_idx[0] += 1
                    current_requires.append({
                        'condition': format_condition(line[1]),
                        'idx': current_idx[0]
                    })
                    
            # Handle storage changes
            elif op in ('store', 'set'):
                if len(line) >= 3:
                    current_idx[0] += 1
                    store_info = {
                        'operation': op,
                        'location': format_storage_location(line[1]) if len(line) > 1 else 'unknown',
                        'value': format_condition(line[2]) if len(line) > 2 else 'unknown',
                        'idx': current_idx[0]
                    }
                    # For 'store' operations, we might have more parameters
                    if op == 'store' and len(line) >= 5:
                        store_info.update({
                            'size': str(line[1]) if len(line) > 1 else 'unknown',
                            'offset': str(line[2]) if len(line) > 2 else 'unknown', 
                            'location': format_storage_location(line[3]) if len(line) > 3 else 'unknown',
                            'value': format_condition(line[4]) if len(line) > 4 else 'unknown'
                        })
                    current_stores.append(store_info)
                    
            # Handle if statements (branches)
            elif op == 'if':
                if len(line) >= 3:
                    # Process if-true branch
                    if isinstance(line[2], list):
                        extract_paths_to_returns(line[2], current_requires.copy(), current_stores.copy(), current_idx)
                    
                    # Process if-false branch (else)
                    if len(line) >= 4 and isinstance(line[3], list):
                        extract_paths_to_returns(line[3], current_requires.copy(), current_stores.copy(), current_idx)
                        
            # Handle while loops
            elif op == 'while':
                if len(line) >= 3 and isinstance(line[2], list):
                    # Add the while condition as a requirement
                    while_requires = current_requires.copy()
                    if len(line) > 1:
                        current_idx[0] += 1
                        while_requires.append({
                            'condition': f"while {format_condition(line[1])}",
                            'idx': current_idx[0]
                        })
                    extract_paths_to_returns(line[2], while_requires, current_stores.copy(), current_idx)
    
    extract_paths_to_returns(trace)
    return flows


def main():
    args = parse_args(sys.argv[1:])

    if args.v.isnumeric():
        coloredlogs.install(level=int(args.v), milliseconds=True)
    elif hasattr(logging, args.v.upper()):
        coloredlogs.install(level=getattr(logging, args.v.upper()), milliseconds=True)
    else:
        raise ValueError("Logging should be DEBUG/INFO/WARNING/ERROR.")

    if "," in args.address_or_bytecode:
        addresses = args.address_or_bytecode.split(",")
        for i, addr in enumerate(addresses):
            print_decompilation(addr, args, i, len(addresses))
    elif args.profile:
        with cProfile.Profile() as profile:
            try:
                print_decompilation(args.address_or_bytecode, args)
            finally:
                profile.dump_stats("panoramix.prof")

    else:
        print_decompilation(args.address_or_bytecode, args)


if __name__ == "__main__":
    main()
