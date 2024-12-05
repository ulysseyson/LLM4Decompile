from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import re
import json

def parse_function_signature(signature):
    match = re.match(r'([\w\s\*\[\]]+)\s+(\w+)\s*\((.*)\)', signature.strip())
    if not match:
        return None, None

    return_type = match.group(1).strip()

    args = match.group(3).strip()
    if args == "void" or not args:  
        arg_types = []
    else:
        arg_types = [arg.strip().split()[:-1] for arg in args.split(',')]
        arg_types = [' '.join(arg) for arg in arg_types]

    return return_type, arg_types


def get_ghid_decompile_func(target_function_name):
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    found_function = None

    functions = currentProgram.getFunctionManager().getFunctions(True)

    for function in functions:
        if function.getName() == target_function_name:
            found_function = function
            break

    if found_function:
        decomp_result = decompiler.decompileFunction(found_function, 30, ConsoleTaskMonitor())
        if decomp_result.decompileCompleted():
            decompiled_function = decomp_result.getDecompiledFunction()
            return decompiled_function.getC()
        else:
            print("[-] Failed to decompile the function.")
    else:
        print("[-] Function '{}' not found.".format(target_function_name))


def save_to_json(file_path, return_type, arg_types, signature):

    result = {
        "return_type": return_type,
        "argument_types": arg_types,
        "function_signature": signature
    }

    with open(file_path, "w") as json_file:
        json.dump(result, json_file, indent=4)
    print("[*] Results saved to ",file_path)



target_function = "func0"
signature = get_ghid_decompile_func(target_function)
if signature:
    return_type, arg_types = parse_function_signature(signature)
    print("Return Type:", return_type)
    print("Argument Types:", arg_types)

    save_to_json("./function_analysis.json", return_type, arg_types, signature)
