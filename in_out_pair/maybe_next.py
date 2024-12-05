from qiling import Qiling
from qiling.const import QL_VERBOSE
import subprocess
import struct
import re
import sys
import os
import glob
import time
import json


byte_list=["byte","char"]
f_type=["float","int","long"]
real_args=[]
real_output=[] 


def zfill_to_multiple_of_two(s):
    current_length = len(s)
    
    if current_length % 2 == 0:
        return s
    else:
        target_length = current_length + 1
        return s.zfill(target_length)

def get_out(binary_path, function_name,target_instruction):
    result = subprocess.run(['objdump', '-d',"-M intel",binary_path], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    function_pattern = re.compile(rf"([0-9a-f]+) <{function_name}>:")
    instruction_pattern = re.compile(rf"^\s+([0-9a-f]+):\s+.*\b{target_instruction}\b.*")
    function_start = None
    in_function=False
    prologue=False
    arg_check=False
    args=[]
    rets=[]
    epilogue=False
    for line in output.splitlines():
        if function_start is None:
            match = function_pattern.search(line)
            if match:
                function_start = int(match.group(1), 16)
                in_function = True
        else:
            if "mov    rbp,rsp" in line:
                prologue=True
                continue
            if "pop    rbp"in line or "leave" in line:
                epilogue=True
            if prologue:
                if target_instruction in line:
                    args.append(line)
                    arg_check=True
                if arg_check==True and target_instruction not in line:
                    prologue=False
            if epilogue:
                rets.append(tmp)
                rets.append(line)
                return args,rets

            tmp=line

    else:
        print("There is no function named ",function_name)
    return args,rets

def hook_tgkill(ql, num, args, syscall):
    print("****assertion failed!!!!***")
    ql.emu_stop()

def get_output_hex(a1):
    return hex(int.from_bytes(a1, byteorder='little'))

def get_output_int(a1):
    return int.from_bytes(a1, byteorder='little')

def get_float(a1):
    if (eval(a1))<0x10000:
        return eval(a1)

    num=bytes.fromhex(zfill_to_multiple_of_two(a1[2:]))[::-1]
    value = struct.unpack('<f',num)[0]
    if 1e-4 <= abs(value) < 1e16:
        return round(value, 5)
    else:
        return eval(a1)
   


def interpret_hex(hex_value):
    hex_value = hex_value.lower()
    if hex_value.startswith('0x'):
        hex_value = hex_value[2:]
        hex_value = zfill_to_multiple_of_two(hex_value)
    unsigned_int = int(hex_value, 16)
    
    if hex_value.startswith('fff'):
        return unsigned_int - 0x100000000
    if unsigned_int<0x100000:
        return unsigned_int
    binary_data = bytes.fromhex(hex_value)[::-1]
    float_num = struct.unpack('<f', binary_data)[0]
    float_str = f"{float_num}"
    if 'e' not in float_str.lower():
        return round(float_num,5)
    return unsigned_int

def get_hex_from_float(value):
    num = struct.pack('<f', value)
    return num

def get_arg_data(out):
    args_addrs=[]
    args_op=[]
    pattern = re.compile(r'\[(rbp-0x[0-9a-fA-F]+)\]')
    for line in out:
        args_addrs.append(line.split("\t")[0].split(":")[0].strip())
        match = pattern.search(line)
        if match:
            addr = match.group(1) 
            args_op.append(addr)
    return args_addrs,args_op

def get_rets(a1):
    ret_addrs=[]
    ret_op=[]
    for line in a1:
        addr=line.split("\t")[0].split(":")[0].strip()
        op=line.split("\t")[2]
        ret_addrs.append(addr)
        ret_op.append(op)
    return ret_addrs,ret_op

def arr_check(ql, target_op):
    try:
        zzz=get_output_int(ql.mem.read(target_op,8))
        zzz=get_output_int(ql.mem.read(zzz,4))
        return True
    
    except Exception as e:
        return False

def get_arr(ql, arr1,arr2):
    cnt=0
    arr=[]
    arr_base=get_output_int(ql.mem.read(arr1,8))
    length=get_output_int(ql.mem.read(arr2,4))
    while cnt<length:
        try:
            value=get_output_int(ql.mem.read(arr_base+cnt*4,4))
            arr.append(value)
            cnt+=1
    
        except Exception as e:
            return arr
    return arr
        
def arg_breakpoint(ql):

    global real_args 
    argggs=[]
    rbp = ql.arch.regs.rbp
    ops=ql.args_op

    dec_types=ql.decomp_data["argument_types"]

    for i in range(len(dec_types)):
        target_op=eval(ops[i])
        arg_type=dec_types[i]

        if arr_check(ql, target_op):
            #print("arr!!")
            if i+1<len(ops):
                array=get_arr(ql,target_op,eval(ops[i+1]))
                tarnsfomed_array=[interpret_hex(hex(i))for i in array]
                
                argggs.append(tarnsfomed_array)
                #print(f"arg{i+1}:{tarnsfomed_array},{len(array)},{arg_type}")
        else:
            #print("none arrr!")
            value=ql.mem.read(target_op, 4)
            if arg_type=="char":
                value=ql.mem.read(target_op, 4)
            else:
                value=ql.mem.read(target_op, 4)
            value=get_output_hex(value)
            real_data=interpret_hex(value)
            argggs.append(real_data)
    real_args.append(argggs)
        
    # print(f"arg{i+1}: {real_data},{arg_type}")
    '''
            if arg_type in f_type:
                new_value = struct.pack('<f',real_data+0.5)
                ql.mem.write(target_op, new_value)
            elif arg_type in byte_list:
                new_value = struct.pack('<I', ord(real_data)+4)
                ql.mem.write(target_op, new_value)
            else:
                new_value = struct.pack('<I', eval(real_data)*10)
                ql.mem.write(target_op, new_value)
        '''
    
def ret_breakpoint(ql):
    global real_output
    zz=ql.ret_op[0]
    out=ql.arch.regs.rax
    if "xmm0" in zz:
        out=ql.arch.regs.xmm0
    ret_type=ql.decomp_data["return_type"]
    real_data=interpret_hex(hex(out))
    real_output.append(real_data)
   # print(f"output:{real_data},{ret_type}")


def run_ghidra_analysis(ghidra_path, project_dir, project_name, binary_path, script_path):

    headless_cmd = [
        os.path.join(ghidra_path, "support", "analyzeHeadless"), 
        project_dir,  
        project_name,  
        "-import", binary_path,
        "-postScript", script_path  
    ]
    result = subprocess.run(headless_cmd,  capture_output=True, text=True)
    '''
    if result.returncode == 0:
      print("[*] Ghidra Headless analysis completed successfully.")
    else:
      print("[-] Ghidra Headless analysis failed!")
    '''

def cleanup_output_directory(output_dir):

    #print(f"[*] Cleaning up directory: {output_dir}")
    for file_path in glob.glob(os.path.join(output_dir, "*.*")):
        os.system(f"rm -rf {file_path}")


def run_qiling(target_bin):
    target_func="func0"
    target_inst="mov"
    rootfs="./rootfs"
    args,rets=get_out(target_bin,target_func,target_inst)
    args_addrs,args_op=get_arg_data(args)
    ret_addrs,ret_op=get_rets(rets)
    ql = Qiling([target_bin], rootfs,verbose=QL_VERBOSE.OFF)

    base=0x0000555555554000
    arg_breakpoint_address = base+int(args_addrs[-1],16)
    ret_breakpoint_address = base+int(ret_addrs[-1],16)

    with open("function_analysis.json", "r") as file:
        decomp_data = json.load(file)
    ql.args_op=args_op

    ql.ret_op=ret_op
    ql.decomp_data=decomp_data
    #print(ql.decomp_data["function_signature"])
    ql.hook_address(arg_breakpoint, arg_breakpoint_address,)
    ql.os.set_syscall("tgkill", hook_tgkill)
    ql.hook_address(ret_breakpoint, ret_breakpoint_address)
    ql.run()

    ql.emu_stop()

if __name__ == "__main__":
    start_time = time.perf_counter() 
    test_binary=[0,2,3,4]
    for i in range(len(test_binary)):
        ghidra_path = "./ghidra_11.2.1_PUBLIC"
        project_dir = "./output_binary"
        target_binary_name = "pgm"+str(test_binary[i]).zfill(3)
        print(f"\n====={target_binary_name}======\n")
        binary_path = project_dir+"/"+target_binary_name
        script_path = "./ttt.py"
       
        run_ghidra_analysis(ghidra_path, project_dir, target_binary_name, binary_path, script_path)
        cleanup_output_directory(project_dir)
        start_time2 = time.perf_counter() 
        run_qiling(binary_path)
        end_time = time.perf_counter()
        print(real_args)
        print(real_output)
        real_args=[]
        real_output=[]
        print(f"Qiling Execution Time: {end_time - start_time2:.6f} seconds")
    print(f"Whole Execution Time: {end_time - start_time:.6f} seconds")

