import subprocess
from transformers import AutoTokenizer, AutoModelForCausalLM
import argparse
import os
import torch
import re
import json
from tqdm import tqdm, trange

os.environ["TOKENIZERS_PARALLELISM"] = "false"
parser = argparse.ArgumentParser()
parser.add_argument(
    "--model_path",
    type=str,
    default="LLM4Binary/llm4decompile-6.7b-v1.5",
    required=False,
)
parser.add_argument(
    "--data_path",
    type=str,
    default="../decompile-eval/decompile-eval-executable-gcc-obj.json",
    required=False,
)

args = parser.parse_args()


def evaluate_func(c_func, c_test, c_func_decompile):
    flag_compile = 0
    flag_run = 0
    c_include = ""
    for line in c_func.split("\n"):
        if "#include" in line:
            c_include += line + "\n"
            c_func = c_func.replace(line, "")
    for line in c_test.split("\n"):
        if "#include" in line:
            c_include += line + "\n"
            c_test = c_test.replace(line, "")
    c_combine = c_include + "\n" + c_func_decompile + "\n" + c_test
    c_onlyfunc = c_include + "\n" + c_func_decompile

    # Define the C file and executable names
    c_file = "combine.c"
    executable = "combine"
    if os.path.exists(executable):
        os.remove(executable)

    c_file_onlyfunc = "onlyfunc.c"
    executable_onlyfunc = "onlyfunc"
    if os.path.exists(executable):
        os.remove(executable_onlyfunc)

    with open(c_file, "w") as f:
        f.write(c_combine)
    with open(c_file_onlyfunc, "w") as f:
        f.write(c_onlyfunc)

    # Compile the C program to an assembly
    compile_command = f"gcc -S {c_file_onlyfunc} -o {executable_onlyfunc} -lm"
    try:
        subprocess.run(compile_command, shell=True, check=True)
        flag_compile = 1
    except:
        return flag_compile, flag_run

    # Compile the C program to an executable
    compile_command = f"gcc {c_file} -o {executable} -lm"
    try:
        subprocess.run(compile_command, shell=True, check=True)
        flag_compile = 1
    except:
        return flag_compile, flag_run

    # Run the compiled executable
    run_command = f"./{executable}"
    try:
        process = subprocess.run(
            run_command, shell=True, check=True, capture_output=True, timeout=5
        )
        flag_run = 1
    except subprocess.CalledProcessError as e:
        pass
    except Exception as e:
        pass
    return flag_compile, flag_run


model_id = args.model_path
tokenizer = AutoTokenizer.from_pretrained(model_id, padding_side="left")
tokenizer.pad_token_id = tokenizer.eos_token_id
terminators = [tokenizer.eos_token_id, tokenizer.convert_tokens_to_ids("<|eot_id|>")]
from transformers import pipeline

pl = pipeline(
    "text-generation",
    model=model_id,
    tokenizer=tokenizer,
    torch_dtype=torch.float16,
    trust_remote_code=True,
    device_map="auto",
    do_sample=False,
    max_new_tokens=512,
    eos_token_id=terminators,  # I already set the eos_token_id here, still no end for its self-coververstaion
    pad_token_id=tokenizer.eos_token_id,
    token="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",
    #     model_kwargs={
    #         # "attn_implementation": "flash_attention_2",
    #         "ch"
    #         # ""
    #     },
)

print("Model Loaded!")
tokenizer.pad_token = tokenizer.eos_token
tokenizer.pad_token_id = tokenizer.eos_token_id
system_prompt = {
    "role": "system",
    "content": (
        "You are a decompiler assistant."
        "User will give you ghidra pseudo code and it's specific optimization level when compiled."
        "The input and output values ​​of the function that the original function must pass through are given."  # Add for ver1.0
        "Your goal is just give refined source code, form as single function."
        "Follow below instructions"
        "- Don't repeat input function which is given by user."
        "- Don't wrap code in formatting symbols."
        "- Don't need to write Doxygen comments."
        "- Aware that now you are writing C/C++ code, compilable and executable"
        "- Every function have return values"
        "- Concern given binary's input-output test values, which our refined function should follows."  # Add for ver1.0
        "User prompt will be provided like below"
        "// This is the Ghidra decompiled pseudo code with [optimization level]:\n"
        "[pseudo code]\n\n"
        "// This is input-output pairs for function testing"  # Add for ver1.0
        "[input]->[output]"  # Add for ver1.0
        "Then You will answer like this"
        "// Refined source code from given pseudo code"
    ),
}
OPT = ["O0", "O1", "O2", "O3"]  # Optimization states
opts = {
    "O0": "// This is the ghidra decompiled pseudo code with O0 optimization:\n",
    "O1": "// This is the ghidra decompiled pseudo code with O1 optimization:\n",
    "O2": "// This is the ghidra decompiled pseudo code with O2 optimization:\n",
    "O3": "// This is the ghidra decompiled pseudo code with O3 optimization:\n",
}
test_values = ""
with open(args.data_path, "r") as f:
    data_all = json.load(f)  # [104:]
total_prompts = []
from transformers.pipelines.text_generation import Chat
import re


def extract_assertions(func):
    # Pattern to capture func0 call within an assert statement
    pattern = re.compile(r"assert\s*\(\s*func0\s*\(([^)]+)\)\s*==\s*(\d+)\s*\);")

    # Find all assertions and store as (input_args_list, output_value) tuples
    results = []
    matches = pattern.findall(func)
    for match in matches:
        # Split function arguments and strip whitespace
        args = match[0].split(",")
        input_args_list = [arg.strip() for arg in args]

        # Expected output is the second captured group
        output_value = int(match[1])

        # Append result as a tuple
        results.append((input_args_list, output_value))

    return results


for data in data_all:
    opt = data["type"]
    input_asm_prompt = data["input_asm_prompt"]
    c_test = data["c_test"]
    # extract assert in c_test
    tests = extract_assertions(c_test)
    user_prompt = {
        "role": "user",
        "content": (
            f"{opts[opt]}" f"{input_asm_prompt[:5000]}"
        ),  # Strip if too long asm code
    }
    if len(tests) > 0:
        user_prompt["content"] += "//This is input-output pairs for function test.\n"
        user_prompt["content"] += "\n".join(
            [str(i) + " -> " + str(o) for i, o in tests]
        )
    else:
        user_prompt["content"] += "There is no input-output for this function.\n"
    total_prompts.append(Chat([system_prompt, user_prompt]))

total_prompts = total_prompts
NUM = int(len(data_all) / 4)
num_compile = {"O0": 0, "O1": 0, "O2": 0, "O3": 0}
num_run = {"O0": 0, "O1": 0, "O2": 0, "O3": 0}
c_func_decompile_list = []
opt_state_list = []
c_func_list = []
c_test_list = []
idx = 0
from torch.utils.data import Dataset


class MDataset(Dataset):
    def __init__(self):
        self.pint = total_prompts

    def __len__(self):
        return len(self.pint)

    def __getitem__(self, index):
        return self.pint[index]


dataset = MDataset()
import os
from torch.utils.data import DataLoader

os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

with torch.no_grad():
    batch_size = 1
    for out in tqdm(
        pl(dataset, batch_size=8, truncation="only_first", max_new_tokens=512),
        total=len(total_prompts),
    ):

        c_func_decompile = out[0]["generated_text"][-1]["content"]
        opt_state = data_all[idx]["type"]
        c_func = data_all[idx]["c_func"]
        c_test = data_all[idx]["c_test"]
        c_func_decompile_list.append(c_func_decompile)
        opt_state_list.append(opt_state)
        c_func_list.append(c_func)
        c_test_list.append(c_test)
        idx += 1
        del out
        torch.cuda.empty_cache()

for idx in trange(len(total_prompts)):
    c_func, c_test, c_func_decompile, opt_state = (
        c_func_list[idx],
        c_test_list[idx],
        c_func_decompile_list[idx],
        opt_state_list[idx],
    )
    flag_compile, flag_run = evaluate_func(c_func, c_test, c_func_decompile)
    num_compile[opt_state] += flag_compile
    num_run[opt_state] += flag_run

with open("results.txt", "a") as f:
    for opt_state in num_compile.keys():
        f.write(
            "model:{},opt:{},compile rate:{:.4f},run_rate:{:.4f}\n".format(
                args.model_path,
                opt_state,
                num_compile[opt_state] / NUM,
                num_run[opt_state] / NUM,
            )
        )
with open("./decompile_result_test_pair.json", "w") as f:
    import json

    json.dump(c_func_decompile_list, f)
