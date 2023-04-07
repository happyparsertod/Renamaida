import idautils
import idc
import json

arm_dict = {
    "arm": {
        "MOV": "a",
        "MVN": "b",
        "ADD": "c",
        "SUB": "d",
        "MUL": "e",
        "LSL": "f",
        "LSR": "g",
        "ASR": "h",
        "ROR": "i",
        "CMP": "j",
        "AND": "k",
        "ORR": "l",
        "EOR": "m",
        "LDR": "n",
        "STR": "o",
        "LDM": "p",
        "STM": "q",
        "PUSH": "r",
        "POP": "s",
        "B": "t",
        "BL": "u",
        "BLX": "v",
        "BEQ": "w",
        "SWI": "x",
        "SVC": "y",
        "NOP": "z",
    },
    "metapc": {
        "MOV": "A",
        "ADD": "B",
        "SUB": "C",
        "CMP": "D",
        "JMP": "E",
        "JE": "F",
        "JNE": "G",
        "JZ": "H",
        "JNZ": "I",
        "CALL": "J",
        "RET": "K",
        "PUSH": "L",
        "POP": "M",
        "LEA": "N",
        "AND": "O",
        "OR": "P",
        "XOR": "Q",
        "NOT": "R",
        "SHL": "S",
        "SHR": "T",
        "ROL": "U",
        "ROR": "V",
        "TEST": "W",
        "LOOP": "X",
        "INT": "Y",
        "NOP": "Z",
    },
    "ppc": {
        "add": "a",
        "addc": "b",
        "addi": "c",
        "addic": "d",
        "and": "e",
        "andi.": "f",
        "b": "g",
        "bc": "h",
        "bca": "i",
        "bcl": "j",
        "bclr": "k",
        "cmp": "l",
        "cmpl": "m",
        "cntlzw": "n",
        "crand": "o",
        "cror": "p",
        "crxor": "q",
        "lbz": "r",
        "li": "s",
        "lis": "t",
        "lwz": "u",
        "mflr": "v",
        "mtlr": "w",
        "mullw": "x",
        "or": "y",
        "ori": "z",
        "rlwinm": "A",
        "srw": "B",
        "stw": "C",
        "subf": "D",
        "subi": "E",
        "xor": "F",
    },
    "mips": {
        "add": "A",
        "addi": "B",
        "addiu": "C",
        "addu": "D",
        "and": "E",
        "andi": "F",
        "beq": "G",
        "bne": "H",
        "j": "I",
        "jal": "J",
        "jr": "K",
        "lbu": "L",
        "lhu": "M",
        "ll": "N",
        "lui": "O",
        "lw": "P",
        "nor": "Q",
        "or": "R",
        "ori": "S",
        "sb": "T",
        "sh": "U",
        "slti": "V",
        "sltiu": "W",
        "sll": "X",
        "srl": "Y",
        "sw": "Z",
    },
}

# Create an empty dictionary to store the function names and instructions
functions_dict = {}

arch = idaapi.get_inf_structure().procName.lower()

# Iterate through all the functions in the binary
for function_ea in idautils.Functions():
    # Get the function name
    function_name = idc.get_func_name(function_ea)
    
    # Pass system or api functions
    if function_name.startswith("__"):
        continue

    # Get the function instructions and join them into a string
    if arch in arm_dict:
        architecture_instructions = arm_dict[arch]
        function_instructions = "".join(
            [
                architecture_instructions[idc.print_insn_mnem(ea)]
                for ea in idautils.FuncItems(function_ea)
                if idc.print_insn_mnem(ea) in architecture_instructions
            ]
        )

    # Get only functions that contains more than 10 instructions
    if len(function_instructions) < 10:
        continue

    # Add the function name and instructions to the dictionary
    functions_dict[function_name] = function_instructions

# Save the function dictionary as a JSON file
with open("", "w") as f:
    json.dump(functions_dict, f)
