from jarowinkler import jaro_similarity
import ida_idaapi
import idautils
import idaapi
import json
import idc
import os


class Renamaida(idaapi.action_handler_t):
    def __init__(self, signature_base_name):
        idaapi.action_handler_t.__init__(self)

        self.arch = idaapi.get_inf_structure().procName.lower()
        self.signature_base_name = signature_base_name

        self.arch_instructions_dict = {
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

        self.unknown_func_names = {}
        self.comparison_result = {}

        with open(self.signature_base_name) as f:
            self.signature_base_json = json.load(f)

        self.make_unknown_base()
        self.make_comparison()
        self.rename_in_IDA()

    def make_unknown_base(self):
        print("Processing...")

        for function_ea in idautils.Functions():
            function_name = idc.get_func_name(function_ea)

            if function_name.startswith("__") or not function_name.startswith("sub"):
                continue

            if self.arch in self.arch_instructions_dict:
                architecture_instructions = self.arch_instructions_dict[self.arch]
                function_instructions = "".join(
                    [
                        architecture_instructions[idc.print_insn_mnem(ea)]
                        for ea in idautils.FuncItems(function_ea)
                        if idc.print_insn_mnem(ea) in architecture_instructions
                    ]
                )

            if len(function_instructions) < 10:
                continue

            self.unknown_func_names[function_name] = function_instructions

    def compare(self, item, exclusion_list):
        similarity_scores = [
            (base, jaro_similarity(item, self.signature_base_json[base]))
            for base in self.signature_base_json
            if base not in exclusion_list
        ]

        most_similar_func, highest_score = max(
            similarity_scores, key=lambda x: x[1], default=("", 0)
        )

        return [most_similar_func, highest_score]

    def make_comparison(self):
        for item in self.unknown_func_names:
            self.unknown_func_names[item] = [self.unknown_func_names[item], []]

        for unk in self.unknown_func_names:
            flag = False

            while True:
                result = self.compare(
                    self.unknown_func_names[unk][0], self.unknown_func_names[unk][1]
                )

                if result[1] < 0.83:
                    break
                else:
                    self.comparison_result[unk] = result

                for comp in self.comparison_result:
                    if (
                        self.comparison_result[comp][0]
                        == self.comparison_result[unk][0]
                        and comp != unk
                    ):
                        if (
                            self.comparison_result[comp][1]
                            > self.comparison_result[unk][1]
                        ):
                            flag = True
                            break

                        elif (
                            self.comparison_result[comp][1]
                            < self.comparison_result[unk][1]
                        ):
                            unk = comp
                            flag = True
                            break

                if flag:
                    self.unknown_func_names[unk][1].append(
                        self.comparison_result[unk][0]
                    )
                    del self.comparison_result[unk]
                    flag = False
                    continue

                break

    def rename_in_IDA(self):
        for func_name, data in self.comparison_result.items():
            new_name = data[0]
            counter = 1
            while idc.get_name_ea_simple(new_name) != ida_idaapi.BADADDR:
                new_name = f"{data[0]}_{counter}"
                counter += 1

            if idc.get_name_ea_simple(func_name) != ida_idaapi.BADADDR:
                idc.set_name(idc.get_name_ea_simple(func_name), new_name)

        print(f"Renamaida: {len(self.comparison_result)} functions renamed!")


class RenamaidaPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_PROC

    explain_action_name = "Renamaida::rename_functions"
    explain_menu_path = "Edit/Renamaida"
    comment = "Description of the Renamaida plugin"
    help = "Usage: RenamaidaPlugin"
    wanted_name = "Renamaida"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Prompt the user to select a file from a directory
        file_path = idaapi.ask_file(0, "*.json", "Select signature base file")
        if not file_path:
            return

        # Get the file name from the path
        signature_base_name = os.path.abspath(file_path)

        # Register the action
        rename_unk_funcs = idaapi.action_desc_t(
            self.explain_action_name,
            "Rename all functions",
            Renamaida(signature_base_name),
            "Ctrl+Alt+M",
            "Rename all unknown functions imported from public libraries",
            200,
        )
        idaapi.register_action(rename_unk_funcs)

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)


def PLUGIN_ENTRY():
    return RenamaidaPlugin()
