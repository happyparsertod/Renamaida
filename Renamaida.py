from jarowinkler import jaro_similarity
import ida_idaapi
import idautils
import idaapi
import json
import idc
import os

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

# =========================================================================================#


class RenamaidaPlugin(idaapi.plugin_t):
    flags = 0
    rename_action_name = "renamaida:rename"
    produce_action_name = "renamaida:produce"

    rename_menu_path = "Edit/Renamaida/Rename functions"
    produce_menu_path = "Edit/Renamaida/Generate JSON"

    comment = "Plugin for renaming unknown functions and generating JSON signature"
    help = ""
    wanted_name = "Renamaida"
    wanted_hotkey = ""

    def init(self):
        # Register the action
        rename_unk_funcs = idaapi.action_desc_t(
            self.rename_action_name,
            "Rename functions",
            RenamaidaRename(),
            None,
            None,
            199,
        )

        produce_json_sign = idaapi.action_desc_t(
            self.produce_action_name,
            "Generate JSON",
            RenamaidaProduce(),
            None,
            None,
            199,
        )

        idaapi.register_action(rename_unk_funcs)
        idaapi.register_action(produce_json_sign)

        idaapi.attach_action_to_menu(
            self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP
        )
        idaapi.attach_action_to_menu(
            self.produce_menu_path, self.produce_action_name, idaapi.SETMENU_APP
        )

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.produce_menu_path, self.produce_action_name)
        return


# =========================================================================================#


class RenamaidaRename(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

        self.arch = idaapi.get_inf_structure().procName.lower()

        self.unknown_func_names = {}
        self.comparison_result = {}

    def load_signature_file(self):
        # Prompt the user to select a file from a directory
        file_path = idaapi.ask_file(0, "*.json", "Select signature base file")
        if not file_path:
            return None

        # Get the file name from the path
        return os.path.abspath(file_path)

    def activate(self, ctx):
        self.signature_base_name = self.load_signature_file()

        if self.signature_base_name != None:
            with open(self.signature_base_name) as f:
                self.signature_base_json = json.load(f)
        else:
            return

        self.make_unknown_base()
        self.make_comparison()
        self.rename_in_IDA()

    def make_unknown_base(self):
        print("Processing...")

        for function_ea in idautils.Functions():
            function_name = idc.get_func_name(function_ea)

            if function_name.startswith("__") or not function_name.startswith("sub"):
                continue

            if self.arch in arm_dict:
                architecture_instructions = arm_dict[self.arch]
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

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# =========================================================================================#


class RenamaidaProduce(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

        self.function_dict = {}
        self.arch = idaapi.get_inf_structure().procName.lower()

    def activate(self, ctx):
        for function_ea in idautils.Functions():
            function_name = idc.get_func_name(function_ea)

            if function_name.startswith("__"):
                continue

            if self.arch in arm_dict:
                architecture_instructions = arm_dict[self.arch]
                function_instructions = "".join(
                    [
                        architecture_instructions[idc.print_insn_mnem(ea)]
                        for ea in idautils.FuncItems(function_ea)
                        if idc.print_insn_mnem(ea) in architecture_instructions
                    ]
                )

            if len(function_instructions) < 10:
                continue

            self.function_dict[function_name] = function_instructions

        fname = idaapi.ask_file(1, "*.json", "Save signature file as")

        if fname:
            with open(fname, "w") as f:
                json.dump(self.function_dict, f)
        else:
            return

        print("Renamaida: Signature JSON file saved!")

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# =========================================================================================#


def PLUGIN_ENTRY():
    return RenamaidaPlugin()
