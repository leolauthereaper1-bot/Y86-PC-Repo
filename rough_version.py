# cpu project Y86-64
import sys
import json
import copy

CC = {"OF": 0, "SF": 0, "ZF": 1} # Condition Codes
MEM = {} # Memory
PC = 0 # Program Counter
REG = {# Registers
    "r10":0, "r11":0, "r12":0, "r13":0, "r14":0,
    "r8":0, "r9":0, "rax":0, "rbp":0, "rbx":0,
    "rcx":0, "rdi":0, "rdx":0, "rsi":0, "rsp":0
}
STAT = 1 # normal state                     

context = {"CC": CC, "MEM": MEM, "PC": PC, "REG": REG, "STAT": STAT}

all_result = []


instruction_set = {
    "halt": "00",
    "nop": "10",
    "rrmovq": "20",
    "cmovle": "21",
    "cmovl": "22",
    "cmove": "23",
    "cmovne": "24",
    "cmovge": "25",
    "cmovg": "26",
    "irmovq": "30",
    "rmmovq": "40",
    "mrmovq": "50",
    "addq": "60",
    "subq": "61",
    "andq": "62",
    "xorq": "63",
    "jmp": "70",
    "jle": "71",
    "jl": "72",
    "je": "73",
    "jne": "74",
    "jge": "75",
    "jg": "76",
    "call": "80",
    "ret": "90",
    "pushq": "a0",
    "popq": "b0"
}

register_set = {
    "rax": "0",
    "rcx": "1",
    "rdx": "2",
    "rbx": "3",
    "rsp": "4",
    "rbp": "5",
    "rsi": "6",
    "rdi": "7",
    "r8":  "8",
    "r9":  "9",
    "r10": "a",
    "r11": "b",
    "r12": "c",
    "r13": "d",
    "r14": "e",
    "no_reg": "f"
}

def memory_check(address, ctx): # memory address cannot be negative
    if address & 0x8000000000000000:
        ctx["STAT"] = 3 # bad address
        return False
    else:
        return True

def icode_decode(ctx,machine_code):
    pc = ctx["PC"]*2
    f_code = machine_code[pc:pc+2] 
    # f_code is a string like "20", "30", "61", etc.
    for type, encoding in instruction_set.items():
        if encoding == f_code:
             f_type = type
             break
    icode = int(f_code[0], 16)  # first nibble
    read_len = 1
    if icode in {0x0, 0x1, 0x9}:      # halt, nop, ret
        read_len = 1
    elif icode in {0x2, 0x6, 0xA, 0xB}:  # rrmovq, OPq, pushq, popq
        read_len = 1+1
    elif icode in {0x3, 0x4, 0x5}:      # irmovq, rmmovq, mrmovq
        read_len = 1 + 1 + 8            # opcode + reg + const
    elif icode in {0x7, 0x8}:           # jXX, call
       read_len = 1 + 8                # opcode + addr
    else:
        ctx["STAT"] = 4
        snapshot(ctx)
        return None, None
    return read_len, f_type

def operate(data):
    all_instructions = fetch(data)
    ctx = context # single context program
    MEM_initialization(ctx,all_instructions)
    while(True):
        try:
           ptr = ctx["PC"]
           read_len, f_type = icode_decode(ctx,all_instructions)
           if(not read_len or not f_type):
               break
           command = all_instructions[ptr*2:ptr*2+read_len*2] # bytes to char
           f_execute(command, f_type, read_len, ctx)
           #time.sleep(0.1)
           if ctx["STAT"] != 1: 
               break
        except:
           print("Error occured during the program")
           break
    return all_result

def MEM_initialization(ctx,all_instructions):
    bytes = len(all_instructions) // 2 # 2 character stands for 1 byte in the system
    num = bytes // 8 # <=「total number」
    padding = 2*(8-(bytes)%8)*'0' # easier to compute
    for i in range(num):
        if(little_endian(all_instructions[i*16:i*16+16])!=0): # 16 chars = 8 bytes = 1 integer
           ctx["MEM"][str(i*8)] = little_endian(all_instructions[i*16:i*16+16]) # un-zero because zero == uninitialized
    if padding and little_endian(all_instructions[num*16:])!=0:
        ctx["MEM"][str(num*8)] = little_endian(all_instructions[num*16:] + padding)

def fetch(data):
    icode = data.split("\n")
    all_instructions=""
    for code in icode:
        code = code.strip()
        if(code and code[:2]=="0x"):
            code, _ = code.split("|")
            code = code.strip()
            address, instruction = code.split(":")
            instruction = instruction.strip()
            if(instruction):
                address= int(address,16)
                all_instructions += 2*(address-(len(all_instructions)//2))*'0' # alignment (built for array initialization)
                all_instructions += instruction

    return all_instructions

def little_endian(value):
    right_value=0
    length = len(value)
    for i in range(0,length,2):
        right_value += int(value[i:i+2],16)*(16**i)
    if right_value & 0x8000000000000000:
        right_value = right_value - 0xffffffffffffffff - 1 # switch to negative in decimal
    return right_value

def snapshot(ctx):
    all_result.append(copy.deepcopy(ctx))


def f_execute(line, f_type, read_len, ctx):
    pc_potential = ctx["PC"] + read_len
    if(f_type[:4] == "cmov"):
        f_type = "cmovxx"
    if(f_type[0] == "j" and f_type != "jmp"):
        f_type = "jxx"
    match f_type:
        case "halt":
            f_halt(ctx)
     
        case "nop":
            f_nop()
            ctx["PC"] = int(pc_potential)
     
        case "rrmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_rrmovq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "cmovxx":
            condition = int(line[1])
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_cmovxx(target_reg1, target_reg2, condition, ctx)
                ctx["PC"] = int(pc_potential)

        case "irmovq":
            value = little_endian(line[4:])
            register_encoding = line[3]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                ctx["STAT"] = 4
            else:
                f_irmovq(target_reg,value, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "rmmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            offset = little_endian(line[4:])
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:   
                if f_rmmovq(target_reg1, target_reg2, offset, ctx):
                   ctx["PC"] = int(pc_potential)
             
        case "mrmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            offset = little_endian(line[4:])
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_mrmovq(target_reg1, target_reg2, offset, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "addq":
            target_reg1 = ""        
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_addq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "subq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_subq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "andq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_andq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "xorq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = line[2]
            reg2_encoding = line[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                ctx["STAT"] = 4
            else:
                f_xorq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
         
        case "jmp":
            destination = little_endian(line[2:])
            f_jmp(destination, ctx)
     
        case "jxx":
            condition = int(line[1])
            destination = little_endian(line[2:])
            f_jmpxx(destination, condition, int(pc_potential), ctx)
     
        case "call":
             destination = little_endian(line[2:])
             f_call(destination, ctx, int(pc_potential))
         
        case "ret":
            f_ret(ctx)
     
        case "pushq":
            register_encoding = line[2]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                ctx["STAT"] = 4
            else:
                if f_pushq(target_reg,ctx):
                   ctx["PC"] = int(pc_potential)
             
        case "popq":
            register_encoding = line[2]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                ctx["STAT"] = 4
            else:
                f_popq(target_reg,ctx)
                ctx["PC"] = int(pc_potential)
    snapshot(ctx)


def f_halt(ctx):
   ctx["STAT"] = 2
   return

def f_nop():
    return

def f_rrmovq(rA, rB, ctx):
   temp = ctx["REG"][rA]
   ctx["REG"][rB] = temp

def f_cmovxx(rA, rB, condition, ctx):
    flag_of = ctx["CC"]["OF"]
    flag_sf = ctx["CC"]["SF"]
    flag_zf = ctx["CC"]["ZF"]
    op_flag = 0
    match condition:
        case 1:
            op_flag = flag_zf | (flag_sf & int(not flag_of))
        case 2:
            op_flag = (flag_sf & int(not flag_of))
        case 3:
            op_flag = flag_zf
        case 4:
            op_flag = int(not flag_zf)
        case 5:
            op_flag = flag_zf | (int(not flag_sf) & int(not flag_of))
        case 6:
            op_flag = int(not flag_sf) & int(not flag_of)
    if(op_flag):
        f_rrmovq(rA, rB, ctx)

def f_irmovq(rB, value, ctx):
    ctx["REG"][rB] = value

def f_rmmovq(rA, rB, offset, ctx):
    temp = ctx["REG"][rA]
    address = ctx["REG"][rB] + offset
    if not memory_check(address, ctx): # wrong address
        return 0
    else:
        ctx["MEM"][str(address)] = temp
        return 1
        
def f_mrmovq(rA, rB, offset, ctx):
    address = ctx["REG"][rB] + offset
    try:
        temp = ctx["MEM"][str(address)]
        ctx["REG"][rA] = temp
    except:
        ctx["REG"][rA] = 0 # uninitializaed

def f_addq(rA, rB, ctx):
    ctx["CC"]["OF"]=0
    temp = ctx["REG"][rA] + ctx["REG"][rB]
    if((temp>0 and ctx["REG"][rA]<0 and ctx["REG"][rB]<0) or (temp<0 and ctx["REG"][rA]>0 and ctx["REG"][rB]>0)): ctx["CC"]["OF"]=1
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def f_subq(rA, rB, ctx):
    ctx["CC"]["OF"]=0
    temp = ctx["REG"][rB] - ctx["REG"][rA]
    if((temp>0 and ctx["REG"][rA]>0 and ctx["REG"][rB]<0) or (temp<0 and ctx["REG"][rA]<0 and ctx["REG"][rB]>0)): ctx["CC"]["OF"]=1
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def f_andq(rA, rB, ctx):
    ctx["CC"]["OF"]=0
    temp = ctx["REG"][rB] & ctx["REG"][rA]
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def f_xorq(rA, rB, ctx):
    ctx["CC"]["OF"]=0
    temp = ctx["REG"][rB] ^ ctx["REG"][rA]
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def flag_set(temp, ctx): 
    if (temp > 0):
        ctx["CC"]["ZF"] = 0
        ctx["CC"]["SF"] = 0
    elif (temp == 0):
        ctx["CC"]["ZF"] = 1
        ctx["CC"]["SF"] = 0
    else:
        ctx["CC"]["ZF"] = 0
        ctx["CC"]["SF"] = 1

def f_jmp(destination, ctx):
    ctx["PC"] = int(destination)

# Jump will only base on the flags' values // condition refers to the fn_code
def f_jmpxx(destination, condition, potential_pc, ctx):
    op_flag = 0
    flag_of = ctx["CC"]["OF"]
    flag_sf = ctx["CC"]["SF"]
    flag_zf = ctx["CC"]["ZF"]
    match condition:
        case 1:
            op_flag = flag_zf | (flag_sf & int(not flag_of))
        case 2:
            op_flag = (flag_sf & int(not flag_of))
        case 3:
            op_flag = flag_zf
        case 4:
            op_flag = int(not flag_zf)
        case 5:
            op_flag = flag_zf | (int(not flag_sf) & int(not flag_of))
        case 6:
            op_flag = int(not flag_sf) & int(not flag_of)
    if(op_flag):
        f_jmp(destination, ctx)
    else:
        ctx["PC"] = potential_pc
    # if jmpxx failed, pc shall point back!!
    
def f_call(destination, ctx, pc_potential): 
    f_return_address = pc_potential 
    ctx["REG"]["rsp"] -= 0x8
    try:
        address_stored_position = ctx["REG"]["rsp"] # uninitializaed address is unacceptable 
        ctx["MEM"][str(address_stored_position)] = f_return_address
        f_jmp(destination, ctx)
    except:
       ctx["STAT"] = 3

def f_ret(ctx):
    try:
       return_mem_position = ctx["REG"]["rsp"]
       return_address = ctx["MEM"][str(return_mem_position)]
       ctx["PC"] = return_address
       ctx["REG"]["rsp"] += 0x8
       f_jmp(return_address, ctx)
    except:
        ctx["STAT"] = 3

def f_pushq(rA, ctx):
    value = ctx["REG"][rA]
    ctx["REG"]["rsp"] -= 0x8
    new_address = ctx["REG"]["rsp"]
    if not memory_check(new_address, ctx):
        return 0
    if value: # value = 0 stands for unitializaed number
        ctx["MEM"][str(new_address)] = value
    return 1

def f_popq(rA, ctx):
    pop_address = ctx["REG"]["rsp"]
    # if the value is not found it is thought as undefined or it is 0, either way pop zero back
    try:
       pop_value = ctx["MEM"][str(pop_address)]
       ctx["REG"][rA] = pop_value
       if(rA != "rsp"):
           ctx["REG"]["rsp"] += 0x8
    except:
        ctx["REG"][rA] = 0
        if(rA != "rsp"):
           ctx["REG"]["rsp"] += 0x8
        return

# a small test
if __name__ == "__main__":
    data = sys.stdin.read()
    all_result = operate(data)
    json.dump(all_result, sys.stdout)

