import time
import sys
import json
import copy
# key issue unresolved: how to calculate the value or the destination
# how to jmp to that specific destination

# cpu project Y86-64

# condtiotion counter initialization
CC = {}
CC["OF"] = 0 # overflow flag
CC["SF"] = 0 # sign flag
CC["ZF"] = 1 # zero flag

# Memory intialization
MEM = {}

# PC (pointer counter) initialization
PC =  0

# Register initialization
REG = {}
REG["r10"] = 0
REG["r11"] = 0
REG["r12"] = 0
REG["r13"] = 0
REG["r14"] = 0
REG["r8"] = 0
REG["r9"] = 0
REG["rax"] = 0
REG["rbp"] = 0
REG["rbx"] = 0
REG["rcx"] = 0
REG["rdi"] = 0
REG["rdx"] = 0
REG["rsi"] = 0
REG["rsp"] = 0


# Status of the computer
STAT = 1

# Context set
context = {}
context["CC"] = CC
context["MEM"] = MEM
context["PC"] = PC
context["REG"] = REG
context["STAT"] = STAT


""" the codes below are for instructions """


# Encode Instructions (prefixes)

halt = "00"
nop = "10"
rrmovq = "20" # reg 2 reg mov
cmovxx = {} # 2 + le, e, ge, l, ne, g from 1 to 6
irmovq = "30" # immediate to register (the value is pre-defined)
rmmovq = "40" # reg to memory
mrmovq = "50" # memory to register
addq = "60"
subq = "61"
andq = "62"
xorq = "63"
jmp = "70"
jxx = {} # again: 7 + le, e, ge, l, ne, g from 1 to 6
call = "80"
ret = "90"
pushq = "a0"
popq = "b0"

# specific conditions: fn encoding
le = "1" # less or equal
l = "2" # less
e = "3" # equal
ne = "4" # not equal
ge = "5" # greater or equal
g = "6" # greater

# cmovxx
cmovxx["le"] = "2" + le
cmovxx["l"] = "2" + l
cmovxx["e"] = "2" + e
cmovxx["ne"] = "2" + ne
cmovxx["ge"] = "2" + ge
cmovxx["g"] = "2" + g

# jxx
jxx["le"] = "7" + le
jxx["l"] = "7" + l
jxx["e"] = "7" + e
jxx["ne"] = "7" + ne
jxx["ge"] = "7" + ge
jxx["g"] = "7" + g


# all instructions first 2 numbers
instruction_set = {}
instruction_set["halt"] = halt 
instruction_set["nop"] = nop
instruction_set["rrmovq"] = rrmovq
instruction_set["cmovle"] = cmovxx["le"]
instruction_set["cmovl"] = cmovxx["l"]
instruction_set["cmove"] = cmovxx["e"]
instruction_set["cmovne"] = cmovxx["ne"]
instruction_set["cmovge"] = cmovxx["ge"]
instruction_set["cmovg"] = cmovxx["g"]
instruction_set["irmovq"] = irmovq
instruction_set["rmmovq"] = rmmovq
instruction_set["mrmovq"] = mrmovq
instruction_set["addq"] = addq
instruction_set["subq"] = subq
instruction_set["andq"] = andq
instruction_set["xorq"] = xorq
instruction_set["jmp"] = jmp
instruction_set["jle"] = jxx["le"]
instruction_set["jl"] = jxx["l"]
instruction_set["je"] = jxx["e"]
instruction_set["jne"] = jxx["ne"]
instruction_set["jge"] = jxx["ge"]
instruction_set["jg"] = jxx["g"]
instruction_set["call"] = call
instruction_set["ret"] = ret
instruction_set["pushq"] = pushq
instruction_set["popq"] = popq


# Encode status
AOK = "1" # Normal
HLT = "2" # Halt 
ADR = "3" # Bad Address
INS = "4" # Invalid Instruction

# Encode status set
status_set = {}
status_set["AOK"] = AOK
status_set["HLT"] = HLT
status_set["ADR"] = ADR
status_set["INS"] = INS

# Encode registers
rdi = "7" # argument 1
rsi = "6" # argument 2
rdx = "2" # argument 3
rcx = "1" # argument 4
r8 = "8" # argument 5
r9 = "9" # argument 6
rax = "0" # return
r10 = "a" # general usage
r11 = "b" # general usage
rbx = "3" # general usage
r12 = "c" # general usage
r13 = "d" # general usage
r14 = "e" # general usage
rsp = "4" # stack pointer
rbp = "5" # base pointer
no_reg = "f" # no register

# Encode register set
register_set = {}
register_set["rdi"] = rdi
register_set["rsi"] = rsi
register_set["rdx"] = rdx
register_set["rcx"] = rcx
register_set["r8"] = r8
register_set["r9"] = r9
register_set["rax"] = rax
register_set["r10"] = r10
register_set["r11"] = r11
register_set["rbx"] = rbx
register_set["r12"] = r12
register_set["r13"] = r13
register_set["r14"] = r14
register_set["rsp"] = rsp
register_set["rbp"] = rbp
register_set["no_reg"] = no_reg


all_result = []

def memory_check(address, ctx): # rA is the register used to access memory
    if address & 0x8000000000000000:
        ctx["STAT"] = 3
        return False
    else:
        return True

# instruction definitions (based on first 2 numbers) getting ready for execution!!
# include 1. next potential pc 2. function_type 3. the complete machine code
def f_decode_instruction(line, ctx):
    machine_code = line
    byte_count = len(line) / 2
    pc_potential = ctx["PC"] + byte_count     # if it is not jmp or ret then...
    instruction = machine_code[:2]
    f_type = ""
    for type, encoding in instruction_set.items():
         if encoding == instruction:
             f_type = type
             break
    if(not f_type):
       print("Error: encoding not found")
       return
    return pc_potential, f_type, machine_code

# This function is built specifically for extracting the value or the destination or the offset
all_result = []
def operate(data):
    lines, num, all_instructions = extract(data)
    ctx = context
    MEM_initialization(ctx,all_instructions)
    while(True):
        try:
           ptr = ctx["PC"]
           command = lines[ptr]
           f_execute(command, lines, ctx)
           #time.sleep(0.1)
           if ctx["STAT"] != 1: 
               break
        except:
           print("Done with computing")
           break

    return all_result

def MEM_initialization(ctx,all_instructions):
    bytes = len(all_instructions) // 2
    num = bytes // 8
    padding = 2*(8-(bytes)%8)*'0'
    for i in range(num):
        if(little_endian(all_instructions[i*16:i*16+16])!=0):
           ctx["MEM"][str(i*8)] = little_endian(all_instructions[i*16:i*16+16])
    if padding and little_endian(all_instructions[num*16:])!=0:
        ctx["MEM"][str(num*8)] = little_endian(all_instructions[num*16:] + padding)

def extract(data):
    real_code={}
    icode = data.split("\n")
    count = 0
    all_instructions=""
    for code in icode:
        code = code.strip()
        if(code and code[:2]=="0x"):
            code, _ = code.split("|")
            code = code.strip()
            address, instruction = code.split(":")
            instruction = instruction.strip()
            if(instruction):
                address = int(address,16)
                real_code[address]=instruction
                all_instructions += 2*(address-(len(all_instructions)//2))*'0'
                all_instructions += instruction
                count += 1
    return real_code, count, all_instructions

def little_endian(value):
    right_value=0
    length = len(value)
    for i in range(0,length,2):
        right_value += int(value[i:i+2],16)*(16**i)
    if right_value & 0x8000000000000000:
        right_value = right_value - 0xffffffffffffffff - 1
    return right_value

# function 3: call the respective function; The f_execute is for function_3 
# function 4: update the pc (this is unpredictable, normally we just add the length but if it is jmp, ret, call ...) 
# ** now i just update pc after executing the command line** 
def f_execute(line, lines, ctx):
    pc_potential, f_type, machine_code = f_decode_instruction(line, ctx)
    if(f_type[:4] == "cmov"):
        f_type = "cmovxx"
    if(f_type[0] == "j" and f_type != "jmp"):
        f_type = "jxx"
    match f_type:
        case "halt":
            f_halt(ctx)
            all_result.append(copy.deepcopy(ctx))
        case "nop":
            f_nop()
            ctx["PC"] = int(pc_potential)
            all_result.append(copy.deepcopy(ctx))
        case "rrmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_rrmovq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "cmovxx":
            condition = int(machine_code[1])
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_cmovxx(target_reg1, target_reg2, condition, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "irmovq":
            value = little_endian(machine_code[4:])
            register_encoding = machine_code[3]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                print(f"Register Encoding in Machine code Wrong: Register {register_encoding} not found")
                return
            else:
                f_irmovq(target_reg,value, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "rmmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            offset = little_endian(machine_code[4:])
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:   
                if f_rmmovq(target_reg1, target_reg2, offset, ctx):
                   ctx["PC"] = int(pc_potential)
                   all_result.append(copy.deepcopy(ctx))
        case "mrmovq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            offset = little_endian(machine_code[4:])
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_mrmovq(target_reg1, target_reg2, offset, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "addq":
            target_reg1 = ""        
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_addq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "subq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_subq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "andq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_andq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "xorq":
            target_reg1 = ""
            target_reg2 = ""
            reg1_encoding = machine_code[2]
            reg2_encoding = machine_code[3]
            for reg_name, reg_i in register_set.items():
                if(reg_i == reg1_encoding):
                     target_reg1 = reg_name
                if(reg_i == reg2_encoding):
                     target_reg2 = reg_name
                if(target_reg1 and target_reg2):
                    break
            if(not (target_reg1 and target_reg2)):
                print(f"Register Encoding in Machine code Wrong: Register {target_reg1} or {target_reg2} not found")
                return
            else:
                f_xorq(target_reg1, target_reg2, ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))
        case "jmp":
            destination = little_endian(machine_code[2:])
            f_jmp(destination, lines, ctx)
            all_result.append(copy.deepcopy(ctx))
        case "jxx":
            condition = int(machine_code[1])
            destination = little_endian(machine_code[2:])
            f_jmpxx(destination, condition, int(pc_potential), lines, ctx)
            all_result.append(copy.deepcopy(ctx))
        case "call":
             destination = little_endian(machine_code[2:])
             f_call(destination, ctx, int(pc_potential), lines)
             all_result.append(copy.deepcopy(ctx))
        case "ret":
            f_ret(ctx, lines)
            all_result.append(copy.deepcopy(ctx))
        case "pushq":
            register_encoding = machine_code[2]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                print(f"Register Encoding in Machine code Wrong: Register {register_encoding} not found")
                return
            else:
                if f_pushq(target_reg,ctx):
                   ctx["PC"] = int(pc_potential)
                   all_result.append(copy.deepcopy(ctx))
        case "popq":
            register_encoding = machine_code[2]
            target_reg = ""
            for reg_name, reg_i in register_set.items():
                 if(reg_i == register_encoding):
                     target_reg = reg_name
            if(not target_reg):
                print(f"Register Encoding in Machine code Wrong: Register {register_encoding} not found")
                return
            else:
                f_popq(target_reg,ctx)
                ctx["PC"] = int(pc_potential)
                all_result.append(copy.deepcopy(ctx))


def f_halt(ctx):
   ctx["STAT"] = 2
   return

def f_nop():
    return

def f_rrmovq(rA, rB, ctx):
   temp = ctx["REG"][rA]
   ctx["REG"][rB] = temp

# condition is to check the comparision type
# this is a conditional move: it will move rA to rB only when xx is satisfied
def f_cmovxx(rA, rB, condition, ctx):
    flag_of = ctx["CC"]["OF"]
    flag_sf = ctx["CC"]["SF"]
    flag_zf = ctx["CC"]["ZF"]
    op_flag = 0
    match condition:
        case 1:
            op_flag = flag_zf | (flag_sf & (not flag_of))
        case 2:
            op_flag = (flag_sf & (not flag_of))
        case 3:
            op_flag = flag_zf
        case 4:
            op_flag = not flag_zf
        case 5:
            op_flag = flag_zf | ((not flag_sf) & (not flag_of))
        case 6:
            op_flag = (not flag_sf) & (not flag_of)
    if(op_flag):
        f_rrmovq(rA, rB, ctx)

def f_irmovq(rB, value, ctx):
    ctx["REG"][rB] = value

def f_rmmovq(rA, rB, offset, ctx):
    temp = ctx["REG"][rA]
    address = ctx["REG"][rB] + offset
    if not memory_check(address, ctx): # wrong address
        all_result.append(copy.deepcopy(ctx))
        return 0
    try:
        ctx["MEM"][str(address)] = temp
        return 1
    except:
        print(f"segmentation fault: address {address} not found")
        return 1

def f_mrmovq(rA, rB, offset, ctx):
    address = ctx["REG"][rB] + offset
    try:
        temp = ctx["MEM"][str(address)]
        ctx["REG"][rA] = temp
    except:
        print(f"segmentation fault: address {address} not found")
        return

def f_addq(rA, rB, ctx):
    temp = ctx["REG"][rA] + ctx["REG"][rB]
    ctx["REG"][rB] = temp
    if((temp>0 and ctx["REG"][rA]<0 and ctx["REG"][rB]<0) or (temp<0 and ctx["REG"][rA]>0 and ctx["REG"][rB]>0)): ctx["CC"]["OF"]=1
    flag_set(temp, ctx)

def f_subq(rA, rB, ctx):
    temp = ctx["REG"][rB] - ctx["REG"][rA]
    ctx["REG"][rB] = temp
    if((temp>0 and ctx["REG"][rA]>0 and ctx["REG"][rB]<0) or (temp<0 and ctx["REG"][rA]<0 and ctx["REG"][rB]>0)): ctx["CC"]["OF"]=1
    flag_set(temp, ctx)

def f_andq(rA, rB, ctx):
    temp = ctx["REG"][rB] & ctx["REG"][rA]
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def f_xorq(rA, rB, ctx):
    temp = ctx["REG"][rB] ^ ctx["REG"][rA]
    ctx["REG"][rB] = temp
    flag_set(temp, ctx)

def flag_set(temp, ctx): 
    # overflow set in calculation
    # set other 2 flags
    if (temp > 0):
        ctx["CC"]["ZF"] = 0
        ctx["CC"]["SF"] = 0
    elif (temp == 0):
        ctx["CC"]["ZF"] = 1
        ctx["CC"]["SF"] = 0
    else:
        ctx["CC"]["ZF"] = 0
        ctx["CC"]["SF"] = 1

def f_jmp(destination, lines, ctx):
    ctx["PC"] = int(destination)
# what's the next line of code? how to express that in python?
# unfinished ...

# Jump will only base on the flags' values // condition refers to the fn_code
def f_jmpxx(destination, condition, potential_pc, lines, ctx):
    op_flag = 0
    flag_of = ctx["CC"]["OF"]
    flag_sf = ctx["CC"]["SF"]
    flag_zf = ctx["CC"]["ZF"]
    match condition:
        case 1:
            op_flag = flag_zf | (flag_sf & (not flag_of))
        case 2:
            op_flag = (flag_sf & (not flag_of))
        case 3:
            op_flag = flag_zf
        case 4:
            op_flag = not flag_zf
        case 5:
            op_flag = flag_zf | ((not flag_sf) & (not flag_of))
        case 6:
            op_flag = (not flag_sf) & (not flag_of)
    if(op_flag):
        f_jmp(destination, lines, ctx)
    else:
        ctx["PC"] = potential_pc
    # if jmpxx failed, pc shall point back!!


# how to jump to the destination?
# unfinished ...
    
def f_call(destination, ctx, pc_potential, lines): 
    # I need to save the return address here
    f_return_address = pc_potential 
    ctx["REG"]["rsp"] -= 0x8
    try:
        address_stored_position = ctx["REG"]["rsp"] 
        ctx["MEM"][str(address_stored_position)] = f_return_address
        f_jmp(destination, lines, ctx)
    except:
        print(f"segmentation error: address {address_stored_position} not found")
        return


def f_ret(ctx, lines):
    try:
       return_mem_position = ctx["REG"]["rsp"]
       return_address = ctx["MEM"][str(return_mem_position)]
       ctx["PC"] = return_address
       ctx["REG"]["rsp"] += 0x8
       f_jmp(return_address, lines, ctx)
    except:
        print(f"segmentation error: address {return_address} not found")
        return


def f_pushq(rA, ctx):
    value = ctx["REG"][rA]
    ctx["REG"]["rsp"] -= 0x8
    new_address = ctx["REG"]["rsp"]
    if not memory_check(new_address, ctx):
        all_result.append(copy.deepcopy(ctx))
        return 0
    try:
       if value:
           ctx["MEM"][str(new_address)] = value
       return 1
    except:
        print(f"segmentation error: address {new_address} not found")
        return

def f_popq(rA, ctx):
    pop_address = ctx["REG"]["rsp"]
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

# solve the address problem today ~ 

# a small test
if __name__ == "__main__":
    data = sys.stdin.read()
    # Run your CPU logic
    all_result = operate(data)
    json.dump(all_result, sys.stdout)

