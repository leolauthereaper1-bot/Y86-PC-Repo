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

register_set = {
    0x0: "rax",
    0x1: "rcx",
    0x2: "rdx",
    0x3: "rbx",
    0x4: "rsp",
    0x5: "rbp",
    0x6: "rsi",
    0x7: "rdi",
    0x8: "r8",
    0x9: "r9",
    0xa: "r10",
    0xb: "r11",
    0xc: "r12",
    0xd: "r13",
    0xe: "r14"
}

Bubbles = 0
Cycles = 0
Valid_instructions = 0

def mapping(index):
    return register_set[index]

def fetch_all(data):
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

def MEM_initialization(ctx,all_instructions):
    bytes = len(all_instructions) // 2 # 2 character stands for 1 byte in the system
    num = bytes // 8 # <=「total number」
    padding = 2*(8-(bytes)%8)*'0' # easier to compute
    for i in range(num):
        if(little_endian(all_instructions[i*16:i*16+16])!=0): # 16 chars = 8 bytes = 1 integer
           ctx["MEM"][str(i*8)] = little_endian(all_instructions[i*16:i*16+16]) # un-zero because zero == uninitialized
    if padding and little_endian(all_instructions[num*16:])!=0:
        ctx["MEM"][str(num*8)] = little_endian(all_instructions[num*16:] + padding)


def little_endian(value):
    right_value=0
    length = len(value)
    for i in range(0,length,2):
        right_value += int(value[i:i+2],16)*(16**i)
    if right_value & 0x8000000000000000:
        right_value = right_value - 0xffffffffffffffff - 1 # switch to negative in decimal
    return right_value

def fetch_graph_initialization():
    fetch_graph = { #info for Decode
        "D_icode": None,
        "D_ifun":None,
        "D_valP": None,
        "D_valC": None,
        "D_rA":None,
        "D_rB":None,
        "stop_signals":0
    }
    return fetch_graph
def fetch(PC, machine_code, fetch_graph):
    pc = PC*2 # read bytes
    f_code = machine_code[pc:pc+2] 
    # machine_code is a string like "20", "30", "61", etc.
    icode = int(f_code, 16) 
    fetch_graph["D_icode"] = icode
    if(icode == 0x00):
        fetch_graph["D_valP"] = PC
    elif (icode == 0x10):
        fetch_graph["D_valP"] = PC+1
    elif (icode == 0x20):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode in {0x21,0x22,0x23,0x24,0x25,0x26}):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_ifun"] = icode - 0x20
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode == 0x30):
        fetch_graph["D_valP"] = PC+10
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
        fetch_graph["D_valC"] = little_endian(machine_code[pc+4:pc+20])
    elif (icode == 0x40):
        fetch_graph["D_valP"] = PC+10
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
        fetch_graph["D_valC"] = little_endian(machine_code[pc+4:pc+20])
    elif (icode == 0x50):
        fetch_graph["D_valP"] = PC+10
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
        fetch_graph["D_valC"] = little_endian(machine_code[pc+4:pc+20])
    elif (icode == 0x60):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode == 0x61):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode == 0x62):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode == 0x63):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
        fetch_graph["D_rB"] = int(machine_code[pc+3],16)
    elif (icode == 0x70):
        fetch_graph["D_valP"] = PC+9
        fetch_graph["D_valC"] = little_endian(machine_code[pc+2:pc+18])
    elif (icode in {0x71,0x72,0x73,0x74,0x75,0x76}):
        fetch_graph["D_valP"] = PC+9
        fetch_graph["D_ifun"] = icode - 0x70
        fetch_graph["D_valC"] = little_endian(machine_code[pc+2:pc+18])
    elif (icode == 0x80):
        fetch_graph["D_valP"] = PC+9
        fetch_graph["D_valC"] = little_endian(machine_code[pc+2:pc+18])
    elif (icode == 0x90):
        fetch_graph["D_valP"] = PC+1
    elif (icode == 0xa0):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rA"] = int(machine_code[pc+2],16)
    elif (icode == 0xb0):
        fetch_graph["D_valP"] = PC+2
        fetch_graph["D_rB"] = int(machine_code[pc+2],16)
def decode_initialization():
    decode_graph = {
    # register IDs
    "srcA": None,     # register read A
    "srcB": None,     # register read B
    "dstE": None,     # ALU result destination
    "dstM": None,     # memory read destination

    # ALU control
    "aluFun": None,   # add/sub/and/xor
    "aluA": None,     # valA / -8 / +8 / valC
    "aluB": None,     # valB / valP / 0

    # condition codes
    "ccWrite": False, # write CC for OPq

    # memory
    "memRead": False,  # mrmovq, popq, ret
    "memWrite": False, # rmmovq, pushq, call

    # branching and conditions
    "condType": None,  # condition type for jXX/cmovXX
    
    # state change
    "change_state": None,
    # immediates from Fetch stage
    "valC": None,
    "valP": None,
    "not_in_branch":False,
    "initiate_fetch_stalling":False,
    "initiate_decode_stalling":False,
    "initiate_execute_stalling":False,
    "initiate_memory_stalling":False,
    "initiate_write_back_stalling":False,
    "OF":None,
    "ZF":None,
    "SF":None,
    "MEM":{}
    }
    return decode_graph


def f_decode(fetch_graph, decode_graph, ctx): # use command as our sole control signal
    global Bubbles
    decode_graph["valP"] = fetch_graph["D_valP"]
    decode_graph["valC"] = fetch_graph["D_valC"]
    decode_graph["srcA"] = fetch_graph["D_rA"]
    decode_graph["srcB"] = fetch_graph["D_rB"]
    decode_graph["condType"] = fetch_graph["D_ifun"]
    command = fetch_graph["D_icode"]
    if (command == 0x00): #halt
        decode_graph["change_state"]=2
    elif (command == 0x10): #nop
        decode_graph["aluFun"] = 1
        decode_graph["aluA"] = 0
        decode_graph["aluB"] = 0
    elif (command == 0x20): #rrmovq
        decode_graph["aluFun"] = 1
        decode_graph["aluA"] = 0
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcA"])] # regA
        decode_graph["dstE"] = decode_graph["srcB"] #regB
    elif (command in {0x21,0x22,0x23,0x24,0x25,0x26}): # cmovxx  
        decode_graph["aluFun"] = 1
        decode_graph["aluA"] = 0
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcA"])] # regA
        decode_graph["dstE"] = decode_graph["srcB"] #regB
    elif (command == 0x30): #irmovq
        decode_graph["aluFun"] = 1
        decode_graph["aluA"] = 0
        decode_graph["aluB"] = decode_graph["valC"]
        decode_graph["dstE"] = decode_graph["srcB"] #regB
    elif (command == 0x40): #rmmovq
        decode_graph["memWrite"] = True
        decode_graph["aluFun"]= 1
        decode_graph["aluA"] = decode_graph["valC"]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        
    elif (command == 0x50): #mrmovq
        decode_graph["memRead"] = True
        decode_graph["aluFun"]= 1
        decode_graph["aluA"] = decode_graph["valC"]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstM"] = decode_graph["srcA"]

    elif (command == 0x60): # addq
        decode_graph["ccWrite"] = True
        decode_graph["aluFun"]= 1
        decode_graph["aluA"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstE"] = decode_graph["srcB"]
    elif (command == 0x61): # subq
        decode_graph["ccWrite"] = True
        decode_graph["aluFun"]= 2
        decode_graph["aluA"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstE"] = decode_graph["srcB"]
    elif (command == 0x62): # andq
        decode_graph["ccWrite"] = True
        decode_graph["aluFun"]= 3
        decode_graph["aluA"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstE"] = decode_graph["srcB"]
    elif (command == 0x63): # xorq
        decode_graph["ccWrite"] = True
        decode_graph["aluFun"]= 4
        decode_graph["aluA"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstE"] = decode_graph["srcB"]
    elif (command == 0x70): #jmp
        decode_graph["not_in_branch"] = True

        decode_graph["initiate_fetch_stalling"] = True
        decode_graph["initiate_decode_stalling"] = True
        pipe_signals["fetch"]["stalling"] = True
        pipe_signals["decode"]["stalling"] = True
        Bubbles += 1
    elif (command in {0x71,0x72,0x73,0x74,0x75,0x76}): #jxx
        decode_graph["not_in_branch"] = True

        decode_graph["initiate_fetch_stalling"] = True
        decode_graph["initiate_decode_stalling"] = True
        pipe_signals["fetch"]["stalling"] = True
        pipe_signals["decode"]["stalling"] = True
        Bubbles += 1
    elif (command == 0x80): #call
        decode_graph["not_in_branch"] = True
        decode_graph["srcB"] = 0x4
        decode_graph["memWrite"] = True
        decode_graph["aluFun"]= 2
        decode_graph["aluA"] = 8
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])] # srcB should be the rsp
        decode_graph["dstE"] = decode_graph["srcB"]
  
        decode_graph["initiate_fetch_stalling"] = True
        decode_graph["initiate_decode_stalling"] = True
        pipe_signals["fetch"]["stalling"] = True
        pipe_signals["decode"]["stalling"] = True
        Bubbles += 1
    elif (command == 0x90): #ret 
        decode_graph["not_in_branch"] = True
        decode_graph["srcA"] = 0x4
        decode_graph["srcB"] = 0x4
        decode_graph["memRead"] = True
        decode_graph["aluFun"]= 1
        decode_graph["aluA"] = 8
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["dstE"] = decode_graph["srcB"]

        decode_graph["initiate_fetch_stalling"] = True
        decode_graph["initiate_decode_stalling"] = True
        pipe_signals["fetch"]["stalling"] = True
        pipe_signals["decode"]["stalling"] = True
        Bubbles += 1
    elif (command == 0xa0): #pushq
        decode_graph["srcB"] = 0x4 
        decode_graph["memWrite"] = True
        decode_graph["aluFun"]= 2
        decode_graph["aluA"] = 8
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcB"])]
        decode_graph["dstE"] = decode_graph["srcB"]

    elif (command == 0xb0): #popq
        decode_graph["srcA"] = 0x4
        decode_graph["memRead"] = True
        decode_graph["aluFun"]= 1
        decode_graph["aluA"] = 8
        decode_graph["aluB"] = ctx["REG"][mapping(decode_graph["srcA"])]
        decode_graph["dstE"] = decode_graph["srcA"]
        decode_graph["dstM"] = decode_graph["srcB"]

def cnd_check(ctx, cnd):
    flag_of = ctx["CC"]["OF"]
    flag_sf = ctx["CC"]["SF"]
    flag_zf = ctx["CC"]["ZF"]
    match cnd:
        case 1:
            return flag_zf | (flag_sf & int(not flag_of))
        case 2:
            return (flag_sf & int(not flag_of))
        case 3:
            return flag_zf
        case 4:
            return int(not flag_zf)
        case 5:
            return flag_zf | (int(not flag_sf) & int(not flag_of))
        case 6:
            return int(not flag_sf) & int(not flag_of)

def flag_set(vA, vB, op, op_v, decode_graph): 
    if (op_v > 0):
        if(op==1 and vA<0 and vB<0) or (op==2 and vA>0 and vB<0):
           decode_graph["OF"] = 1
        else:
           decode_graph["OF"] = 0
        decode_graph["ZF"] = 0
        decode_graph["SF"] = 0
    elif (op_v == 0):
        decode_graph["OF"] = 0
        decode_graph["ZF"] = 1
        decode_graph["SF"] = 0
    else:
        if(op==1 and vA>0 and vB>0) or (op==2 and vA<0 and vB>0):
           decode_graph["OF"] = 1
        else:
           decode_graph["OF"] = 0
        decode_graph["ZF"] = 0
        decode_graph["SF"] = 1

MASK64 = (1 << 64) - 1

def to_signed_64(x):
    x &= MASK64
    if x & (1 << 63):
        x -= (1 << 64)
    return x

def f_ALU_compute(decode_graph):
    cnd = decode_graph["aluFun"]
    vA = decode_graph["aluA"]
    vB = decode_graph["aluB"]

    if cnd == 1:  # ADD
        raw = vA + vB
        valE = to_signed_64(raw)
        if decode_graph["ccWrite"]:
            flag_set(vA, vB, cnd, valE, decode_graph)
        return valE

    elif cnd == 2:  # SUB (vB - vA)
        raw = vB - vA
        valE = to_signed_64(raw)
        if decode_graph["ccWrite"]:
            flag_set(vA, vB, cnd, valE, decode_graph)
        return valE

    elif cnd == 3:  # AND
        valE = to_signed_64(vB & vA)
        if decode_graph["ccWrite"]:
            flag_set(vA, vB, cnd, valE, decode_graph)
        return valE

    elif cnd == 4:  # XOR
        valE = to_signed_64(vB ^ vA)
        if decode_graph["ccWrite"]:
            flag_set(vA, vB, cnd, valE, decode_graph)
        return valE

def f_mem_read(ctx, ALU_v, decode_graph):
    if ALU_v == None or not decode_graph["memRead"]:
        return None
    src = ALU_v
    try:
        if(decode_graph["srcA"]==0x4 and decode_graph["dstE"] != None ): # popq, ret -- avoid mrmovq rsp
            address = ctx["REG"][mapping(0x4)]
            value = ctx["MEM"][str(address)]
        else:
            value = ctx["MEM"][str(src)]
    except:
        value = 0 # not found in the memory return 0 uninitialized 
    return value

def f_mem_write(ctx, ALU_v, decode_graph):
    if ALU_v == None:
        return 
    address = ALU_v
    if(decode_graph["memWrite"]): # reg to memory
        if address>0:
            if(decode_graph["srcA"] == None):
                 decode_graph["MEM"][str(address)] = decode_graph["valP"] # call
            else:
              if(ctx["REG"][mapping(decode_graph["srcA"])]>0):
                 decode_graph["MEM"][str(address)] = ctx["REG"][mapping(decode_graph["srcA"])] # rmmovq, pushq
        else:
            decode_graph["change_state"]=3
    
def memory(ctx, ALU_v, decode_graph):
    value = f_mem_read(ctx, ALU_v, decode_graph)
    f_mem_write(ctx, ALU_v, decode_graph)
    return value
  
def Write_back(ctx, value, ALU_v, decode_graph):
    if ALU_v == None:
        return
    if(decode_graph["MEM"]):
        for k,v in decode_graph["MEM"].items():
           ctx["MEM"][k] = v
    if(decode_graph["ZF"]!=None):
       ctx["CC"]["ZF"] = decode_graph["ZF"]
       ctx["CC"]["SF"] = decode_graph["SF"]
       ctx["CC"]["OF"] = decode_graph["OF"]
    if(value != None and decode_graph["dstM"] != None ): # popq
        ctx["REG"][mapping(decode_graph["dstM"])] = value # mrmovq
     # reg to reg 
    cnd = decode_graph["condType"]
    if(cnd == None):
        if(decode_graph["srcA"]==None and decode_graph["memWrite"]==None):
            val = decode_graph["valC"] # irmmovq
        else:
            val = ALU_v # popq ret call pushq 
        if(decode_graph["dstE"]!=None and (not (decode_graph["dstM"]==0x4 and decode_graph["dstE"]==0x4))): # distinguish popq ra and popq rsp
            ctx["REG"][mapping(decode_graph["dstE"])] = val  
    else:
        if(cnd_check(ctx, cnd)): # cmmovq
            ctx["REG"][mapping(decode_graph["dstE"])] = ALU_v

def f_update_pc(ctx, value, decode_graph):
    cnd = decode_graph["condType"]
    if(ctx["STAT"]!=1):
        return
    if decode_graph["not_in_branch"]:
        if(cnd!=None): # jxx
            if(cnd_check(ctx, cnd)):
                ctx["PC"] = decode_graph["valC"]
            else:
                ctx["PC"] = decode_graph["valP"]
                decode_graph["not_in_branch"] = False
        elif (decode_graph["memRead"]): # ret
            if(value>0):
               ctx["PC"] = value
        elif (decode_graph["memWrite"]): # call
            ctx["PC"] = decode_graph["valC"]
        else: #jmp
            ctx["PC"] = decode_graph["valC"]
    else: # call, jmp , normal ones
        ctx["PC"] = decode_graph["valP"]

def operate_one_line(ctx, all_instructions):
    fetch_graph0 = fetch_graph_initialization()
    fetch(ctx["PC"], all_instructions, fetch_graph0)
    decode_graph0 = decode_initialization()
    f_decode(fetch_graph0, decode_graph0, ctx)
    ALU_v = f_ALU_compute(ctx, decode_graph0)
    value = memory(ctx, ALU_v, decode_graph0)
    Write_back(ctx, value, ALU_v, decode_graph0)
    f_update_pc(ctx, value, decode_graph0)

def predict_pc(decode_graph_dec):
    if(decode_graph_dec["not_in_branch"] == True): # if it is ret, this will return None
        return decode_graph_dec["valC"]
    else:
        return decode_graph_dec["valP"]

pipe_registers = {"fetch_to_decode":{}, 
                  "decode_to_execute":{}, 
                  "execute_to_memory":{},
                  "memory_to_write_back":{}} 
# store the fetch_graph / decode_graph / alu values / memory_values
# fetch_to_decode: always fetch_graph // decode_to_execute: always decode_graph // execute_to_memory: decode_graph && alu_v 
# // memory_to_write_back: value , alu_v, decode_graph
pipe_signals = {"fetch":{"stalling":False, "bubble":False},
                "decode":{"stalling":False, "bubble":False},
                "execute":{"stalling":False, "bubble":False},
                "memory":{"stalling":False, "bubble":False},
                "write_back":{"stalling":False, "bubble":False},
                }

def clear_state(pipe_registers, stage):
    pipe_registers[stage]={}

def resume(decode_graph, pipe_signals):
    if(decode_graph["initiate_fetch_stalling"]):
        pipe_signals["fetch"]["stalling"] = False
    if(decode_graph["initiate_decode_stalling"]):
        pipe_signals["decode"]["stalling"] = False
    if(decode_graph["initiate_execute_stalling"]):
        pipe_signals["execute"]["stalling"] = False
    if(decode_graph["initiate_memory_stalling"]):
        pipe_signals["memory"]["stalling"] = False
    if(decode_graph["initiate_write_back_stalling"]):
        pipe_signals["write_back"]["stalling"] = False
    if(decode_graph["not_in_branch"]):
        clear_state(pipe_registers, "decode_to_execute")

def Data_hazard(decode_graph_dec, decode_graph_exe):
    if decode_graph_dec!= None:
       decode_ra = decode_graph_dec["srcA"]
       decode_rb = decode_graph_dec["srcB"]
    else:
       decode_ra = None
       decode_rb = None

    if decode_graph_exe!= None:
       execute_dstM = decode_graph_exe["dstM"]
    else:
       execute_dstM = None   
    check = False
    if(((decode_ra == execute_dstM) and (decode_ra!=None)) or ((decode_rb == execute_dstM) and (decode_rb!=None))):
        pipe_signals["decode"]["stalling"] = True
        decode_graph_exe["initiate_decode_stalling"] = True
        pipe_signals["fetch"]["stalling"] = True # info from new fetch should not cover decode_graph
        decode_graph_exe["initiate_fetch_stalling"] = True
        check = True
        
    return check

def exe_forward(decode_graph_exe, ALU_v, ctx_): # decode ret, call, 
    if decode_graph_exe["ccWrite"]:
        ctx_["CC"]["ZF"] = decode_graph_exe["ZF"]
        ctx_["CC"]["SF"] = decode_graph_exe["SF"]
        ctx_["CC"]["OF"] = decode_graph_exe["OF"]
    dstE = decode_graph_exe["dstE"]
    if(dstE == None):
        return ctx_
    cnd = decode_graph_exe["condType"]
    if(cnd!=None):
        if(cnd_check(ctx_, cnd)):
            ctx_["REG"][mapping(dstE)] = ALU_v
            return ctx_
        else:
            return ctx_
    ctx_["REG"][mapping(dstE)] = ALU_v
    return ctx_
    
def mem_forward(decode_graph_mem, value_mem, ctx_):
    dstM = decode_graph_mem["dstM"]
    if(dstM == None):
        return ctx_
    ctx_["REG"][mapping(dstM)] = value_mem
    if(pipe_signals["decode"]["stalling"] and not decode_graph_mem["not_in_branch"] and decode_graph_mem["initiate_decode_stalling"]):
        pipe_signals["decode"]["stalling"] = False
        pipe_signals["fetch"]["stalling"] = False
    return ctx_

def operate_as_pipe(ctx, all_instructions, pipe_registers, all_context):
    global Cycles, Valid_instructions
    decode_graph_wb = None
    decode_graph_exe = None
    decode_graph_dec = None
    decode_graph_mem = None
    if(pipe_registers["memory_to_write_back"]):
         value_wb = pipe_registers["memory_to_write_back"]["value"]
         ALU_v_wb = pipe_registers["memory_to_write_back"]["ALU_v"]
         decode_graph_wb = pipe_registers["memory_to_write_back"]["decode_graph"]
         Write_back(ctx, value_wb, ALU_v_wb, decode_graph_wb)
         Valid_instructions += 1
         if(decode_graph_wb["change_state"]!=None):
             ctx["STAT"] = decode_graph_wb["change_state"]
         clear_state(pipe_registers, "memory_to_write_back")

    #ctx_exe = copy.deepcopy(ctx) # both are virtual memories for forwarding
    ctx_mem = copy.deepcopy(ctx) # after the implementation of the write_back(updated_version)

    if(pipe_registers["execute_to_memory"]):
         ALU_v_mem = pipe_registers["execute_to_memory"]["ALU_v"]
         decode_graph_mem = pipe_registers["execute_to_memory"]["decode_graph"]
         value_mem = memory(ctx, ALU_v_mem, decode_graph_mem)
         pipe_registers["memory_to_write_back"]["value"] = value_mem
         pipe_registers["memory_to_write_back"]["ALU_v"] = ALU_v_mem
         pipe_registers["memory_to_write_back"]["decode_graph"] = decode_graph_mem
         ctx_mem = mem_forward(decode_graph_mem, value_mem, ctx_mem)
         ctx_mem = exe_forward(decode_graph_mem, ALU_v_mem, ctx_mem)
         clear_state(pipe_registers, "execute_to_memory")
    
    if(pipe_registers["decode_to_execute"]):
        decode_graph_exe = pipe_registers["decode_to_execute"]["decode_graph"]
        ALU_v_exe = f_ALU_compute(decode_graph_exe)
        pipe_registers["execute_to_memory"]["ALU_v"] = ALU_v_exe
        pipe_registers["execute_to_memory"]["decode_graph"] = decode_graph_exe
        ctx_mem = exe_forward(decode_graph_exe,ALU_v_exe, ctx_mem)
        clear_state(pipe_registers, "decode_to_execute")
  
    if(not pipe_signals["decode"]["stalling"] and pipe_registers["fetch_to_decode"]):
        fetch_graph_dec = pipe_registers["fetch_to_decode"]["fetch_graph"]
        decode_graph_dec = decode_initialization()
        f_decode(fetch_graph_dec, decode_graph_dec, ctx_mem)
        if(not Data_hazard(decode_graph_dec, decode_graph_exe)):
            pipe_registers["decode_to_execute"]["decode_graph"] = decode_graph_dec
            clear_state(pipe_registers, "fetch_to_decode" )

    if(not pipe_signals["fetch"]["stalling"]):
        if(pipe_registers["decode_to_execute"]):
            predict_new_pc = predict_pc(pipe_registers["decode_to_execute"]["decode_graph"])
        else:
            predict_new_pc = ctx["PC"]
        if(2*predict_new_pc<len(all_instructions)):
            fetch_graph_fetch = fetch_graph_initialization()
            fetch(predict_new_pc, all_instructions, fetch_graph_fetch)
            pipe_registers["fetch_to_decode"]["fetch_graph"] = fetch_graph_fetch
    if(decode_graph_wb != None):
        f_update_pc(ctx, value_wb, decode_graph_wb)
        resume(decode_graph_wb, pipe_signals)
        all_context.append(copy.deepcopy(ctx))
    Cycles += 1

# check if all pipeline registers are empty
def pipeline_empty(pipe_registers):
    return all(not reg for reg in pipe_registers.values())


if __name__ == "__main__":
    data = sys.stdin.read()
    all_instructions = fetch_all(data)
    ctx = context
    MEM_initialization(ctx, all_instructions)
    all_context = []
    for i in range(4):
       operate_as_pipe(ctx, all_instructions, pipe_registers, all_context)
    halted = False
    while True:
         operate_as_pipe(ctx, all_instructions, pipe_registers, all_context)
         if ctx["STAT"] != 1:
              halted = True
         if halted:
             break
    IPC = Valid_instructions / Cycles
    print(f"{IPC:.2f}")
   # json.dump(all_context, sys.stdout)