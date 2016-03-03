#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: asm_helper.py
#
# A helper for some verbose asm tasks
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
#-----------------------------------------------------------------------------

#-----------------------------------
#Instructions
#-----------------------------------
#All of the mov instructions as given in the AMD64 manual
add_insts = [ #r_r, rw_r
    'adc','add']
addx_insts = [ #r_r rw_r w_r_r
    'addpd','addps','addsd','addss','addsubpd','addsubps','haddps','haddpd'
]
and_insts = ['and'] #r_r rw_r
andx_insts = ['andnpd','andnps','andpd','andps'] #r_r rw_r w_r_r
arpl_insts = ['arpl'] #r_r
#blend skipped
bound_insts = ['bound'] #r_r
bsf_insts = ['bsf'] #w_r
bsr_insts = ['bsr'] #w_r
bswap_insts = ['bswap'] #r
bt_insts = ['bt','btc','btr','bts'] #r_r
call_insts = ['call'] #r
c_insts = ['cbw','cwde','cdqe','cwd','cdq','cqo'] #none
cl_insts = ['clc','cld'] #none
clflush_insts = ['clflush'] #w
cmov_insts = [ #w_r
    'cmovo','cmovno','cmovb','cmovc','cmovnb','cmovnc','cmovae','cmovz',
    'cmove','cmovnz','cmovne','cmovbe','cmovna','cmovnbe','cmova','cmovs',
    'cmovns','cmovp','cmovpe','cmovnp','cmovpo','cmovl','cmovnge','cmovnl',
    'cmovge','cmovle','cmovng','cmovnle','cmovg'
]
cmp_insts = [ #r_r
    'cmp','cmps','cmpsb','cmpsw','cmpsd','cmpsq','cmppd','cmpps','cmpss'
]
cmpxchg_insts = ['cmpxchg'] #r_r rw_r
cmpxchgn_insts = ['cmpxchg8b','cmpxchg8b'] #rw
comis_insts = [ #r_r
    'comiss','vcomiss','comisd','vcomisd','ucomiss','vucomiss','ucomisd',
    'vucomisd'
]
cpuid_insts = ['cpuid'] #none
#crc32 skipped
cvt_insts = [ #w_r
    'cvtdq2pd','cvtdq2ps','cvtpd2dq','cvtpd2pi','cvtpd2ps','cvtpi2pd',
    'cvtpi2ps','cvtps2dq','cvtps2pd','cvtps2pi','cvtsd2si','cvtsd2ss',
    'cvtsi2sd','cvtsi2ss','cvtss2sd','cvtss2si','cvttpd2dq','cvttpd2pi',
    'cvttps2dq','cvttps2pi','cvttsd2si','cvttss2si'
]
da_insts = ['daa', 'das'] #none
dec_insts = ['dec'] #rw?
div_insts = ['div','idiv'] #r
divx_insts = ['divpd','divps','divsd','divss'] #r_r rw_r w_r_r
dp_insts = ['dpps','dppd'] #r_r rw_r w_r_r
enter_insts = ['enter'] #r_r
#---------Bookmark F's (many are just prefixes, but I don't have bases yet)

mov_insts = [
    'mov','movapd','movaps','movd','movddup','movdq2q','movdqa','movdqu',
    'movhlps','movhpd','movhps','movlhps', 'movlpd','movlps','movmskpd',
    'movmskps','movntdq','movntdqa','movnti','movntpd','movntps','movntq',
    'movntsd','movntss',' movq','movq2dq','movs','movsb','movsd','movshdup',
    'movsldup','movsq','movss','movsw','movsx','movsxd','movupd','movups',
    'movzx'
]
mul_insts = ['imul'] #r r_r rw_r w_r_r
lea_insts = ['lea']
ret_insts = ['ret']
hlt_insts = ['hlt']
nop_insts = ['nop']
subx_insts = ['hsubps','hsubpd']

#-----------------------------------
#Instruction groups
#-----------------------------------
mov_prefix = 'mov'
cmp_prefix = 'cmp'

rw_insts = cmpxchgn_insts.append(dec_insts)
r_insts = bswap_insts.append(call_insts).append(div_insts)
w_insts = clflush_insts
r_r_insts = add_insts.append(and_insts).append(arpl_insts).append(
    bound_insts).append(bt_insts).append(cmp_insts).append(
    cmpxchg_insts).append(comis_insts).append(divx_insts).append(
    addx_insts).append(enter_insts)
rw_r_insts = add_insts.append(and_insts).append(cmpxchg_insts).append(
    divx_insts).append(addx_insts)
w_r_insts = bsf_insts.append(bsr_insts).append(cmov_insts).append(
    cvt_insts)

#-----------------------------------
#Registers
#-----------------------------------
arg_regs = ['rdi','rsi','rdx','rcx','r8','r9']
arg_regs_syscall = ['rdi','rsi','rdx','r10','r8','r9']
arg_regs_fp = ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']
#TODO: lt: adding low (dl, cl) for rdx, and rcx might be correct?
arg_regs_all = [
    'rdi','edi','di','rsi','esi','si','rdx','edx','dx','dl','rcx','ecx','cx',
    'cl','r10','r10d','r10w','r10b','r8','r8d','r8w','r8b','r9','r9d','r9w',
    'r9b','xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7'
]
arg_reg_rdi = ['rdi','edi','di']
arg_reg_rsi = ['rsi','esi','si']
arg_reg_rdx = ['rdx','edx','dx','dl']
arg_reg_rcx = ['rcx','ecx','cx','cl']
arg_reg_r10 = ['r10','r10d','r10w','r10b']
arg_reg_r8 = ['r8','r8d','r8w','r8b']
arg_reg_r9 = ['r9','r9d','r9w','r9b']
arg_reg_xmm0 = ['xmm0']
arg_reg_xmm1 = ['xmm1']
arg_reg_xmm2 = ['xmm2']
arg_reg_xmm3 = ['xmm3']
arg_reg_xmm4 = ['xmm4']
arg_reg_xmm5 = ['xmm5']
arg_reg_xmm6 = ['xmm6']
arg_reg_xmm7 = ['xmm7']


#-------------------------------------
#Basic arg finding
#-------------------------------------

#lt: still misses some mov's ex. movabs
#def is_mov(mnemonic):
#    if mnemonic in mov_insts:
#        return True
#    return False

def is_mov(mnemonic):
    if mov_prefix in mnemonic:
        return True
    return False

def is_cmp(mnemonic):
    if cmp_prefix in mnemonic:
        return True
    return False

def is_lea(mnemonic):
    if mnemonic in lea_insts:
        return True
    return False

def is_call(mnemonic):
    if mnemonic in call_insts:
        return True
    return False

def is_ret(mnemonic):
    if mnemonic in ret_insts:
        return True
    return False

def is_hlt(mnemonic):
    if mnemonic in hlt_insts:
        return True
    return False

def is_nop(mnemonic):
    if mnemonic in nop_insts:
        return True
    return False

#TODO: actually use in cpc_extract
def is_arg_reg(operand):
    if operand in arg_regs_all:
        return True
    return False


#-------------------------------------
#Advanced arg finding
#-------------------------------------

#push, mov to stack, pop as assignment
