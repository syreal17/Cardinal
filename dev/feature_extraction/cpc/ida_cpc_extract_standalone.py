# -----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: ida_cpc_extract.py
#
# The driver for ennumerating CPC for a Linux AMD64 binary using IDA Pro.
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# -----------------------------------------------------------------------------
from idaapi import *
from idautils import *
from idc import *
import re
import sys


#ASM-HELPER.PY-----------------------------------------------------------------
#-----------------------------------
#Instructions
#-----------------------------------
#All of the mov instructions as given in the AMD64 manual
add_insts = [ #r_r, rw_r
    'adc','add'
]
addx_insts = [ #r_r rw_r w_r_r
    'vaddpd','vaddps','vaddsd','vaddss','addsubpd','addsubps','haddps','haddpd'
    'vhaddps','vhaddpd','addpd','addps','addsd','addss','vpaddb','vpaddw',
    'vpaddd','vpaddq','vpaddsb','vpaddsw','vpaddusb','vpaddusw','paddb',
    'paddw','paddd','paddq','paddsb','paddsw','paddusb','paddusw','pfadd',
    'pmaddwd','vpmaddwd'
]
and_insts = ['and'] #r_r rw_r
andx_insts = [ #r_r rw_r w_r_r
    'vandnpd','vandnps','vandpd','vandps','andnpd','andnps','andpd','andps',
    'pand','pandn','vpand','vpandn'
]
arpl_insts = ['arpl'] #r_r
blend_insts = [ #r_r rw_r w_r_r
    'blendps','vblendps','blendpd','vblendpd','blendvps','vblendvps',
    'blendvpd','vblendvpd','pblendvb','vpblendvb','pblendw','vpblendw'
]
bound_insts = ['bound'] #r_r
bsf_insts = ['bsf'] #w_r
bsr_insts = ['bsr'] #w_r
bswap_insts = ['bswap'] #r
bt_insts = ['bt','btc','btr','bts'] #r_r
call_insts = ['call'] #r
c_insts = ['cbw','cwde','cdqe','cwd','cdq','cqo'] #none
flag_insts = ['clc','cld','cli','cmc','stc','std','sti'] #none
clflush_insts = ['clflush'] #w
cmov_insts = [ #w_r
    'cmovo','cmovno','cmovb','cmovc','cmovnb','cmovnc','cmovae','cmovz',
    'cmove','cmovnz','cmovne','cmovbe','cmovna','cmovnbe','cmova','cmovs',
    'cmovns','cmovp','cmovpe','cmovnp','cmovpo','cmovl','cmovnge','cmovnl',
    'cmovge','cmovle','cmovng','cmovnle','cmovg'
]
cmp_insts = [ #r_r
    'cmp','cmps','cmpsb','cmpsw','cmpsd','cmpsq','cmppd','cmpps','cmpss'
    'vcmpps','vcmppd','vcmpss','vcmpsd'
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
    'cvttps2dq','cvttps2pi','cvttsd2si','cvttss2si','vcvtdq2pd','vcvtdq2ps',
    'vcvtpd2dq','vcvtpd2ps','vcvtps2dq','vcvtps2pd','vcvtsd2si','vcvtsd2ss',
    'vcvtsi2sd','vcvtsi2ss','vcvtss2sd','vcvtss2si','vcvttpd2dq','vcvttps2dq',
    'vcvttsd2si','vcvttss2si',
]
da_insts = ['daa', 'das'] #none
dec_insts = ['dec'] #rw?
div_insts = ['div','idiv'] #r
divx_insts = [ #r_r rw_r w_r_r
    'divpd','divps','divsd','divss','vdivps','vdispd','vdivss','vdivsd'
]
dp_insts = ['dpps','dppd','vdpps','vdppd'] #r_r rw_r w_r_r
enter_insts = ['enter'] #r_r
extract_insts = [ #w_r
    'extractps','extrq','pextrb','pextrw','pextrd','pextrq','vpextrb',
    'vpextrw','vpextrd','vpextrq','vextractps'
]
#lt:skipping F's in AMD64 manual, vol 1, because they are all x87 instructions
#that don't deal with operands like x86
imul_insts = ['imul'] #r r_r rw_r w_r_r
in_insts = ['in'] #w_r
inc_insts = ['inc'] #rw
ins_insts = ['ins','insb','insw','insd'] #r_r
insert_insts = [ #w_r
    'insertps','insertq','pinsrb','pinsrw','pinsrd','pinsrq','vpinsrb',
    'vpinsrw','vpinsrd','vpinsrq','vinsertps'
]
int_insts = ['int'] #r
into_insts = ['into'] #none
iret_insts = ['iret','iretd','iretq'] #r
j_insts = [ #r
    'jo','jno','jb','jc','jnae','jnb','jnc','jae','jz','je','jnz','jne','jna',
    'jbe','jnbe','ja','js','jns','jp','jpe','jnp','jpo','jl','jnge','jge',
    'jnl','jng','jle','jnle','jg','jcxz','jecxz','jrcxz'
]
jmp_insts = ['jmp'] #r
lahf_insts = ['lahf'] #none
load_insts = [ #w_r
    'lddqu','vlddqu','lds','les','lfs','lgs','lss'
]
#ldmxcsr
lea_insts = ['lea'] #w_r
leave_insts = ['leave'] #none
lfence_insts = ['lfence'] #none
lod_insts = ['lods','lodsb','lodsw','lodsd','lodsq'] #r
loop_insts = ['loop','loope','loopne','loopnz','loopz'] #r
maskmov_insts = ['maskmovdqu','vmaskmovdqu'] #r_r
max_insts = [ #r_r rw_r w_r_r
    'vmaxps','vmaxpd','vmaxss','vmaxsd','maxps','maxpd','maxss','maxsd',
    'pfmax','vpmaxub','vpmaxuw','vpmaxud','vpmaxsb','vpmaxsw','vpmaxsd',
    'pmaxub','pmaxuw','pmaxud','pmaxsb','pmaxsw','pmaxsd'
]
min_insts = [ #r_r rw_r w_r_r
    'vminps','vminpd','vminss','vminsd','minps','minpd','minss','minsd',
    'pfmin','vpminub','vpminuw','vpminud','vpminsb','vpminsw','vpminsd',
    'pminub','pminuw','pminud','pminsb','pminsw','pminsd'
]
mfence_insts = ['mfence'] #none
mov_insts = [ #w_r
    'mov','movapd','movaps','movd','movddup','movdq2q','movdqa','movdqu',
    'movhlps','movhpd','movhps','movlhps', 'movlpd','movlps','movmskpd',
    'movmskps','movntdq','movntdqa','movnti','movntpd','movntps','movntq',
    'movntsd','movntss',' movq','movq2dq','movshdup',
    'movsldup','movss','movsx','movsxd','movupd','movups',
    'movzx','vmovapd','vmovaps','vmovd','vmovddup','vmovdqa','vmovdqu',
    'vmovhlps','vmovhpd','vmovhps','vmovlhps','vmovlpd','vmovlps','vmovmskpd',
    'vmovmskps','vmovntdq','vmovntdqa','vmovntpd','vmovntps','vmovq','vmovsd',
    'vmovshdup','vmovsldup','vmovss','vmovupd','vmovups','pmovmskb',
    'vpmovmskb','vpmovsxbd','vpmovsxbq','vpmovsxbw','vpmovsxdq','vpmovsxwd',
    'vpmovsxwq','vpmovzxbd','vpmovzxbq','vpmovzxbw','vpmovzxdq','vpmovzxwd',
    'vpmovzxwq','pmovsxbd','pmovsxbq','pmovsxbw','pmovsxdq','pmovsxwd',
    'pmovsxwq','pmovzxbd','pmovzxbq','pmovzxbw','pmovzxdq','pmovzxwd',
    'pmovzxwq','movabs','movsd'
]
movs_insts = [ #r_r
    'movs','movsb','movsw','movsq'#movsd aliases with one above
]
mul_insts = ['mul'] #r
mulx_insts = [ #r_r rw_r w_r_r
    'vmulps','vmulpd','vmulss','vmulsd','mulps','mulpd','mulss','mulsd',
    'vpmulhw','vpmullw','vpmulhuw','vpmuludq','vmpulld','vmpuldq','pmulhw',
    'pmullw','pmulhuw','pmuludq','mpulld','mpuldq','pmulhrw'
]
neg_insts = ['neg'] #rw
nop_insts = ['nop'] #none
not_insts = ['not'] #rw
or_insts = ['or'] # r_r rw_r
orx_insts = ['orps','vorps','orpd','vorpd','por','vpor'] # r_r rw_r w_r_r
out_insts = ['out','outs','outsb','outsw','outsd'] #r_r
pack_insts = [ #r_r rw_r w_r_r
    'vpackssdw','vpackusdw','vpacksswb','vpackuswb','packssdw','packusdw',
    'packsswb','packuswb'
]
pavg_insts = ['pavgb','pavgw','vpavgb','vpavgw'] #r_r rw_r w_r_r
pcmp_insts = [ #r_r rw_r w_r_r
    'vpcmpeqq','vpcmpgtb','vpcmpgtw','vpcmpgtd','vpcmpgtq','vpcmpeqb',
    'vpcmpeqw','vpcmpeqd','pcmpeqq','pcmpgtb','pcmpgtw','pcmpgtd','pcmpgtq',
    'pcmpeqb','pcmpeqw','pcmpeqd'
]
pcmpstr_insts = [ #r_r w_r_r
    'vpcmpestri','vpcmpestrm','vpcmpistri','vpcmpistrm','pcmpestri',
    'pcmpestrm','pcmpistri','pcmpistrm'
]
p_insts = ['pf2iw','pf2id','pi2fw','pi2fd'] #w_r
pfacc_insts = ['pfacc','pfnacc','pfpnacc'] #r_r rw_r
pfcmp_insts = ['pfcmpeq','pfcmpgt','pfcmpge'] #r_r rw_r
pfrcp_insts = ['pfrcp'] #w_r
pfrcpit_insts = ['pfrcpit1', 'pfrcpit2'] #r_r
pfrsqrt_insts = ['pfrsqrt'] # w_r
pfrsqit_insts = ['pfrsqit1'] # r_r
phminposuw_insts = ['phminposuw','vphminposuw'] #w_r
pop_insts = ['pop'] #w
popa_insts = ['popa','popad'] #none
popcnt_insts = ['popcnt'] #w_r
popf_insts = ['popf','popfd','popfq'] #none
#prefetch
psadbw_insts = ['psadbw','vpsadbw'] #r_r rw_r w_r_r
psll_insts = [ #r_r rw_r w_r_r
    'vpsllw','vpslld','vpsllq','vpslldq','psllw','pslld','psllq','pslldq'
]
psra_insts = [ #r_r rw_r w_r_r
    'psraw','psrad','vpsraw','vpsrad'
]
psrl_insts = [ #r_r rw_r w_r_r
    'vpsrlw','vpsrld','vpsrlq','vpsrldq','psrlw','psrld','psrlq','psrldq'
]
pswap_insts = ['pswapd'] #r_r rw_r
punpck_insts = [ #r_r rw_r
    'vpunpckhbw','vpunpckhwd','vpunpckhdq','vpunpckhqdq','vpunpcklbw',
    'vpunpcklwd','vpunpckldq','vpunpcklqdq','punpckhbw','punpckhwd',
    'punpckhdq','punpckhqdq','punpcklbw','punpcklwd','punpckldq','punpcklqdq'
]
push_insts = ['push'] #r
pusha_insts = ['pusha','pushad'] #none
pushf_insts = ['pushf','pushfd','pushfq'] #none
r_insts = ['rcl','rcr','rol','ror'] #r_r rw_r
rcp_insts = ['rcpps','rcpss','vrcpps','vrcpss'] #r_r rw_r w_r_r
ret_insts = ['ret'] #none r
round_insts = [ #r_r rw_r w_r_r
    'vroundps','vroundpd','vroundss','vroundsd','roundps','roundpd','roundss',
    'roundsd'
]
sahf_insts = ['sahf'] #none
s_insts = ['sal','sar','shl','shr','shld','shrd'] #r_r rw_r
scas_insts = ['scas','scasb','scasd','scasq','scasw'] #none r
set_insts = [ #w
    'seto','setno','setb','setc','setnae','setae','setnb','setnc',
    'sete','setz','setne','setnz','setbe','setna','seta','setnbe',
    'sets','setns','setp','setpe','setnp','setpo','setl','setnge','setge',
    'setnl','setle','setng','setg','setnle'
]
sfence_insts = ['sfence'] #none
shuf_insts = [ #r_r rw_r w_r_r
    'vpshufb','vpshufd','vpshufhw','vpshuflw','pshufb','pshufd','pshufhw',
    'pshuflw','shufps','vshufps','shufpd','vshufpd'
]
sqrt_insts = [ #r_r rw_r w_r_r
    'vsqrtps','vsqrtpd','vsqrtss','vsqrtsd','sqrtps','sqrtpd','sqrtss',
    'sqrtsd','rsqrtps','rsqrtss','vrsqrtps','vrsqrtss'
]
#stmxcsr
stos_insts = ['stos','stosb','stosw','stosd','stosq'] #none r
sub_insts = ['sub','sbb'] #r_r, rw_r
subx_insts = [ #r_r rw_r w_r_r
    'hsubps','hsubpd','vhsubps','vhsubpd','pfsub','pfsubr'
    'vpsubb','vpsubw','vpsubd','vpsubq','vpsubsb','vpsubsw','vpsubusb',
    'vpsubusw','psubb','psubw','psubd','psubq','psubsb','psubsw','psubusb',
    'psubusw','subpd','subps','subsd','subss','vsubpd','vsubps','vsubsd',
    'vsubss'
]
#syscall,sysret,sysenter,sysexit
test_insts = ['test','ptest','vptest'] #r_r
unpck_insts = [ #r_r rw_r w_r_r
    'vunpckhps','vunpckhpd','vunpcklps','vunpcklpd','unpckhps','unpckhpd',
    'unpcklps','unpcklpd'
]
xadd_insts = ['xadd'] #r_r rw_r
xchg_insts = ['xchg'] #r_r rw_r rw_rw
xlat_insts = ['xlat','xlatb'] #r
xor_insts = ['xor'] #r_r rw_r
xorx_insts = ['pxor','xorps','vxorps','xorpd','vxorpd'] #r_r rw_r w_r_r

hlt_insts = ['hlt'] #lt:not in AMD64, machine instruction?

#-----------------------------------
#Instruction groups
#-----------------------------------
mov_prefix = 'mov'
cmp_prefix = 'cmp'

rw_group = cmpxchgn_insts + dec_insts + inc_insts + neg_insts + not_insts +\
    s_insts
r_group = bswap_insts + call_insts + div_insts + int_insts + iret_insts +\
    j_insts + jmp_insts + lod_insts+loop_insts + imul_insts + mul_insts +\
    push_insts + ret_insts + scas_insts + stos_insts + xlat_insts
w_group = clflush_insts + pop_insts + set_insts
r_r_group = add_insts + and_insts + arpl_insts + bound_insts + bt_insts +\
    cmp_insts + cmpxchg_insts + comis_insts + divx_insts + addx_insts +\
    enter_insts + blend_insts + maskmov_insts + min_insts + max_insts +\
    movs_insts + imul_insts + mulx_insts + or_insts + orx_insts + out_insts +\
    pack_insts + test_insts + pavg_insts + pcmp_insts + pcmpstr_insts +\
    pfacc_insts + pfrcpit_insts + pfrsqit_insts + subx_insts + pfcmp_insts +\
    psadbw_insts + shuf_insts + psll_insts + psrl_insts + psra_insts +\
    pswap_insts + punpck_insts + xorx_insts + r_insts + rcp_insts +\
    round_insts + sqrt_insts + s_insts + sub_insts + unpck_insts +\
    xadd_insts + xchg_insts + xor_insts
rw_r_group = add_insts + and_insts + cmpxchg_insts + divx_insts + addx_insts +\
    blend_insts + min_insts + max_insts + imul_insts + mulx_insts + or_insts +\
    orx_insts + pack_insts + pavg_insts + pcmp_insts + pfacc_insts +\
    subx_insts + pfcmp_insts + psadbw_insts + shuf_insts + psll_insts +\
    psrl_insts + psra_insts + pswap_insts + punpck_insts + xorx_insts +\
    r_insts + rcp_insts + round_insts + sqrt_insts + s_insts + sub_insts +\
    unpck_insts + xadd_insts + xchg_insts + xor_insts
w_r_group = bsf_insts + bsr_insts + cmov_insts + cvt_insts + in_insts +\
    extract_insts + insert_insts + load_insts + lea_insts + mov_insts +\
    p_insts + pfrcp_insts + pfrsqrt_insts + phminposuw_insts + popcnt_insts
rw_rw_group = xchg_insts

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
arg_reg_r10 = ['r10d','r10w','r10b','r10']
arg_reg_r8 = ['r8d','r8w','r8b','r8']
arg_reg_r9 = ['r9d','r9w','r9b','r9']
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
def remove_prefixes(mnemonic):
    new = re.sub('rep[a-z]?[a-z]?', '', mnemonic)
    new = re.sub('lock', '', new)
    return new.strip()

def is_mov(mnemonic):
    if mov_prefix in mnemonic:
        return True
    return False

def is_cmp(mnemonic):
    if cmp_prefix in mnemonic:
        return True
    return False

def is_lea(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in lea_insts:
        return True
    return False

def is_call(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in call_insts:
        return True
    return False

def is_jcc(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in j_insts:
        return True
    return False

def is_jmp(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in jmp_insts:
        return True
    return False

def is_ret(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in ret_insts:
        return True
    return False

def is_hlt(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in hlt_insts:
        return True
    return False

def is_nop(mnemonic):
    mnemonic = remove_prefixes(mnemonic)
    if mnemonic in nop_insts:
        return True
    return False

def is_arg_reg(operand):
    if operand in arg_regs_all:
        return True
    return False
#END ASM_HELPER.PY-------------------------------------------------------------

#CALLEE_CONTEXT.PY-------------------------------------------------------------
class CalleeContext(object):
    def __init__(self):
        self.extra_args = 0
        self.def_chain = list() #for debugging purpose, functions for ea cpc
        self.init_regs()

    def init_regs(self):
        self.rdi_set = False
        self.rsi_set = False
        self.rdx_set = False
        self.rcx_set = False
        self.r10_set = False
        self.r8_set = False
        self.r9_set = False
        self.xmm0_set = False
        self.xmm1_set = False
        self.xmm2_set = False
        self.xmm3_set = False
        self.xmm4_set = False
        self.xmm5_set = False
        self.xmm6_set = False
        self.xmm7_set = False

        self.rdi_src = False
        self.rsi_src = False
        self.rdx_src = False
        self.rcx_src = False
        self.r10_src = False
        self.r8_src = False
        self.r9_src = False
        self.xmm0_src = False
        self.xmm1_src = False
        self.xmm2_src = False
        self.xmm3_src = False
        self.xmm4_src = False
        self.xmm5_src = False
        self.xmm6_src = False
        self.xmm7_src = False

    def print_arg_regs(self):
        if self.rdi_src is True:
            print("rdi,")
        if self.rsi_src is True:
            print("rsi,")
        if self.rdx_src is True:
            print("rdx,")
        if self.rcx_src is True:
            print("rcx,")
        if self.r10_src is True:
            print("r10,")
        if self.r8_src is True:
            print("r8,")
        if self.r9_src is True:
            print("r9,")
        if self.xmm0_src is True:
            print("xmm0,")
        if self.xmm1_src is True:
            print("xmm1,")
        if self.xmm2_src is True:
            print("xmm2,")
        if self.xmm3_src is True:
            print("xmm3,")
        if self.xmm4_src is True:
            print("xmm4,")
        if self.xmm5_src is True:
            print("xmm5,")
        if self.xmm6_src is True:
            print("xmm6,")
        if self.xmm7_src is True:
            print("xmm7,")

    def add_set_arg(self,operand):
        """ Adds a possible argument to args
        """
        if operand in arg_reg_rdi and not self.rdi_src:
            self.rdi_set = True
        elif operand in arg_reg_rsi and not self.rsi_src:
            self.rsi_set = True
        elif operand in arg_reg_rdx and not self.rdx_src:
            self.rdx_set = True
        elif operand in arg_reg_rcx and not self.rcx_src:
            self.rcx_set = True
        elif operand in arg_reg_r10 and not self.r10_src:
            self.r10_set = True
        elif operand in arg_reg_r8 and not self.r8_src:
            self.r8_set = True
        elif operand in arg_reg_r9 and not self.r9_src:
            self.r9_set = True
        elif operand in arg_reg_xmm0 and not self.xmm0_src:
            self.xmm0_set = True
        elif operand in arg_reg_xmm1 and not self.xmm1_src:
            self.xmm1_set = True
        elif operand in arg_reg_xmm2 and not self.xmm2_src:
            self.xmm2_set = True
        elif operand in arg_reg_xmm3 and not self.xmm3_src:
            self.xmm3_set = True
        elif operand in arg_reg_xmm4 and not self.xmm4_src:
            self.xmm4_set = True
        elif operand in arg_reg_xmm5 and not self.xmm5_src:
            self.xmm5_set = True
        elif operand in arg_reg_xmm6 and not self.xmm6_src:
            self.xmm6_set = True
        elif operand in arg_reg_xmm7 and not self.xmm7_src:
            self.xmm7_set = True

    def add_src_arg(self,operand):
        """ Adds a possible argument to args
        """
        if operand in arg_reg_rdi and not self.rdi_set:
            self.rdi_src = True
        elif operand in arg_reg_rsi and not self.rsi_set:
            self.rsi_src = True
        elif operand in arg_reg_rdx and not self.rdx_set:
            self.rdx_src = True
        elif operand in arg_reg_rcx and not self.rcx_set:
            self.rcx_src = True
        elif operand in arg_reg_r10 and not self.r10_set:
            self.r10_src = True
        elif operand in arg_reg_r8 and not self.r8_set:
            self.r8_src = True
        elif operand in arg_reg_r9 and not self.r9_set:
            self.r9_src = True
        elif operand in arg_reg_xmm0 and not self.xmm0_set:
            self.xmm0_src = True
        elif operand in arg_reg_xmm1 and not self.xmm1_set:
            self.xmm1_src = True
        elif operand in arg_reg_xmm2 and not self.xmm2_set:
            self.xmm2_src = True
        elif operand in arg_reg_xmm3 and not self.xmm3_set:
            self.xmm3_src = True
        elif operand in arg_reg_xmm4 and not self.xmm4_set:
            self.xmm4_src = True
        elif operand in arg_reg_xmm5 and not self.xmm5_set:
            self.xmm5_src = True
        elif operand in arg_reg_xmm6 and not self.xmm6_set:
            self.xmm6_src = True
        elif operand in arg_reg_xmm7 and not self.xmm7_set:
            self.xmm7_src = True

    def callee_calculate_cpc(self):
        """ Determine callsite parameter cardinality based on argument
            registers seen in assignment commands and their order
        """
        int_regs = 0
        fp_regs = 0

        #Calculate number of int-ptr arguments used in context
        if self.rdi_src is False:
            int_regs = 0
        elif self.rdi_src is True and self.rsi_src is False:
            int_regs = 1
        elif self.rsi_src is True and self.rdx_src is False:
            int_regs = 2
        #special handling for syscalls where r10 is used
        elif self.rdx_src is True and self.rcx_src is False and self.r10_src is False:
            int_regs = 3
        elif (self.rcx_src is True or self.r10_src is True) and self.r8_src is False:
            int_regs = 4
        elif self.r8_src is True and self.r9_src is False:
            int_regs = 5
        elif self.r9_src is True:
            int_regs = 6

        #Calculate number of fp arguments used in context
        if self.xmm0_src is False:
            fp_regs = 0
        elif self.xmm0_src is True and self.xmm1_src is False:
            fp_regs = 1
        elif self.xmm1_src is True and self.xmm2_src is False:
            fp_regs = 2
        elif self.xmm2_src is True and self.xmm3_src is False:
            fp_regs = 3
        elif self.xmm3_src is True and self.xmm4_src is False:
            fp_regs = 4
        elif self.xmm4_src is True and self.xmm5_src is False:
            fp_regs = 5
        elif self.xmm5_src is True and self.xmm6_src is False:
            fp_regs = 6
        elif self.xmm6_src is True and self.xmm7_src is False:
            fp_regs = 7
        elif self.xmm7_src is True:
            fp_regs = 8

        return int_regs + fp_regs + self.extra_args
#END CALLEE_CONTEXT.PY---------------------------------------------------------

MAX_CALLEE_SWEEP = 200
def callee_arg_sweep(ea, debug, next_func_ea):
    context = CalleeContext()
    for head in Heads(ea, ea+MAX_CALLEE_SWEEP):
        mnem = GetMnem(head)
        num_opnds = 0
        opnd_1 = GetOpnd(head, 0)
        opnd_2 = GetOpnd(head, 1)

        if opnd_1 != "":
            num_opnds = 1
        if opnd_2 != "":
            num_opnds = 2

        if num_opnds == 1:
            opnd_1_type = GetOpType(head, 0)
            if opnd_1_type == o_reg:
                if is_arg_reg(opnd_1):
                    if mnem in r_group or mnem in rw_group:
                        context.add_src_arg(opnd_1)
                        if debug:
                            print("%x: %s %s" % (head,mnem,opnd_1))
                    elif mnem in w_group:
                        context.add_set_arg(opnd_1)
                    else:
                        print("Unrecognized mnemonic: %s" % mnem)
            if opnd_1_type == o_phrase or opnd_1_type == o_displ:
                if debug:
                    print("%x: %s %s" % (head,mnem,opnd_1))
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

        if num_opnds == 2:
            opnd_1_type = GetOpType(head, 0)
            opnd_2_type = GetOpType(head, 1)

            #XOR REG1 REG1 case:
            if opnd_1 == opnd_2:
                if mnem in xor_insts or mnem in xorx_insts:
                    context.add_set_arg(opnd_1)

            if opnd_1_type == o_reg:
                if is_arg_reg(opnd_1):
                    if mnem in w_r_group:
                        context.add_set_arg(opnd_1)
                    elif mnem in r_r_group or mnem in rw_r_group:
                        context.add_src_arg(opnd_1)
                        if debug:
                            print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                    else:
                        print("Unrecognized mnemonic: %s" % mnem)
            elif opnd_1_type == o_phrase or opnd_1_type == o_displ:
                if debug:
                    print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                for arg in arg_extract(opnd_1):
                    context.add_src_arg(arg)

            if opnd_2_type == o_reg:
                if is_arg_reg(opnd_2):
                    context.add_src_arg(opnd_2)
                    if debug:
                        print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
            elif opnd_2_type == o_phrase or opnd_2_type == o_displ:
                if debug:
                    print("%x: %s %s %s" % (head,mnem,opnd_1,opnd_2))
                for arg in arg_extract(opnd_2):
                    context.add_src_arg(arg)

        if is_ret(mnem) or is_hlt(mnem) or is_call(mnem) or (is_jmp(mnem) and
        GetOperandValue(head,0) in func_ea_list) or head > next_func_ea:
            break

    if debug:
        context.print_arg_regs()
    return context.callee_calculate_cpc()

def arg_extract(opnd):
    arg_list = list()

    arg_rdi = check_arg(arg_reg_rdi, opnd)
    arg_rsi = check_arg(arg_reg_rsi, opnd)
    arg_rdx = check_arg(arg_reg_rdx, opnd)
    arg_rcx = check_arg(arg_reg_rcx, opnd)
    arg_r10 = check_arg(arg_reg_r10, opnd)
    arg_r8 = check_arg(arg_reg_r8, opnd)
    arg_r9 = check_arg(arg_reg_r9, opnd)
    arg_xmm0 = check_arg(arg_reg_xmm0, opnd)
    arg_xmm1 = check_arg(arg_reg_xmm1, opnd)
    arg_xmm2 = check_arg(arg_reg_xmm2, opnd)
    arg_xmm3 = check_arg(arg_reg_xmm3, opnd)
    arg_xmm4 = check_arg(arg_reg_xmm4, opnd)
    arg_xmm5 = check_arg(arg_reg_xmm5, opnd)
    arg_xmm6 = check_arg(arg_reg_xmm6, opnd)
    arg_xmm7 = check_arg(arg_reg_xmm7, opnd)

    if arg_rdi != "":
        arg_list.append(arg_rdi)
    if arg_rsi != "":
        arg_list.append(arg_rsi)
    if arg_rdx != "":
        arg_list.append(arg_rdx)
    if arg_rcx != "":
        arg_list.append(arg_rcx)
    if arg_r10 != "":
        arg_list.append(arg_r10)
    if arg_r8 != "":
        arg_list.append(arg_r8)
    if arg_r9 != "":
        arg_list.append(arg_r9)
    if arg_xmm0 != "":
        arg_list.append(arg_xmm0)
    if arg_xmm1 != "":
        arg_list.append(arg_xmm1)
    if arg_xmm2 != "":
        arg_list.append(arg_xmm2)
    if arg_xmm3 != "":
        arg_list.append(arg_xmm3)
    if arg_xmm4 != "":
        arg_list.append(arg_xmm4)
    if arg_xmm5 != "":
        arg_list.append(arg_xmm5)
    if arg_xmm6 != "":
        arg_list.append(arg_xmm6)
    if arg_xmm7 != "":
        arg_list.append(arg_xmm7)

    return arg_list

def check_arg(arg_regs, opnd):
    for reg in arg_regs:
        if reg in opnd:
            return reg
    return ""

DICT_OUTPUT = False
CPC_OUTPUT = False
ADDR_DEBUG = False
NAME_DEBUG = False
sep = ","

if __name__ == '__main__':
    if ARGV[1] == '-c':
        sep = ","
        CPC_OUTPUT = True
        ext = "chain"
    elif ARGV[1] == '-f':
        sep = "\n"
        NAME_DEBUG = True
        CPC_OUTPUT = True
        ext = "func"
    elif ARGV[1] == '-l':
        sep = "\n"
        CPC_OUTPUT = True
        ext = "feature"
    elif ARGV[1] == '-d':
        DICT_OUTPUT = True
        ext = "dict"
    else:
        print("Must pass -c (chain), -f (per function), or -l (list)")

    autoWait()
    #print("Starting")
    #ea = ScreenEA()    #ltj:screen ea not set in -A mode
    #ea = GetEntryPoint(GetEntryOrdinal(0)) #ltj: not always 0...
    sel = SegByName(".text")
    ea = SegByBase(sel)
    #print("%x" % ea)
    func_ea_list = list()
    func_name_list = list()
    func_dict = dict()

    for function_ea in Functions(SegStart(ea), SegEnd(ea)):
        #print hex(function_ea), GetFunctionName(function_ea)
        func_ea_list.append(function_ea)
        func_name_list.append(GetFunctionName(function_ea))
        func_dict[function_ea] = GetFunctionName(function_ea)
    func_ea_list.append(sys.maxint)

    cpc_dict = dict()
    cpc_chain = ""

    f = 0
    for head in Heads(SegStart(ea), SegEnd(ea)):
        if head > func_ea_list[f]:
            cpc_chain += sep
            if NAME_DEBUG:
                cpc_chain = cpc_chain + func_name_list[f] + " "
            if ADDR_DEBUG:
                cpc_chain += hex(head)
            f += 1

        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            if is_call(mnem):
                op_type = GetOpType(head, 0)
                if op_type == o_near or op_type == o_far:
                    op_val = GetOperandValue(head, 0)
                    if op_val < SegEnd(head) and op_val > SegStart(head):
                        #print("@%x, %d" % (op_val, op_type))
                        cpc = cpc_dict.get(op_val, None)
                        if cpc is None:
                            i = func_ea_list.index(op_val)
                            if func_name_list[i] == '//':
                                cpc = callee_arg_sweep(op_val, True, func_ea_list[i+1])
                            else:
                                cpc = callee_arg_sweep(op_val, False, func_ea_list[i+1])
                            cpc_dict[op_val] = cpc

                        cpc_chain += str(cpc)

            if is_jmp(mnem):
                op_type = GetOpType(head, 0)
                if op_type == o_near or op_type == o_far:
                    op_val = GetOperandValue(head, 0)
                    if op_val in func_ea_list:
                        cpc = cpc_dict.get(op_val, None)
                        if cpc is None:
                            cpc = callee_arg_sweep(op_val, False, func_ea_list[i+1])
                            cpc_dict[op_val] = cpc

                        cpc_chain += str(cpc)

    if CPC_OUTPUT:
        print cpc_chain
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(cpc_chain)
        f.close()
    elif DICT_OUTPUT:
        dict_out = ""
        for ea in cpc_dict:
            try:
                dict_out += func_dict[ea] + ": " + str(cpc_dict[ea]) + "\n"
            except KeyError:
                pass
                #dict_out += str(ea) + " not found as start of function"
        print dict_out
        filename = GetInputFilePath() + ".cpc." + ext
        f = open(filename, 'w')
        f.write(dict_out)
        f.close()

    Exit(0)