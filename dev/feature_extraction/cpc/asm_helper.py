#-----------------------------------------------------------------------------
# A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
# Callsite Parameter Cardinality (CPC) Counting: asm_helper.py
#
# A helper for some verbose asm tasks
#
# Luke Jones (luke.t.jones.814@gmail.com)
#
# The MIT License (MIT)
# Copyright (c) 2016 Chthonian Cyber Services
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#-----------------------------------------------------------------------------

import re

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
    'movntsd','movntss','movq','movq2dq','movshdup',
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
ret_insts = ['ret', 'retn'] #none r
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
    xadd_insts + xchg_insts + xor_insts + andx_insts
rw_r_group = add_insts + and_insts + cmpxchg_insts + divx_insts + addx_insts +\
    blend_insts + min_insts + max_insts + imul_insts + mulx_insts + or_insts +\
    orx_insts + pack_insts + pavg_insts + pcmp_insts + pfacc_insts +\
    subx_insts + pfcmp_insts + psadbw_insts + shuf_insts + psll_insts +\
    psrl_insts + psra_insts + pswap_insts + punpck_insts + xorx_insts +\
    r_insts + rcp_insts + round_insts + sqrt_insts + s_insts + sub_insts +\
    unpck_insts + xadd_insts + xchg_insts + xor_insts + andx_insts
w_r_group = bsf_insts + bsr_insts + cmov_insts + cvt_insts + in_insts +\
    extract_insts + insert_insts + load_insts + lea_insts + mov_insts +\
    p_insts + pfrcp_insts + pfrsqrt_insts + phminposuw_insts + popcnt_insts
rw_rw_group = xchg_insts
w_r_r_group = addx_insts + andx_insts + blend_insts + divx_insts +\
    dp_insts + imul_insts + max_insts + min_insts + mulx_insts +\
    orx_insts + pack_insts + pavg_insts + pcmp_insts + pcmpstr_insts +\
    psadbw_insts + psll_insts + psra_insts + psrl_insts + rcp_insts +\
    round_insts + shuf_insts + sqrt_insts + subx_insts + unpck_insts +\
    xorx_insts

#-----------------------------------
#Registers
#-----------------------------------
arg_regs = ['rdi','rsi','rdx','rcx','r8','r9']
arg_regs_syscall = ['rdi','rsi','rdx','r10','r8','r9']
arg_regs_fp = ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']
#TODO: lt: adding low (dl, cl) for rdx, and rcx might be correct?
#arg_regs_all = [
#    'rdi','edi','di','rsi','esi','si','rdx','edx','dx','dl','rcx','ecx','cx',
#    'cl','r10','r10d','r10w','r10b','r8','r8d','r8w','r8b','r9','r9d','r9w',
#    'r9b','xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7'
#]
arg_reg_rdi = ['rdi','edi','di']
arg_reg_rsi = ['rsi','esi','si']
#arg_reg_rsi = ['derp']
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
arg_regs_all = arg_reg_rdi + arg_reg_rsi + arg_reg_rdx + arg_reg_rcx +\
                arg_reg_r10 + arg_reg_r8 + arg_reg_r9 + arg_reg_xmm0 +\
                arg_reg_xmm1 + arg_reg_xmm2 + arg_reg_xmm3 + arg_reg_xmm4 +\
                arg_reg_xmm5 + arg_reg_xmm6 + arg_reg_xmm7

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