from idautils import *
from idc import *
seg_ea = SegByName(".text")
heads = Heads(seg_ea, SegEnd(seg_ea))
jumpsSameTarget = []
heads = list(heads)
newlist = []
for i in heads:
	if(GetMnem(i).isalnum):
		newlist.append(i)
		
for index in range(0, len(newlist)-1):
	instr1 = str(GetMnem(newlist[index]))
	instr2 = str(GetMnem(newlist[index+1]))
	if(len(instr1)>0 and len(instr2)>0):
		if ((instr1[0] == "j") and (instr2[0] == "j")):
			jumpsSameTarget.append(newlist[index])
			jumpsSameTarget.append(newlist[index+1])

print "Number of potential Anti-Disassembly instructions: %d" % (len(jumpsSameTarget))

for i in jumpsSameTarget:
	SetColor(i, CIC_ITEM, 0x0000ff)
	Message("Possible Anti-Disassembly: %08x\n" % i)
	

condJumps =	["ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "je", "jg", "jge", "jl",
"jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno",
"jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz", "ja", "jae", "jb", "jbe",
"jc", "je", "jz", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne",
"jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
"js", "jz"]


jumpsConstantCond  = []	
jumpsBetterChance = []

for index in range(0, len(newlist)-1):
	instr1 = str(GetMnem(newlist[index]))
	instr2 = str(GetMnem(newlist[index+1]))
	if(len(instr1)>0 and len(instr2)>0):
		if (instr1 in condJumps) and (newlist[index] not in jumpsSameTarget):
			jumpsConstantCond.append(newlist[index])
		if(instr1 == "xor") and (instr2 in condJumps and (newlist[index+1] not in jumpsSameTarget)):
			jumpsBetterChance.append(newlist[index])
			jumpsBetterChance.append(newlist[index+1])
		if((instr1 == "test") and (instr2 in condJumps) and (newlist[index+1] not in jumpsSameTarget)):
			jumpsBetterChance.append(newlist[index])
			jumpsBetterChance.append(newlist[index+1])

print "Number of potential Anti-Disassembly instructions: %d" % (len(jumpsConstantCond))
print "All conditional jumps in green"
print "Condtional Jumps with xor or test in front in yellow"

for i in jumpsConstantCond:
	SetColor(i, CIC_ITEM, 0x008000)
	Message("Possible Anti-Disassembly: %08x\n" % i)
	
for i in jumpsBetterChance:
	SetColor(i, CIC_ITEM, 0xffa500)
	
	
	
	
