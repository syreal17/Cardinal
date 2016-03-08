#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <map>

using namespace llvm;
using namespace std;

const bool PRINT_CPCC = false; //prints cpc chains
const bool PRINT_CPCD = true; //prints cpc dictionaries

int main(int argc, char* argv[])
{
	if(argc < 2 || argc > 2){
		outs() << "Pass in one file for cpc checking\n";
		return 1;
	}
	LLVMContext context;
	SMDiagnostic error;
	std::unique_ptr<Module> m = parseIRFile(argv[1], error, context);
	
	map<StringRef,unsigned int> func_name_to_cpc;
	for(auto fit = m->begin(); fit != m->end(); ++fit)
	{
		if(PRINT_CPCC){
			outs() << ","; //every new function, insert ","
		}
		for(auto bit = fit->begin(); bit != fit->end(); ++bit)
		{
			for(auto iit = bit->begin(); iit != bit->end(); ++iit)
			{
				if( CallInst *call = dyn_cast<CallInst>(iit) ){
					Function *f = call->getCalledFunction();
					if( f != NULL )
					{
						if( !f->isDeclaration())
						{
							if(PRINT_CPCC){
								outs() << call->getNumArgOperands();
							}
							if(PRINT_CPCD){
								StringRef name = f->getName();
								unsigned int cpc = call->getNumArgOperands();
								func_name_to_cpc.insert(pair<StringRef,unsigned int>(name, cpc));
							}
						}
					}
				}
			}	
		}
	}
	if(PRINT_CPCD){
		for(auto it = func_name_to_cpc.begin(); it != func_name_to_cpc.end(); it++)
		{
			outs() << it->first << ": " << it->second << "\n";	
		}
	}
	outs() << "\n";

	return 0;
}
