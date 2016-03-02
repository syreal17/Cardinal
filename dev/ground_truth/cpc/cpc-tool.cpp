#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>

using namespace llvm;
int main(int argc, char* argv[])
{
	if(argc < 2 || argc > 2){
		outs() << "Pass in one file for cpc checking\n";
		return 1;
	}
	LLVMContext context;
	SMDiagnostic error;
	std::unique_ptr<Module> m = parseIRFile(argv[1], error, context);
	
	for(auto fit = m->begin(); fit != m->end(); ++fit)
	{
		for(auto bit = fit->begin(); bit != fit->end(); ++bit)
		{
			for(auto iit = bit->begin(); iit != bit->end(); ++iit)
			{
				if( CallInst *call = dyn_cast<CallInst>(iit) ){
					Function *f = call->getCalledFunction();
					if( !f->isDeclaration())
					{
						//outs() << *call << "\n";
						outs() << call->getNumArgOperands();
					}
				}
			}	
			outs() << ",";
		}
	}
	outs() << "\n";

	return 0;
}
