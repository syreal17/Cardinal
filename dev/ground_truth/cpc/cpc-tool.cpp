// -----------------------------------------------------------------------------
// A Three-Pronged Approach to Exploring the Limits of Static Malware Analyses:
// Ground Truth LLVM Generation Tool: cpc-tool.cpp
//
// Creates CPC ground truth about each function in module
//
// Luke Jones (luke.t.jones.814@gmail.com)
//
// The MIT License (MIT)
// Copyright (c) 2016 Chthonian Cyber Services
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// -----------------------------------------------------------------------------

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
			if( it == func_name_to_cpc.begin() ){
				outs() << it->first << ": " << it->second;
			} else {
				outs() << "\n" << it->first << ": " << it->second;
			}
		}
	}
	outs() << "\n";

	return 0;
}
