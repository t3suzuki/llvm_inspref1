#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ProfileData/SampleProf.h"
#include "llvm/ProfileData/SampleProfReader.h"
#include "llvm/Transforms/IPO/SampleProfile.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/ADT/SetVector.h"

using namespace llvm;

static cl::opt<std::string> fdo_file("input-file", cl::desc("Specify FDO file."), cl::value_desc("filename"));

static cl::opt<bool> my_verbose("verbose", cl::desc("verbose flag"), cl::value_desc("verbose"));

namespace {
  struct Inspref1Pass : public FunctionPass {
  private:
    std::unique_ptr<llvm::sampleprof::SampleProfileReader> Reader = nullptr;
  public:
    static char ID;
    Inspref1Pass() : FunctionPass(ID) {}
    Instruction *OtherInstr;
    
    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.addRequired<LoopInfoWrapperPass>();
    }
    bool doInitialization(Module &M) override {
      if (fdo_file.empty()){
	errs() << "[Error] input file is not specified!\n";
	return false;
      }
      auto FS = vfs::getRealFileSystem();      
      LLVMContext &Ctx = M.getContext();
      ErrorOr<std::unique_ptr<SampleProfileReader>> ReaderOrErr = SampleProfileReader::create(fdo_file, Ctx, *FS);
      if (std::error_code EC = ReaderOrErr.getError()) {
	std::string Msg = "Could not open profile: " + EC.message();
	Ctx.diagnose(DiagnosticInfoSampleProfile(fdo_file, Msg, DiagnosticSeverity::DS_Warning));
	return false;
      }
      
      Reader = std::move(ReaderOrErr.get());
      Reader->read();
      
      return true;
    }


    Instruction* GetIncomingValue(Loop* L, llvm::Instruction* curPN) {  
      BasicBlock *H = L->getHeader();
      BasicBlock *Backedge = nullptr;
      pred_iterator PI = pred_begin(H);
      Backedge = *PI++;

      for (BasicBlock::iterator I = H->begin(); isa<PHINode>(I); ++I) {
	PHINode *PN = cast<PHINode>(I);
	if (PN == curPN) {
	  if (Instruction *IncomingInstr = dyn_cast<Instruction>(PN->getIncomingValueForBlock(Backedge))){
	    if (OtherInstr = dyn_cast<Instruction>(PN->getIncomingValueForBlock(*PI++))){
	      errs() << "other: ";
	      OtherInstr->dump();
	    }
	    return IncomingInstr;
	  }
	}
      }
      return nullptr;
    }


    CmpInst* getCompareInstrGetElememntPtr(Loop* L, Instruction* nextInd){
      SetVector<Instruction*> BBInsts;
      auto B = L->getExitingBlock();
      int count = 0;
      
      if (!B)
	return nullptr;
      for (Instruction &J : *B) {
	Instruction* I = &J;
	BBInsts.insert(I);
	count++;
      }
      for (int i= BBInsts.size()-1; i>=0; i--) {
	CmpInst *CI = dyn_cast<CmpInst>(BBInsts[i]);
	if (CI &&
	    (CI->getOperand(0) == nextInd || CI->getOperand(1) == nextInd) &&
	    nextInd->getOpcode() == Instruction::GetElementPtr){
	  return CI;
	}
      }
      
      return nullptr;
    }
    
    virtual bool runOnFunction(Function &F) override {
      if (Reader) {
	const llvm::sampleprof::FunctionSamples* read_samples = Reader->getSamplesFor(F);
	if (read_samples) {
	  LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>().getLoopInfo();
	  for (auto &BB : F) {
	    bool isBBLoop = LI.getLoopFor(&BB);
	    for (auto &I : BB) {
	      if (const DILocation *Loc = I.getDebugLoc()){
		if (const auto *samples = read_samples->findFunctionSamples(Loc)) {
		  auto ret = samples->findCallTargetMapAt(FunctionSamples::getOffset(Loc),
							  Loc->getBaseDiscriminator()*2);
		  if (ret) {
		    Use* OperandList0 = I.getOperandList();
		    LoadInst *curLoad = dyn_cast<LoadInst>(&I);
		    if (!curLoad) {
		      for (Use* op0 = OperandList0; op0 < OperandList0 + I.getNumOperands(); op0++) {
			curLoad = dyn_cast<LoadInst>(op0->get());
			if (curLoad)
			  break;
		      }
		    }

		    if (curLoad) {
		      errs() << "curLoad : ";
		      curLoad->dump();
		      PHINode *phi = nullptr;
		      Use* OperandList = curLoad->getOperandList();
		      Loop* curLoop = LI.getLoopFor(curLoad->getParent());
		      for (Use* op = OperandList; op < OperandList + curLoad->getNumOperands(); op++) {
			Instruction* insn = dyn_cast<Instruction>(op->get());
			errs() << "dep_insn : ";
			insn->dump();
			if (dyn_cast<PHINode>(insn)) {
			  phi = dyn_cast<PHINode>(insn);
			}

			
			Use* OperandList2 = insn->getOperandList();
			for (Use* op2 = OperandList2; op2 < OperandList2 + insn->getNumOperands(); op2++) {
			  Instruction* insn2 = dyn_cast<Instruction>(op2->get());
			  if (insn2) {
			    insn2->dump();
			    errs() << "isLoopInv: " << curLoop->isLoopInvariant(insn2) << "\n";
			    if (curLoop->isLoopInvariant(insn2)) {
			      Type *I32 = Type::getInt32Ty(F.getContext());
			      Function *PrefetchFunc = Intrinsic::getDeclaration((curLoad->getFunction())->getParent(), Intrinsic::prefetch, (curLoad->getOperand(0))->getType());
			      Instruction* gep = dyn_cast<Instruction>(curLoad->getOperand(0));
			      Value* args[] = {
					       gep,
					       ConstantInt::get(I32 ,0),
					       ConstantInt::get(I32 ,3),
					       ConstantInt::get(I32 ,1)
			      };
			      auto aargs = ArrayRef<Value *>(args, 4);
			      CallInst* pref_call = CallInst::Create(PrefetchFunc, aargs);
			      pref_call->insertBefore(curLoad);

			      if (phi) {
				Instruction* IncInstr = GetIncomingValue(curLoop, phi);
				errs() << "IncInsn : ";
				IncInstr->dump();
				if (IncInstr->getOpcode() == Instruction::GetElementPtr && IncInstr->getOperand(0) == phi){
				  CmpInst* compareInstr = getCompareInstrGetElememntPtr(curLoop, IncInstr);
				  errs() << "CmpInsn : ";
				  compareInstr->dump();

				  IRBuilder<> builder(curLoad);
				  //Value *i = builder.CreateAlloca(I32, nullptr, "i");
				  //builder.CreateStore(ConstantInt::get(I32, 0), i);
				  //builder.CreateStore(OtherInstr, i);
				  //Instruction* gep2 = dyn_cast<Instruction>(curLoad->getOperand(0));
				  Value* args2[] = {
						    OtherInstr,
						    ConstantInt::get(I32 ,0),
						    ConstantInt::get(I32 ,3),
						    ConstantInt::get(I32 ,1)
				  };
				  auto aargs2 = ArrayRef<Value *>(args2, 4);
				  builder.CreateCall(PrefetchFunc, aargs2);
				  /*
				  Value *added = builder.CreateAdd(OtherInstr, ConstantInt::get(I32 ,4));
				  Value* args3[] = {
						    added,
						    ConstantInt::get(I32 ,0),
						    ConstantInt::get(I32 ,3),
						    ConstantInt::get(I32 ,1)
				  };
				  auto aargs3 = ArrayRef<Value *>(args3, 4);
				  builder.CreateCall(PrefetchFunc, aargs3);
				  */
				  //builder.Insert(pref_call);
				  
				  //BasicBlock *loop_cond = BasicBlock::Create(F.getContext(), "myloop.cond", &F);
				  //BasicBlock *loop_body = BasicBlock::Create(F.getContext(), "myloop.body", &F);
				  //BasicBlock *loop_end = BasicBlock::Create(F.getContext(), "myloop.end", &F);
				  //builder.CreateBr(loop_cond);
				  //builder.SetInsertPoint(loop_cond);
				  
				}
			      }
			      
			      bool changed;
			      curLoop->makeLoopInvariant(pref_call, changed);
			      errs() << "insert OK: " << changed << "\n";
			    }
			  }
			}
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
      return false;
    }
  };
}

char Inspref1Pass::ID = 0;

#if 0
// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerInspref1Pass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new Inspref1Pass());
}

static RegisterStandardPasses
  RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                 registerInspref1Pass);
#endif

static RegisterPass<Inspref1Pass>
    X("Inspref1", "Inspref1 Pass",
      true, // This pass doesn't modify the CFG => true
      false // This pass is not a pure analysis pass => false
    );
