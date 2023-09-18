#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ProfileData/SampleProf.h"
#include "llvm/ProfileData/SampleProfReader.h"
#include "llvm/Transforms/IPO/SampleProfile.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/IR/DebugInfoMetadata.h"
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

    bool doInitialization(Module &M) {
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

    virtual bool runOnFunction(Function &F) {

      if (Reader) {
	const llvm::sampleprof::FunctionSamples* read_samples = Reader->getSamplesFor(F);
	if (read_samples) {
	  //read_samples->dump();
	  for (auto &BB : F) {
	    for (auto &I : BB) {
	      if (const DILocation *Loc = I.getDebugLoc()){
		if (const auto *samples = read_samples->findFunctionSamples(Loc)) {
		  auto ret = samples->findCallTargetMapAt(FunctionSamples::getOffset(Loc),
							  Loc->getBaseDiscriminator()*2);
		  if (ret) {
		    errs() << "---------------------------\n";
		    samples->dump();
		    Loc->dump();
		    I.dump();
		    errs() << FunctionSamples::getOffset(Loc) << "\n";
		    errs() << "Base : " << Loc->getBaseDiscriminator() << "\n";
		    errs() << "\n";
		    if (LoadInst *curLoad = dyn_cast<LoadInst>(&I)) {
		      curLoad->dump();
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
