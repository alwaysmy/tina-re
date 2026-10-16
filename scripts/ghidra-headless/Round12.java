// Ghidra headless post-script (round 12): RMD320 compress + cipher-family hooks (glue layer).
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round12 extends GhidraScript {
    private DecompInterface DI;

    private void decompileVa(FunctionManager fm, long va, String tag) {
        Address addr = toAddr(va);
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                // ignore
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        }
        Function f = fm.getFunctionContaining(addr);
        println("");
        println("==== [" + tag + "] " + (f == null ? "<none>" : f.getName() + " @" + f.getEntryPoint()) + " ====");
        if (f == null) {
            return;
        }
        DecompileResults r = DI.decompileFunction(f, 300, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        decompileVa(fm, 0x561588L, "RMD320 compress #2 (+0x34)");
        decompileVa(fm, 0x561560L, "RMD320 family +0x1C?");
        decompileVa(fm, 0x55972CL, "cipher hook FUN_0055972c");
        decompileVa(fm, 0x559750L, "cipher hook FUN_00559750");
        decompileVa(fm, 0x559774L, "cipher hook FUN_00559774");
        decompileVa(fm, 0x56B490L, "mode-1 path FUN_0056b490");

        println("");
        println("==== done ====");
    }
}
