// Ghidra headless post-script (round 20): the sparse-solve callers.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round20 extends GhidraScript {
    private DecompInterface DI;
    private FunctionManager FM;

    private void show(long va, String tag, int maxChars) {
        Address addr = toAddr(va);
        Function f = FM.getFunctionContaining(addr);
        if (f == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                // ignore
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
            f = FM.getFunctionContaining(addr);
        }
        println("");
        if (f == null) {
            println("[" + tag + "] VA 0x" + Long.toHexString(va) + " -> <none>");
            return;
        }
        println("[" + tag + "] " + f.getName() + " @" + f.getEntryPoint()
                + " (RVA 0x" + Long.toHexString(f.getEntryPoint().getOffset() - 0x400000L)
                + ") body=" + f.getBody().getNumAddresses());
        DecompileResults r = DI.decompileFunction(f, 300, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            String c = r.getDecompiledFunction().getC();
            println(c.length() > maxChars ? c.substring(0, maxChars) + "\n... (truncated)" : c);
        } else {
            println("[decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        FM = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        show(0x910c58L, "sparse solve wrapper", 4000);
        show(0x5888ecL, "solver-core caller of the wrapper", 9000);
        show(0x71630dL, "AC sweep caller (runtime frame)", 2000);

        println("");
        println("==== done ====");
    }
}
