// Round 24: decompile the command-handler candidates found by Round23.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round24 extends GhidraScript {
    private DecompInterface DI;

    private void show(long va, String tag, int maxChars) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionContaining(toAddr(va));
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
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);
        show(0x72114cL, "command handler candidate (A6/A7)", 9000);
        show(0x903bdcL, "command handler candidate (0x503bdc)", 7000);
        show(0x99613cL, "command handler candidate (0x59613c)", 5000);
        show(0x71aa58L, "analysis worker candidate (0x31aa58)", 5000);
        println("");
        println("==== done ====");
    }
}
