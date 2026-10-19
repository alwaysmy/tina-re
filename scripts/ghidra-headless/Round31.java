// Round 31: sparse_dll numeric LU + ordering core.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round31 extends GhidraScript {
    private DecompInterface di;

    private void show(long va, String tag, int maxChars) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionContaining(toAddr(va));
        println("");
        if (f == null) {
            println("[" + tag + "] VA 0x" + Long.toHexString(va) + " -> <none>");
            return;
        }
        println("[" + tag + "] " + f.getName() + " @" + f.getEntryPoint()
                + " body=" + f.getBody().getNumAddresses());
        DecompileResults r = di.decompileFunction(f, 300, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            String c = r.getDecompiledFunction().getC();
            println(c.length() > maxChars ? c.substring(0, maxChars) + "\n... (truncated)" : c);
        } else {
            println("[decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);
        show(0x405b14L, "numeric LU (real path)", 22000);
        show(0x40340cL, "ordering / reorder core", 9000);
        show(0x4040dcL, "cleanup/drop pass", 3000);
        println("");
        println("==== done ====");
    }
}
