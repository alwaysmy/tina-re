// Round 30: full sparse_dll algorithm inventory (structures, ordering, factorization, solve).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round30 extends GhidraScript {
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

        // wrappers first (to learn the core targets)
        show(0x406c20L, "SMPluFac wrapper", 1500);
        show(0x406c50L, "SMPcReorder wrapper", 1500);
        show(0x406c84L, "SMPreorder wrapper", 1500);
        show(0x406c04L, "SMPcLUfac wrapper", 1500);

        // internals
        show(0x402f18L, "makeElt index handling", 3500);
        show(0x403020L, "element allocation", 3500);
        show(0x401448L, "preOrder part1", 3500);
        show(0x4029d8L, "preOrder part2", 3500);
        show(0x402ba0L, "luFac prep", 2500);
        show(0x40367cL, "luFac core", 14000);
        show(0x4074ccL, "solve alternative path", 5000);
        show(0x406f90L, "pluFac core", 6000);
        println("");
        println("==== done ====");
    }
}
