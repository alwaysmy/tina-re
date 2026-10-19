// Dump sparse_dll exports and decompile them.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class DumpSparseExports extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            String n = f.getName();
            if (!n.contains("_SMP")) {
                continue;
            }
            println("");
            println("==== " + n + " @" + f.getEntryPoint() + " ====");
            DecompileResults r = di.decompileFunction(f, 240, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                String c = r.getDecompiledFunction().getC();
                println(c.length() > 3500 ? c.substring(0, 3500) + "\n... (truncated)" : c);
            } else {
                println("[decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
            }
        }
        println("");
        println("==== done ====");
    }
}
