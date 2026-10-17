// Ghidra headless post-script (round 21): who drives the sparse solve entry.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

public class Round21 extends GhidraScript {
    private DecompInterface DI;
    private FunctionManager FM;

    private void decompile(Function f, String tag, int maxChars) {
        println("");
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

        int shown = 0;
        int total = 0;
        for (Reference r : getReferencesTo(toAddr(0x5888ECL))) {
            if (!(r.getReferenceType().isCall() || r.getReferenceType().isJump())) {
                continue;
            }
            total++;
            Function caller = FM.getFunctionContaining(r.getFromAddress());
            print("caller[" + total + "]: " + r.getFromAddress()
                    + (caller != null ? " in " + caller.getName() : "") + "\n");
            if (shown < 2 && caller != null) {
                decompile(caller, "caller of 0x1888ec", 7000);
                shown++;
            }
        }
        println("total callers: " + total);

        println("");
        println("==== done ====");
    }
}
