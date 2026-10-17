// Ghidra headless post-script (round 18, Phase 3 / M2): resolve the runtime
// call chain captured by Frida (tina_sparse_trace.js) into functions.
//
// Frida module-relative offsets == RVAs; Ghidra VA = RVA + 0x400000.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

public class Round18 extends GhidraScript {
    private DecompInterface DI;
    private FunctionManager FM;

    private Function ensureFunction(long va) {
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
        return f;
    }

    private void show(long va, String tag, int maxChars) {
        Function f = ensureFunction(va);
        println("");
        if (f == null) {
            println("[" + tag + "] VA 0x" + Long.toHexString(va) + " -> <no function>");
            return;
        }
        println("[" + tag + "] VA 0x" + Long.toHexString(va) + " -> " + f.getName()
                + " @" + f.getEntryPoint() + " (RVA 0x"
                + Long.toHexString(f.getEntryPoint().getOffset() - 0x400000L)
                + ") body=" + f.getBody().getNumAddresses());

        int shown = 0;
        for (Reference r : getReferencesTo(f.getEntryPoint())) {
            if (!(r.getReferenceType().isCall() || r.getReferenceType().isJump())) {
                continue;
            }
            Function caller = FM.getFunctionContaining(r.getFromAddress());
            if (shown < 5) {
                println("    caller: " + r.getFromAddress()
                        + (caller != null ? "  in " + caller.getName() : ""));
            }
            shown++;
        }
        println("    caller count: " + shown);

        DecompileResults r = DI.decompileFunction(f, 240, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            String c = r.getDecompiledFunction().getC();
            println(c.length() > maxChars ? c.substring(0, maxChars) + "\n... (truncated)" : c);
        } else {
            println("    [decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        FM = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        // frames from the Frida capture (RVA -> VA)
        show(0x910c72L, "direct caller of _SMPcSolve", 7000);
        show(0x71630dL, "AC sweep frame A", 5000);
        show(0x716ad8L, "AC sweep frame B", 5000);
        show(0x829726L, "analysis orchestrator", 6000);
        show(0x493a38L, "command dispatch A", 4000);
        show(0x4936b3L, "command dispatch B", 4000);
        show(0x42ec26L, "message handler", 4000);

        println("");
        println("==== done ====");
    }
}
