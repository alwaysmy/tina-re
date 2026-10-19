// Round 25: map the analysis workers via the solver/dispatch entry points.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

public class Round25 extends GhidraScript {
    private DecompInterface DI;

    private void callers(long va, String tag, int decompileN, int maxChars) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Address addr = toAddr(va);
        Function target = fm.getFunctionContaining(addr);
        println("");
        println("== callers of 0x" + Long.toHexString(va) + " (" + tag + ") ==");
        if (target == null) {
            println("   <no function>");
            return;
        }
        println("   function: " + target.getName() + " @" + target.getEntryPoint()
                + " RVA 0x" + Long.toHexString(target.getEntryPoint().getOffset() - 0x400000L));
        int total = 0;
        int decompiled = 0;
        for (Reference r : getReferencesTo(target.getEntryPoint())) {
            if (!(r.getReferenceType().isCall() || r.getReferenceType().isJump())) continue;
            total++;
            Function caller = fm.getFunctionContaining(r.getFromAddress());
            println("   " + r.getFromAddress() + (caller != null
                    ? "  in " + caller.getName()
                    + " (RVA 0x" + Long.toHexString(caller.getEntryPoint().getOffset() - 0x400000L) + ")"
                    : ""));
            if (decompiled < decompileN && caller != null) {
                DecompileResults res = DI.decompileFunction(caller, 240, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    String c = res.getDecompiledFunction().getC();
                    println("   ---- " + caller.getName() + " ----");
                    println(c.length() > maxChars ? c.substring(0, maxChars) + "\n   ... (truncated)" : c);
                }
                decompiled++;
            }
        }
        println("   total references: " + total);
    }

    @Override
    public void run() throws Exception {
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);
        callers(0x873368L, "solve driver FUN_00873368", 2, 5000);
        callers(0x873638L, "analysis dispatch FUN_00873638", 2, 4000);
        println("");
        println("==== done ====");
    }
}
