// Ghidra headless post-script (round 11): the cipher-side Begin/Process/End trio + RipeMD320 methods.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round11 extends GhidraScript {
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
        DecompileResults r = DI.decompileFunction(f, 240, monitor);
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

        decompileVa(fm, 0x56B844L, "TCipher vtable +0x00");
        decompileVa(fm, 0x56B924L, "TCipher vtable +0x04");
        decompileVa(fm, 0x56B95CL, "TCipher vtable +0x08 = Process(buf,len,mode)");

        decompileVa(fm, 0x562A04L, "THash_RipeMD320 +0x20 (Init?)");
        decompileVa(fm, 0x55D6BCL, "THash_RipeMD320 +0x24 (Update?)");
        decompileVa(fm, 0x55D624L, "THash_RipeMD320 +0x28 (Final?)");
        decompileVa(fm, 0x55D5B0L, "THash_RipeMD320 +0x2C");

        println("");
        println("==== done ====");
    }
}
