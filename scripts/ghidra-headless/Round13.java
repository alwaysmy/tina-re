// Ghidra headless post-script (round 13): delegate getter + RMD320 init immediates + SetKey helpers.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Round13 extends GhidraScript {
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

    private void disasmVa(long va, int limit) {
        println("");
        println("==== disasm VA " + String.format("%08x", va) + " ====");
        Address addr = toAddr(va);
        try {
            disassemble(addr);
        } catch (Exception e) {
            // ignore
        }
        for (int i = 0; i < limit; i++) {
            ghidra.program.model.listing.Instruction ins = getInstructionAt(addr);
            if (ins == null) {
                println("  <no instruction>");
                break;
            }
            println("  " + ins.getAddress() + "  " + ins.toString());
            addr = ins.getNext().getAddress();
        }
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        decompileVa(fm, 0x559634L, "delegate getter FUN_00559634");
        decompileVa(fm, 0x56AB78L, "length fixup FUN_0056ab78");
        decompileVa(fm, 0x5595CCL, "FUN_005595cc (neighbor)");
        disasmVa(0x562A04L, 40);   // RMD320 init immediates

        println("");
        println("==== done ====");
    }
}
