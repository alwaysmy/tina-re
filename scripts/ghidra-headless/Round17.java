// Ghidra headless post-script (round 17, Phase 3): corrected engine-region survey (VA space).
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class Round17 extends GhidraScript {
    private DecompInterface DI;

    private List<Function> region(String label, long rvaLo, long rvaHi) {
        FunctionManager fm = currentProgram.getFunctionManager();
        long lo = 0x400000L + rvaLo;
        long hi = 0x400000L + rvaHi;
        AddressSet set = new AddressSet(toAddr(lo), toAddr(hi - 1));
        FunctionIterator it = fm.getFunctions(set, true);
        int count = 0;
        long bytes = 0;
        List<Function> funcs = new ArrayList<>();
        while (it.hasNext()) {
            Function f = it.next();
            count++;
            bytes += f.getBody().getNumAddresses();
            funcs.add(f);
        }
        println(String.format("[region] %-24s RVA 0x%06x-0x%06x  functions=%d  body=%.1f KB",
                label, rvaLo, rvaHi, count, bytes / 1024.0));
        funcs.sort(Comparator.comparingLong((Function f) -> f.getBody().getNumAddresses()).reversed());
        int shown = 0;
        for (Function f : funcs) {
            if (shown >= 5) break;
            println(String.format("    big: %s (RVA 0x%06x) %s  body=%d",
                    f.getEntryPoint(), f.getEntryPoint().getOffset() - 0x400000L, f.getName(),
                    f.getBody().getNumAddresses()));
            shown++;
        }
        return funcs;
    }

    private void decompile(Function f, String tag, int maxChars) {
        if (f == null) return;
        println("");
        println("==== [" + tag + "] " + f.getName() + " @" + f.getEntryPoint() + " body=" + f.getBody().getNumAddresses() + " ====");
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
        FunctionManager fm = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        println("total functions = " + fm.getFunctionCount());

        region("crypto/protection", 0x159000L, 0x16F000L);
        List<Function> solver = region("solver core", 0x177000L, 0x186000L);
        List<Function> la = region("linear algebra", 0x2E7000L, 0x2EA000L);
        region("analysis orchestration", 0x330000L, 0x350000L);
        region("library loader (0x58Fxxx)", 0x58F000L, 0x592000L);

        if (!solver.isEmpty()) decompile(solver.get(0), "largest in solver core", 7000);
        if (!la.isEmpty()) decompile(la.get(0), "largest in linear algebra", 5000);

        println("");
        println("==== done ====");
    }
}
