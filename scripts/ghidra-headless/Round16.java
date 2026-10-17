// Ghidra headless post-script (round 16, Phase 3 survey): engine inventory.
//  A) region function statistics + largest functions per region
//  B) netlist-compile checkpoint (0x58F851) container + its callers
//  C) external imports sample
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class Round16 extends GhidraScript {
    private DecompInterface DI;

    private void regionStats(String label, long lo, long hi) {
        FunctionManager fm = currentProgram.getFunctionManager();
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
        println(String.format("[region] %-26s 0x%06x-0x%06x  functions=%d  body=%.1f KB",
                label, lo, hi, count, bytes / 1024.0));
        funcs.sort(Comparator.comparingLong((Function f) -> f.getBody().getNumAddresses()).reversed());
        int shown = 0;
        for (Function f : funcs) {
            if (shown >= 6) {
                break;
            }
            println(String.format("    big: %s  %s  body=%d", f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses()));
            shown++;
        }
    }

    private void decompileVa(long va, String tag, int maxChars) {
        Address addr = toAddr(va);
        FunctionManager fm = currentProgram.getFunctionManager();
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
        println("==== [" + tag + "] " + (f == null ? "<none>" : f.getName() + " @" + f.getEntryPoint()
                + " body=" + f.getBody().getNumAddresses()) + " ====");
        if (f == null) {
            return;
        }
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

        regionStats("crypto/protection", 0x159000L, 0x16F000L);
        regionStats("solver core", 0x177000L, 0x186000L);
        regionStats("linear algebra", 0x2E7000L, 0x2EA000L);
        regionStats("analysis orchestration", 0x330000L, 0x350000L);
        regionStats("whole code section", 0x401000L, 0xA0C000L);

        decompileVa(0x58F851L, "netlist compile checkpoint", 9000);
        Function f = fm.getFunctionContaining(toAddr(0x58F851L));
        if (f != null) {
            println("");
            println("== callers of " + f.getName() + " @" + f.getEntryPoint() + " ==");
            int shown = 0;
            int total = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                if (!(r.getReferenceType().isCall() || r.getReferenceType().isJump())) {
                    continue;
                }
                total++;
                Function caller = fm.getFunctionContaining(r.getFromAddress());
                if (total <= 8) {
                    println("   " + r.getFromAddress() + (caller != null ? "  in " + caller.getName() : ""));
                }
                if (shown < 1 && caller != null) {
                    decompileVa(caller.getEntryPoint().getOffset(), "caller of compile checkpoint", 5000);
                    shown++;
                }
            }
            println("   total callers: " + total);
        }

        println("");
        println("== external symbols (imports) sample ==");
        SymbolIterator syms = currentProgram.getSymbolTable().getExternalSymbols();
        int n = 0;
        while (syms.hasNext() && n < 30) {
            Symbol s = syms.next();
            println("   " + s.getName(true));
            n++;
        }
        if (n == 0) {
            println("   <none in symbol table>");
        }

        println("");
        println("==== done ====");
    }
}
