// Ghidra headless post-script (round 15, Phase 3 kickoff): engine region survey.
//  A) function/size statistics for the engine-related regions
//  B) decompile the netlist-compile checkpoint (0x58F851) container + callers
//  C) external symbol (import) inventory sample
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

public class Round15 extends GhidraScript {
    private DecompInterface DI;

    private void regionStats(String label, long lo, long hi) {
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSet set = new AddressSet(toAddr(lo), toAddr(hi - 1));
        FunctionIterator it = fm.getFunctions(set, true);
        int count = 0;
        long bytes = 0;
        while (it.hasNext()) {
            Function f = it.next();
            count++;
            bytes += f.getBody().getNumAddresses();
        }
        println(String.format("[region] %-28s 0x%06x-0x%06x  functions=%d  body=%.1f KB",
                label, lo, hi, count, bytes / 1024.0));
    }

    private void decompileVa(long va, String tag) {
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
        println("==== [" + tag + "] " + (f == null ? "<none>" : f.getName() + " @" + f.getEntryPoint()) + " ====");
        if (f == null) {
            return;
        }
        DecompileResults r = DI.decompileFunction(f, 300, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            String c = r.getDecompiledFunction().getC();
            println(c.length() > 12000 ? c.substring(0, 12000) + "\n... (truncated)" : c);
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

        regionStats("crypto/protection", 0x159000L, 0x16F000L);
        regionStats("solver core", 0x177000L, 0x186000L);
        regionStats("linear algebra", 0x2E7000L, 0x2EA000L);
        regionStats("analysis orchestration", 0x330000L, 0x350000L);
        regionStats("whole image", 0x401000L, 0xA0C000L);

        // netlist compile checkpoint
        decompileVa(0x58F851L, "netlist compile checkpoint");
        Address entry = null;
        Function f = fm.getFunctionContaining(toAddr(0x58F851L));
        if (f != null) {
            entry = f.getEntryPoint();
            println("");
            println("== callers of " + f.getName() + " @" + entry + " ==");
            int shown = 0;
            for (Reference r : getReferencesTo(entry)) {
                if (!(r.getReferenceType().isCall() || r.getReferenceType().isJump())) {
                    continue;
                }
                Function caller = fm.getFunctionContaining(r.getFromAddress());
                println("   " + r.getFromAddress() + (caller != null ? "  in " + caller.getName() : ""));
                if (shown < 2 && caller != null) {
                    decompileVa(caller.getEntryPoint().getOffset(), "caller of compile checkpoint");
                    shown++;
                }
            }
        }

        // imports sample
        println("");
        println("== external symbols (imports) sample ==");
        SymbolIterator syms = currentProgram.getSymbolTable().getExternalSymbols();
        int n = 0;
        while (syms.hasNext() && n < 25) {
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
