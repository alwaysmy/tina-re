// Diagnostic: function distribution across the address space.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

import java.util.TreeMap;

public class Round15b extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        println("function count (getFunctionCount) = " + fm.getFunctionCount());
        println("memory min/max = " + currentProgram.getMinAddress() + " / " + currentProgram.getMaxAddress());
        println("toAddr(0058f851) = " + toAddr(0x58F851L) + " space=" + toAddr(0x58F851L).getAddressSpace().getName());
        println("function containing 0058f851 = " + fm.getFunctionContaining(toAddr(0x58F851L)));

        TreeMap<Long, Integer> bins = new TreeMap<>();
        FunctionIterator it = fm.getFunctions(true);
        int n = 0;
        while (it.hasNext()) {
            Function f = it.next();
            long entry = f.getEntryPoint().getOffset();
            long bin = entry & ~0xFFFFFL; // 1MB bins
            bins.merge(bin, 1, Integer::sum);
            if (n < 8) {
                println("  sample: " + f.getEntryPoint() + "  " + f.getName() + "  body=" + f.getBody().getNumAddresses());
            }
            n++;
        }
        println("iterated = " + n);
        println("bins (1MB):");
        for (var e : bins.entrySet()) {
            println(String.format("  0x%07x : %d", e.getKey(), e.getValue()));
        }
    }
}
