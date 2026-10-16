// Ghidra headless post-script (round 6): target the open "G generator layering" route.
//  - full decompile of mode engine FUN_0056b034 (all cases, incl. mode 5)
//  - THash family helpers 0x55cbf0 / 0x55cc28 / 0x55cc50
//  - Haval version selector 0x166650 + v3 scheduler 0x1666d0 (verification vs static_g.py)
//  - xrefs to 'BlowFish'/'<Encrypted Library>' strings and to 0x55b326 (static keystream staging)
//  - raw dumps of candidate table/blob regions for cross-check
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

public class Round6 extends GhidraScript {
    private void ensureFunction(FunctionManager fm, Address addr) {
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                println("[disasm warn] " + addr + " : " + e);
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
            boolean ok = cmd.applyTo(currentProgram, monitor);
            println("[create] " + addr + " ok=" + ok);
        }
    }

    private void decompileRva(FunctionManager fm, DecompInterface di, long rva) {
        Address addr = toAddr(0x400000L + rva);
        ensureFunction(fm, addr);
        Function f = fm.getFunctionContaining(addr);
        println("");
        println("==== RVA 0x" + Long.toHexString(rva) + " VA " + addr + " : "
                + (f == null ? "<no function>" : f.getName() + " @" + f.getEntryPoint()) + " ====");
        if (f == null) {
            return;
        }
        DecompileResults r = di.decompileFunction(f, 240, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decomp fail] " + (r == null ? "null result" : r.getErrorMessage()));
        }
    }

    private void xrefs(long va) {
        Address a = toAddr(va);
        println("");
        println("==== xrefs to VA " + a + " ====");
        Reference[] refs = getReferencesTo(a);
        int n = 0;
        for (Reference r : refs) {
            if (n++ > 60) {
                println("  ... more");
                break;
            }
            Function f = getFunctionContaining(r.getFromAddress());
            println("  from " + r.getFromAddress() + " (" + r.getReferenceType() + ")"
                    + (f != null ? "  in " + f.getName() : ""));
        }
        if (n == 0) {
            println("  <none>");
        }
    }

    private void dump(long rva, int len) {
        Address a = toAddr(0x400000L + rva);
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < len; i++) {
                sb.append(String.format("%02x ", getByte(a.add(i)) & 0xFF));
            }
        } catch (Exception e) {
            sb.append("<err ").append(e).append(">");
        }
        println("dump RVA 0x" + Long.toHexString(rva) + " (" + len + "B): " + sb);
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);

        decompileRva(fm, di, 0x16b034L);          // mode engine (all cases)
        decompileRva(fm, di, 0x15cbf0L);
        decompileRva(fm, di, 0x15cc28L);
        decompileRva(fm, di, 0x15cc50L);
        decompileRva(fm, di, 0x166650L);          // Haval version selector
        decompileRva(fm, di, 0x1666d0L);          // Haval v3 scheduler

        xrefs(0x98FABC);   // "BlowFish"
        xrefs(0x98FAA0);   // "<Encrypted Library>"
        xrefs(0x55B326);   // static keystream staging area

        dump(0x61293cL, 48);
        dump(0x612b3cL, 32);
        dump(0x56662eL, 48);
        dump(0x567626L, 48);
        dump(0x55b326L, 64);

        println("");
        println("==== done ====");
    }
}
