// Ghidra headless post-script (round 2b):
// 1) remove junk functions accidentally created at wrong addresses (VA double-based),
// 2) decompile the corrected target list (RVA space, base 0x400000).
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class CleanupDecomp extends GhidraScript {
    private static final long BASE = 0x400000L;

    private void removeJunk(FunctionManager fm, long va) {
        Address addr = toAddr(va);
        Function f = fm.getFunctionAt(addr);
        if (f == null) {
            println("[cleanup] no function at " + addr);
            return;
        }
        AddressSet body = new AddressSet(f.getBody());
        println("[cleanup] removing " + f.getName() + " @" + f.getEntryPoint() + " body=" + body);
        try {
            fm.removeFunction(addr);
            println("[cleanup] removed.");
        } catch (Throwable t) {
            println("[cleanup] removeFunction failed: " + t);
        }
    }

    private void ensureFunction(FunctionManager fm, Address addr) {
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                println("[disasm warn] " + addr + " : " + e);
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
            boolean ok = cmd.applyTo(currentProgram, monitor);
            println("[create] " + addr + " ok=" + ok + " status=" + cmd.getStatusMsg());
        }
    }

    private void decompileRva(FunctionManager fm, DecompInterface di, long rva) {
        Address addr = toAddr(BASE + rva);
        ensureFunction(fm, addr);
        Function f = fm.getFunctionContaining(addr);
        println("");
        println("==== RVA 0x" + Long.toHexString(rva) + " VA " + addr + " : "
                + (f == null ? "<no function>" : f.getName() + " @" + f.getEntryPoint()) + " ====");
        if (f == null) {
            return;
        }
        DecompileResults r = di.decompileFunction(f, 120, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decomp fail] " + (r == null ? "null result" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();

        // ---- 1) cleanup junk from the previous (buggy) run ----
        long[] junk = {
                0x970c2cL, 0x959698L, 0x95c9acL, 0x95c9b4L, 0x95ca24L, 0x95ca2cL,
                0x95ca3cL, 0x96aeb4L, 0x96aee8L, 0x96ab5cL, 0x96ac68L, 0x96a4b8L,
                0x96a4f8L, 0x96a3d4L, 0x96ad74L
        };
        for (long va : junk) {
            removeJunk(fm, va);
        }

        // ---- 2) corrected decompile list (RVA) ----
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);

        long[] rvas = {
                0x170c2cL,                                  // factory helper
                0x159698L,                                  // classref setter / base
                0x1597f8L, 0x1599c0L, 0x159b58L, 0x159af0L, // shared base virtuals (编排)
                0x15c9acL, 0x15c9b4L, 0x15ca24L, 0x15ca2cL, 0x15ca3cL, // THash +0x20..+0x30
                0x16aeb4L, 0x16aee8L,                       // TCipher_TEA +0x1c / +0x20
                0x16ab5cL, 0x16ac68L,                       // TCipher_TEA +0x00 / +0x04
                0x16a4b8L, 0x16a4f8L, 0x16a3d4L, 0x16ad74L  // block odds
        };
        for (long rva : rvas) {
            decompileRva(fm, di, rva);
        }

        println("");
        println("==== done ====");
    }
}
