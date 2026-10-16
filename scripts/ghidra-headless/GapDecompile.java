// Ghidra headless post-script: create missing (indirectly-called) functions and decompile them.
// Run: analyzeHeadless <projdir> <projname> -process tina_unpacked_fixed.exe -noanalysis -postScript GapDecompile.java
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class GapDecompile extends GhidraScript {
    private static final long BASE = 0x400000L;

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

    private void dumpBlock(long va, int count) {
        println("");
        println("==== memory block @ VA 0x" + Long.toHexString(va) + " (" + count + " dwords) ====");
        for (int i = 0; i < count; i++) {
            Address a = toAddr(va + (long) i * 4);
            try {
                long v = getInt(a) & 0xFFFFFFFFL;
                println(String.format("  [+0x%02x] = 0x%08x", i * 4, v));
            } catch (Exception e) {
                println(String.format("  [+0x%02x] = <unreadable>", i * 4));
            }
        }
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);

        long[] rvas = {
                0x570c2cL,  // factory helper (class selection?)
                0x559698L,  // classref setter called by base ctor
                0x55c9acL, 0x55c9b4L, 0x55ca24L, 0x55ca2cL, 0x55ca3cL,  // THash +0x20..+0x30 (key pipeline)
                0x56aeb4L, 0x56aee8L,  // TCipher_TEA +0x1c / +0x20
                0x56ab5cL, 0x56ac68L,  // TCipher_TEA +0x00 / +0x04
                0x56a4b8L, 0x56a4f8L, 0x56a3d4L, 0x56ad74L  // block odds
        };
        for (long rva : rvas) {
            decompileRva(fm, di, rva);
        }

        dumpBlock(0x55b5b8L, 24);   // scheduler class ref (from PTR_PTR_0055b56c)
        dumpBlock(0x56a43cL, 40);   // TCipher_TEA block (extended view)

        println("");
        println("==== done ====");
    }
}
