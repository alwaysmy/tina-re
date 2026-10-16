// Ghidra headless post-script (round 10): resolve pipeline class VMT + callers of key wiring points.
//  A) dumps: 0x569E50..0x569EC8 (claimed TCipher_Blowfish VMT area), 0x55B8E8.. (THash VMT candidate from 0xA1A0BC)
//  B) xrefs: DEC_CipherSetKey(0x56adfc), DEC_CipherCreate(0x56acd8), TSC_DecryptEntry(0x571084), TSC_CipherFactory(0x570bfc)
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;

public class Round10 extends GhidraScript {
    private DecompInterface DI;

    private void dump(long va, int len, String label) {
        StringBuilder sb = new StringBuilder();
        println("[dump] " + label + " @ " + String.format("%08x", va));
        for (int i = 0; i < len; i += 4) {
            long v;
            try {
                v = getInt(toAddr(va + i)) & 0xFFFFFFFFL;
            } catch (Exception e) {
                v = -1;
            }
            println(String.format("   +0x%02x = %08x", i, v));
        }
    }

    private void xrefs(long va, String label) {
        println("");
        println("==== xrefs to " + label + " (VA " + String.format("%08x", va) + ") ====");
        Reference[] refs = getReferencesTo(toAddr(va));
        int n = 0;
        for (Reference r : refs) {
            if (n++ > 80) {
                println("  ...");
                break;
            }
            Function f = getFunctionContaining(r.getFromAddress());
            println("  " + r.getFromAddress() + " (" + r.getReferenceType() + ")"
                    + (f != null ? "  in " + f.getName() : ""));
        }
        if (n == 0) {
            println("  <none>");
        }
    }

    private void decompileFn(FunctionManager fm, Address addr, String tag) {
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                // ignore
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        }
        Function f = fm.getFunctionContaining(addr);
        if (f == null) {
            println("[decomp] none at " + addr);
            return;
        }
        println("");
        println("==== [" + tag + "] " + f.getName() + " @" + f.getEntryPoint() + " ====");
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

        dump(0x569E30L, 0x98, "Blowfish class region (VMT candidate @ 0x569E88)");
        dump(0x55B8E8L, 0xA8, "THash VMT candidate region (from 0xA1A0BC=0x55B910)");

        xrefs(0x56ADFCL, "DEC_CipherSetKey");
        xrefs(0x56ACD8L, "DEC_CipherCreate");
        xrefs(0x571084L, "TSC_DecryptEntry");
        xrefs(0x570BFCL, "TSC_CipherFactory");

        // decompile callers of the decrypt entry (who supplies streams/size)
        Reference[] refs = getReferencesTo(toAddr(0x571084L));
        for (Reference r : refs) {
            if (r.getReferenceType().isCall() || r.getReferenceType().isJump()) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) {
                    decompileFn(fm, f.getEntryPoint(), "caller of TSC_DecryptEntry");
                }
            }
        }

        println("");
        println("==== done ====");
    }
}
