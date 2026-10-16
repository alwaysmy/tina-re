// Ghidra headless post-script (round 4):
// A) corrected class scan: for each TCipher_*/THash* name, dump the 9-slot method array (align-fixed)
// B) decompile the TCipher_Blowfish class-specific slots + factory helpers
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.charset.StandardCharsets;

public class Round4 extends GhidraScript {
    private static final long CODE_LO = 0x401000L;
    private static final long CODE_HI = 0xA0C000L;

    private boolean inCode(long v) {
        return v >= CODE_LO && v < CODE_HI;
    }

    private long readIntSafe(Address a) {
        try {
            return getInt(a) & 0xFFFFFFFFL;
        } catch (Exception e) {
            return -1L;
        }
    }

    private String readShortString(Address a) {
        try {
            int len = getByte(a) & 0xFF;
            if (len <= 0 || len > 64) {
                return "<len=" + len + ">";
            }
            byte[] buf = new byte[len];
            currentProgram.getMemory().getBytes(a.add(1), buf);
            return new String(buf, StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return "<err>";
        }
    }

    private void scanName(Memory mem, String needle) throws Exception {
        byte[] pat = needle.getBytes(StandardCharsets.US_ASCII);
        println("");
        println("######## scanning for \"" + needle + "\" ########");
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            long size = block.getSize();
            int chunk = 0x100000;
            byte[] buf = new byte[chunk + pat.length];
            for (long off = 0; off < size; off += chunk) {
                int n = (int) Math.min(chunk + pat.length, size - off);
                Address start = block.getStart().add(off);
                try {
                    mem.getBytes(start, buf, 0, n);
                } catch (Exception e) {
                    continue;
                }
                for (int i = 0; i + pat.length <= n; i++) {
                    boolean hit = true;
                    for (int j = 0; j < pat.length; j++) {
                        if (buf[i + j] != pat[j]) {
                            hit = false;
                            break;
                        }
                    }
                    if (hit) {
                        dumpClassName(start.add(i));
                    }
                }
            }
        }
    }

    private void dumpClassName(Address nameAddr) {
        String name = readShortString(nameAddr.subtract(1));
        println("");
        println("== " + nameAddr + " \"" + name + "\" ==");
        // method array ends immediately before the 4-aligned length byte
        Address q = nameAddr.subtract(1).subtract(4);
        int count = 0;
        long[] vals = new long[24];
        while (count < 24) {
            long v = readIntSafe(q);
            if (v < 0 || !inCode(v)) {
                break;
            }
            vals[count] = v;
            q = q.subtract(4);
            count++;
        }
        Address arr = q.add(4);
        print("  array @ " + arr + " :");
        for (int i = 0; i < count; i++) {
            if (i % 4 == 0) {
                print("\n    ");
            }
            print(String.format("+%02x=%08x ", i * 4, vals[i]));
        }
        println("");
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
        DecompileResults r = di.decompileFunction(f, 120, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decomp fail] " + (r == null ? "null result" : r.getErrorMessage()));
        }
    }

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        scanName(mem, "TCipher_");
        scanName(mem, "THash");

        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.openProgram(currentProgram);

        // TCipher_Blowfish class-specific slots (from VMT array) + factory helpers
        long[] rvas = {
                0x16bd38L, 0x16bd54L, 0x16be80L, 0x16bef0L, 0x16bf5cL,   // Blowfish slots 2..6
                0x16a8b0L, 0x16a8b8L                                     // factory helpers
        };
        for (long rva : rvas) {
            decompileRva(fm, di, rva);
        }
        println("");
        println("==== done ====");
    }
}
