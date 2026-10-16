// Ghidra headless post-script (round 3):
// 1) remove junk functions created over data at 0x56a4b8 / 0x56a4f8 / 0x56a3d4
// 2) scan memory for class-name shortstrings (TCipher_*, THash*) and dump surrounding VMT-like pointer arrays
// Run: analyzeHeadless <projdir> <projname> -process tina_unpacked_fixed.exe -noanalysis \
//      -scriptPath <this dir> -postScript ScanClasses.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.nio.charset.StandardCharsets;

public class ScanClasses extends GhidraScript {
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

    private int readByteSafe(Address a) {
        try {
            return getByte(a) & 0xFF;
        } catch (Exception e) {
            return -1;
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
                        dumpNameAndVmt(start.add(i));
                    }
                }
            }
        }
    }

    private void dumpNameAndVmt(Address nameAddr) {
        Address lenAddr = nameAddr.subtract(1);
        String name = readShortString(lenAddr);
        int nameLen = readByteSafe(lenAddr);
        if (nameLen < 0 || nameLen > 64) {
            nameLen = 0;
        }
        println("");
        println("== NAME @ " + nameAddr + " = \"" + name + "\" ==");

        // walk back while dwords point into code
        Address q = nameAddr.subtract(4);
        int count = 0;
        while (count < 48) {
            long v = readIntSafe(q);
            if (v < 0 || !inCode(v)) {
                break;
            }
            q = q.subtract(4);
            count++;
        }
        Address vmt = q.add(4);
        println("  VMT-candidate start = " + vmt + " (" + count + " code-ptrs before name)");
        for (int i = 0; i < count; i++) {
            long v = readIntSafe(vmt.add((long) i * 4));
            println(String.format("    [%08x +0x%02x] = %08x", vmt.getOffset(), i * 4, v));
        }
        // forward tail (VMT metadata: instance size, parent, runtime vtables ...)
        for (int i = 0; i < 20; i++) {
            long off = (long) (nameLen + 1) + (long) i * 4;
            long v = readIntSafe(nameAddr.add(off));
            println(String.format("    [name+%02x] = %08x", off, v));
        }
    }

    private void removeJunk(FunctionManager fm, long va) {
        Address addr = toAddr(va);
        Function f = fm.getFunctionAt(addr);
        if (f == null) {
            println("[cleanup] no function at " + addr);
            return;
        }
        println("[cleanup] removing " + f.getName() + " @" + f.getEntryPoint());
        try {
            fm.removeFunction(addr);
        } catch (Throwable t) {
            println("[cleanup] failed: " + t);
        }
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        removeJunk(fm, 0x56a4b8L);
        removeJunk(fm, 0x56a4f8L);
        removeJunk(fm, 0x56a3d4L);

        Memory mem = currentProgram.getMemory();
        scanName(mem, "TCipher_");
        scanName(mem, "THash");

        println("");
        println("==== done ====");
    }
}
