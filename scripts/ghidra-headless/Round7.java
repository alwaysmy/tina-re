// Ghidra headless post-script (round 7): find consumers of the pipeline strings and helpers.
//  A) scan code for immediate loads of 0x98FABC / 0x98FAA0 / 0x98FAD0 (B8/68 encodings) -> decompile consumers
//  B) decompile TStream-family helpers + function containing 0x55cc8 + digest staging helpers
//  C) dump the 40B key string region
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.LinkedHashSet;
import java.util.Set;

public class Round7 extends GhidraScript {
    private void ensureFunction(FunctionManager fm, Address addr) {
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                println("[disasm warn] " + addr + " : " + e);
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        }
    }

    private void decompileFn(FunctionManager fm, DecompInterface di, Address addr, String tag) {
        ensureFunction(fm, addr);
        Function f = fm.getFunctionContaining(addr);
        if (f == null) {
            println("[decomp] no function at " + addr);
            return;
        }
        println("");
        println("==== [" + tag + "] " + f.getName() + " @" + f.getEntryPoint() + " ====");
        DecompileResults r = di.decompileFunction(f, 240, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("[decomp fail] " + (r == null ? "null" : r.getErrorMessage()));
        }
    }

    private void scanImmediate(Memory mem, long targetVa) throws Exception {
        byte[] t = new byte[]{
            (byte) (targetVa & 0xFF), (byte) ((targetVa >> 8) & 0xFF),
            (byte) ((targetVa >> 16) & 0xFF), (byte) ((targetVa >> 24) & 0xFF)
        };
        byte[][] pats = new byte[][]{{(byte) 0xB8, t[0], t[1], t[2], t[3]}, {(byte) 0x68, t[0], t[1], t[2], t[3]}};
        println("");
        println("######## immediate-load scan for 0x" + Long.toHexString(targetVa) + " ########");
        Set<Long> hitFns = new LinkedHashSet<>();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.getStart().getOffset() < 0x401000L || block.getStart().getOffset() > 0xA0C000L) {
                continue;
            }
            long size = block.getSize();
            int chunk = 0x100000;
            byte[] buf = new byte[chunk + 5];
            for (long off = 0; off < size; off += chunk) {
                int n = (int) Math.min(chunk + 5, size - off);
                Address start = block.getStart().add(off);
                try {
                    mem.getBytes(start, buf, 0, n);
                } catch (Exception e) {
                    continue;
                }
                for (int i = 0; i + 5 <= n; i++) {
                    for (byte[] p : pats) {
                        boolean hit = true;
                        for (int j = 0; j < 5; j++) {
                            if (buf[i + j] != p[j]) {
                                hit = false;
                                break;
                            }
                        }
                        if (hit) {
                            Address a = start.add(i);
                            Function f = getFunctionContaining(a);
                            println("  hit @ " + a + "  fn=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                            if (f != null) {
                                hitFns.add(f.getEntryPoint().getOffset());
                            }
                        }
                    }
                }
            }
        }
        for (long fn : hitFns) {
            decompileFn(currentProgram.getFunctionManager(), DI, toAddr(fn), "consumer of 0x" + Long.toHexString(targetVa));
        }
    }

    private DecompInterface DI;

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        DI = new DecompInterface();
        DI.toggleCCode(true);
        DI.openProgram(currentProgram);

        scanImmediate(currentProgram.getMemory(), 0x98FABCL);  // "BlowFish"
        scanImmediate(currentProgram.getMemory(), 0x98FAA0L);  // "<Encrypted Library>"
        scanImmediate(currentProgram.getMemory(), 0x98FAD0L);  // 40B key string

        // function containing 0x55cc8 ("0x15cc8 buffer init" from notes)
        Address cc8 = toAddr(0x55cc8L);
        Function f = fm.getFunctionContaining(cc8);
        println("");
        println("[info] function containing VA 0055cc8: " + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));

        long[] misc = {0x55cc8L, 0x40cb88L, 0x40ce28L, 0x427934L, 0x55ac38L, 0x55ac58L};
        for (long va : misc) {
            decompileFn(fm, DI, toAddr(va), "misc");
        }

        // dump key string region
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            sb.append(String.format("%02x ", getByte(toAddr(0x98FAD0L + i)) & 0xFF));
        }
        println("");
        println("dump VA 0098fad0 (64B): " + sb);
        StringBuilder asc = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            int b = getByte(toAddr(0x98FAD0L + i)) & 0xFF;
            asc.append(b >= 32 && b < 127 ? (char) b : '.');
        }
        println("ascii: " + asc);

        println("");
        println("==== done ====");
    }
}
