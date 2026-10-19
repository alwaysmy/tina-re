// Round 23: find code sites comparing against TINA analysis command IDs.
// Goal: locate the WM_COMMAND dispatch that routes 0xA0..0xAB (DC/AC/TRAN).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Round23 extends GhidraScript {
    private static final long[] IDS = {0xA0, 0xA1, 0xA2, 0xA3, 0xA5, 0xA6, 0xA7, 0xAB, 0xAC};

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Function, List<String>> hits = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            String mnemonic = ins.getMnemonicString();
            if (!(mnemonic.equalsIgnoreCase("CMP") || mnemonic.equalsIgnoreCase("SUB"))) {
                continue;
            }
            for (int op = 0; op < ins.getNumOperands(); op++) {
                if ((ins.getOperandType(op) & OperandType.SCALAR) == 0) {
                    continue;
                }
                Scalar sc = ins.getScalar(op);
                if (sc == null) {
                    continue;
                }
                long v = sc.getUnsignedValue();
                boolean match = false;
                for (long id : IDS) {
                    if (v == id) {
                        match = true;
                        break;
                    }
                }
                if (!match) {
                    continue;
                }
                Function f = fm.getFunctionContaining(ins.getAddress());
                if (f == null) {
                    continue;
                }
                hits.computeIfAbsent(f, k -> new ArrayList<>())
                        .add(String.format("%s  cmp 0x%02x", ins.getAddress(), v));
                break;
            }
        }

        println("functions with analysis-ID comparisons: " + hits.size());
        for (Map.Entry<Function, List<String>> e : hits.entrySet()) {
            Function f = e.getKey();
            println("");
            println("FUNC " + f.getName() + " @" + f.getEntryPoint()
                    + " (RVA 0x" + Long.toHexString(f.getEntryPoint().getOffset() - 0x400000L)
                    + ") hits=" + e.getValue().size());
            for (String s : e.getValue()) {
                println("    " + s);
            }
        }
        println("");
        println("==== done ====");
    }
}
