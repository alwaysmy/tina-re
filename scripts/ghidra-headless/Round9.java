// Ghidra headless post-script (round 9, corrected):
// 1) remove the 30 junk functions created at wrong (VA+0x400000) addresses by round 8
// 2) apply the intended renames at the CORRECT addresses (VA space)
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class Round9 extends GhidraScript {
    private void removeAt(long va) {
        Address addr = toAddr(va);
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (f == null) {
            println("[cleanup] none at " + String.format("%08x", va));
            return;
        }
        println("[cleanup] removing " + f.getName() + " @" + f.getEntryPoint());
        try {
            currentProgram.getFunctionManager().removeFunction(addr);
        } catch (Throwable t) {
            println("[cleanup] fail: " + t);
        }
    }

    private void ensureFunction(Address addr) {
        FunctionManager fm = currentProgram.getFunctionManager();
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                // ignore
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        }
    }

    private void renameVa(long va, String name) {
        Address addr = toAddr(va);
        ensureFunction(addr);
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (f == null) {
            println("[rename] no function at " + String.format("%08x", va) + " for " + name);
            return;
        }
        try {
            f.setName(name, SourceType.USER_DEFINED);
            println("[rename] " + String.format("%08x", va) + " -> " + name);
        } catch (Exception e) {
            println("[rename] fail " + String.format("%08x", va) + " -> " + name + " : " + e);
        }
    }

    @Override
    public void run() throws Exception {
        // 1) cleanup junk from round 8
        long[] junk = {
            0x971084L, 0x970bfcL, 0x970c2cL, 0x96acd8L, 0x96adfcL, 0x96d010L, 0x96b034L,
            0x9599c0L, 0x959b58L, 0x959af0L, 0x95cbf0L, 0x95cc50L, 0x95cc28L, 0x95a854L,
            0x95a720L, 0x96cf18L, 0x96cef8L, 0x96bd38L, 0x96ab5cL, 0x96ac68L, 0x96aeb4L,
            0x96aee8L, 0x96ad74L, 0x96708cL, 0x96755cL, 0x96710cL, 0x967610L, 0x966650L,
            0x966960L, 0x966c9cL
        };
        for (long va : junk) {
            removeAt(va);
        }

        // 2) correct renames (VA space)
        Object[][] names = {
            {0x571084L, "TSC_DecryptEntry"},
            {0x570bfcL, "TSC_CipherFactory"},
            {0x570c2cL, "TSC_GetAuxObject"},
            {0x56acd8L, "DEC_CipherCreate"},
            {0x56adfcL, "DEC_CipherSetKey"},
            {0x56d010L, "DEC_CipherInitKey"},
            {0x56b034L, "DEC_ModeEngine"},
            {0x5597f8L, "DEC_DoStream"},
            {0x5599c0L, "DEC_DoStreamStrings"},
            {0x559b58L, "DEC_DoCipherString"},
            {0x559af0L, "DEC_DoBuffer"},
            {0x55cbf0L, "DEC_HashDriver_Begin"},
            {0x55cc50L, "DEC_HashDriver_Process"},
            {0x55cc28L, "DEC_HashDriver_End"},
            {0x55a854L, "memxor"},
            {0x55a720L, "ClassCheck"},
            {0x55ac38L, "LCG32_Keystream"},
            {0x55ac58L, "RandSeed"},
            {0x56cf18L, "TCipher_TEA_GetParams"},
            {0x56cf34L, "TCipher_TEA_GetBlobPtr"},
            {0x56cf5cL, "TCipher_TEA_EncryptBlock"},
            {0x56cfb4L, "TCipher_TEA_DecryptBlock"},
            {0x56cef8L, "DEC_setRounds_clamp"},
            {0x56bd38L, "TCipher_Blowfish_GetParams"},
            {0x56bd54L, "TCipher_Blowfish_GetBlobPtr"},
            {0x56be80L, "TCipher_Blowfish_EncryptBlock"},
            {0x56bef0L, "TCipher_Blowfish_DecryptBlock"},
            {0x56bf5cL, "TCipher_Blowfish_InitKey"},
            {0x56ab5cL, "DEC_SetFlag"},
            {0x56ac68L, "DEC_SetBlock"},
            {0x56aeb4L, "DEC_CmpCopyBlock"},
            {0x56aee8L, "DEC_ClearBuffers"},
            {0x56ad74L, "DEC_CipherDestroy"},
            {0x56708cL, "THash_Haval_Init"},
            {0x56755cL, "THash_Haval_Update"},
            {0x56710cL, "THash_Haval_Final"},
            {0x567610L, "THash_Haval_GetDigestPtr"},
            {0x567084L, "THash_Haval256_GetDigestSize"},
            {0x567644L, "THash_Haval224_GetDigestSize"},
            {0x566650L, "THash_Haval_SetPasses"},
            {0x5666d0L, "Haval_v3_Compress"},
            {0x566960L, "Haval_v4_Compress"},
            {0x566c9cL, "Haval_v5_Compress"},
            {0x57112cL, "Delphi_UnitInit_0x57112c_stub"},
        };
        for (Object[] row : names) {
            renameVa((Long) row[0], (String) row[1]);
        }

        println("");
        println("==== done ====");
    }
}
