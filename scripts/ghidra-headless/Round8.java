// Ghidra headless post-script (round 8): batch-rename key functions (persisted) + dump wiring globals.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class Round8 extends GhidraScript {
    private void ensureFunction(FunctionManager fm, Address addr) {
        if (fm.getFunctionContaining(addr) == null) {
            try {
                disassemble(addr);
            } catch (Exception e) {
                // ignore
            }
            new CreateFunctionCmd(addr).applyTo(currentProgram, monitor);
        }
    }

    private void renameRva(FunctionManager fm, long rva, String name) {
        Address addr = toAddr(0x400000L + rva);
        ensureFunction(fm, addr);
        Function f = fm.getFunctionAt(addr);
        if (f == null) {
            println("[rename] no function at " + addr + " for " + name);
            return;
        }
        try {
            f.setName(name, SourceType.USER_DEFINED);
            println("[rename] " + addr + " -> " + name);
        } catch (Exception e) {
            println("[rename] fail " + addr + " -> " + name + " : " + e);
        }
    }

    private void dump(long va, int len, String label) {
        StringBuilder sb = new StringBuilder();
        StringBuilder asc = new StringBuilder();
        try {
            for (int i = 0; i < len; i++) {
                int b = getByte(toAddr(va + i)) & 0xFF;
                sb.append(String.format("%02x ", b));
                asc.append(b >= 32 && b < 127 ? (char) b : '.');
            }
        } catch (Exception e) {
            sb.append("<err>");
        }
        println("dump " + label + " VA " + String.format("%08x", va) + " (" + len + "B): " + sb);
        println("  ascii: " + asc);
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();

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
            renameRva(fm, (Long) row[0], (String) row[1]);
        }

        println("");
        dump(0xA28B64L, 16, "global");
        dump(0xA1A0BCL, 16, "global");
        dump(0xA64318L, 8, "global(seed ptr var)");
        dump(0xA65164L, 8, "global(fnptr?)");
        dump(0xA63EB8L, 8, "global");
        dump(0xA1293CL, 16, "CST/P8 area");
        dump(0xA12B3CL, 16, "IDX");

        // follow seed pointer variable if readable
        try {
            long p = getInt(toAddr(0xA64318L)) & 0xFFFFFFFFL;
            println("seed ptr value = " + String.format("0x%08x", p));
            if (p > 0x400000 && p < 0xA30000) {
                dump(p, 16, "seed buffer contents");
            }
        } catch (Exception e) {
            println("seed ptr read fail: " + e);
        }

        println("");
        println("==== done ====");
    }
}
