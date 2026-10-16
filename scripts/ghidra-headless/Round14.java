// Ghidra headless post-script (round 14): emulate the RMD256 compress function to get golden vectors.
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class Round14 extends GhidraScript {
    private static final long CODE = 0x561588L;     // RMD256 compress(state*, msg*)
    private static final long STATE = 0x1F00000L;   // scratch state buffer
    private static final long MSG = 0x1F01000L;     // scratch message buffer
    private static final long STACK = 0x1F02000L;   // fake stack top
    private static final long RETADDR = 0x1F02004L; // fake return address

    private void runCase(EmulatorHelper emu, String label, long[] init10, byte[] msg) throws Exception {
        // write state (10 words little-endian)
        byte[] st = new byte[40];
        for (int i = 0; i < 10; i++) {
            long v = init10[i];
            for (int b = 0; b < 4; b++) {
                st[i * 4 + b] = (byte) ((v >> (8 * b)) & 0xFF);
            }
        }
        emu.writeMemory(toAddr(STATE + 0x58), st);
        emu.writeMemory(toAddr(MSG), msg);
        // stack: return address = RETADDR marker with HALT-ish value; put a breakpoint there
        emu.writeMemory(toAddr(STACK - 4), new byte[]{(byte) 0xCC, 0, 0, 0});
        emu.writeRegister("ESP", STACK - 4);
        emu.writeRegister("EAX", STATE);
        emu.writeRegister("EDX", MSG);
        emu.writeRegister("EIP", CODE);
        emu.setBreakpoint(toAddr(STACK - 4 + 1));
        boolean hit = emu.run(monitor);
        byte[] out = emu.readMemory(toAddr(STATE + 0x58), 40);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            sb.append(String.format("%02x", out[i]));
        }
        println("CASE " + label + " hit=" + hit + " state40=" + sb);
        println("  err=" + emu.getLastError());
    }

    @Override
    public void run() throws Exception {
        long[] iv = {
            0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L, 0x76543210L,
            0xFEDCBA98L, 0x89ABCDEFL, 0x01234567L, 0x01234567L, 0x3C2D1E0FL
        };
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            byte[] m1 = new byte[64];                       // all zero block
            runCase(emu, "zero-block", iv, m1);
            byte[] m2 = new byte[64];
            for (int i = 0; i < 64; i++) {
                m2[i] = (byte) i;
            }
            runCase(emu, "seq-block", iv, m2);
            byte[] m3 = new byte[64];
            byte[] abc = "abc".getBytes("US-ASCII");
            System.arraycopy(abc, 0, m3, 0, 3);
            m3[3] = (byte) 0x80;
            m3[56] = 24; // bit length 24 = 3 bytes
            runCase(emu, "abc-padded", iv, m3);
        } finally {
            emu.dispose();
        }
        println("==== done ====");
    }
}

