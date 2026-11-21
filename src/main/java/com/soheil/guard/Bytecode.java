package com.soheil.guard;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Reads deployed EVM bytecode without running it: the function selectors its dispatcher compares against, whether it
 * hands calls to other code (DELEGATECALL), and the target of a minimal proxy (EIP-1167). Opcodes are walked one by
 * one so the data pushed by PUSH instructions is never mistaken for an instruction; the compiler's metadata at the end
 * is cut off first, since it is data too.
 */
public final class Bytecode {

    private static final int PUSH1 = 0x60;
    private static final int PUSH3 = 0x62;
    private static final int PUSH4 = 0x63;
    private static final int PUSH32 = 0x7f;
    private static final int DELEGATECALL = 0xf4;
    /** Solidity's CBOR metadata starts with a map holding "ipfs" or "bzzr0"/"bzzr1" (and "solc"). */
    private static final String[] METADATA = {"a264697066735822", "a165627a7a72", "a265627a7a72"};
    private static final String MINIMAL_PROXY_HEAD = "363d3d373d3d3d363d73";
    private static final String MINIMAL_PROXY_TAIL = "5af43d82803e903d91602b57fd5bf3";
    /** The same proxy written with PUSH0 (EIP-7511). */
    private static final String MINIMAL_PROXY0_HEAD = "365f5f375f5f365f73";
    private static final String MINIMAL_PROXY0_TAIL = "5af43d5f5f3e6029573d5ffd5b3d5ff3";

    private final byte[] code;

    private Bytecode(byte[] code) {
        this.code = code;
    }

    /** Parses hex as returned by eth_getCode ("0x…"); an empty result means nothing is deployed there. */
    public static Bytecode of(String hex) {
        String h = clean(hex);
        int cut = -1;
        for (String m : METADATA) {
            int i = h.lastIndexOf(m);
            if (i % 2 == 0 && i > cut) {
                cut = i;
            }
        }
        if (cut >= 0) {
            h = h.substring(0, cut);
        }
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(h, 2 * i, 2 * i + 2, 16);
        }
        return new Bytecode(b);
    }

    boolean isEmpty() {
        return code.length == 0;
    }

    /**
     * Every 4-byte value the code pushes, as 8 hex characters: the dispatcher's selectors are among them. Selectors
     * starting with a zero byte are pushed with PUSH3, so 3-byte pushes count too (padded).
     */
    Set<String> selectors() {
        Set<String> out = new HashSet<>();
        for (int i = 0; i < code.length; i++) {
            int op = code[i] & 0xff;
            if (op >= PUSH1 && op <= PUSH32) {
                int n = op - PUSH1 + 1;
                if ((op == PUSH4 || op == PUSH3) && i + n < code.length) {
                    StringBuilder sb = new StringBuilder(op == PUSH3 ? "00" : "");
                    for (int k = 1; k <= n; k++) {
                        sb.append(String.format(Locale.ROOT, "%02x", code[i + k] & 0xff));
                    }
                    out.add(sb.toString());
                }
                i += n;
            }
        }
        return out;
    }

    /** Whether the code can run other contracts' code in its own storage (proxies and libraries do). */
    boolean delegates() {
        for (int i = 0; i < code.length; i++) {
            int op = code[i] & 0xff;
            if (op == DELEGATECALL) {
                return true;
            }
            if (op >= PUSH1 && op <= PUSH32) {
                i += op - PUSH1 + 1;
            }
        }
        return false;
    }

    /** The contract an EIP-1167 minimal proxy forwards every call to, or null when this is not one. */
    public static String minimalProxyTarget(String hex) {
        String h = clean(hex);
        for (String[] form : new String[][] {{MINIMAL_PROXY_HEAD, MINIMAL_PROXY_TAIL}, {MINIMAL_PROXY0_HEAD, MINIMAL_PROXY0_TAIL}}) {
            if (h.startsWith(form[0]) && h.length() == form[0].length() + 40 + form[1].length() && h.endsWith(form[1])) {
                return "0x" + h.substring(form[0].length(), form[0].length() + 40);
            }
        }
        return null;
    }

    private static String clean(String hex) {
        String h = hex == null ? "" : hex.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("0x")) {
            h = h.substring(2);
        }
        if (h.length() % 2 != 0 || !h.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            throw new IllegalArgumentException("Not bytecode");
        }
        return h;
    }
}
