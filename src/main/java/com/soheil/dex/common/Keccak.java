package com.soheil.dex.common;

import java.nio.charset.StandardCharsets;

/**
 * Keccak-256 as Ethereum uses it (the original Keccak padding, not NIST SHA3-256): function selectors and storage
 * slots are derived from their text with it, so they never have to be copied in as magic numbers.
 */
public final class Keccak {

    private static final long[] ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROTATIONS = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
    /** 1088 bits: what Keccak-256 absorbs per permutation. */
    private static final int RATE = 136;

    private Keccak() {
    }

    public static byte[] hash(byte[] input) {
        long[] state = new long[25];
        int blocks = input.length / RATE + 1;
        byte[] padded = new byte[blocks * RATE];
        System.arraycopy(input, 0, padded, 0, input.length);
        padded[input.length] ^= 0x01;
        padded[padded.length - 1] ^= (byte) 0x80;
        for (int b = 0; b < blocks; b++) {
            for (int i = 0; i < RATE / 8; i++) {
                state[i] ^= littleEndian(padded, b * RATE + i * 8);
            }
            permute(state);
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) (state[i / 8] >>> (8 * (i % 8)));
        }
        return out;
    }

    /** Hex (no 0x) of the hash of this text in UTF-8. */
    public static String hex(String text) {
        return toHex(hash(text.getBytes(StandardCharsets.UTF_8)));
    }

    /** The 4-byte function selector of a signature such as "transfer(address,uint256)", as 8 hex characters. */
    public static String selector(String signature) {
        return hex(signature).substring(0, 8);
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte x : bytes) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    private static long littleEndian(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (b[off + i] & 0xffL);
        }
        return v;
    }

    private static void permute(long[] a) {
        long[] c = new long[5];
        long[] b = new long[25];
        for (long rc : ROUND_CONSTANTS) {
            for (int x = 0; x < 5; x++) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) {
                    a[y + x] ^= d;
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int from = x + 5 * y;
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[from], ROTATIONS[from]);
                }
            }
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) {
                    a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
                }
            }
            a[0] ^= rc;
        }
    }
}
