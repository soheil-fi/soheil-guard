package com.soheil.dex.common;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Solana addresses worked out without a node: a public key's 32 bytes, and program-derived addresses (the same result
 * as PublicKey.findProgramAddressSync in @solana/web3.js). On its own, with no other class of ours, so the token checks
 * (guard/) can use it too.
 */
public final class SolanaAddress {

    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);

    private SolanaAddress() {
    }

    /** The 32 bytes of a base58 address. */
    public static byte[] pubkey(String base58) {
        byte[] b = Base58.decode(base58);
        if (b.length != 32) {
            throw new IllegalArgumentException("Not a Solana address: " + base58);
        }
        return b;
    }

    /** The program-derived address for these seeds (the first bump from 255 down that lands off the curve). */
    public static String programAddress(byte[][] seeds, String programId) {
        byte[] program = pubkey(programId);
        for (int bump = 255; bump >= 0; bump--) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                for (byte[] seed : seeds) {
                    sha.update(seed);
                }
                sha.update((byte) bump);
                sha.update(program);
                sha.update("ProgramDerivedAddress".getBytes(StandardCharsets.US_ASCII));
                byte[] hash = sha.digest();
                if (!onCurve(hash)) {
                    return Base58.encode(hash);
                }
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        throw new IllegalStateException("No program address found");
    }

    /** Whether 32 bytes decode to a point on ed25519 (a program address must not). */
    public static boolean onCurve(byte[] key) {
        byte[] le = key.clone();
        le[31] &= 0x7f;
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = le[31 - i];
        }
        BigInteger y = new BigInteger(1, be);
        if (y.compareTo(P) >= 0) {
            return false;
        }
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = u.multiply(v.modInverse(P)).mod(P);
        if (x2.signum() == 0) {
            return (key[31] & 0x80) == 0;
        }
        // x2 must be a square mod p (Euler's criterion)
        return x2.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P).equals(BigInteger.ONE);
    }
}
