package com.soheil.dex.common;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

/** Base58 (Bitcoin alphabet), as Solana keys and Tron addresses use it, and Tron's hex form of an address. */
public final class Base58 {

    public static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);
    private static final byte TRON_VERSION = 0x41;

    private Base58() {
    }

    public static String encode(byte[] bytes) {
        int zeros = 0;
        while (zeros < bytes.length && bytes[zeros] == 0) {
            zeros++;
        }
        StringBuilder sb = new StringBuilder();
        BigInteger n = new BigInteger(1, bytes);
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        sb.append("1".repeat(zeros));
        return sb.reverse().toString();
    }

    /** @throws IllegalArgumentException on a character outside the alphabet */
    public static byte[] decode(String s) {
        BigInteger n = BigInteger.ZERO;
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') {
            zeros++;
        }
        for (char c : s.toCharArray()) {
            int d = ALPHABET.indexOf(c);
            if (d < 0) {
                throw new IllegalArgumentException("Not base58: " + s);
            }
            n = n.multiply(BASE).add(BigInteger.valueOf(d));
        }
        byte[] raw = n.signum() == 0 ? new byte[0] : n.toByteArray();
        int skip = raw.length > 0 && raw[0] == 0 ? 1 : 0; // BigInteger's sign byte
        byte[] out = new byte[zeros + raw.length - skip];
        System.arraycopy(raw, skip, out, zeros, raw.length - skip);
        return out;
    }

    /** A Tron address (T…) as 0x + 20 bytes hex, the form Tron's JSON-RPC takes. */
    public static String tronToHex(String address) {
        byte[] b = decode(address);
        if (b.length != 25 || b[0] != TRON_VERSION || !Arrays.equals(Arrays.copyOfRange(b, 21, 25), checksum(Arrays.copyOf(b, 21)))) {
            throw new IllegalArgumentException("Not a Tron address: " + address);
        }
        StringBuilder sb = new StringBuilder("0x");
        for (int i = 1; i < 21; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }

    /** 0x + 20 bytes hex (or 41 + 20 bytes) as a Tron address (T…). */
    public static String tronFromHex(String hex) {
        String h = hex.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        if (h.length() == 42 && h.startsWith("41")) {
            h = h.substring(2);
        }
        if (h.length() != 40) {
            throw new IllegalArgumentException("Not a 20-byte address: " + hex);
        }
        byte[] payload = new byte[21];
        payload[0] = TRON_VERSION;
        for (int i = 0; i < 20; i++) {
            payload[i + 1] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        byte[] full = Arrays.copyOf(payload, 25);
        System.arraycopy(checksum(payload), 0, full, 21, 4);
        return encode(full);
    }

    /** The first four bytes of a double SHA-256. */
    private static byte[] checksum(byte[] payload) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] once = sha.digest(payload);
            return Arrays.copyOf(sha.digest(once), 4);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
