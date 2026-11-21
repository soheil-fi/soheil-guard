package com.soheil.dex.common;

import java.util.Base64;

/** Converts raw TON addresses ("0:abcd…") to the user-friendly base64url form used by wallets and APIs. */
public final class TonAddress {

    private TonAddress() {
    }

    /** @param bounceable true for contracts (EQ…), false for wallets (UQ…) */
    public static String friendly(String raw, boolean bounceable) {
        if (raw == null || !raw.matches("^-?[0-9]+:[0-9a-fA-F]{64}$")) {
            return raw;
        }
        String[] parts = raw.split(":");
        byte[] out = new byte[36];
        out[0] = (byte) (bounceable ? 0x11 : 0x51);
        out[1] = (byte) Integer.parseInt(parts[0]);
        for (int i = 0; i < 32; i++) {
            out[2 + i] = (byte) Integer.parseInt(parts[1].substring(i * 2, i * 2 + 2), 16);
        }
        int crc = crc16(out, 34);
        out[34] = (byte) (crc >> 8);
        out[35] = (byte) crc;
        return Base64.getUrlEncoder().encodeToString(out);
    }

    /** CRC-16/XMODEM, as used by TON user-friendly addresses. */
    static int crc16(byte[] data, int len) {
        int crc = 0;
        for (int i = 0; i < len; i++) {
            crc ^= (data[i] & 0xff) << 8;
            for (int j = 0; j < 8; j++) {
                crc = (crc & 0x8000) != 0 ? (crc << 1) ^ 0x1021 : crc << 1;
            }
        }
        return crc & 0xffff;
    }

    /**
     * Whether two TON addresses name the same account: a user-friendly address has several spellings (bounceable or
     * not, + / or - _), and the raw form is another, so they are compared as raw addresses. False when either is not one.
     */
    public static boolean same(String a, String b) {
        try {
            return a != null && b != null && raw(a).equals(raw(b));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String raw(String address) {
        return toRaw(address.trim());
    }

    /** User-friendly (EQ…/UQ…) → raw "0:hex", so addresses compare equal whatever flags they carry. */
    public static String toRaw(String friendly) {
        if (friendly == null) {
            return null;
        }
        if (friendly.matches("^-?[0-9]+:[0-9a-fA-F]{64}$")) {
            return friendly.toLowerCase(java.util.Locale.ROOT);
        }
        byte[] b;
        try {
            b = Base64.getUrlDecoder().decode(friendly.replace('+', '-').replace('/', '_'));
        } catch (IllegalArgumentException e) {
            return friendly;
        }
        if (b.length != 36) {
            return friendly;
        }
        StringBuilder hex = new StringBuilder();
        for (int i = 2; i < 34; i++) {
            hex.append(String.format("%02x", b[i]));
        }
        return b[1] + ":" + hex;
    }
}
