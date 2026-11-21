package com.soheil.guard;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.soheil.dex.common.Keccak;

/**
 * The sale test: what actually happens when someone buys this token, moves it and sells it, right now. A small
 * helper contract (resources/guard/SellProbe.sol, compiled to SellProbe.bin) is placed at a fresh address for one
 * eth_call with a state override, given some of the network's coin, and asked to:
 * <ol>
 *   <li>buy the token through KyberSwap's router (a real route, built for that address),</li>
 *   <li>move a little of it to a second address (wallet to wallet),</li>
 *   <li>sell part of it back through KyberSwap's router.</li>
 * </ol>
 * Nothing is signed or sent. A sale that fails is a honeypot or a sell tax above the route's 20% slippage limit; a
 * gap between what the quotes promised and what arrived is a hidden tax. Unusual function names do not matter here:
 * whatever the token does, it does it in the test.
 */
public final class SellSimulation {

    /** KyberSwap for one network: a route (its "data": routeSummary, routerAddress) and a transaction for it. */
    public interface Kyber {
        Map<String, Object> routes(String tokenIn, String tokenOut, String amountIn);

        /** Built transaction ("data", "routerAddress", "transactionValue", "amountIn") for this sender. */
        Map<String, Object> build(Object routeSummary, String sender);
    }

    /** The network: an eth_call with a state override (throws when no endpoint supports it). */
    public interface Chain {
        String call(String from, String to, String data, Map<String, Map<String, String>> overrides);
    }

    /**
     * @param findings what the test found (empty when it could not run)
     * @param pool     the pool the token's first hop trades in (for the liquidity check), or null
     */
    public record Result(List<Finding> findings, String pool) {
    }

    /** The helper's runtime bytecode (see SellProbe.sol for the source and compiler settings). */
    public static final String PROBE = load();
    /** Fresh addresses nobody holds keys to: where the helper runs, and where it moves tokens. */
    public static final String TESTER = "0x" + Keccak.hex("soheil-guard/tester").substring(24);
    public static final String OTHER = "0x" + Keccak.hex("soheil-guard/other").substring(24);
    private static final String RUN = Keccak.selector("run(address,address,bytes,uint256,address,uint256,address,uint256,bytes)");
    /** KyberSwap's slippage limit: a sale losing more than this to a tax fails in the test. */
    public static final int SLIPPAGE_BPS = 2_000;
    /** Below this a difference is noise between two quotes, not a tax. */
    private static final double NOISE_PCT = 2;
    private static final BigInteger COIN = BigInteger.TEN.pow(18);

    private SellSimulation() {
    }

    /**
     * Runs the test for {@code amount} (raw units) of the token, in native coin and back.
     *
     * @return the findings and the pool, or null when no KyberSwap route exists (the sell test already covers that)
     */
    public static Result run(Kyber kyber, Chain chain, String token, String nativeToken, BigInteger amount, double cautionPct, double riskyPct) {
        // What the amount is worth in the network's coin, then a buy of that much
        Map<String, Object> worth = kyber.routes(token, nativeToken, amount.toString());
        BigInteger coin = amountOut(worth);
        if (coin == null || coin.signum() <= 0) {
            return null;
        }
        String pool = firstPool(worth, token);
        Map<String, Object> buy = kyber.routes(nativeToken, token, coin.toString());
        BigInteger expected = amountOut(buy);
        if (expected == null || expected.signum() <= 0) {
            return null;
        }
        // Sell 40% and move 5% of what the buy should bring: room for a buy tax up to 55% before the test stops
        BigInteger sellAmount = expected.multiply(BigInteger.valueOf(40)).divide(BigInteger.valueOf(100));
        BigInteger moveAmount = expected.divide(BigInteger.valueOf(20));
        Map<String, Object> sell = kyber.routes(token, nativeToken, sellAmount.toString());
        BigInteger quotedBack = amountOut(sell);
        if (quotedBack == null || quotedBack.signum() <= 0 || moveAmount.signum() <= 0) {
            return null;
        }
        Map<String, Object> buyTx = kyber.build(buy.get("routeSummary"), TESTER);
        Map<String, Object> sellTx = kyber.build(sell.get("routeSummary"), TESTER);
        BigInteger value = number(buyTx.getOrDefault("transactionValue", buyTx.get("amountIn")));
        if (value == null) {
            value = coin;
        }
        String data = encode(token, (String) buyTx.get("routerAddress"), (String) buyTx.get("data"), value, OTHER, moveAmount,
                (String) sellTx.get("routerAddress"), sellAmount, (String) sellTx.get("data"));
        Map<String, Map<String, String>> overrides = Map.of(TESTER, Map.of("code", "0x" + PROBE, "balance", "0x" + value.add(COIN.multiply(BigInteger.valueOf(100))).toString(16)));
        String out = chain.call(TESTER, TESTER, data, overrides);
        return new Result(judge(words(out), expected, moveAmount, quotedBack, cautionPct, riskyPct), pool);
    }

    /**
     * What the helper's answer means.
     *
     * @param w          its four words: stage, received, moved, nativeOut
     * @param expected   tokens the buy quote promised
     * @param moveAmount tokens sent to the second address
     * @param quotedBack native coin the sell quote promised for the part sold
     */
    public static List<Finding> judge(BigInteger[] w, BigInteger expected, BigInteger moveAmount, BigInteger quotedBack, double cautionPct, double riskyPct) {
        int stage = w[0].intValueExact();
        BigInteger received = w[1];
        BigInteger moved = w[2];
        BigInteger nativeOut = w[3];
        switch (stage) {
            case 0:
                return List.of(Finding.of("SIM_BUY_FAILS", Finding.Level.CAUTION, Map.of()));
            case 1:
                return List.of(Finding.of("SIM_TRANSFER_FAILS", Finding.Level.RISKY, Map.of()));
            case 2:
            case 4:
                return List.of(Finding.of("SIM_SELL_FAILS", Finding.Level.RISKY, Map.of()));
            case 3:
                return List.of(Finding.of("SIM_TAX", Finding.Level.RISKY, taxes(pct(received, expected), 0, 0)));
            case 5:
                break;
            default:
                throw new IllegalStateException("Unknown stage " + stage);
        }
        double buy = pct(received, expected);
        double move = pct(moved, moveAmount);
        double sell = pct(nativeOut, quotedBack);
        double worst = Math.max(buy, Math.max(move, sell));
        if (worst < NOISE_PCT) {
            return List.of(Finding.info("SIM_OK"));
        }
        Finding.Level level = worst >= riskyPct ? Finding.Level.RISKY : worst >= cautionPct ? Finding.Level.CAUTION : Finding.Level.INFO;
        return List.of(Finding.of("SIM_TAX", level, taxes(buy, sell, move)));
    }

    /** The share (0–100) that did not arrive: 1 − got / promised; 0 when more arrived (prices moved our way). */
    public static double pct(BigInteger got, BigInteger promised) {
        if (promised.signum() <= 0) {
            return 0;
        }
        double lost = 100 - new BigDecimal(got).multiply(BigDecimal.valueOf(100)).divide(new BigDecimal(promised), 4, RoundingMode.HALF_UP).doubleValue();
        return Math.max(0, lost);
    }

    private static Map<String, String> taxes(double buy, double sell, double transfer) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("buy", shown(buy));
        m.put("sell", shown(sell));
        m.put("transfer", shown(transfer));
        return m;
    }

    /** A tax for the page: whole percent, noise shown as 0. */
    private static String shown(double pct) {
        return pct < NOISE_PCT ? "0" : Long.toString(Math.round(pct));
    }

    // ---- KyberSwap answers ----------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static BigInteger amountOut(Map<String, Object> route) {
        if (route == null || !(route.get("routeSummary") instanceof Map<?, ?> summary)) {
            return null;
        }
        return number(((Map<String, Object>) summary).get("amountOut"));
    }

    /** The pool of the first swap that sells the token (KyberSwap's routeSummary.route is a list of paths of swaps). */
    @SuppressWarnings("unchecked")
    public static String firstPool(Map<String, Object> route, String token) {
        if (route == null || !(route.get("routeSummary") instanceof Map<?, ?> summary) || !(summary.get("route") instanceof List<?> paths)) {
            return null;
        }
        for (Object path : paths) {
            if (path instanceof List<?> swaps) {
                for (Object s : swaps) {
                    if (s instanceof Map<?, ?> swap && token.equalsIgnoreCase(String.valueOf(swap.get("tokenIn")))) {
                        Object pool = ((Map<String, Object>) swap).get("pool");
                        if (pool instanceof String p && p.matches("^0x[0-9a-fA-F]{40}$")) {
                            return p.toLowerCase(Locale.ROOT);
                        }
                    }
                }
            }
        }
        return null;
    }

    private static BigInteger number(Object v) {
        try {
            return v == null ? null : new BigInteger(String.valueOf(v));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    // ---- ABI ----------------------------------------------------------------------------------------------------------

    /** Calldata for run(token, buyRouter, buyData, buyValue, other, moveAmount, sellRouter, sellAmount, sellData). */
    public static String encode(String token, String buyRouter, String buyData, BigInteger buyValue, String other, BigInteger moveAmount,
                         String sellRouter, BigInteger sellAmount, String sellData) {
        String buyBytes = hex(buyData);
        String sellBytes = hex(sellData);
        int head = 9 * 32;
        int buyTail = 32 + padded(buyBytes.length() / 2);
        StringBuilder sb = new StringBuilder("0x").append(RUN)
                .append(address(token)).append(address(buyRouter)).append(uint(BigInteger.valueOf(head))).append(uint(buyValue))
                .append(address(other)).append(uint(moveAmount)).append(address(sellRouter)).append(uint(sellAmount))
                .append(uint(BigInteger.valueOf(head + buyTail)));
        appendBytes(sb, buyBytes);
        appendBytes(sb, sellBytes);
        return sb.toString();
    }

    private static void appendBytes(StringBuilder sb, String bytesHex) {
        int len = bytesHex.length() / 2;
        sb.append(uint(BigInteger.valueOf(len))).append(bytesHex).append("00".repeat(padded(len) - len));
    }

    private static int padded(int len) {
        return (len + 31) / 32 * 32;
    }

    private static String address(String a) {
        String h = hex(a);
        if (h.length() != 40) {
            throw new IllegalArgumentException("Not an address: " + a);
        }
        return "0".repeat(24) + h;
    }

    private static String uint(BigInteger v) {
        String h = v.toString(16);
        if (v.signum() < 0 || h.length() > 64) {
            throw new IllegalArgumentException("Out of range: " + v);
        }
        return "0".repeat(64 - h.length()) + h;
    }

    private static String hex(String v) {
        String h = v == null ? "" : v.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("0x")) {
            h = h.substring(2);
        }
        if (h.length() % 2 != 0 || !h.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            throw new IllegalArgumentException("Not hex");
        }
        return h;
    }

    /** The first four 32-byte words of a call result. */
    public static BigInteger[] words(String result) {
        String h = hex(result);
        if (h.length() < 4 * 64) {
            throw new IllegalStateException("Short answer from the sale test");
        }
        BigInteger[] w = new BigInteger[4];
        for (int i = 0; i < 4; i++) {
            w[i] = new BigInteger(h.substring(i * 64, i * 64 + 64), 16);
        }
        return w;
    }

    private static String load() {
        try (java.io.InputStream in = SellSimulation.class.getResourceAsStream("/guard/SellProbe.bin")) {
            if (in == null) {
                throw new IllegalStateException("guard/SellProbe.bin missing");
            }
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.US_ASCII).trim();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
