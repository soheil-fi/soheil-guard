package com.soheil.guard;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** The holder findings every network shares: the share of the supply the largest ordinary wallets hold. */
public final class Holders {

    private Holders() {
    }

    /**
     * @param wallets balances of ordinary wallets only (pools, lockers and programs left out), in any order
     * @param supply  the token's total supply, same units
     */
    public static List<Finding> judge(List<BigInteger> wallets, BigInteger supply, double topWalletPct, double topWalletsPct) {
        if (supply == null || supply.signum() <= 0) {
            throw new NotCheckedException("no supply");
        }
        List<BigInteger> sorted = new ArrayList<>(wallets);
        sorted.sort(Comparator.reverseOrder());
        BigDecimal top = sorted.isEmpty() ? BigDecimal.ZERO : share(sorted.getFirst(), supply);
        BigDecimal topTen = share(sorted.stream().limit(10).reduce(BigInteger.ZERO, BigInteger::add), supply);
        List<Finding> out = new ArrayList<>();
        if (top.doubleValue() >= topWalletPct) {
            out.add(Finding.of("TOP_WALLET", Finding.Level.CAUTION, Map.of("pct", Finding.pct(top))));
        }
        if (topTen.doubleValue() >= topWalletsPct) {
            out.add(Finding.of("TOP_WALLETS", Finding.Level.CAUTION, Map.of("pct", Finding.pct(topTen))));
        }
        if (out.isEmpty()) {
            out.add(Finding.of("HOLDERS_SPREAD", Finding.Level.INFO, Map.of("pct", Finding.pct(topTen))));
        }
        return out;
    }

    /** {@code amount} as a percentage of {@code total} (four decimals). */
    public static BigDecimal share(BigInteger amount, BigInteger total) {
        return new BigDecimal(amount).multiply(BigDecimal.valueOf(100)).divide(new BigDecimal(total), 4, RoundingMode.HALF_UP);
    }

    /**
     * Who holds a pool's liquidity, as findings: burned for good (from {@code burnedPct}), else its largest holder, an
     * ordinary wallet (it can withdraw at any time) or a contract (often a locker, whose terms are not read).
     *
     * @param burned    the part nobody can withdraw
     * @param topHolder the largest other holder's part (null when there is none)
     */
    public static List<Finding> liquidity(BigInteger burned, BigInteger topHolder, boolean topIsWallet, BigInteger total, double burnedPct) {
        if (total == null || total.signum() <= 0) {
            throw new NotCheckedException("no liquidity");
        }
        BigDecimal burnedShare = share(burned.max(BigInteger.ZERO), total);
        if (burnedShare.doubleValue() >= burnedPct) {
            return List.of(Finding.of("LIQUIDITY_BURNED", Finding.Level.INFO, Map.of("pct", Finding.pct(burnedShare))));
        }
        if (topHolder == null || topHolder.signum() <= 0) {
            throw new NotCheckedException("no liquidity holders");
        }
        Map<String, String> params = Map.of("pct", Finding.pct(share(topHolder, total)));
        return topIsWallet
                ? List.of(Finding.of("LIQUIDITY_WALLET", Finding.Level.CAUTION, params))
                : List.of(Finding.of("LIQUIDITY_CONTRACT", Finding.Level.INFO, params));
    }
}
