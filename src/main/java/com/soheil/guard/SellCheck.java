package com.soheil.guard;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Can these tokens be sold again, and for how much? The tokens a route would deliver are quoted straight back into
 * the network's native coin through our own route sources; the best answer is compared with the value the route
 * states for them. A large gap means thin liquidity (a big price impact) or a fee the sources price in. No route back
 * at all is the strongest warning there is. This is a quote, not an execution: a token that only fails when a sale
 * is actually sent (a honeypot) is not caught here but by the contract and simulation checks.
 */
public final class SellCheck {

    private SellCheck() {
    }

    /**
     * @param backUsd  the USD value of each route found for selling the tokens back (null where a route gave none);
     *                 empty when the sources answered and none had a route
     * @param valueUsd what the route states the tokens are worth, or null when unknown
     */
    public static List<Finding> judge(List<BigDecimal> backUsd, BigDecimal valueUsd, double cautionPct, double riskyPct) {
        if (backUsd.isEmpty()) {
            return List.of(Finding.of("NO_SELL_ROUTE", Finding.Level.RISKY, Map.of()));
        }
        BigDecimal best = backUsd.stream().filter(Objects::nonNull).max(BigDecimal::compareTo).orElse(null);
        if (best == null || valueUsd == null || valueUsd.signum() <= 0) {
            return List.of(Finding.info("SELL_ROUTE"));
        }
        BigDecimal loss = BigDecimal.ONE.subtract(best.divide(valueUsd, 6, RoundingMode.HALF_UP)).multiply(BigDecimal.valueOf(100));
        if (loss.signum() < 0) {
            loss = BigDecimal.ZERO;
        }
        Map<String, String> params = new LinkedHashMap<>();
        params.put("lossPct", Finding.pct(loss));
        params.put("backUsd", best.setScale(2, RoundingMode.HALF_UP).toPlainString());
        params.put("valueUsd", valueUsd.setScale(2, RoundingMode.HALF_UP).toPlainString());
        double l = loss.doubleValue();
        if (l >= riskyPct) {
            return List.of(Finding.of("SELL_LOSS", Finding.Level.RISKY, params));
        }
        if (l >= cautionPct) {
            return List.of(Finding.of("SELL_LOSS", Finding.Level.CAUTION, params));
        }
        return List.of(Finding.of("SELL_OK", Finding.Level.INFO, params));
    }
}
