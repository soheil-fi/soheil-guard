package com.soheil.guard;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Guard's answer for one token.
 *
 * @param verdict    KNOWN for well-known coins (not checked: nothing to warn about); otherwise the worst finding, with
 *                   OK only when the contract itself could be checked; NOT_CHECKED when no check got an answer or the
 *                   contract could not be read
 * @param findings   worst first
 * @param checked    which checks answered: "sell", "contract", "holders"
 * @param notChecked which checks this network does not have yet, or that got no answer this time
 * @param pending    checks still running in the background; asking again shortly brings their findings
 */
public record GuardReport(long chainId, String token, Verdict verdict, List<Finding> findings, List<String> checked,
                           List<String> notChecked, List<String> pending, OffsetDateTime checkedAt) {

    public enum Verdict { KNOWN, OK, CAUTION, RISKY, NOT_CHECKED }

    public static final String SELL = "sell";
    public static final String CONTRACT = "contract";
    public static final String HOLDERS = "holders";
    public static final String SIMULATION = "simulation";
    public static final String AGE = "age";
    public static final String LIQUIDITY = "liquidity";

    public static GuardReport known(long chainId, String token, OffsetDateTime now) {
        return new GuardReport(chainId, token, Verdict.KNOWN, List.of(), List.of(), List.of(), List.of(), now);
    }

    /** The report for what the checks found; the verdict follows from the findings and what could be checked. */
    public static GuardReport of(long chainId, String token, List<Finding> findings, List<String> checked, List<String> notChecked,
                                  OffsetDateTime now) {
        return of(chainId, token, findings, checked, notChecked, List.of(), now);
    }

    public static GuardReport of(long chainId, String token, List<Finding> findings, List<String> checked, List<String> notChecked,
                                  List<String> pending, OffsetDateTime now) {
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator.comparing((Finding f) -> f.level()).reversed());
        return new GuardReport(chainId, token, verdict(sorted, checked), List.copyOf(sorted), List.copyOf(checked),
                List.copyOf(notChecked), List.copyOf(pending), now);
    }

    public static Verdict verdict(List<Finding> findings, List<String> checked) {
        if (findings.stream().anyMatch(f -> f.level() == Finding.Level.RISKY)) {
            return Verdict.RISKY;
        }
        if (findings.stream().anyMatch(f -> f.level() == Finding.Level.CAUTION)) {
            return Verdict.CAUTION;
        }
        // "OK" is a claim about the token itself: without its contract read, a clean sell test alone is not enough
        return checked.contains(CONTRACT) ? Verdict.OK : Verdict.NOT_CHECKED;
    }
}
