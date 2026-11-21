package com.soheil.guard;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;

/**
 * One thing Guard found about a token. The host words it from {@code code} and {@code params} in the
 * user's language, so the codes are stable: change one only together with the page.
 *
 * @param level  INFO is reassuring or neutral; CAUTION and RISKY decide the token's label
 * @param params values for the sentence (percentages, dollar amounts, who holds a power), all as plain strings
 */
public record Finding(String code, Level level, Map<String, String> params) {

    public enum Level { INFO, CAUTION, RISKY }

    public Finding {
        params = params == null ? Map.of() : Map.copyOf(params);
    }

    public static Finding info(String code) {
        return new Finding(code, Level.INFO, Map.of());
    }

    public static Finding of(String code, Level level, Map<String, String> params) {
        return new Finding(code, level, params);
    }

    /** A percentage for the page: one decimal, no trailing zero ("12.5", "3"). */
    public static String pct(BigDecimal v) {
        return v.setScale(1, RoundingMode.HALF_UP).stripTrailingZeros().toPlainString();
    }
}
