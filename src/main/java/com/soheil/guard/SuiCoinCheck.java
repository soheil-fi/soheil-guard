package com.soheil.guard;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;

/**
 * What a Sui coin's creator can still do, read from the chain. A coin is created when its package is published: that
 * transaction made its TreasuryCap (the right to create more) and, for a regulated coin, its DenyCap (the right to
 * block addresses). Where those objects are now decides the findings: frozen (immutable) means nobody can use them,
 * owned by an address means that address can, anything else means someone may.
 *
 * A coin made later through the coin registry has no such objects in its publish transaction: its powers are then
 * not checked.
 */
public final class SuiCoinCheck {

    private static final Pattern ADDRESS = Pattern.compile("0x[0-9a-fA-F]+");

    /**
     * @param findings  the powers found
     * @param complete  false when the TreasuryCap could not be followed (then no finding says the supply is fixed)
     * @param createdMs when the coin's package was published
     */
    public record Result(List<Finding> findings, boolean complete, Long createdMs) {
    }

    private SuiCoinCheck() {
    }

    public static Result check(SolanaMintCheck.Reader r, String coinType) {
        int sep = coinType.indexOf("::");
        if (sep < 0) {
            throw new NotCheckedException("not a coin type: " + coinType);
        }
        String pkg = coinType.substring(0, sep);
        String digest = SolanaMintCheck.text(r.result("sui_getObject", List.of(pkg, Map.of("showPreviousTransaction", true)))
                .path("data").path("previousTransaction"));
        if (digest == null) {
            throw new NotCheckedException("package not found");
        }
        JsonNode tx = r.result("sui_getTransactionBlock", List.of(digest, Map.of("showObjectChanges", true)));
        String type = normalize(coinType);
        String treasury = null;
        String deny = null;
        for (JsonNode change : tx.path("objectChanges")) {
            if (!"created".equals(change.path("type").asString(""))) {
                continue;
            }
            String objectType = normalize(change.path("objectType").asString(""));
            if (objectType.equals("0x2::coin::treasurycap<" + type + ">")) {
                treasury = SolanaMintCheck.text(change.path("objectId"));
            } else if (objectType.equals("0x2::coin::denycapv2<" + type + ">") || objectType.equals("0x2::coin::denycap<" + type + ">")) {
                deny = SolanaMintCheck.text(change.path("objectId"));
            }
        }
        Long created = tx.hasNonNull("timestampMs") ? Long.valueOf(tx.path("timestampMs").asString("0")) : null;

        List<Finding> out = new ArrayList<>();
        boolean complete = false;
        if (treasury != null) {
            Holder h = holder(r, treasury);
            if (h.frozen()) {
                out.add(Finding.info("MINT_FIXED"));
                complete = true;
            } else if (h.known()) {
                out.add(power("CAN_MINT", h.address()));
                complete = true;
            }
        }
        if (deny != null) {
            Holder h = holder(r, deny);
            if (!h.frozen() && h.known()) {
                out.add(power("CAN_BLACKLIST", h.address()));
            }
        }
        return new Result(out, complete, created);
    }

    /** Where an object is now: frozen, owned by an address, held some other way (shared, inside another object), or gone. */
    private record Holder(boolean frozen, boolean known, String address) {
    }

    private static Holder holder(SolanaMintCheck.Reader r, String objectId) {
        JsonNode res = r.result("sui_getObject", List.of(objectId, Map.of("showOwner", true)));
        JsonNode owner = res.path("data").path("owner");
        if (owner.isMissingNode() || owner.isNull()) {
            // Deleted or wrapped into another object (a launchpad, a vault): who can use it is not visible
            return new Holder(false, false, null);
        }
        if (owner.isString() && "Immutable".equals(owner.asString())) {
            return new Holder(true, true, null);
        }
        String address = SolanaMintCheck.text(owner.path("AddressOwner"));
        if (address == null) {
            address = SolanaMintCheck.text(owner.path("ConsensusAddressOwner").path("owner"));
        }
        return new Holder(false, true, address); // shared or owned by an object: someone may use it, we cannot say who
    }

    private static Finding power(String code, String owner) {
        return owner == null
                ? Finding.of(code, Finding.Level.CAUTION, Map.of("by", "unknown"))
                : Finding.of(code, Finding.Level.CAUTION, Map.of("by", "owner", "owner", owner));
    }

    /** A type with every address in its short form ("0x0…02" → "0x2"), lowercase, for comparing. */
    public static String normalize(String type) {
        Matcher m = ADDRESS.matcher(type);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, "0x" + new BigInteger(m.group().substring(2), 16).toString(16));
        }
        m.appendTail(sb);
        return sb.toString().toLowerCase(Locale.ROOT);
    }
}
