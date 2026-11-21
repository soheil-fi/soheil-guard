package com.soheil.guard;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;

/**
 * What a Solana token's mint allows, read from the mint account itself: whether more can be created (mint authority),
 * whether holders' tokens can be frozen (freeze authority), and the Token-2022 extensions that matter to a buyer
 * (a fee on every transfer, a permanent delegate that can move anyone's tokens, a transfer hook running custom code,
 * pausing, tokens that cannot be transferred, accounts frozen by default).
 *
 * Holders: the 20 largest token accounts, each traced to its owner; only owners that are ordinary wallets (System
 * Program accounts) count, so pools, bonding curves, lockers and other programs do not look like whales.
 */
public final class SolanaMintCheck {

    /** One Solana JSON-RPC call's "result"; throws when no endpoint answered. */
    public interface Reader {
        JsonNode result(String method, List<Object> params);
    }

    public static final String SYSTEM_PROGRAM = "11111111111111111111111111111111";
    public static final Map<String, Object> PARSED = Map.of("encoding", "jsonParsed", "commitment", "confirmed");

    /** The mint's findings and its supply (raw units), which the holder check needs. */
    public record Mint(List<Finding> findings, BigInteger supply) {
    }

    private SolanaMintCheck() {
    }

    /** @throws NotCheckedException when the address is not a token mint */
    public static Mint mint(Reader r, String mint, double transferFeeRiskyPct) {
        JsonNode value = r.result("getAccountInfo", List.of(mint, PARSED)).path("value");
        JsonNode parsed = value.path("data").path("parsed");
        if (value.isNull() || value.isMissingNode() || !"mint".equals(parsed.path("type").asString(""))) {
            throw new NotCheckedException("not a token mint: " + mint);
        }
        JsonNode info = parsed.path("info");
        List<Finding> out = new ArrayList<>();
        out.add(text(info.path("mintAuthority")) != null
                ? Finding.of("MINT_AUTHORITY", Finding.Level.CAUTION, Map.of())
                : Finding.info("MINT_FIXED"));
        out.add(text(info.path("freezeAuthority")) != null
                ? Finding.of("FREEZE_AUTHORITY", Finding.Level.RISKY, Map.of())
                : Finding.info("FREEZE_NONE"));

        for (JsonNode ext : info.path("extensions")) {
            JsonNode state = ext.path("state");
            switch (ext.path("extension").asString("")) {
                case "transferFeeConfig" -> {
                    int bps = Math.max(state.path("newerTransferFee").path("transferFeeBasisPoints").asInt(0),
                            state.path("olderTransferFee").path("transferFeeBasisPoints").asInt(0));
                    if (bps > 0) {
                        double pct = bps / 100.0;
                        out.add(Finding.of("TRANSFER_FEE", pct >= transferFeeRiskyPct ? Finding.Level.RISKY : Finding.Level.CAUTION,
                                Map.of("pct", Finding.pct(BigDecimal.valueOf(pct)))));
                    }
                }
                case "permanentDelegate" -> {
                    if (text(state.path("delegate")) != null) {
                        out.add(Finding.of("PERMANENT_DELEGATE", Finding.Level.RISKY, Map.of()));
                    }
                }
                case "transferHook" -> {
                    if (text(state.path("programId")) != null) {
                        out.add(Finding.of("TRANSFER_HOOK", Finding.Level.CAUTION, Map.of()));
                    }
                }
                case "pausableConfig" -> out.add(state.path("paused").asBoolean(false)
                        ? Finding.of("PAUSED", Finding.Level.RISKY, Map.of())
                        : Finding.of("PAUSABLE", Finding.Level.CAUTION, Map.of()));
                case "nonTransferable" -> out.add(Finding.of("NON_TRANSFERABLE", Finding.Level.RISKY, Map.of()));
                case "defaultAccountState" -> {
                    if ("frozen".equals(state.path("accountState").asString(""))) {
                        out.add(Finding.of("FROZEN_BY_DEFAULT", Finding.Level.RISKY, Map.of()));
                    }
                }
                default -> {
                    // metadata, interest, group pointers and the like change nothing for a buyer
                }
            }
        }
        BigInteger supply;
        try {
            supply = new BigInteger(info.path("supply").asString("0"));
        } catch (NumberFormatException e) {
            supply = BigInteger.ZERO;
        }
        return new Mint(out, supply);
    }

    /**
     * How much of the supply the largest ordinary wallets hold.
     *
     * @throws NotCheckedException when the supply is zero or the network gave no holders
     */
    public static List<Finding> holders(Reader r, String mint, BigInteger supply, double topWalletPct, double topWalletsPct) {
        if (supply == null || supply.signum() <= 0) {
            throw new NotCheckedException("no supply");
        }
        Map<String, BigInteger> byOwner = largestByOwner(r, mint);
        List<String> owners = List.copyOf(byOwner.keySet());
        List<String> programs = programsOf(r, owners);
        List<BigInteger> wallets = new ArrayList<>();
        for (int i = 0; i < owners.size(); i++) {
            // A wallet is an account of the System Program; a missing account (a program address) is not counted
            if (SYSTEM_PROGRAM.equals(programs.get(i))) {
                wallets.add(byOwner.get(owners.get(i)));
            }
        }
        return Holders.judge(wallets, supply, topWalletPct, topWalletsPct);
    }

    /** One of a mint's largest token accounts: its address, the wallet or program that owns it, and its balance. */
    public record Account(String address, String owner, BigInteger amount) {
    }

    /** A mint's largest token accounts (up to 20), largest first, each with its owner. */
    public static List<Account> largestAccounts(Reader r, String mint) {
        JsonNode largest = r.result("getTokenLargestAccounts", List.of(mint, Map.of("commitment", "confirmed"))).path("value");
        List<String> addresses = new ArrayList<>();
        List<BigInteger> amounts = new ArrayList<>();
        for (JsonNode a : largest) {
            String address = text(a.path("address"));
            if (address != null) {
                addresses.add(address);
                amounts.add(new BigInteger(a.path("amount").asString("0")));
            }
        }
        if (addresses.isEmpty()) {
            throw new NotCheckedException("no holders");
        }
        JsonNode tokenAccounts = r.result("getMultipleAccounts", List.of(addresses, PARSED)).path("value");
        List<Account> out = new ArrayList<>();
        for (int i = 0; i < addresses.size(); i++) {
            String owner = text(tokenAccounts.path(i).path("data").path("parsed").path("info").path("owner"));
            if (owner != null) {
                out.add(new Account(addresses.get(i), owner, amounts.get(i)));
            }
        }
        return out;
    }

    /** The largest token accounts of a mint, summed per owner, largest first. */
    public static Map<String, BigInteger> largestByOwner(Reader r, String mint) {
        Map<String, BigInteger> byOwner = new LinkedHashMap<>();
        for (Account a : largestAccounts(r, mint)) {
            byOwner.merge(a.owner(), a.amount(), BigInteger::add);
        }
        return byOwner;
    }

    /** The program owning each account (a wallet is owned by the System Program); null where the account is missing. */
    public static List<String> programsOf(Reader r, List<String> accounts) {
        List<String> out = new ArrayList<>();
        if (accounts.isEmpty()) {
            return out;
        }
        JsonNode values = r.result("getMultipleAccounts", List.of(accounts, Map.of("encoding", "base64", "commitment", "confirmed",
                "dataSlice", Map.of("offset", 0, "length", 0)))).path("value");
        for (int i = 0; i < accounts.size(); i++) {
            out.add(text(values.path(i).path("owner")));
        }
        return out;
    }

    /** A non-empty string value, or null for a missing, null or empty one. */
    public static String text(JsonNode n) {
        if (n == null || n.isNull() || n.isMissingNode()) {
            return null;
        }
        String s = n.asString("");
        return s.isBlank() ? null : s;
    }
}
