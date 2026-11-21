package com.soheil.guard;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.soheil.dex.common.Keccak;

/**
 * What an EVM token's contract lets someone do, read from the chain alone: whether its code can be replaced (a proxy),
 * who controls it (an owner, an owner who gave up control, or roles), and which special powers its code has (minting,
 * pausing, blocking wallets, changing fees, switching trading on and off, limiting how much can be sold).
 *
 * Powers are found from the function selectors in the bytecode (of the implementation behind a proxy), so a power
 * under an unusual function name is missed; Guard says "checked", never "safe". A power counts only while
 * someone holds it: an owner that renounced (zero or dead address) and no role system means nobody can use the
 * owner's functions any more.
 */
public final class EvmContractCheck {

    /** Reads one network's state; {@code code} and {@code storage} throw when no endpoint answered. */
    public interface Reader {
        String code(String address);

        String storage(String address, String slot);

        /** The eth_call result, or null when the call reverted or no endpoint answered. */
        String call(String to, String data);
    }

    public enum Power {
        MINT("CAN_MINT"), PAUSE("CAN_PAUSE"), BLACKLIST("CAN_BLACKLIST"), FEES("CAN_CHANGE_FEES"),
        TRADING("CAN_STOP_TRADING"), LIMITS("CAN_LIMIT_SELLS");

        final String code;

        Power(String code) {
            this.code = code;
        }
    }

    /** The functions each power is known by in token contracts (OpenZeppelin, USDT-style, and common launch templates). */
    public static final Map<Power, List<String>> SIGNATURES = new EnumMap<>(Map.of(
            Power.MINT, List.of("mint(address,uint256)", "mint(uint256)", "mintTo(address,uint256)", "mintFor(address,uint256)",
                    "issue(uint256)", "mint(address[],uint256[])"),
            Power.PAUSE, List.of("pause()", "setPaused(bool)", "togglePause()", "pauseTrading()", "pauseTransfers()"),
            Power.BLACKLIST, List.of("blacklist(address)", "addBlackList(address)", "addBlacklist(address)", "addToBlacklist(address)",
                    "addToBlackList(address)", "setBlacklist(address,bool)", "setBlackList(address,bool)", "blacklistAddress(address,bool)",
                    "setBlacklisted(address,bool)", "manageBlacklist(address[],bool)", "setBlacklistMultiple(address[],bool)",
                    "addBot(address)", "addBots(address[])", "setBot(address,bool)", "setBots(address[],bool)", "blockBots(address[])",
                    "freeze(address)", "freezeAccount(address)", "freezeAccount(address,bool)", "blockAccount(address)"),
            Power.FEES, List.of("setFee(uint256)", "setFees(uint256,uint256)", "setTaxFee(uint256)", "setTaxFeePercent(uint256)",
                    "setTax(uint256)", "setTaxes(uint256,uint256)", "setBuyTax(uint256)", "setSellTax(uint256)", "setBuyFee(uint256)",
                    "setSellFee(uint256)", "updateFees(uint256,uint256)", "updateBuyFees(uint256,uint256,uint256)",
                    "updateSellFees(uint256,uint256,uint256)", "setFeePercent(uint256)", "setTransferFee(uint256)",
                    "setLiquidityFeePercent(uint256)", "setSwapFees(uint256,uint256)"),
            Power.TRADING, List.of("enableTrading()", "openTrading()", "startTrading()", "setTradingEnabled(bool)",
                    "setTradingOpen(bool)", "setTrading(bool)", "tradingStatus(bool)", "enableTrading(uint256)"),
            Power.LIMITS, List.of("setMaxTxAmount(uint256)", "setMaxTxPercent(uint256)", "setMaxWalletSize(uint256)",
                    "setMaxWallet(uint256)", "setMaxSellAmount(uint256)", "updateMaxTxnAmount(uint256)",
                    "updateMaxWalletAmount(uint256)", "setMaxTransactionAmount(uint256)")));

    private static final Map<Power, Set<String>> SELECTORS = new EnumMap<>(Power.class);

    static {
        SIGNATURES.forEach((power, sigs) -> {
            Set<String> s = new HashSet<>();
            sigs.forEach(sig -> s.add(Keccak.selector(sig)));
            SELECTORS.put(power, s);
        });
    }

    private static final String HAS_ROLE = Keccak.selector("hasRole(bytes32,address)");
    private static final String TRANSFER = Keccak.selector("transfer(address,uint256)");
    private static final String OWNER = "0x" + Keccak.selector("owner()");
    private static final String GET_OWNER = "0x" + Keccak.selector("getOwner()");
    private static final String IMPLEMENTATION = "0x" + Keccak.selector("implementation()");

    /** EIP-1967 implementation and beacon slots, EIP-1822 (UUPS), and the older OpenZeppelin (zos) slot. */
    public static final String IMPLEMENTATION_SLOT = minusOne("eip1967.proxy.implementation");
    public static final String BEACON_SLOT = minusOne("eip1967.proxy.beacon");
    public static final String UUPS_SLOT = "0x" + Keccak.hex("PROXIABLE");
    public static final String ZOS_SLOT = "0x" + Keccak.hex("org.zeppelinos.proxy.implementation");

    private static final Set<String> GONE = Set.of("0000000000000000000000000000000000000000", "000000000000000000000000000000000000dead");

    private EvmContractCheck() {
    }

    /**
     * The findings for this token contract.
     *
     * @throws NotCheckedException when nothing is deployed at the address or the network did not answer
     */
    public static List<Finding> check(Reader r, String token) {
        String code = r.code(token);
        Bytecode own = Bytecode.of(code);
        if (own.isEmpty()) {
            throw new NotCheckedException("no contract at " + token);
        }
        Set<String> selectors = new HashSet<>(own.selectors());

        boolean upgradeable = false;
        String target = Bytecode.minimalProxyTarget(code); // a fixed forwarder: its target's code is what runs
        if (target == null) {
            target = slotAddress(r.storage(token, IMPLEMENTATION_SLOT));
            if (target == null) {
                String beacon = slotAddress(r.storage(token, BEACON_SLOT));
                target = beacon == null ? null : wordAddress(r.call(beacon, IMPLEMENTATION));
            }
            if (target == null) {
                target = slotAddress(r.storage(token, UUPS_SLOT));
            }
            if (target == null) {
                target = slotAddress(r.storage(token, ZOS_SLOT));
            }
            upgradeable = target != null;
        }
        boolean hidden = false;
        if (target != null) {
            Bytecode impl = Bytecode.of(r.code(target));
            if (impl.isEmpty()) {
                throw new NotCheckedException("proxy target " + target + " has no code");
            }
            selectors.addAll(impl.selectors());
        } else if (own.delegates() && !selectors.contains(TRANSFER)) {
            // Calls go to code we could not find: a proxy of a kind we do not read, so its powers are unknown
            hidden = true;
        }

        List<Finding> out = new ArrayList<>();
        if (upgradeable) {
            out.add(Finding.of("UPGRADEABLE", Finding.Level.CAUTION, Map.of()));
        }
        if (hidden) {
            out.add(Finding.of("HIDDEN_CODE", Finding.Level.CAUTION, Map.of()));
        }

        boolean roles = selectors.contains(HAS_ROLE);
        String owner = anyAddress(r.call(token, OWNER));
        if (owner == null) {
            owner = anyAddress(r.call(token, GET_OWNER));
        }
        boolean renounced = owner != null && GONE.contains(owner.substring(2));
        String by = roles ? "roles" : owner != null && !renounced ? "owner" : renounced ? null : "unknown";

        List<Power> powers = new ArrayList<>();
        for (Power p : Power.values()) {
            if (SELECTORS.get(p).stream().anyMatch(selectors::contains)) {
                powers.add(p);
            }
        }
        if (by != null) {
            for (Power p : powers) {
                Map<String, String> params = new LinkedHashMap<>();
                params.put("by", by);
                if ("owner".equals(by)) {
                    params.put("owner", owner);
                }
                out.add(Finding.of(p.code, Finding.Level.CAUTION, params));
            }
        }
        if (renounced && !roles) {
            out.add(Finding.info("OWNER_RENOUNCED"));
        }
        if ((powers.isEmpty() || by == null) && !upgradeable && !hidden) {
            out.add(Finding.info("NO_OWNER_POWERS"));
        }
        return out;
    }

    /** The address stored in a slot (its last 20 bytes), or null when the slot is empty. */
    public static String slotAddress(String word) {
        String a = wordAddress(word);
        return a == null || GONE.contains(a.substring(2)) ? null : a;
    }

    /** The non-zero address in the first 32-byte word of a call result, or null. */
    public static String wordAddress(String result) {
        String a = anyAddress(result);
        return a == null || a.substring(2).chars().allMatch(c -> c == '0') ? null : a;
    }

    /** The address in the first 32-byte word of a call result (the zero address included), or null for no answer. */
    public static String anyAddress(String result) {
        if (result == null) {
            return null;
        }
        String h = result.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        if (h.length() < 64 || !h.substring(0, 24).chars().allMatch(c -> c == '0')) {
            return null; // empty, short or not address-shaped
        }
        return "0x" + h.substring(24, 64);
    }

    private static String minusOne(String text) {
        return "0x" + String.format(Locale.ROOT, "%064x", new BigInteger(Keccak.hex(text), 16).subtract(BigInteger.ONE));
    }
}
