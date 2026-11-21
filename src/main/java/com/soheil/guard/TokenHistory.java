package com.soheil.guard;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

import com.soheil.dex.common.Keccak;

/**
 * A token's history on an EVM network (and on Tron, whose contracts and logs work the same), read from the chain:
 * when its contract was created, who holds it (rebuilt from its Transfer events), and who holds its pool's liquidity.
 * These reads are slow and the answers change little, so a host should run them in the background and keep the answers.
 *
 * Only ordinary wallets count as holders (addresses without code, or with an EIP-7702 delegation): pools, lockers,
 * vesting and other contracts never look like whales.
 */
public final class TokenHistory {

    /** One network's state. Calls throw when no endpoint could answer (an old block without an archive node, a log range refused). */
    public interface Reader {
        long latestBlock();

        /** Whether the address had code at that block. */
        boolean hasCodeAt(String address, long block);

        long timestamp(long block);

        /** Events of a contract in a block range; {@code topic0} null = every event. */
        List<Log> logs(String address, String topic0, long fromBlock, long toBlock);

        /** Current code ("0x" when none). */
        String code(String address);

        /** eth_call result, or null when it reverted. */
        String call(String to, String data);
    }

    /** One event: its topics, data (hex), transaction and block. */
    public record Log(List<String> topics, String data, String tx, long block) {
    }

    public record Transfer(String from, String to, BigInteger value) {
    }

    /** The block a contract appeared in, and when. */
    public record Created(long block, long timestamp) {
    }

    /** How many log requests one run may still make: holders and liquidity share it, so a run has a fixed cost. */
    public static final class Calls {
        private int left;

        public Calls(int max) {
            this.left = Math.max(0, max);
        }

        boolean take() {
            if (left <= 0) {
                return false;
            }
            left--;
            return true;
        }

        int left() {
            return left;
        }
    }

    public static final String TRANSFER_TOPIC = topic("Transfer(address,address,uint256)");
    /** Uniswap V3 style pools (and their forks: PancakeSwap V3, Aerodrome Slipstream, Algebra). */
    public static final String MINT_TOPIC = topic("Mint(address,address,int24,int24,uint128,uint256,uint256)");
    public static final String BURN_TOPIC = topic("Burn(address,int24,int24,uint128,uint256,uint256)");
    /** Their position managers: one NFT per position. */
    public static final String INCREASE_TOPIC = topic("IncreaseLiquidity(uint256,uint128,uint256,uint256)");
    public static final String DECREASE_TOPIC = topic("DecreaseLiquidity(uint256,uint128,uint256,uint256)");
    private static final String TOTAL_SUPPLY = "0x" + Keccak.selector("totalSupply()");
    private static final String BALANCE_OF = Keccak.selector("balanceOf(address)");
    private static final String GET_RESERVES = "0x" + Keccak.selector("getReserves()");
    private static final String TOKEN0 = "0x" + Keccak.selector("token0()");
    private static final String SLOT0 = "0x" + Keccak.selector("slot0()");
    private static final String LIQUIDITY = "0x" + Keccak.selector("liquidity()");
    private static final String OWNER_OF = Keccak.selector("ownerOf(uint256)");
    private static final String ZERO = "0x0000000000000000000000000000000000000000";
    private static final String DEAD = "0x000000000000000000000000000000000000dead";
    private static final Set<String> NOBODY = Set.of(ZERO, DEAD);
    /** Log ranges: start here, halve when an endpoint refuses, grow back after answers. */
    private static final long FIRST_RANGE = 10_000;
    private static final long MIN_RANGE = 200;
    private static final long MAX_RANGE = 100_000;
    /** Positions whose owner is looked up, largest first; the rest still count in the total. */
    private static final int MAX_POSITIONS = 40;

    private TokenHistory() {
    }

    private static String topic(String signature) {
        return "0x" + Keccak.hex(signature);
    }

    // ---- creation -------------------------------------------------------------------------------------------------

    /** The first block with the contract's code: a binary search over block numbers (about 25 reads). */
    public static Created created(Reader r, String address) {
        long hi = r.latestBlock();
        if (!r.hasCodeAt(address, hi)) {
            throw new NotCheckedException("no code at the latest block");
        }
        long lo = 0;
        while (lo < hi) {
            long mid = lo + (hi - lo) / 2;
            if (r.hasCodeAt(address, mid)) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return new Created(lo, r.timestamp(lo));
    }

    /** The token's age as a finding: young tokens are a caution; the page words the age itself. */
    public static Finding age(long createdSeconds, long nowSeconds, double youngHours) {
        long hours = Math.max(0, (nowSeconds - createdSeconds) / 3600);
        Map<String, String> params = ageParams(hours);
        return hours < youngHours ? Finding.of("TOKEN_YOUNG", Finding.Level.CAUTION, params) : Finding.of("TOKEN_AGE", Finding.Level.INFO, params);
    }

    public static Finding age(Created c, long nowSeconds, double youngHours) {
        return age(c.timestamp(), nowSeconds, youngHours);
    }

    /**
     * When only a lower bound of the age is known (the history was too long to read to its start): a finding when
     * even that bound is past the young limit, else null (the age is then not checked, never guessed).
     */
    public static Finding ageAtLeast(long olderThanSeconds, long nowSeconds, double youngHours) {
        long hours = Math.max(0, (nowSeconds - olderThanSeconds) / 3600);
        return hours < youngHours ? null : Finding.of("TOKEN_AGE_MIN", Finding.Level.INFO, ageParams(hours));
    }

    private static Map<String, String> ageParams(long hours) {
        return hours < 48 ? Map.of("hours", Long.toString(hours)) : Map.of("days", Long.toString(hours / 24));
    }

    // ---- reading events -------------------------------------------------------------------------------------------

    /**
     * Every event with {@code topic0} of a contract from {@code fromBlock} to {@code toBlock}, in ranges that adapt
     * to what the endpoint accepts.
     *
     * @return false when the events could not all be read (out of calls, or even the smallest range refused)
     */
    public static boolean scan(Reader r, String address, String topic0, long fromBlock, long toBlock, Calls calls, Consumer<Log> each) {
        long range = FIRST_RANGE;
        long start = fromBlock;
        while (start <= toBlock) {
            if (!calls.take()) {
                return false;
            }
            long end = Math.min(toBlock, start + range - 1);
            List<Log> logs;
            try {
                logs = r.logs(address, topic0, start, end);
            } catch (RuntimeException e) {
                if (range <= MIN_RANGE) {
                    return false;
                }
                range = Math.max(MIN_RANGE, range / 2);
                continue;
            }
            logs.forEach(each);
            start = end + 1;
            range = Math.min(MAX_RANGE, range * 2);
        }
        return true;
    }

    /**
     * Every address's balance, rebuilt from the contract's Transfer events since {@code fromBlock}; null when the
     * events could not all be read with the calls left (then the check is not run, never guessed).
     */
    public static Map<String, BigInteger> balances(Reader r, String address, long fromBlock, long toBlock, Calls calls) {
        Map<String, BigInteger> out = new HashMap<>();
        boolean all = scan(r, address, TRANSFER_TOPIC, fromBlock, toBlock, calls, l -> {
            // ERC-20 Transfer: from and to in topics, the amount in data (ERC-721 puts the id in a 4th topic instead)
            if (l.topics().size() != 3 || l.data() == null || l.data().length() < 66) {
                return;
            }
            BigInteger v = word(l.data(), 0);
            out.merge(topicAddress(l.topics().get(1)), v.negate(), BigInteger::add);
            out.merge(topicAddress(l.topics().get(2)), v, BigInteger::add);
        });
        return all ? out : null;
    }

    public static Map<String, BigInteger> balances(Reader r, String address, long fromBlock, long toBlock, int maxCalls) {
        return balances(r, address, fromBlock, toBlock, new Calls(maxCalls));
    }

    // ---- holders ----------------------------------------------------------------------------------------------------

    /** The share of the supply held by the largest ordinary wallets (the same findings as on Solana). */
    public static List<Finding> holders(Reader r, String token, Map<String, BigInteger> balances, double topWalletPct, double topWalletsPct) {
        BigInteger supply = uint(r.call(token, TOTAL_SUPPLY));
        if (supply == null || supply.signum() <= 0) {
            throw new NotCheckedException("no supply");
        }
        List<BigInteger> wallets = new ArrayList<>();
        for (Map.Entry<String, BigInteger> e : largest(balances, token, 25)) {
            if (wallet(r.code(e.getKey()))) {
                wallets.add(e.getValue());
                if (wallets.size() == 10) {
                    break;
                }
            }
        }
        return Holders.judge(wallets, supply, topWalletPct, topWalletsPct);
    }

    /**
     * The largest holders from Ankr's indexed ankr_getTokenHolders answer, as balances by lowercase address; null when
     * the answer has none (an error, a chain Ankr does not index).
     */
    public static Map<String, BigInteger> indexedHolders(tools.jackson.databind.JsonNode body) {
        tools.jackson.databind.JsonNode list = body == null ? null : body.path("result").path("holders");
        if (list == null || !list.isArray() || list.isEmpty()) {
            return null;
        }
        Map<String, BigInteger> out = new HashMap<>();
        for (tools.jackson.databind.JsonNode h : list) {
            String address = h.path("holderAddress").asString("");
            String raw = h.path("balanceRawInteger").asString("");
            if (address.matches("^0x[0-9a-fA-F]{40}$") && raw.matches("^\\d+$")) {
                out.merge(address.toLowerCase(Locale.ROOT), new BigInteger(raw), BigInteger::add);
            }
        }
        return out.isEmpty() ? null : out;
    }

    // ---- liquidity ----------------------------------------------------------------------------------------------------

    /**
     * Who holds the pool's liquidity. Pools whose liquidity is a token (Uniswap V2 style): burned, or its largest
     * holder (from an index when there is one, else from its Transfer events). Pools with positions (Uniswap V3 style):
     * the positions rebuilt from the pool's and position manager's
     * events, each traced to the owner of its NFT. Other pool kinds are not checked.
     *
     * @param fromBlock where to start reading the pool's events (the token's creation: the pool cannot be older)
     * @param calls     log requests left; 0 still answers a V2 pool whose liquidity is burned
     */
    public static List<Finding> liquidity(Reader r, String pool, long fromBlock, long toBlock, Calls calls, double burnedPct) {
        return liquidity(r, pool, fromBlock, toBlock, calls, burnedPct, p -> null);
    }

    /**
     * @param indexed the largest holders of a liquidity token from an index (Ankr), or null: used before reading
     *                events, so a pool of any age is answered
     */
    public static List<Finding> liquidity(Reader r, String pool, long fromBlock, long toBlock, Calls calls, double burnedPct,
                                   java.util.function.Function<String, Map<String, BigInteger>> indexed) {
        if (r.call(pool, GET_RESERVES) != null) {
            return liquidityToken(r, pool, fromBlock, toBlock, calls, burnedPct, indexed);
        }
        if (r.call(pool, SLOT0) != null && r.call(pool, LIQUIDITY) != null) {
            return positions(r, pool, fromBlock, toBlock, calls, burnedPct);
        }
        throw new NotCheckedException("pool kind not checked");
    }

    public static List<Finding> liquidity(Reader r, String pool, long fromBlock, long toBlock, int maxCalls, double burnedPct) {
        return liquidity(r, pool, fromBlock, toBlock, new Calls(maxCalls), burnedPct);
    }

    /** A pool whose liquidity is itself a token: burned share, else the largest holder of that token. */
    private static List<Finding> liquidityToken(Reader r, String pool, long fromBlock, long toBlock, Calls calls, double burnedPct,
                                                java.util.function.Function<String, Map<String, BigInteger>> indexed) {
        BigInteger supply = uint(r.call(pool, TOTAL_SUPPLY));
        if (supply == null || supply.signum() <= 0 || r.call(pool, TOKEN0) == null) {
            throw new NotCheckedException("not a pool with a liquidity token");
        }
        BigInteger burned = BigInteger.ZERO;
        for (String nobody : NOBODY) {
            BigInteger b = uint(r.call(pool, "0x" + BALANCE_OF + "0".repeat(24) + nobody.substring(2)));
            burned = burned.add(b == null ? BigInteger.ZERO : b);
        }
        if (Holders.share(burned, supply).doubleValue() >= burnedPct) {
            return Holders.liquidity(burned, null, false, supply, burnedPct);
        }
        Map<String, BigInteger> lp = null;
        try {
            lp = indexed.apply(pool);
        } catch (RuntimeException e) {
            // the index is a shortcut: the events still answer a young pool
        }
        if (lp == null || lp.isEmpty()) {
            lp = balances(r, pool, fromBlock, toBlock, calls);
        }
        if (lp == null) {
            throw new NotCheckedException("liquidity events not readable");
        }
        List<Map.Entry<String, BigInteger>> top = largest(lp, pool, 1);
        if (top.isEmpty()) {
            throw new NotCheckedException("no liquidity holders");
        }
        return Holders.liquidity(burned, top.getFirst().getValue(), wallet(r.code(top.getFirst().getKey())), supply, burnedPct);
    }

    /** A pool event for a position: who it is booked to, how much liquidity, in which transaction and block. */
    private record Change(String owner, BigInteger amount, String tx, long block) {
    }

    /**
     * A pool with positions. Its Mint and Burn events say how much liquidity each owner added and removed; when the
     * owner is a position manager, the manager's IncreaseLiquidity and DecreaseLiquidity events in the same
     * transaction (same amount) name the position's NFT, whose owner is the real holder. Positions are compared by
     * their liquidity, not their dollar value: a fair measure of who controls the pool, not of what it is worth.
     */
    private static List<Finding> positions(Reader r, String pool, long fromBlock, long toBlock, Calls calls, double burnedPct) {
        List<Change> mints = new ArrayList<>();
        List<Change> burns = new ArrayList<>();
        boolean all = scan(r, pool, MINT_TOPIC, fromBlock, toBlock, calls, l -> {
            if (l.topics().size() == 4 && l.data() != null && l.data().length() >= 2 + 64 * 2) {
                mints.add(new Change(topicAddress(l.topics().get(1)), word(l.data(), 1), l.tx(), l.block()));
            }
        }) && scan(r, pool, BURN_TOPIC, fromBlock, toBlock, calls, l -> {
            if (l.topics().size() == 4 && l.data() != null && l.data().length() >= 2 + 64) {
                BigInteger amount = word(l.data(), 0);
                if (amount.signum() > 0) { // a zero burn only collects fees
                    burns.add(new Change(topicAddress(l.topics().get(1)), amount, l.tx(), l.block()));
                }
            }
        });
        if (!all) {
            throw new NotCheckedException("pool events not readable");
        }
        if (mints.isEmpty()) {
            throw new NotCheckedException("no positions");
        }

        // Liquidity per holder: owners booked directly, and positions (by NFT) of owners that are position managers
        Map<String, BigInteger> holders = new LinkedHashMap<>();
        Map<String, Map<BigInteger, BigInteger>> nfts = new LinkedHashMap<>();
        Set<String> owners = new TreeSet<>();
        mints.forEach(m -> owners.add(m.owner()));
        for (String owner : owners) {
            List<Change> in = mints.stream().filter(m -> m.owner().equals(owner)).toList();
            List<Change> out = burns.stream().filter(b -> b.owner().equals(owner)).toList();
            Map<BigInteger, BigInteger> byNft = wallet(r.code(owner)) ? Map.of() : nftsOf(r, owner, in, out, calls);
            if (byNft.isEmpty()) {
                BigInteger net = sum(in).subtract(sum(out));
                holders.merge(owner, net, BigInteger::add);
            } else {
                nfts.put(owner, byNft);
            }
        }
        // Each position's owner, largest positions first; the rest stay in the total under no name
        BigInteger unnamed = BigInteger.ZERO;
        List<Map.Entry<String, Map.Entry<BigInteger, BigInteger>>> ranked = new ArrayList<>();
        nfts.forEach((manager, byNft) -> byNft.entrySet().forEach(e -> ranked.add(Map.entry(manager, e))));
        ranked.sort(Comparator.comparing((Map.Entry<String, Map.Entry<BigInteger, BigInteger>> e) -> e.getValue().getValue()).reversed());
        for (int i = 0; i < ranked.size(); i++) {
            BigInteger liquidity = ranked.get(i).getValue().getValue();
            if (liquidity.signum() <= 0) {
                continue;
            }
            String holder = i < MAX_POSITIONS ? ownerOf(r, ranked.get(i).getKey(), ranked.get(i).getValue().getKey()) : null;
            if (holder == null) {
                unnamed = unnamed.add(liquidity);
            } else {
                holders.merge(holder, liquidity, BigInteger::add);
            }
        }
        BigInteger total = unnamed;
        BigInteger burned = BigInteger.ZERO;
        for (Map.Entry<String, BigInteger> e : holders.entrySet()) {
            if (e.getValue().signum() > 0) {
                total = total.add(e.getValue());
                if (NOBODY.contains(e.getKey())) {
                    burned = burned.add(e.getValue());
                }
            }
        }
        List<Map.Entry<String, BigInteger>> top = largest(holders, pool, 1);
        String topHolder = top.isEmpty() ? null : top.getFirst().getKey();
        return Holders.liquidity(burned, top.isEmpty() ? null : top.getFirst().getValue(), topHolder != null && wallet(r.code(topHolder)),
                total, burnedPct);
    }

    /**
     * The NFT positions behind a contract's pool events, if it is a position manager: its events in the same blocks,
     * matched by transaction and amount. Empty when none match (the contract holds the liquidity itself, a vault for
     * example).
     *
     * @throws NotCheckedException when some match and some do not (positions could not all be named)
     */
    private static Map<BigInteger, BigInteger> nftsOf(Reader r, String manager, List<Change> in, List<Change> out, Calls calls) {
        Set<Long> blocks = new TreeSet<>();
        in.forEach(c -> blocks.add(c.block()));
        out.forEach(c -> blocks.add(c.block()));
        List<Log> increases = new ArrayList<>();
        List<Log> decreases = new ArrayList<>();
        for (long block : blocks) {
            if (!calls.take()) {
                throw new NotCheckedException("out of calls for positions");
            }
            for (Log l : r.logs(manager, null, block, block)) {
                if (l.topics().size() >= 2 && l.data() != null && l.data().length() >= 2 + 64) {
                    if (INCREASE_TOPIC.equalsIgnoreCase(l.topics().getFirst())) {
                        increases.add(l);
                    } else if (DECREASE_TOPIC.equalsIgnoreCase(l.topics().getFirst())) {
                        decreases.add(l);
                    }
                }
            }
        }
        Map<BigInteger, BigInteger> byNft = new LinkedHashMap<>();
        int matched = 0;
        int unmatched = 0;
        for (Change c : in) {
            Log l = take(increases, c);
            if (l == null) {
                unmatched++;
            } else {
                matched++;
                byNft.merge(uint(l.topics().get(1)), c.amount(), BigInteger::add);
            }
        }
        for (Change c : out) {
            Log l = take(decreases, c);
            if (l == null) {
                unmatched++;
            } else {
                matched++;
                byNft.merge(uint(l.topics().get(1)), c.amount().negate(), BigInteger::add);
            }
        }
        if (matched == 0) {
            return Map.of();
        }
        if (unmatched > 0) {
            throw new NotCheckedException("positions not all matched");
        }
        return byNft;
    }

    /** Removes and returns the manager event of the same transaction with the same liquidity, or null. */
    private static Log take(List<Log> events, Change c) {
        for (int i = 0; i < events.size(); i++) {
            Log l = events.get(i);
            if (l.tx() != null && l.tx().equalsIgnoreCase(c.tx()) && word(l.data(), 0).equals(c.amount())) {
                return events.remove(i);
            }
        }
        return null;
    }

    private static String ownerOf(Reader r, String manager, BigInteger tokenId) {
        String result = r.call(manager, "0x" + OWNER_OF + hex64(tokenId));
        String h = result == null ? "" : result.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        return h.length() < 64 ? null : "0x" + h.substring(24, 64);
    }

    private static BigInteger sum(List<Change> changes) {
        return changes.stream().map(Change::amount).reduce(BigInteger.ZERO, BigInteger::add);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    /** The largest positive balances, leaving out the zero and dead addresses and the contract itself. */
    private static List<Map.Entry<String, BigInteger>> largest(Map<String, BigInteger> balances, String self, int n) {
        return balances.entrySet().stream()
                .filter(e -> e.getValue().signum() > 0 && !NOBODY.contains(e.getKey()) && !e.getKey().equalsIgnoreCase(self))
                .sorted(Map.Entry.<String, BigInteger>comparingByValue(Comparator.reverseOrder()))
                .limit(n)
                .toList();
    }

    /** An ordinary wallet: no code, or only an EIP-7702 delegation (0xef0100 + address). */
    public static boolean wallet(String code) {
        String c = code == null ? "" : code.toLowerCase(Locale.ROOT);
        return c.isEmpty() || c.equals("0x") || c.startsWith("0xef0100");
    }

    private static BigInteger uint(String result) {
        if (result == null) {
            return null;
        }
        String h = result.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        return h.length() < 64 ? null : new BigInteger(h.substring(0, 64), 16);
    }

    /** The {@code i}-th 32-byte word of event data. */
    public static BigInteger word(String data, int i) {
        String h = data.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        return new BigInteger(h.substring(i * 64, i * 64 + 64), 16);
    }

    private static String hex64(BigInteger v) {
        String h = v.toString(16);
        return "0".repeat(Math.max(0, 64 - h.length())) + h;
    }

    /** An address from a 32-byte log topic. */
    public static String topicAddress(String topic) {
        String h = topic.toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        return "0x" + h.substring(h.length() - 40);
    }
}
