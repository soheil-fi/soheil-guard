package com.soheil.guard;

import java.math.BigInteger;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;

import com.soheil.dex.common.Base58;
import com.soheil.dex.common.SolanaAddress;

/**
 * A Solana token's age and pool liquidity, read from the chain.
 *
 * Age: the mint's oldest transaction, paging back through its signatures; a mint with more history than the pages
 * allow gets a lower bound only.
 *
 * Liquidity: the pool is found from the token's largest accounts (a pool's vault is among them): a pump.fun launch
 * curve (its liquidity cannot be pulled), a PumpSwap pool, or a Raydium AMM v4 or CPMM pool. For a pool, the share
 * of its liquidity tokens that was burned (the program's own count minus what still exists), else who holds the most
 * of them. Concentrated pools (Orca Whirlpool, Raydium CLMM) have positions instead of a liquidity token: the
 * largest position's owner (the holder of its NFT). Their layouts prove themselves on every read: each position's
 * address must be derived from the NFT mint read at its offset, and the in-range positions must add up to the pool's
 * own liquidity; otherwise the part is not checked. Other pool kinds are not checked.
 */
public final class SolanaHistory {

    public static final String PUMP_CURVE = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
    public static final String PUMP_AMM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";
    public static final String RAYDIUM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    public static final String RAYDIUM_V4_AUTHORITY = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1";
    public static final String RAYDIUM_CPMM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
    public static final String RAYDIUM_CPMM_AUTHORITY = "GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL";
    private static final int PAGE = 1000;

    /** A pool layout: where its two mints, its liquidity mint and the program's count of liquidity tokens are. */
    public record Layout(String program, int minLength, int mintA, int mintB, int lpMint, int lpSupply, int vaultA, int vaultB) {
    }

    public static final String ORCA_WHIRLPOOL = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
    public static final String RAYDIUM_CLMM = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";

    /**
     * A concentrated pool layout (Anchor accounts): the pool account's name, mints, vaults, its in-range liquidity
     * (u128) and current tick (i32); the position account's name and where its pool, NFT mint, liquidity and tick
     * range are. Positions are found by their discriminator and pool; the NFT mint, liquidity and ticks are read in one
     * slice from {@code posMint}.
     */
    public record Clmm(String program, String poolName, int mintA, int mintB, int vaultA, int vaultB, int liquidity, int tick,
                String positionName, int posPool, int posMint, int posLiquidity, int posTickLower, int posTickUpper) {
        /** The pool account's bytes needed to read every field. */
        int poolLength() {
            return Math.max(Math.max(Math.max(mintA, mintB), Math.max(vaultA, vaultB)) + 32, Math.max(liquidity + 16, tick + 4));
        }

        int sliceLength() {
            return Math.max(posLiquidity + 16, Math.max(posTickLower, posTickUpper) + 4) - posMint;
        }
    }

    /** Orca Whirlpool: config, bump, tick spacing (+seed), fees, then liquidity, price, tick, fees owed, mint/vault A and B. */
    public static final Clmm ORCA = new Clmm(ORCA_WHIRLPOOL, "Whirlpool", 101, 181, 133, 213, 49, 81,
            "Position", 8, 40, 72, 88, 92);
    /** Raydium CLMM: bump, config, owner, mints, vaults, observation, decimals, tick spacing, then liquidity, price, tick. */
    public static final Clmm RAYDIUM_CL = new Clmm(RAYDIUM_CLMM, "PoolState", 73, 105, 137, 169, 237, 269,
            "PersonalPositionState", 41, 9, 81, 73, 77);
    /** Positions read for a pool at most (the largest decide who controls it). */
    public static final int MAX_POSITIONS = 5_000;

    /** PumpSwap pool (Anchor account: 8-byte discriminator, bump, index, creator, then these). */
    public static final Layout PUMP_POOL = new Layout(PUMP_AMM, 211, 43, 75, 107, 203, 139, 171);
    /** Raydium AMM v4 (752 bytes, no discriminator). */
    public static final Layout RAYDIUM_V4_POOL = new Layout(RAYDIUM_V4, 752, 400, 432, 464, 720, 336, 368);
    /** Raydium CPMM pool state (Anchor account). */
    public static final Layout RAYDIUM_CPMM_POOL = new Layout(RAYDIUM_CPMM, 341, 168, 200, 136, 333, 72, 104);

    /** When the mint was created, or a lower bound when its history goes back further than the pages read. */
    public record Age(long seconds, boolean exact) {
    }

    private SolanaHistory() {
    }

    // ---- age ------------------------------------------------------------------------------------------------------

    /** @throws NotCheckedException when the mint has no dated transaction */
    public static Age age(SolanaMintCheck.Reader r, String mint, int maxPages) {
        return age(r, mint, maxPages, 0);
    }

    /**
     * Pages back through the mint's signatures until its first transaction, or until the oldest one seen is already
     * before {@code oldEnoughSeconds} (then a lower bound is all the caller needs: the token is not young), or until
     * {@code maxPages} pages were read. A busy young token has few pages; a busy old one stops at the bound.
     *
     * @throws NotCheckedException when the mint has no dated transaction
     */
    public static Age age(SolanaMintCheck.Reader r, String mint, int maxPages, long oldEnoughSeconds) {
        String before = null;
        Long oldest = null;
        for (int page = 0; page < maxPages; page++) {
            if (oldest != null && oldest < oldEnoughSeconds) {
                break;
            }
            Map<String, Object> opts = new HashMap<>(Map.of("limit", PAGE, "commitment", "confirmed"));
            if (before != null) {
                opts.put("before", before);
            }
            JsonNode sigs = r.result("getSignaturesForAddress", List.of(mint, opts));
            if (!sigs.isArray() || sigs.isEmpty()) {
                if (oldest != null) {
                    return new Age(oldest, true); // the previous page was the last
                }
                break;
            }
            for (JsonNode s : sigs) {
                if (s.hasNonNull("blockTime")) {
                    oldest = s.path("blockTime").asLong();
                }
            }
            if (sigs.size() < PAGE) {
                if (oldest == null) {
                    throw new NotCheckedException("no dated transaction");
                }
                return new Age(oldest, true);
            }
            before = SolanaMintCheck.text(sigs.get(sigs.size() - 1).path("signature"));
        }
        if (oldest == null) {
            throw new NotCheckedException("no dated transaction");
        }
        return new Age(oldest, false);
    }

    // ---- liquidity ------------------------------------------------------------------------------------------------

    public static List<Finding> liquidity(SolanaMintCheck.Reader r, String mint, double burnedPct) {
        List<SolanaMintCheck.Account> accounts = SolanaMintCheck.largestAccounts(r, mint);
        List<String> owners = accounts.stream().map(SolanaMintCheck.Account::owner).toList();
        List<String> programs = SolanaMintCheck.programsOf(r, owners);
        for (int i = 0; i < accounts.size(); i++) {
            SolanaMintCheck.Account a = accounts.get(i);
            String program = programs.get(i);
            if (PUMP_CURVE.equals(program)) {
                return List.of(Finding.info("LIQUIDITY_CURVE"));
            }
            String pool = null;
            Layout layout = null;
            if (PUMP_AMM.equals(program)) {
                pool = a.owner();
                layout = PUMP_POOL;
            } else if (RAYDIUM_V4_AUTHORITY.equals(a.owner())) {
                layout = RAYDIUM_V4_POOL;
                pool = poolByVault(r, layout, a.address());
            } else if (RAYDIUM_CPMM_AUTHORITY.equals(a.owner())) {
                layout = RAYDIUM_CPMM_POOL;
                pool = poolByVault(r, layout, a.address());
            } else if (ORCA_WHIRLPOOL.equals(program)) {
                return concentrated(r, a.owner(), a.address(), ORCA, mint, burnedPct);
            } else if (RAYDIUM_CLMM.equals(program)) {
                return concentrated(r, a.owner(), a.address(), RAYDIUM_CL, mint, burnedPct);
            }
            if (pool != null) {
                return pool(r, pool, layout, mint, burnedPct);
            }
        }
        throw new NotCheckedException("no pool of a kind we check");
    }

    /** The pool of {@code layout}'s program whose vault is this token account. */
    private static String poolByVault(SolanaMintCheck.Reader r, Layout layout, String vault) {
        for (int offset : new int[] {layout.vaultA(), layout.vaultB()}) {
            JsonNode found = r.result("getProgramAccounts", List.of(layout.program(), Map.of("encoding", "base64", "commitment", "confirmed",
                    "dataSlice", Map.of("offset", 0, "length", 0),
                    "filters", List.of(Map.of("memcmp", Map.of("offset", offset, "bytes", vault))))));
            if (found.isArray() && !found.isEmpty()) {
                return SolanaMintCheck.text(found.get(0).path("pubkey"));
            }
        }
        return null;
    }

    private static List<Finding> pool(SolanaMintCheck.Reader r, String pool, Layout layout, String mint, double burnedPct) {
        JsonNode value = r.result("getAccountInfo", List.of(pool, Map.of("encoding", "base64", "commitment", "confirmed"))).path("value");
        if (!layout.program().equals(SolanaMintCheck.text(value.path("owner")))) {
            throw new NotCheckedException("pool owned by another program");
        }
        byte[] data = Base64.getDecoder().decode(value.path("data").path(0).asString(""));
        Pool p = parse(data, layout);
        if (!mint.equals(p.mintA()) && !mint.equals(p.mintB())) {
            throw new NotCheckedException("pool of other tokens");
        }
        JsonNode lp = r.result("getAccountInfo", List.of(p.lpMint(), SolanaMintCheck.PARSED)).path("value").path("data").path("parsed");
        if (!"mint".equals(lp.path("type").asString(""))) {
            throw new NotCheckedException("no liquidity mint");
        }
        BigInteger exists = new BigInteger(lp.path("info").path("supply").asString("0"));
        BigInteger burned = p.lpSupply().subtract(exists).max(BigInteger.ZERO);
        if (p.lpSupply().signum() > 0 && Holders.share(burned, p.lpSupply()).doubleValue() >= burnedPct) {
            return Holders.liquidity(burned, null, false, p.lpSupply(), burnedPct);
        }
        List<SolanaMintCheck.Account> holders = exists.signum() > 0 ? SolanaMintCheck.largestAccounts(r, p.lpMint()) : List.of();
        if (holders.isEmpty()) {
            return Holders.liquidity(burned, null, false, p.lpSupply(), burnedPct);
        }
        SolanaMintCheck.Account top = holders.getFirst();
        boolean wallet = SolanaMintCheck.SYSTEM_PROGRAM.equals(SolanaMintCheck.programsOf(r, List.of(top.owner())).getFirst());
        return Holders.liquidity(burned, top.amount(), wallet, p.lpSupply(), burnedPct);
    }

    // ---- concentrated pools -----------------------------------------------------------------------------------------

    /** A position: its NFT mint, liquidity and tick range. */
    public record Position(String address, String nftMint, BigInteger liquidity, int tickLower, int tickUpper) {
    }

    /**
     * Who controls a concentrated pool: the largest position's NFT holder (a wallet can withdraw at any time).
     *
     * @param pool  the vault's owner (these pools own their vaults)
     * @param vault the token account it was found by (must be one of the pool's vaults)
     */
    public static List<Finding> concentrated(SolanaMintCheck.Reader r, String pool, String vault, Clmm c, String mint, double burnedPct) {
        JsonNode value = r.result("getAccountInfo", List.of(pool, Map.of("encoding", "base64", "commitment", "confirmed"))).path("value");
        if (!c.program().equals(SolanaMintCheck.text(value.path("owner")))) {
            throw new NotCheckedException("pool owned by another program");
        }
        byte[] data = Base64.getDecoder().decode(value.path("data").path(0).asString(""));
        if (data.length < c.poolLength() || !startsWith(data, discriminator(c.poolName()))) {
            throw new NotCheckedException("not a " + c.poolName() + " account");
        }
        String mintA = key(data, c.mintA());
        String mintB = key(data, c.mintB());
        if (!mint.equals(mintA) && !mint.equals(mintB)) {
            throw new NotCheckedException("pool of other tokens");
        }
        if (!vault.equals(key(data, mint.equals(mintA) ? c.vaultA() : c.vaultB()))) {
            throw new NotCheckedException("layout check failed: vault");
        }
        BigInteger poolLiquidity = u128(data, c.liquidity());
        int tick = i32(data, c.tick());

        List<Position> positions = positions(r, pool, c);
        if (positions.isEmpty()) {
            throw new NotCheckedException("no positions");
        }
        BigInteger inRange = BigInteger.ZERO;
        BigInteger total = BigInteger.ZERO;
        Position top = null;
        for (Position p : positions) {
            total = total.add(p.liquidity());
            if (p.tickLower() <= tick && tick < p.tickUpper()) {
                inRange = inRange.add(p.liquidity());
            }
            if (top == null || p.liquidity().compareTo(top.liquidity()) > 0) {
                top = p;
            }
        }
        if (!inRange.equals(poolLiquidity)) {
            throw new NotCheckedException("layout check failed: liquidity " + inRange + " vs " + poolLiquidity);
        }
        if (top.liquidity().signum() <= 0) {
            throw new NotCheckedException("no liquidity");
        }
        // Its address must be derived from the NFT mint read at its offset (a bundled position has another address:
        // its holder cannot be named this way, so the part is not checked)
        if (!top.address().equals(positionAddress(top.nftMint(), c))) {
            throw new NotCheckedException("largest position not derived from its mint");
        }
        List<SolanaMintCheck.Account> holders = SolanaMintCheck.largestAccounts(r, top.nftMint());
        SolanaMintCheck.Account holder = holders.stream().filter(h -> h.amount().signum() > 0).findFirst()
                .orElseThrow(() -> new NotCheckedException("position NFT not held"));
        boolean wallet = SolanaMintCheck.SYSTEM_PROGRAM.equals(SolanaMintCheck.programsOf(r, List.of(holder.owner())).getFirst());
        return Holders.liquidity(BigInteger.ZERO, top.liquidity(), wallet, total, burnedPct);
    }

    /** The pool's positions: found by the position account's discriminator and pool, read as one slice each. */
    private static List<Position> positions(SolanaMintCheck.Reader r, String pool, Clmm c) {
        JsonNode found = r.result("getProgramAccounts", List.of(c.program(), Map.of("encoding", "base64", "commitment", "confirmed",
                "dataSlice", Map.of("offset", c.posMint(), "length", c.sliceLength()),
                "filters", List.of(
                        Map.of("memcmp", Map.of("offset", 0, "bytes", Base58.encode(discriminator(c.positionName())))),
                        Map.of("memcmp", Map.of("offset", c.posPool(), "bytes", pool))))));
        if (!found.isArray()) {
            throw new NotCheckedException("positions not readable");
        }
        if (found.size() > MAX_POSITIONS) {
            throw new NotCheckedException("too many positions");
        }
        List<Position> out = new java.util.ArrayList<>();
        for (JsonNode f : found) {
            byte[] d = Base64.getDecoder().decode(f.path("account").path("data").path(0).asString(""));
            if (d.length < c.sliceLength()) {
                throw new NotCheckedException("position data too short");
            }
            int base = c.posMint();
            out.add(new Position(SolanaMintCheck.text(f.path("pubkey")), key(d, 0), u128(d, c.posLiquidity() - base),
                    i32(d, c.posTickLower() - base), i32(d, c.posTickUpper() - base)));
        }
        return out;
    }

    /** A position's own address: the program address of ["position", NFT mint]. */
    public static String positionAddress(String nftMint, Clmm c) {
        try {
            return SolanaAddress.programAddress(new byte[][] {"position".getBytes(java.nio.charset.StandardCharsets.US_ASCII), SolanaAddress.pubkey(nftMint)}, c.program());
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** An Anchor account's discriminator: the first 8 bytes of SHA-256("account:" + name). */
    public static byte[] discriminator(String accountName) {
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(("account:" + accountName).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Arrays.copyOf(h, 8);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        return data.length >= prefix.length && java.util.Arrays.equals(java.util.Arrays.copyOf(data, prefix.length), prefix);
    }

    /** Little-endian unsigned 128-bit integer. */
    public static BigInteger u128(byte[] data, int offset) {
        byte[] be = new byte[17];
        for (int i = 0; i < 16; i++) {
            be[16 - i] = data[offset + i];
        }
        return new BigInteger(be);
    }

    /** Little-endian signed 32-bit integer. */
    public static int i32(byte[] data, int offset) {
        return (data[offset] & 0xff) | (data[offset + 1] & 0xff) << 8 | (data[offset + 2] & 0xff) << 16 | data[offset + 3] << 24;
    }

    /** A pool's mints, liquidity mint and the program's count of liquidity tokens issued. */
    public record Pool(String mintA, String mintB, String lpMint, BigInteger lpSupply) {
    }

    public static Pool parse(byte[] data, Layout layout) {
        if (data.length < layout.minLength()) {
            throw new NotCheckedException("pool data too short");
        }
        return new Pool(key(data, layout.mintA()), key(data, layout.mintB()), key(data, layout.lpMint()), u64(data, layout.lpSupply()));
    }

    private static String key(byte[] data, int offset) {
        byte[] k = new byte[32];
        System.arraycopy(data, offset, k, 0, 32);
        return Base58.encode(k);
    }

    /** Little-endian unsigned 64-bit integer. */
    private static BigInteger u64(byte[] data, int offset) {
        byte[] be = new byte[9]; // a leading zero keeps it unsigned
        for (int i = 0; i < 8; i++) {
            be[8 - i] = data[offset + i];
        }
        return new BigInteger(be);
    }
}
