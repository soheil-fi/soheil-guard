package com.soheil.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import com.soheil.dex.common.Base58;
import com.soheil.dex.common.TonAddress;

/** Solana age and liquidity, Sui coins, TON jettons, Tron addresses and the shared holder rules: no network. */
class GuardNetworksTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private static List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    private static String key(int fill) {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) fill);
        return Base58.encode(b);
    }

    // ---- shared rules -------------------------------------------------------------------------------------------------

    @Test
    void holderRules() {
        BigInteger supply = BigInteger.valueOf(1000);
        assertThat(codes(Holders.judge(List.of(BigInteger.valueOf(50), BigInteger.valueOf(300)), supply, 20, 50))).containsExactly("TOP_WALLET");
        assertThat(codes(Holders.judge(List.of(), supply, 20, 50))).containsExactly("HOLDERS_SPREAD");
        assertThatThrownBy(() -> Holders.judge(List.of(), BigInteger.ZERO, 20, 50)).isInstanceOf(NotCheckedException.class);

        assertThat(codes(Holders.liquidity(BigInteger.valueOf(950), null, false, supply, 90))).containsExactly("LIQUIDITY_BURNED");
        assertThat(codes(Holders.liquidity(BigInteger.ZERO, BigInteger.valueOf(700), true, supply, 90))).containsExactly("LIQUIDITY_WALLET");
        assertThat(codes(Holders.liquidity(BigInteger.ZERO, BigInteger.valueOf(700), false, supply, 90))).containsExactly("LIQUIDITY_CONTRACT");
        assertThatThrownBy(() -> Holders.liquidity(BigInteger.ZERO, null, true, supply, 90)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void base58AndTronAddresses() {
        assertThat(Base58.encode(new byte[32])).isEqualTo("11111111111111111111111111111111"); // the System Program
        assertThat(Base58.encode(Base58.decode(key(7)))).isEqualTo(key(7));
        assertThat(Base58.decode(key(7)).length).isEqualTo(32);
        // USDT on Tron
        assertThat(Base58.tronToHex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")).isEqualTo("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c");
        assertThat(Base58.tronFromHex("0xa614f803b6fd780986a42c78ec9c7f77e6ded13c")).isEqualTo("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assertThat(Base58.tronFromHex("41a614f803b6fd780986a42c78ec9c7f77e6ded13c")).isEqualTo("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assertThatThrownBy(() -> Base58.tronToHex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u")).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- Solana -------------------------------------------------------------------------------------------------------

    private static final String MINT = key(7);
    private static final String POOL = key(8);
    private static final String LP_MINT = key(9);
    private static final String VAULT = key(10);
    private static final String WALLET = key(11);
    private static final String LP_ACCOUNT = key(12);
    private static final String LP_OWNER = key(13);
    private static final String SYSTEM = SolanaMintCheck.SYSTEM_PROGRAM;

    /** A Solana node answering from fixed accounts: who owns which account, token balances, pools and mints. */
    private static final class FakeSolana implements SolanaMintCheck.Reader {
        final Map<String, String> largest = new java.util.HashMap<>();   // mint -> getTokenLargestAccounts body
        final Map<String, String> tokenOwner = new java.util.HashMap<>(); // token account -> owner
        final Map<String, String> program = new java.util.HashMap<>();    // account -> owning program
        final Map<String, String> info = new java.util.HashMap<>();       // getAccountInfo bodies
        final Map<String, String> byVault = new java.util.HashMap<>();    // "program|offset|vault" -> pool
        final Map<String, String> positions = new java.util.HashMap<>();  // "program|offset|pool" -> getProgramAccounts body
        List<String> signaturePages = List.of();
        int calls;

        @Override
        @SuppressWarnings("unchecked")
        public JsonNode result(String method, List<Object> params) {
            String body = switch (method) {
                case "getTokenLargestAccounts" -> largest.getOrDefault((String) params.get(0), "{\"value\":[]}");
                case "getMultipleAccounts" -> {
                    List<String> accounts = (List<String>) params.get(0);
                    boolean parsed = "jsonParsed".equals(((Map<String, Object>) params.get(1)).get("encoding"));
                    StringBuilder sb = new StringBuilder("{\"value\":[");
                    for (int i = 0; i < accounts.size(); i++) {
                        sb.append(i > 0 ? "," : "").append(parsed
                                ? "{\"data\":{\"parsed\":{\"info\":{\"owner\":\"" + tokenOwner.get(accounts.get(i)) + "\"}}}}"
                                : program.containsKey(accounts.get(i)) ? "{\"owner\":\"" + program.get(accounts.get(i)) + "\"}" : "null");
                    }
                    yield sb.append("]}").toString();
                }
                case "getAccountInfo" -> info.getOrDefault((String) params.get(0), "{\"value\":null}");
                case "getProgramAccounts" -> {
                    Map<String, Object> opts = (Map<String, Object>) params.get(1);
                    List<Object> filters = (List<Object>) opts.get("filters");
                    if (filters.size() == 2) { // positions of a pool: discriminator and pool
                        Map<String, Object> pool = (Map<String, Object>) ((Map<String, Object>) filters.get(1)).get("memcmp");
                        yield positions.getOrDefault(params.get(0) + "|" + pool.get("offset") + "|" + pool.get("bytes"), "[]");
                    }
                    Map<String, Object> memcmp = (Map<String, Object>) ((Map<String, Object>) filters.get(0)).get("memcmp");
                    String pool = byVault.get(params.get(0) + "|" + memcmp.get("offset") + "|" + memcmp.get("bytes"));
                    yield pool == null ? "[]" : "[{\"pubkey\":\"" + pool + "\"}]";
                }
                case "getSignaturesForAddress" -> {
                    calls++;
                    Map<String, Object> opts = (Map<String, Object>) params.get(1);
                    int page = opts.containsKey("before") ? Integer.parseInt(((String) opts.get("before")).substring(1)) : 0;
                    yield page < signaturePages.size() ? signaturePages.get(page) : "[]";
                }
                default -> throw new IllegalArgumentException(method);
            };
            return JSON.readTree(body);
        }
    }

    private static byte[] poolData(SolanaHistory.Layout layout, String mintA, String mintB, String lpMint, long lpSupply) {
        byte[] d = new byte[layout.minLength()];
        put(d, layout.mintA(), mintA);
        put(d, layout.mintB(), mintB);
        put(d, layout.lpMint(), lpMint);
        for (int i = 0; i < 8; i++) {
            d[layout.lpSupply() + i] = (byte) (lpSupply >>> (8 * i));
        }
        return d;
    }

    private static void put(byte[] d, int offset, String key) {
        System.arraycopy(Base58.decode(key), 0, d, offset, 32);
    }

    private static String account(String program, byte[] data) {
        return "{\"value\":{\"owner\":\"" + program + "\",\"data\":[\"" + Base64.getEncoder().encodeToString(data) + "\",\"base64\"]}}";
    }

    private static String mintInfo(long supply) {
        return "{\"value\":{\"data\":{\"parsed\":{\"type\":\"mint\",\"info\":{\"supply\":\"" + supply + "\"}}}}}";
    }

    private static FakeSolana pumpSwap(long lpSupply, long lpExists) {
        FakeSolana s = new FakeSolana();
        s.largest.put(MINT, "{\"value\":[{\"address\":\"" + VAULT + "\",\"amount\":\"900\"},{\"address\":\"" + WALLET + "\",\"amount\":\"100\"}]}");
        s.tokenOwner.put(VAULT, POOL);
        s.tokenOwner.put(WALLET, WALLET);
        s.program.put(POOL, SolanaHistory.PUMP_AMM);
        s.program.put(WALLET, SYSTEM);
        s.info.put(POOL, account(SolanaHistory.PUMP_AMM, poolData(SolanaHistory.PUMP_POOL, MINT, key(1), LP_MINT, lpSupply)));
        s.info.put(LP_MINT, mintInfo(lpExists));
        s.largest.put(LP_MINT, "{\"value\":[{\"address\":\"" + LP_ACCOUNT + "\",\"amount\":\"" + lpExists + "\"}]}");
        s.tokenOwner.put(LP_ACCOUNT, LP_OWNER);
        s.program.put(LP_OWNER, SYSTEM);
        return s;
    }

    @Test
    void solanaPoolLiquidityBurnedOrHeld() {
        List<Finding> burned = SolanaHistory.liquidity(pumpSwap(1000, 30), MINT, 90);
        assertThat(codes(burned)).containsExactly("LIQUIDITY_BURNED");
        assertThat(burned.getFirst().params()).containsEntry("pct", "97");

        List<Finding> wallet = SolanaHistory.liquidity(pumpSwap(1000, 800), MINT, 90);
        assertThat(codes(wallet)).containsExactly("LIQUIDITY_WALLET");
        assertThat(wallet.getFirst().params()).containsEntry("pct", "80");

        FakeSolana locked = pumpSwap(1000, 800);
        locked.program.put(LP_OWNER, "LockerProgram1111111111111111111111111111111");
        assertThat(codes(SolanaHistory.liquidity(locked, MINT, 90))).containsExactly("LIQUIDITY_CONTRACT");

        // A pool of other tokens at that address is never taken as this token's pool
        FakeSolana other = pumpSwap(1000, 800);
        other.info.put(POOL, account(SolanaHistory.PUMP_AMM, poolData(SolanaHistory.PUMP_POOL, key(2), key(1), LP_MINT, 1000)));
        assertThatThrownBy(() -> SolanaHistory.liquidity(other, MINT, 90)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void solanaLaunchCurveAndRaydium() {
        FakeSolana curve = pumpSwap(1000, 800);
        curve.program.put(POOL, SolanaHistory.PUMP_CURVE);
        assertThat(codes(SolanaHistory.liquidity(curve, MINT, 90))).containsExactly("LIQUIDITY_CURVE");

        // Raydium AMM v4: the vault belongs to Raydium's authority; the pool is found by its vault
        FakeSolana ray = pumpSwap(1000, 50);
        ray.tokenOwner.put(VAULT, SolanaHistory.RAYDIUM_V4_AUTHORITY);
        ray.byVault.put(SolanaHistory.RAYDIUM_V4 + "|" + SolanaHistory.RAYDIUM_V4_POOL.vaultB() + "|" + VAULT, POOL);
        ray.info.put(POOL, account(SolanaHistory.RAYDIUM_V4, poolData(SolanaHistory.RAYDIUM_V4_POOL, key(1), MINT, LP_MINT, 1000)));
        List<Finding> f = SolanaHistory.liquidity(ray, MINT, 90);
        assertThat(codes(f)).containsExactly("LIQUIDITY_BURNED");
        assertThat(f.getFirst().params()).containsEntry("pct", "95");

        // No pool of a kind we read: not checked
        FakeSolana none = pumpSwap(1000, 800);
        none.program.put(POOL, "SomeOtherAmm11111111111111111111111111111111");
        assertThatThrownBy(() -> SolanaHistory.liquidity(none, MINT, 90)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void concentratedPoolsNameTheLargestPositionsHolder() {
        SolanaHistory.Clmm c = SolanaHistory.ORCA;
        String nftBig = key(20);
        String nftSmall = key(21);
        String holderAccount = key(22);
        // Pool: our mint as A, its vault the token account we found it by, 1500 in range at tick 10
        byte[] pool = new byte[c.poolLength()];
        System.arraycopy(SolanaHistory.discriminator(c.poolName()), 0, pool, 0, 8);
        put(pool, c.mintA(), MINT);
        put(pool, c.mintB(), key(1));
        put(pool, c.vaultA(), VAULT);
        le(pool, c.liquidity(), 1500, 16);
        le(pool, c.tick(), 10, 4);

        FakeSolana s = new FakeSolana();
        s.info.put(POOL, account(c.program(), pool));
        String positions = "[" + position(c, nftBig, 1000, 0, 20) + "," + position(c, nftSmall, 500, -5, 15) + ","
                + position(c, key(23), 700, 50, 60) + "]"; // out of range: not in the pool's liquidity
        s.positions.put(c.program() + "|" + c.posPool() + "|" + POOL, positions);
        s.largest.put(nftBig, "{\"value\":[{\"address\":\"" + holderAccount + "\",\"amount\":\"1\"}]}");
        s.tokenOwner.put(holderAccount, WALLET);
        s.program.put(WALLET, SYSTEM);
        List<Finding> f = SolanaHistory.concentrated(s, POOL, VAULT, c, MINT, 90);
        assertThat(codes(f)).containsExactly("LIQUIDITY_WALLET");
        assertThat(f.getFirst().params()).containsEntry("pct", "45.5"); // 1000 of 2200

        // Held by a program address (a locker): information only
        s.program.put(WALLET, "Lock1111111111111111111111111111111111111111");
        assertThat(codes(SolanaHistory.concentrated(s, POOL, VAULT, c, MINT, 90))).containsExactly("LIQUIDITY_CONTRACT");

        // In-range positions that do not add up to the pool's liquidity: the layout is not trusted
        le(pool, c.liquidity(), 1499, 16);
        s.info.put(POOL, account(c.program(), pool));
        assertThatThrownBy(() -> SolanaHistory.concentrated(s, POOL, VAULT, c, MINT, 90)).isInstanceOf(NotCheckedException.class);
        le(pool, c.liquidity(), 1500, 16);
        s.info.put(POOL, account(c.program(), pool));

        // The largest position's address not derived from its mint: not checked
        s.positions.put(c.program() + "|" + c.posPool() + "|" + POOL,
                "[{\"pubkey\":\"" + key(30) + "\",\"account\":{\"data\":[\"" + slice(c, nftBig, 1000, 0, 20) + "\",\"base64\"]}}]");
        le(pool, c.liquidity(), 1000, 16);
        s.info.put(POOL, account(c.program(), pool));
        assertThatThrownBy(() -> SolanaHistory.concentrated(s, POOL, VAULT, c, MINT, 90)).isInstanceOf(NotCheckedException.class);

        // Found by a token account that is not the pool's vault for our mint: not checked
        assertThatThrownBy(() -> SolanaHistory.concentrated(s, POOL, key(31), c, MINT, 90)).isInstanceOf(NotCheckedException.class);
        // Raydium CLMM's offsets fit their slice
        assertThat(SolanaHistory.RAYDIUM_CL.sliceLength()).isEqualTo(81 + 16 - 9);
        assertThat(SolanaHistory.ORCA.sliceLength()).isEqualTo(96 - 40);
    }

    private static String position(SolanaHistory.Clmm c, String nft, long liquidity, int lower, int upper) {
        return "{\"pubkey\":\"" + SolanaHistory.positionAddress(nft, c) + "\",\"account\":{\"data\":[\"" + slice(c, nft, liquidity, lower, upper)
                + "\",\"base64\"]}}";
    }

    /** What getProgramAccounts returns for a position with a data slice from its NFT mint. */
    private static String slice(SolanaHistory.Clmm c, String nft, long liquidity, int lower, int upper) {
        byte[] d = new byte[c.sliceLength()];
        put(d, 0, nft);
        le(d, c.posLiquidity() - c.posMint(), liquidity, 16);
        le(d, c.posTickLower() - c.posMint(), lower, 4);
        le(d, c.posTickUpper() - c.posMint(), upper, 4);
        return Base64.getEncoder().encodeToString(d);
    }

    /** Writes {@code v} little-endian over {@code n} bytes (sign-extended, for ticks). */
    private static void le(byte[] d, int offset, long v, int n) {
        for (int i = 0; i < n; i++) {
            d[offset + i] = i < 8 ? (byte) (v >>> (8 * i)) : (byte) (v < 0 ? 0xff : 0);
        }
    }

    @Test
    void solanaAge() {
        FakeSolana s = new FakeSolana();
        s.signaturePages = List.of("[{\"signature\":\"x3\",\"blockTime\":300},{\"signature\":\"x2\",\"blockTime\":200},{\"signature\":\"x1\",\"blockTime\":100}]");
        assertThat(SolanaHistory.age(s, MINT, 4)).isEqualTo(new SolanaHistory.Age(100, true));

        // More history than the pages allow: only a lower bound
        List<String> pages = new ArrayList<>();
        for (int p = 0; p < 2; p++) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < 1000; i++) {
                sb.append(i > 0 ? "," : "").append("{\"signature\":\"p").append(p + 1).append("\",\"blockTime\":").append(10_000 - p * 1000 - i).append("}");
            }
            pages.add(sb.append("]").toString());
        }
        s.signaturePages = pages;
        assertThat(SolanaHistory.age(s, MINT, 2)).isEqualTo(new SolanaHistory.Age(8001, false));
        // With more pages allowed, a busy token is read until the bound: the oldest seen after page one (9001)
        // is before 9500, so reading stops there; a bound further back reads on to the end (exact)
        s.calls = 0;
        assertThat(SolanaHistory.age(s, MINT, 20, 9500)).isEqualTo(new SolanaHistory.Age(9001, false));
        assertThat(s.calls).isEqualTo(1);
        assertThat(SolanaHistory.age(s, MINT, 20, 0)).isEqualTo(new SolanaHistory.Age(8001, true));

        s.signaturePages = List.of("[{\"signature\":\"x1\",\"blockTime\":null}]");
        assertThatThrownBy(() -> SolanaHistory.age(s, MINT, 4)).isInstanceOf(NotCheckedException.class);
    }

    // ---- Sui ----------------------------------------------------------------------------------------------------------

    private static final String COIN = "0xabc::meme::MEME";

    private static SolanaMintCheck.Reader sui(String capOwner, String denyOwner) {
        return (method, params) -> {
            String id = (String) params.get(0);
            String body = switch (method) {
                case "sui_getObject" -> switch (id) {
                    case "0xabc" -> "{\"data\":{\"previousTransaction\":\"D1\"}}";
                    case "0xcap" -> capOwner == null ? "{\"error\":{\"code\":\"deleted\"}}" : "{\"data\":{\"owner\":" + capOwner + "}}";
                    case "0xdeny" -> "{\"data\":{\"owner\":" + denyOwner + "}}";
                    default -> "{\"error\":{\"code\":\"notExists\"}}";
                };
                case "sui_getTransactionBlock" -> """
                        {"timestampMs":"1700000000000","objectChanges":[
                          {"type":"published","packageId":"0xabc"},
                          {"type":"created","objectType":"0x2::coin::TreasuryCap<0x0000000000000000000000000000000000000000000000000000000000000abc::meme::MEME>","objectId":"0xcap"},
                          {"type":"created","objectType":"0x0000000000000000000000000000000000000000000000000000000000000002::coin::DenyCapV2<0xabc::meme::MEME>","objectId":"0xdeny"},
                          {"type":"created","objectType":"0x2::coin::TreasuryCap<0xabc::other::OTHER>","objectId":"0xelse"}]}
                        """;
                default -> throw new IllegalArgumentException(method);
            };
            JsonNode n = JSON.readTree(body);
            return n;
        };
    }

    @Test
    void suiTreasuryAndDenyCaps() {
        SuiCoinCheck.Result frozen = SuiCoinCheck.check(sui("\"Immutable\"", "\"Immutable\""), COIN);
        assertThat(codes(frozen.findings())).containsExactly("MINT_FIXED");
        assertThat(frozen.complete()).isTrue();
        assertThat(frozen.createdMs()).isEqualTo(1_700_000_000_000L);

        SuiCoinCheck.Result owned = SuiCoinCheck.check(sui("{\"AddressOwner\":\"0xdev\"}", "{\"AddressOwner\":\"0xdev\"}"), COIN);
        assertThat(codes(owned.findings())).containsExactly("CAN_MINT", "CAN_BLACKLIST");
        assertThat(owned.findings().getFirst().params()).containsEntry("by", "owner").containsEntry("owner", "0xdev");

        SuiCoinCheck.Result shared = SuiCoinCheck.check(sui("{\"Shared\":{\"initial_shared_version\":1}}", "\"Immutable\""), COIN);
        assertThat(codes(shared.findings())).containsExactly("CAN_MINT");
        assertThat(shared.findings().getFirst().params()).containsEntry("by", "unknown");

        // Wrapped into another object: who can mint is not visible, so the supply is never called fixed
        SuiCoinCheck.Result wrapped = SuiCoinCheck.check(sui(null, "\"Immutable\""), COIN);
        assertThat(wrapped.findings()).isEmpty();
        assertThat(wrapped.complete()).isFalse();

        assertThat(SuiCoinCheck.normalize("0x0000000000000000000000000000000000000000000000000000000000000002::coin::TreasuryCap<0x0ABC::m::N>"))
                .isEqualTo("0x2::coin::treasurycap<0xabc::m::n>");
    }

    // ---- TON ----------------------------------------------------------------------------------------------------------

    private static final String RAW_ADMIN = "0:" + "ab".repeat(32);

    private static TonJettonCheck.Reader ton(String jetton) {
        return path -> {
            if (path.equals("/v2/jettons/EQjetton")) {
                return JSON.readTree(jetton);
            }
            if (path.equals("/v2/jettons/EQjetton/holders?limit=20")) {
                return JSON.readTree("""
                        {"addresses":[
                          {"address":"0:01","owner":{"address":"0:pool","is_wallet":false},"balance":"600"},
                          {"address":"0:02","owner":{"address":"0:whale","is_wallet":true},"balance":"300"},
                          {"address":"0:03","owner":{"address":"0:small","is_wallet":true},"balance":"10"}],"total":3}
                        """);
            }
            if (path.equals("/v2/blockchain/accounts/EQjetton/transactions?limit=1&sort_order=asc")) {
                return JSON.readTree("{\"transactions\":[{\"utime\":1700000000}]}");
            }
            throw new IllegalArgumentException(path);
        };
    }

    @Test
    void tonJettonAdminHoldersAndAge() {
        TonJettonCheck.Reader noAdmin = ton("{\"mintable\":true,\"total_supply\":\"1000\"}");
        assertThat(codes(TonJettonCheck.powers(TonJettonCheck.jetton(noAdmin, "EQjetton")))).containsExactly("OWNER_RENOUNCED", "MINT_FIXED");

        TonJettonCheck.Reader admin = ton("{\"mintable\":true,\"total_supply\":\"1000\",\"admin\":{\"address\":\"" + RAW_ADMIN + "\",\"is_wallet\":true}}");
        List<Finding> powers = TonJettonCheck.powers(TonJettonCheck.jetton(admin, "EQjetton"));
        assertThat(codes(powers)).containsExactly("CAN_MINT");
        assertThat(powers.getFirst().params()).containsEntry("owner", TonAddress.friendly(RAW_ADMIN, false));

        TonJettonCheck.Reader closed = ton("{\"mintable\":false,\"total_supply\":\"1000\",\"admin\":{\"address\":\"" + RAW_ADMIN + "\"}}");
        assertThat(codes(TonJettonCheck.powers(TonJettonCheck.jetton(closed, "EQjetton")))).containsExactly("MINT_FIXED");

        // The pool's 60% is not a whale; the wallet's 30% is
        List<Finding> holders = TonJettonCheck.holders(admin, "EQjetton", TonJettonCheck.jetton(admin, "EQjetton"), 20, 50);
        assertThat(codes(holders)).containsExactly("TOP_WALLET");
        assertThat(holders.getFirst().params()).containsEntry("pct", "30");

        assertThat(TonJettonCheck.created(admin, "EQjetton")).isEqualTo(1_700_000_000L);
        assertThatThrownBy(() -> TonJettonCheck.jetton(ton("{\"error\":\"not found\"}"), "EQjetton")).isInstanceOf(NotCheckedException.class);
    }

    // ---- Ankr's indexed holders -----------------------------------------------------------------------------------

    @Test
    void indexedHoldersFromAnkr() {
        Map<String, BigInteger> top = TokenHistory.indexedHolders(JSON.readTree("""
                {"id":1,"jsonrpc":"2.0","result":{"blockchain":"base","tokenDecimals":6,"holders":[
                  {"holderAddress":"0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb","balance":"234813828.743648","balanceRawInteger":"234813828743648"},
                  {"holderAddress":"0xb026BA5501c9fcDB5b4B746c37e349cd61B81B22","balance":"158707881.660177","balanceRawInteger":"158707881660177"},
                  {"holderAddress":"not-an-address","balanceRawInteger":"5"}]}}
                """));
        assertThat(top).containsEntry("0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb", new BigInteger("234813828743648"))
                .containsEntry("0xb026ba5501c9fcdb5b4b746c37e349cd61b81b22", new BigInteger("158707881660177"));
        assertThat(top.size()).isEqualTo(2);
        // A chain Ankr does not index, or a refused key: no answer, so the log scan takes over
        assertThat(TokenHistory.indexedHolders(JSON.readTree("{\"error\":\"message: API key is not allowed to access blockchain\"}"))).isNull();
        assertThat(TokenHistory.indexedHolders(JSON.readTree("{\"result\":{\"holders\":[]}}"))).isNull();
    }
}
