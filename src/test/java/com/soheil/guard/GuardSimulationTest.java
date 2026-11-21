package com.soheil.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.soheil.dex.common.Keccak;

/** The sale test and the token history on fixed inputs: no network, no Spring. */
class GuardSimulationTest {

    private static final String TOKEN = "0x" + "11".repeat(20);
    private static final String ROUTER = "0x" + "22".repeat(20);
    private static final String NATIVE = "0x" + "ee".repeat(20);
    private static final String POOL = "0x" + "44".repeat(20);
    private static final String ALICE = "0x" + "a1".repeat(20);
    private static final String BOB = "0x" + "b0".repeat(20);
    private static final String LOCKER = "0x" + "1c".repeat(20);
    private static final String ZERO = "0x" + "00".repeat(20);
    private static final String DEAD = "0x000000000000000000000000000000000000dead";
    private static final BigInteger E18 = BigInteger.TEN.pow(18);

    private static BigInteger[] w(long stage, long received, long moved, long nativeOut) {
        return new BigInteger[] {BigInteger.valueOf(stage), BigInteger.valueOf(received), BigInteger.valueOf(moved), BigInteger.valueOf(nativeOut)};
    }

    private static List<Finding> judge(BigInteger[] words) {
        // promised: 1000 bought, 50 moved, 400 native back
        return SellSimulation.judge(words, BigInteger.valueOf(1000), BigInteger.valueOf(50), BigInteger.valueOf(400), 10, 30);
    }

    // ---- the sale test: what the helper's answer means ------------------------------------------------------------

    @Test
    void cleanTokenPasses() {
        assertThat(judge(w(5, 1000, 50, 400))).containsExactly(Finding.info("SIM_OK"));
        // under 2% is price noise, not a tax
        assertThat(judge(w(5, 990, 50, 395))).containsExactly(Finding.info("SIM_OK"));
    }

    @Test
    void taxesAreMeasuredPerStep() {
        Finding f = judge(w(5, 950, 45, 360)).getFirst(); // 5% buy, 10% transfer, 10% sell
        assertThat(f.code()).isEqualTo("SIM_TAX");
        assertThat(f.level()).isEqualTo(Finding.Level.CAUTION);
        assertThat(f.params()).containsEntry("buy", "5").containsEntry("transfer", "10").containsEntry("sell", "10");

        Finding small = judge(w(5, 960, 50, 400)).getFirst(); // 4% buy only
        assertThat(small.level()).isEqualTo(Finding.Level.INFO);
        assertThat(small.params()).containsEntry("buy", "4").containsEntry("sell", "0").containsEntry("transfer", "0");

        assertThat(judge(w(5, 1000, 50, 240)).getFirst().level()).isEqualTo(Finding.Level.RISKY); // 40% sell
    }

    @Test
    void failuresByStage() {
        assertThat(codeLevel(judge(w(0, 0, 0, 0)).getFirst())).isEqualTo("SIM_BUY_FAILS/CAUTION");
        assertThat(codeLevel(judge(w(1, 1000, 0, 0)).getFirst())).isEqualTo("SIM_TRANSFER_FAILS/RISKY");
        assertThat(judge(w(2, 1000, 50, 0)).getFirst().code()).isEqualTo("SIM_SELL_FAILS");
        assertThat(codeLevel(judge(w(4, 1000, 50, 0)).getFirst())).isEqualTo("SIM_SELL_FAILS/RISKY");
        Finding buyTax = judge(w(3, 400, 0, 0)).getFirst();
        assertThat(buyTax.code()).isEqualTo("SIM_TAX");
        assertThat(buyTax.level()).isEqualTo(Finding.Level.RISKY);
        assertThat(buyTax.params()).containsEntry("buy", "60");
        assertThatThrownBy(() -> judge(w(9, 0, 0, 0))).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void pctNeverNegative() {
        assertThat(SellSimulation.pct(BigInteger.valueOf(110), BigInteger.valueOf(100))).isZero();
        assertThat(SellSimulation.pct(BigInteger.valueOf(75), BigInteger.valueOf(100))).isEqualTo(25.0);
        assertThat(SellSimulation.pct(BigInteger.ONE, BigInteger.ZERO)).isZero();
    }

    @Test
    void encodesTheHelperCall() {
        String data = SellSimulation.encode(TOKEN, ROUTER, "0xabcdef", BigInteger.TEN, ALICE, BigInteger.TWO, ROUTER, BigInteger.ONE, "0x" + "01".repeat(33));
        String h = data.substring(2);
        assertThat(h.substring(0, 8)).isEqualTo(Keccak.selector("run(address,address,bytes,uint256,address,uint256,address,uint256,bytes)"));
        String body = h.substring(8);
        BigInteger buyOffset = new BigInteger(body.substring(2 * 64, 3 * 64), 16);
        BigInteger sellOffset = new BigInteger(body.substring(8 * 64, 9 * 64), 16);
        assertThat(buyOffset).isEqualTo(BigInteger.valueOf(288));
        assertThat(sellOffset).isEqualTo(BigInteger.valueOf(288 + 32 + 32)); // 3 bytes pad to one word
        int buyAt = buyOffset.intValue() * 2;
        assertThat(new BigInteger(body.substring(buyAt, buyAt + 64), 16)).isEqualTo(BigInteger.valueOf(3));
        assertThat(body.substring(buyAt + 64, buyAt + 70)).isEqualTo("abcdef");
        int sellAt = sellOffset.intValue() * 2;
        assertThat(new BigInteger(body.substring(sellAt, sellAt + 64), 16)).isEqualTo(BigInteger.valueOf(33));
        assertThat(body.length() % 64).isZero();
        assertThat(body.length()).isEqualTo(sellAt + 64 + 2 * 64); // 33 bytes pad to two words
        assertThatThrownBy(() -> SellSimulation.encode("0x12", ROUTER, "0x", BigInteger.ONE, ALICE, BigInteger.ONE, ROUTER, BigInteger.ONE, "0x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void readsKyberAnswers() {
        Map<String, Object> route = Map.of("routeSummary", Map.of("amountOut", "12345",
                "route", List.of(List.of(Map.of("tokenIn", NATIVE, "pool", ROUTER), Map.of("tokenIn", TOKEN.toUpperCase().replace("0X", "0x"), "pool", POOL)))));
        assertThat(SellSimulation.amountOut(route)).isEqualTo(BigInteger.valueOf(12345));
        assertThat(SellSimulation.firstPool(route, TOKEN)).isEqualTo(POOL);
        assertThat(SellSimulation.amountOut(Map.of())).isNull();
        assertThat(SellSimulation.firstPool(Map.of("routeSummary", Map.of("route", List.of(List.of(Map.of("tokenIn", TOKEN, "pool", "not-an-address"))))), TOKEN)).isNull();
    }

    @Test
    void runPutsTheHelperAtTheTesterAndJudgesItsAnswer() {
        assertThat(SellSimulation.PROBE).matches("^[0-9a-f]+$").hasSizeGreaterThan(1000);
        SellSimulation.Kyber kyber = new SellSimulation.Kyber() {
            @Override
            public Map<String, Object> routes(String in, String out, String amount) {
                BigInteger a = new BigInteger(amount);
                // 1 token = 0.001 coin both ways; the sell route goes through POOL
                BigInteger o = in.equals(TOKEN) ? a.divide(BigInteger.valueOf(1000)) : a.multiply(BigInteger.valueOf(1000));
                return Map.of("routeSummary", Map.of("amountOut", o.toString(), "route", List.of(List.of(Map.of("tokenIn", in, "pool", POOL)))));
            }

            @Override
            public Map<String, Object> build(Object routeSummary, String sender) {
                assertThat(sender).isEqualTo(SellSimulation.TESTER);
                return Map.of("routerAddress", ROUTER, "data", "0x1234", "transactionValue", "0");
            }
        };
        AtomicReference<Map<String, Map<String, String>>> seen = new AtomicReference<>();
        SellSimulation.Chain chain = (from, to, data, overrides) -> {
            seen.set(overrides);
            // stage 5, everything as promised: 1000e18 bought, 50e18 moved, 0.4 coin back
            return "0x" + word(5) + word(new BigInteger("1000").multiply(E18)) + word(new BigInteger("50").multiply(E18)) + word(new BigInteger("400000000000000000"));
        };
        SellSimulation.Result r = SellSimulation.run(kyber, chain, TOKEN, NATIVE, new BigInteger("1000").multiply(E18), 10, 30);
        assertThat(r.pool()).isEqualTo(POOL);
        assertThat(r.findings()).containsExactly(Finding.info("SIM_OK"));
        assertThat(seen.get().get(SellSimulation.TESTER)).containsEntry("code", "0x" + SellSimulation.PROBE).containsKey("balance");

        // no route: the sell test already covers it, so no finding here
        SellSimulation.Kyber none = new SellSimulation.Kyber() {
            @Override
            public Map<String, Object> routes(String in, String out, String amount) {
                return Map.of();
            }

            @Override
            public Map<String, Object> build(Object routeSummary, String sender) {
                throw new AssertionError();
            }
        };
        assertThat(SellSimulation.run(none, chain, TOKEN, NATIVE, BigInteger.TEN, 10, 30)).isNull();
    }

    private static String codeLevel(Finding f) {
        return f.code() + "/" + f.level();
    }

    private static List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    private static String word(long v) {
        return word(BigInteger.valueOf(v));
    }

    private static String word(BigInteger v) {
        String h = v.toString(16);
        return "0".repeat(64 - h.length()) + h;
    }

    // ---- token history ------------------------------------------------------------------------------------------------

    /** A chain where the token appears at block 4321 and every block is 2 seconds long. */
    private static final class FakeChain implements TokenHistory.Reader {
        /** An event of one contract (null: answered for any contract, as the Transfer events here are). */
        private record Entry(String address, TokenHistory.Log log) {
        }

        final long created = 4321;
        final long latest = 10_000;
        final List<Entry> entries = new ArrayList<>();
        final Map<String, String> codes = new HashMap<>();
        final Map<String, String> calls = new HashMap<>();
        long refuseRangesOver = Long.MAX_VALUE;

        void log(long block, String from, String to, long value) {
            entries.add(new Entry(null, new TokenHistory.Log(List.of(TokenHistory.TRANSFER_TOPIC, topic(from), topic(to)), "0x" + word(value), "tx" + block, block)));
        }

        void event(String address, long block, String tx, List<String> topics, BigInteger... data) {
            StringBuilder d = new StringBuilder("0x");
            for (BigInteger w : data) {
                d.append(word(w));
            }
            entries.add(new Entry(address, new TokenHistory.Log(topics, d.toString(), tx, block)));
        }

        @Override
        public long latestBlock() {
            return latest;
        }

        @Override
        public boolean hasCodeAt(String address, long block) {
            return block >= created;
        }

        @Override
        public long timestamp(long block) {
            return block * 2;
        }

        @Override
        public List<TokenHistory.Log> logs(String address, String topic0, long fromBlock, long toBlock) {
            if (toBlock - fromBlock + 1 > refuseRangesOver) {
                throw new IllegalStateException("range too large");
            }
            List<TokenHistory.Log> out = new ArrayList<>();
            for (Entry e : entries) {
                TokenHistory.Log l = e.log();
                if ((e.address() == null || e.address().equals(address)) && (topic0 == null || topic0.equals(l.topics().getFirst()))
                        && l.block() >= fromBlock && l.block() <= toBlock) {
                    out.add(l);
                }
            }
            return out;
        }

        @Override
        public String code(String address) {
            return codes.getOrDefault(address, "0x");
        }

        @Override
        public String call(String to, String data) {
            return calls.get(to + data);
        }
    }

    private static String topic(String address) {
        return "0x" + "0".repeat(24) + address.substring(2);
    }

    private static String balanceOf(String who) {
        return "0x" + Keccak.selector("balanceOf(address)") + "0".repeat(24) + who.substring(2);
    }

    private static final String TOTAL_SUPPLY = "0x" + Keccak.selector("totalSupply()");

    @Test
    void findsTheCreationBlock() {
        FakeChain c = new FakeChain();
        assertThat(TokenHistory.created(c, TOKEN)).isEqualTo(new TokenHistory.Created(4321, 8642));
    }

    @Test
    void ageInHoursThenDays() {
        TokenHistory.Created c = new TokenHistory.Created(1, 0);
        Finding young = TokenHistory.age(c, 5 * 3600, 72);
        assertThat(young.code()).isEqualTo("TOKEN_YOUNG");
        assertThat(young.params()).containsExactly(Map.entry("hours", "5"));
        Finding stillYoung = TokenHistory.age(c, 60 * 3600, 72);
        assertThat(stillYoung.code()).isEqualTo("TOKEN_YOUNG");
        assertThat(stillYoung.params()).containsExactly(Map.entry("days", "2"));
        Finding old = TokenHistory.age(c, 40L * 24 * 3600, 72);
        assertThat(codeLevel(old)).isEqualTo("TOKEN_AGE/INFO");
        assertThat(old.params()).containsExactly(Map.entry("days", "40"));
    }

    @Test
    void balancesFromTransfersWithAdaptiveRanges() {
        FakeChain c = new FakeChain();
        c.log(4321, ZERO, ALICE, 1000);
        c.log(5000, ALICE, BOB, 300);
        c.log(9999, BOB, ALICE, 100);
        c.refuseRangesOver = 1_000;
        Map<String, BigInteger> b = TokenHistory.balances(c, TOKEN, 4321, 10_000, 200);
        assertThat(b).containsEntry(ALICE, BigInteger.valueOf(800)).containsEntry(BOB, BigInteger.valueOf(200)).containsEntry(ZERO, BigInteger.valueOf(-1000));
        // too few calls for the range: no answer rather than a partial one
        assertThat(TokenHistory.balances(c, TOKEN, 0, 10_000, 3)).isNull();
        // an endpoint that refuses even the smallest range
        c.refuseRangesOver = 10;
        assertThat(TokenHistory.balances(c, TOKEN, 4321, 10_000, 200)).isNull();
    }

    @Test
    void holdersCountWalletsOnly() {
        FakeChain c = new FakeChain();
        c.calls.put(TOKEN + TOTAL_SUPPLY, "0x" + word(1000));
        c.codes.put(POOL, "0x6080");
        c.codes.put(BOB, "0xef0100" + "ab".repeat(20)); // an EIP-7702 wallet still counts as a wallet
        Map<String, BigInteger> b = Map.of(POOL, BigInteger.valueOf(500), ALICE, BigInteger.valueOf(400), BOB, BigInteger.valueOf(50),
                ZERO, BigInteger.valueOf(-1000), TOKEN, BigInteger.valueOf(50));
        List<Finding> f = TokenHistory.holders(c, TOKEN, b, 20, 50);
        assertThat(codes(f)).containsExactly("TOP_WALLET");
        assertThat(f.getFirst().params()).containsEntry("pct", "40");

        Map<String, BigInteger> spread = Map.of(ALICE, BigInteger.valueOf(100), BOB, BigInteger.valueOf(50));
        assertThat(codes(TokenHistory.holders(c, TOKEN, spread, 20, 50))).containsExactly("HOLDERS_SPREAD");
        assertThatThrownBy(() -> TokenHistory.holders(new FakeChain(), TOKEN, b, 20, 50)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void liquidityBurnedOrHeld() {
        FakeChain c = new FakeChain();
        c.calls.put(POOL + TOTAL_SUPPLY, "0x" + word(1000));
        c.calls.put(POOL + "0x" + Keccak.selector("getReserves()"), "0x" + word(1) + word(1) + word(1));
        c.calls.put(POOL + "0x" + Keccak.selector("token0()"), "0x" + word(1));
        c.calls.put(POOL + balanceOf(DEAD), "0x" + word(950));
        c.calls.put(POOL + balanceOf(ZERO), "0x" + word(1));
        List<Finding> burned = TokenHistory.liquidity(c, POOL, 4321, 10_000, 0, 90);
        assertThat(codes(burned)).containsExactly("LIQUIDITY_BURNED");
        assertThat(burned.getFirst().params()).containsEntry("pct", "95.1");

        // nothing burned: the largest holder decides
        c.calls.put(POOL + balanceOf(DEAD), "0x" + word(0));
        c.calls.put(POOL + balanceOf(ZERO), "0x" + word(0));
        c.log(4400, ZERO, ALICE, 800);
        c.log(4400, ZERO, LOCKER, 200);
        List<Finding> wallet = TokenHistory.liquidity(c, POOL, 4321, 10_000, 50, 90);
        assertThat(codeLevel(wallet.getFirst())).isEqualTo("LIQUIDITY_WALLET/CAUTION");
        assertThat(wallet).hasSize(1);
        assertThat(wallet.getFirst().params()).containsEntry("pct", "80");

        c.log(4500, ALICE, LOCKER, 700);
        c.codes.put(LOCKER, "0x6080");
        assertThat(codes(TokenHistory.liquidity(c, POOL, 4321, 10_000, 50, 90))).containsExactly("LIQUIDITY_CONTRACT");

        // not a V2 pool, or no budget left to read its events
        assertThatThrownBy(() -> TokenHistory.liquidity(new FakeChain(), POOL, 4321, 10_000, 50, 90)).isInstanceOf(NotCheckedException.class);
        assertThatThrownBy(() -> TokenHistory.liquidity(c, POOL, 4321, 10_000, 0, 90)).isInstanceOf(NotCheckedException.class);

        // An old pool (no event reads left): the index names the liquidity token's holders; burn addresses never count
        java.util.function.Function<String, Map<String, BigInteger>> index = pool -> pool.equals(POOL)
                ? Map.of(DEAD.toLowerCase(), BigInteger.valueOf(400), ALICE, BigInteger.valueOf(300), LOCKER, BigInteger.valueOf(100))
                : null;
        List<Finding> indexed = TokenHistory.liquidity(c, POOL, 4321, 10_000, new TokenHistory.Calls(0), 90, index);
        assertThat(codeLevel(indexed.getFirst())).isEqualTo("LIQUIDITY_WALLET/CAUTION");
        assertThat(indexed.getFirst().params()).containsEntry("pct", "30");
        // The index failing falls back to the events
        assertThatThrownBy(() -> TokenHistory.liquidity(c, POOL, 4321, 10_000, new TokenHistory.Calls(0), 90, pool -> {
            throw new IllegalStateException("ankr down");
        })).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void liquidityOfPositionsTracedToTheirNftOwners() {
        String manager = "0x" + "e1".repeat(20);
        FakeChain c = new FakeChain();
        c.calls.put(POOL + "0x" + Keccak.selector("slot0()"), "0x" + word(1));
        c.calls.put(POOL + "0x" + Keccak.selector("liquidity()"), "0x" + word(1));
        c.codes.put(manager, "0x6080");
        c.codes.put(LOCKER, "0x6080");
        BigInteger tick = BigInteger.ONE;
        // Two positions opened through the manager, part of the first one later removed
        c.event(POOL, 4400, "t1", List.of(TokenHistory.MINT_TOPIC, topic(manager), word(tick), word(tick)), BigInteger.ZERO, BigInteger.valueOf(600), BigInteger.ONE, BigInteger.ONE);
        c.event(manager, 4400, "t1", List.of(TokenHistory.INCREASE_TOPIC, "0x" + word(1)), BigInteger.valueOf(600), BigInteger.ONE, BigInteger.ONE);
        c.event(POOL, 4500, "t2", List.of(TokenHistory.MINT_TOPIC, topic(manager), word(tick), word(tick)), BigInteger.ZERO, BigInteger.valueOf(400), BigInteger.ONE, BigInteger.ONE);
        c.event(manager, 4500, "t2", List.of(TokenHistory.INCREASE_TOPIC, "0x" + word(2)), BigInteger.valueOf(400), BigInteger.ONE, BigInteger.ONE);
        c.event(POOL, 4600, "t3", List.of(TokenHistory.BURN_TOPIC, topic(manager), word(tick), word(tick)), BigInteger.valueOf(100), BigInteger.ONE, BigInteger.ONE);
        c.event(manager, 4600, "t3", List.of(TokenHistory.DECREASE_TOPIC, "0x" + word(1)), BigInteger.valueOf(100), BigInteger.ONE, BigInteger.ONE);
        // A fee collection burns zero liquidity: ignored
        c.event(POOL, 4700, "t4", List.of(TokenHistory.BURN_TOPIC, topic(manager), word(tick), word(tick)), BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE);
        String ownerOf = "0x" + Keccak.selector("ownerOf(uint256)");
        c.calls.put(manager + ownerOf + word(1), "0x" + word(new BigInteger(ALICE.substring(2), 16)));
        c.calls.put(manager + ownerOf + word(2), "0x" + word(new BigInteger(LOCKER.substring(2), 16)));

        List<Finding> wallet = TokenHistory.liquidity(c, POOL, 4321, 10_000, 50, 90);
        assertThat(codeLevel(wallet.getFirst())).isEqualTo("LIQUIDITY_WALLET/CAUTION");
        assertThat(wallet.getFirst().params()).containsEntry("pct", "55.6"); // 500 of 900

        // The first position's NFT sent to the dead address: burned, and the locker is now the largest holder
        c.calls.put(manager + ownerOf + word(1), "0x" + word(new BigInteger(DEAD.substring(2), 16)));
        List<Finding> locker = TokenHistory.liquidity(c, POOL, 4321, 10_000, 50, 90);
        assertThat(codeLevel(locker.getFirst())).isEqualTo("LIQUIDITY_CONTRACT/INFO");
        assertThat(locker.getFirst().params()).containsEntry("pct", "44.4");

        // Out of calls, or a manager position that cannot be named: not checked rather than guessed
        assertThatThrownBy(() -> TokenHistory.liquidity(c, POOL, 4321, 10_000, 2, 90)).isInstanceOf(NotCheckedException.class);
        c.event(POOL, 4800, "t5", List.of(TokenHistory.MINT_TOPIC, topic(manager), word(tick), word(tick)), BigInteger.ZERO, BigInteger.valueOf(50), BigInteger.ONE, BigInteger.ONE);
        assertThatThrownBy(() -> TokenHistory.liquidity(c, POOL, 4321, 10_000, 50, 90)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void liquidityOfOtherPoolKindsIsNotChecked() {
        assertThatThrownBy(() -> TokenHistory.liquidity(new FakeChain(), POOL, 4321, 10_000, 50, 90))
                .isInstanceOf(NotCheckedException.class);
    }

    @Test
    void ageLowerBound() {
        assertThat(TokenHistory.ageAtLeast(0, 5 * 3600, 72)).isNull(); // could still be young: not decided
        Finding f = TokenHistory.ageAtLeast(0, 10L * 24 * 3600, 72);
        assertThat(codeLevel(f)).isEqualTo("TOKEN_AGE_MIN/INFO");
        assertThat(f.params()).containsExactly(Map.entry("days", "10"));
    }

    @Test
    void walletsAndTopics() {
        assertThat(TokenHistory.wallet("0x")).isTrue();
        assertThat(TokenHistory.wallet(null)).isTrue();
        assertThat(TokenHistory.wallet("0xEF0100" + "ab".repeat(20))).isTrue();
        assertThat(TokenHistory.wallet("0x6080604052")).isFalse();
        assertThat(TokenHistory.topicAddress("0x000000000000000000000000" + "A1".repeat(20))).isEqualTo(ALICE);
        assertThat(TokenHistory.TRANSFER_TOPIC).isEqualTo("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
        // Uniswap V3's events, as on Etherscan
        assertThat(TokenHistory.MINT_TOPIC).isEqualTo("0x7a53080ba414158be7ec69b987b5fb7d07dee101fe85488f0853ae16239d0bde");
        assertThat(TokenHistory.BURN_TOPIC).isEqualTo("0x0c396cd989a39f4459b5fa1aed6a9a8dcdbc45908acfd67e028cd568da98982c");
        assertThat(TokenHistory.INCREASE_TOPIC).isEqualTo("0x3067048beee31b25b2f1681f88dac838c8bba36af25bfb2b7cf7473a5847e35f");
        assertThat(TokenHistory.DECREASE_TOPIC).isEqualTo("0x26f6a048ee9138f2c0ce266f322cb99228e8d619ae2bff30c67f8dcf9d2377b4");
    }
}
