package com.soheil.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import com.soheil.dex.common.Keccak;

/** The checks on fixed inputs: no network. */
class GuardChecksTest {

    private static final String TOKEN = "0x" + "11".repeat(20);
    private static final String IMPL = "0x" + "22".repeat(20);
    private static final String OWNER = "0x" + "33".repeat(20);
    private static final String ZERO_WORD = "0x" + "0".repeat(64);

    // ---- Keccak and the derived constants ------------------------------------------------------------------------

    @Test
    void keccakMatchesEthereum() {
        assertThat(Keccak.hex("")).isEqualTo("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assertThat(Keccak.selector("transfer(address,uint256)")).isEqualTo("a9059cbb");
        assertThat(Keccak.hex("a".repeat(136))).isEqualTo("a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
        assertThat(EvmContractCheck.IMPLEMENTATION_SLOT).isEqualTo("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
        assertThat(EvmContractCheck.BEACON_SLOT).isEqualTo("0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50");
        assertThat(EvmContractCheck.UUPS_SLOT).isEqualTo("0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7");
        assertThat(EvmContractCheck.ZOS_SLOT).isEqualTo("0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3");
    }

    // ---- bytecode ------------------------------------------------------------------------------------------------

    @Test
    void selectorsSkipPushedDataAndMetadata() {
        String code = "0x6080604052"
                + "63a9059cbb14"                      // PUSH4 transfer, EQ
                + "6240c10f14"                        // PUSH3 (a selector starting with 00)
                + "7f" + "63deadbeef" + "00".repeat(27) // PUSH32 whose data looks like PUSH4 deadbeef
                + "fe"
                + "a264697066735822" + "1220" + "63cafebabe" + "00".repeat(30); // metadata
        java.util.Set<String> s = Bytecode.of(code).selectors();
        assertThat(s).contains("a9059cbb", "0040c10f").doesNotContain("deadbeef", "cafebabe");
    }

    @Test
    void delegatecallIsAnInstructionNotData() {
        assertThat(Bytecode.of("0x60f4").delegates()).isFalse();
        assertThat(Bytecode.of("0x6000f4").delegates()).isTrue();
    }

    @Test
    void minimalProxyTarget() {
        String target = "be".repeat(20);
        assertThat(Bytecode.minimalProxyTarget("0x363d3d373d3d3d363d73" + target + "5af43d82803e903d91602b57fd5bf3")).isEqualTo("0x" + target);
        assertThat(Bytecode.minimalProxyTarget("0x365f5f375f5f365f73" + target + "5af43d5f5f3e6029573d5ffd5b3d5ff3")).isEqualTo("0x" + target);
        assertThat(Bytecode.minimalProxyTarget("0x6080604052")).isNull();
    }

    // ---- EVM contract ----------------------------------------------------------------------------------------------

    /** A network with fixed answers: code per address, storage per slot, call results per "to|data". */
    private static final class FakeChain implements EvmContractCheck.Reader {
        final Map<String, String> code = new HashMap<>();
        final Map<String, String> storage = new HashMap<>();
        final Map<String, String> calls = new HashMap<>();

        @Override
        public String code(String address) {
            return code.getOrDefault(address, "0x");
        }

        @Override
        public String storage(String address, String slot) {
            return storage.getOrDefault(address + "|" + slot, ZERO_WORD);
        }

        @Override
        public String call(String to, String data) {
            return calls.get(to + "|" + data);
        }

        void owner(String address) {
            calls.put(TOKEN + "|0x" + Keccak.selector("owner()"), "0x" + "0".repeat(24) + address.substring(2));
        }
    }

    /** Runtime code whose dispatcher compares against these functions (plus transfer, like any token). */
    private static String token(String... signatures) {
        StringBuilder sb = new StringBuilder("0x6080604052").append("63").append(Keccak.selector("transfer(address,uint256)")).append("14");
        for (String sig : signatures) {
            sb.append("63").append(Keccak.selector(sig)).append("14");
        }
        return sb.toString();
    }

    private static List<String> codes(List<Finding> findings) {
        return findings.stream().map(Finding::code).toList();
    }

    @Test
    void ownedPowersAreCautions() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, token("mint(address,uint256)", "blacklist(address)", "owner()"));
        c.owner(OWNER);
        List<Finding> f = EvmContractCheck.check(c, TOKEN);
        assertThat(codes(f)).containsExactlyInAnyOrder("CAN_MINT", "CAN_BLACKLIST");
        assertThat(f).allMatch(x -> x.level() == Finding.Level.CAUTION && "owner".equals(x.params().get("by")) && OWNER.equals(x.params().get("owner")));
    }

    @Test
    void renouncedOwnerHoldsNoPowers() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, token("mint(address,uint256)", "setFee(uint256)"));
        c.owner("0x" + "0".repeat(40));
        assertThat(codes(EvmContractCheck.check(c, TOKEN))).containsExactlyInAnyOrder("OWNER_RENOUNCED", "NO_OWNER_POWERS");
    }

    @Test
    void rolesKeepPowersEvenWithoutAnOwner() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, token("pause()", "hasRole(bytes32,address)"));
        List<Finding> f = EvmContractCheck.check(c, TOKEN);
        assertThat(codes(f)).containsExactly("CAN_PAUSE");
        assertThat(f.getFirst().params()).containsEntry("by", "roles");
    }

    @Test
    void plainTokenHasNoPowers() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, token("approve(address,uint256)"));
        assertThat(codes(EvmContractCheck.check(c, TOKEN))).containsExactly("NO_OWNER_POWERS");
    }

    @Test
    void proxyIsUpgradeableAndItsImplementationIsRead() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, "0x6080604052366000f4"); // forwards with DELEGATECALL
        c.storage.put(TOKEN + "|" + EvmContractCheck.IMPLEMENTATION_SLOT, "0x" + "0".repeat(24) + IMPL.substring(2));
        c.code.put(IMPL, token("pause()", "setMaxTxAmount(uint256)"));
        c.owner(OWNER);
        assertThat(codes(EvmContractCheck.check(c, TOKEN))).containsExactlyInAnyOrder("UPGRADEABLE", "CAN_PAUSE", "CAN_LIMIT_SELLS");
    }

    @Test
    void beaconProxyIsFollowed() {
        FakeChain c = new FakeChain();
        String beacon = "0x" + "44".repeat(20);
        c.code.put(TOKEN, "0x6080604052366000f4");
        c.storage.put(TOKEN + "|" + EvmContractCheck.BEACON_SLOT, "0x" + "0".repeat(24) + beacon.substring(2));
        c.calls.put(beacon + "|0x" + Keccak.selector("implementation()"), "0x" + "0".repeat(24) + IMPL.substring(2));
        c.code.put(IMPL, token("enableTrading()"));
        assertThat(codes(EvmContractCheck.check(c, TOKEN))).containsExactlyInAnyOrder("UPGRADEABLE", "CAN_STOP_TRADING");
    }

    @Test
    void unreadableDelegationIsHiddenCode() {
        FakeChain c = new FakeChain();
        c.code.put(TOKEN, "0x6080604052366000f4"); // delegates, no known proxy slot, no token functions of its own
        assertThat(codes(EvmContractCheck.check(c, TOKEN))).containsExactly("HIDDEN_CODE");
    }

    @Test
    void nothingDeployedIsNotChecked() {
        assertThatThrownBy(() -> EvmContractCheck.check(new FakeChain(), TOKEN)).isInstanceOf(NotCheckedException.class);
    }

    // ---- sell test --------------------------------------------------------------------------------------------------

    @Test
    void sellTestJudgesTheRoundTrip() {
        BigDecimal value = new BigDecimal("100");
        assertThat(SellCheck.judge(List.of(), value, 10, 30).getFirst().code()).isEqualTo("NO_SELL_ROUTE");
        Finding ok = SellCheck.judge(List.of(new BigDecimal("95"), new BigDecimal("90")), value, 10, 30).getFirst();
        assertThat(ok.code()).isEqualTo("SELL_OK");
        assertThat(ok.params()).containsEntry("lossPct", "5").containsEntry("backUsd", "95.00").containsEntry("valueUsd", "100.00");
        assertThat(SellCheck.judge(List.of(new BigDecimal("80")), value, 10, 30).getFirst().level()).isEqualTo(Finding.Level.CAUTION);
        assertThat(SellCheck.judge(List.of(new BigDecimal("50")), value, 10, 30).getFirst().level()).isEqualTo(Finding.Level.RISKY);
        List<BigDecimal> unknownValue = new ArrayList<>();
        unknownValue.add(null);
        assertThat(SellCheck.judge(unknownValue, value, 10, 30).getFirst().code()).isEqualTo("SELL_ROUTE");
        assertThat(SellCheck.judge(List.of(new BigDecimal("50")), null, 10, 30).getFirst().code()).isEqualTo("SELL_ROUTE");
    }

    // ---- verdict ----------------------------------------------------------------------------------------------------

    @Test
    void okNeedsTheContractChecked() {
        OffsetDateTime now = OffsetDateTime.now();
        List<Finding> clean = List.of(Finding.info("SELL_OK"));
        assertThat(GuardReport.of(1, TOKEN, clean, List.of("sell"), List.of("contract"), now).verdict()).isEqualTo(GuardReport.Verdict.NOT_CHECKED);
        assertThat(GuardReport.of(1, TOKEN, clean, List.of("sell", "contract"), List.of(), now).verdict()).isEqualTo(GuardReport.Verdict.OK);
        GuardReport risky = GuardReport.of(1, TOKEN,
                List.of(Finding.info("SELL_OK"), Finding.of("CAN_MINT", Finding.Level.CAUTION, Map.of()), Finding.of("NO_SELL_ROUTE", Finding.Level.RISKY, Map.of())),
                List.of("sell"), List.of(), now);
        assertThat(risky.verdict()).isEqualTo(GuardReport.Verdict.RISKY);
        assertThat(codes(risky.findings())).containsExactly("NO_SELL_ROUTE", "CAN_MINT", "SELL_OK");
    }

    // ---- Solana ------------------------------------------------------------------------------------------------------

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String MINT = "Mint1111111111111111111111111111111111111111";

    /** Answers by RPC method; getMultipleAccounts by whether it asks for parsed token accounts or their owners. */
    private static SolanaMintCheck.Reader solana(String mintAccount, String largest, String tokenAccounts, String owners) {
        return (method, params) -> {
            String body = switch (method) {
                case "getAccountInfo" -> mintAccount;
                case "getTokenLargestAccounts" -> largest;
                case "getMultipleAccounts" -> ((Map<?, ?>) params.get(1)).get("encoding").equals("jsonParsed") ? tokenAccounts : owners;
                default -> throw new IllegalArgumentException(method);
            };
            return JSON.readTree(body);
        };
    }

    @Test
    void solanaMintAuthoritiesAndExtensions() {
        String mint = """
                {"value":{"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb","data":{"program":"spl-token-2022","parsed":{"type":"mint","info":{
                  "decimals":6,"supply":"1000000","mintAuthority":"Auth111","freezeAuthority":null,
                  "extensions":[
                    {"extension":"transferFeeConfig","state":{"newerTransferFee":{"transferFeeBasisPoints":500},"olderTransferFee":{"transferFeeBasisPoints":0}}},
                    {"extension":"permanentDelegate","state":{"delegate":"Del111"}},
                    {"extension":"transferHook","state":{"programId":null}},
                    {"extension":"metadataPointer","state":{}}
                  ]}}}}}
                """;
        SolanaMintCheck.Mint m = SolanaMintCheck.mint(solana(mint, null, null, null), MINT, 10);
        assertThat(codes(m.findings())).containsExactlyInAnyOrder("MINT_AUTHORITY", "FREEZE_NONE", "TRANSFER_FEE", "PERMANENT_DELEGATE");
        assertThat(m.findings().stream().filter(f -> f.code().equals("TRANSFER_FEE")).findFirst().orElseThrow().params()).containsEntry("pct", "5");
        assertThat(m.supply()).isEqualTo(BigInteger.valueOf(1_000_000));
    }

    @Test
    void solanaNonMintIsNotChecked() {
        String account = """
                {"value":{"data":{"parsed":{"type":"account","info":{}}}}}
                """;
        assertThatThrownBy(() -> SolanaMintCheck.mint(solana(account, null, null, null), MINT, 10)).isInstanceOf(NotCheckedException.class);
        assertThatThrownBy(() -> SolanaMintCheck.mint(solana("{\"value\":null}", null, null, null), MINT, 10)).isInstanceOf(NotCheckedException.class);
    }

    @Test
    void solanaHoldersCountWalletsNotPrograms() {
        String largest = """
                {"value":[{"address":"Acc1","amount":"600000"},{"address":"Acc2","amount":"250000"},{"address":"Acc3","amount":"50000"}]}
                """;
        String tokenAccounts = """
                {"value":[
                  {"data":{"parsed":{"info":{"owner":"PoolPda"}}}},
                  {"data":{"parsed":{"info":{"owner":"Whale"}}}},
                  {"data":{"parsed":{"info":{"owner":"Small"}}}}]}
                """;
        String owners = """
                {"value":[{"owner":"675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"},{"owner":"11111111111111111111111111111111"},{"owner":"11111111111111111111111111111111"}]}
                """;
        List<Finding> f = SolanaMintCheck.holders(solana(null, largest, tokenAccounts, owners), MINT, BigInteger.valueOf(1_000_000), 20, 50);
        // The pool's 60% does not count; the whale's 25% does
        assertThat(codes(f)).containsExactly("TOP_WALLET");
        assertThat(f.getFirst().params()).containsEntry("pct", "25");

        List<Finding> spread = SolanaMintCheck.holders(solana(null, largest, tokenAccounts, owners), MINT, BigInteger.valueOf(10_000_000), 20, 50);
        assertThat(codes(spread)).containsExactly("HOLDERS_SPREAD");
        assertThat(spread.getFirst().params()).containsEntry("pct", "3");
    }
}
