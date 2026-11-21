package com.soheil.guard;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;

import com.soheil.dex.common.TonAddress;

/**
 * A TON jetton, read through TonAPI: whether an admin can still create more (the minter's admin and mintable flag),
 * who holds it (only wallets count, so DEX pools and other contracts never look like whales), and when its minter
 * first appeared.
 */
public final class TonJettonCheck {

    /** A TonAPI GET (path and query) as JSON; throws when it gave no answer. */
    public interface Reader {
        JsonNode get(String pathAndQuery);
    }

    private TonJettonCheck() {
    }

    /** @throws NotCheckedException when the address is not a jetton */
    public static JsonNode jetton(Reader r, String address) {
        JsonNode j = r.get("/v2/jettons/" + address);
        if (!j.hasNonNull("total_supply")) {
            throw new NotCheckedException("not a jetton: " + address);
        }
        return j;
    }

    /** The minter's powers: none without an admin; with one, more can be created while the minter says so. */
    public static List<Finding> powers(JsonNode jetton) {
        JsonNode admin = jetton.path("admin");
        String raw = SolanaMintCheck.text(admin.path("address"));
        if (raw == null) {
            return List.of(Finding.info("OWNER_RENOUNCED"), Finding.info("MINT_FIXED"));
        }
        if (!jetton.path("mintable").asBoolean(true)) {
            return List.of(Finding.info("MINT_FIXED"));
        }
        String owner;
        try {
            owner = TonAddress.friendly(raw, !admin.path("is_wallet").asBoolean(false));
        } catch (RuntimeException e) {
            owner = raw;
        }
        return List.of(Finding.of("CAN_MINT", Finding.Level.CAUTION, Map.of("by", "owner", "owner", owner)));
    }

    public static List<Finding> holders(Reader r, String address, JsonNode jetton, double topWalletPct, double topWalletsPct) {
        BigInteger supply = new BigInteger(jetton.path("total_supply").asString("0"));
        JsonNode holders = r.get("/v2/jettons/" + address + "/holders?limit=20");
        List<BigInteger> wallets = new ArrayList<>();
        int seen = 0;
        for (JsonNode h : holders.path("addresses")) {
            seen++;
            if (h.path("owner").path("is_wallet").asBoolean(false)) {
                wallets.add(new BigInteger(h.path("balance").asString("0")));
            }
        }
        if (seen == 0) {
            throw new NotCheckedException("no holders");
        }
        return Holders.judge(wallets, supply, topWalletPct, topWalletsPct);
    }

    /** When the minter's first transaction happened (seconds). */
    public static long created(Reader r, String address) {
        JsonNode txs = r.get("/v2/blockchain/accounts/" + address + "/transactions?limit=1&sort_order=asc").path("transactions");
        if (!txs.isArray() || txs.isEmpty() || !txs.get(0).hasNonNull("utime")) {
            throw new NotCheckedException("no transactions");
        }
        return txs.get(0).path("utime").asLong();
    }
}
