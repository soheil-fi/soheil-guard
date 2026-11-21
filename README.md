# Soheil Guard

The token checks behind the safety label on [soheil.fi](https://soheil.fi/guard/): before someone buys a token, Guard
looks at what its creator can still do with it, whether it can be sold again, who holds it and how old it is.

This repository is the checking code itself, as soheil.fi runs it. It is a Java library with one dependency (Jackson).
It opens no connections and holds no keys: every check asks for its data through a small `Reader` interface, and you
decide where that data comes from (your own RPC endpoint, an indexer, a test fixture).

Guard says "checked", never "safe": no check catches everything.

## What it checks

| Network | Check | Class |
|---|---|---|
| EVM | What the owner can still do: mint, pause, blacklist, change fees, stop trading, limit sells; proxies and hidden code; renounced ownership | `EvmContractCheck` |
| EVM | A real buy, transfer and sell, run inside one `eth_call` with nothing sent on-chain: taxes and sales that fail | `SellSimulation` |
| EVM | Holders, liquidity (burned, locked in a contract, or in a wallet) and the token's age, from its events | `TokenHistory` |
| Solana | Mint and freeze authority, Token-2022 extensions (transfer fee, permanent delegate, transfer hook, pausable), holders | `SolanaMintCheck` |
| Solana | Age and liquidity of the token's pools | `SolanaHistory` |
| Sui | Who holds the coin's TreasuryCap and what they can do | `SuiCoinCheck` |
| TON | A jetton's admin powers, holders and age | `TonJettonCheck` |
| any | Whether the tokens can be sold back, and for how much of their value | `SellCheck` |
| any | Whether a few wallets hold most of the supply | `Holders` |

Each check returns `Finding`s: a stable `code`, a `level` (`INFO`, `CAUTION`, `RISKY`) and values for a sentence.
`GuardReport.of(...)` sorts them and gives the verdict: `OK`, `CAUTION`, `RISKY`, or `NOT_CHECKED` when the contract
itself could not be read.

## Finding codes

`CAN_MINT` `CAN_PAUSE` `CAN_BLACKLIST` `CAN_CHANGE_FEES` `CAN_STOP_TRADING` `CAN_LIMIT_SELLS` `UPGRADEABLE` `HIDDEN_CODE`
`OWNER_RENOUNCED` `NO_OWNER_POWERS` · `MINT_AUTHORITY` `MINT_FIXED` `FREEZE_AUTHORITY` `FREEZE_NONE` `FROZEN_BY_DEFAULT`
`TRANSFER_FEE` `TRANSFER_HOOK` `PERMANENT_DELEGATE` `NON_TRANSFERABLE` `PAUSABLE` `PAUSED` · `SELL_OK` `SELL_LOSS`
`SELL_ROUTE` `NO_SELL_ROUTE` · `SIM_OK` `SIM_TAX` `SIM_BUY_FAILS` `SIM_SELL_FAILS` `SIM_TRANSFER_FAILS` · `TOP_WALLET` `TOP_WALLETS`
`HOLDERS_SPREAD` · `LIQUIDITY_BURNED` `LIQUIDITY_CONTRACT` `LIQUIDITY_WALLET` `LIQUIDITY_CURVE` · `TOKEN_AGE` `TOKEN_AGE_MIN` `TOKEN_YOUNG`

The codes are stable: wording them for people (in any language) is the host's job.

## Use it

Implement the `Reader` of the check you want, then call it:

```java
List<Finding> findings = EvmContractCheck.check(reader, tokenAddress);
GuardReport report = GuardReport.of(chainId, tokenAddress, findings, List.of(GuardReport.CONTRACT), List.of(), OffsetDateTime.now());
System.out.println(report.verdict());
```

`example/CheckContract.java` is a complete host in one file: it reads a token contract through any EVM JSON-RPC endpoint.

```
./gradlew example -Prpc=https://your-rpc-endpoint -Ptoken=0xTokenAddress
```

Thresholds (what share of the supply in one wallet is "risky", how much loss on a sale is a "tax") are parameters of
the checks, so each host sets its own.

## Build and test

```
./gradlew test
```

Java 21. The tests run on fixed inputs, with no network.

## Layout

- `src/main/java/com/soheil/guard`: the checks, `Finding` and `GuardReport`.
- `src/main/java/com/soheil/dex/common`: four small helpers the checks use (Keccak-256, Base58, TON and Solana addresses).
- `src/main/resources/guard/SellProbe.sol`: the helper contract of the sale test, with its compiled bytecode (`SellProbe.bin`).
  It is never deployed: its code is placed at a fresh address for one `eth_call` through a state override.

## Where this comes from

soheil.fi runs this same code. This repository is published from soheil.fi's own source, so changes are made there and
arrive here as a whole; issues and suggestions are welcome.

## License

MIT
