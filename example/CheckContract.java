import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import com.soheil.guard.EvmContractCheck;
import com.soheil.guard.Finding;
import com.soheil.guard.GuardReport;

/**
 * The smallest host for Soheil Guard: reads a token contract through any EVM JSON-RPC endpoint and prints what its
 * owner can still do. Usage: CheckContract <rpc url> <token address>
 */
public class CheckContract {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: CheckContract <rpc url> <token address>");
            System.exit(2);
        }
        Rpc rpc = new Rpc(args[0]);
        List<Finding> findings = EvmContractCheck.check(rpc, args[1].toLowerCase());
        GuardReport report = GuardReport.of(0, args[1], findings, List.of(GuardReport.CONTRACT), List.of(), java.time.OffsetDateTime.now());
        System.out.println("Verdict: " + report.verdict());
        report.findings().forEach(f -> System.out.println("  " + f.level() + "  " + f.code() + "  " + f.params()));
    }

    /** What the contract check reads, answered by one JSON-RPC endpoint. */
    static final class Rpc implements EvmContractCheck.Reader {

        private final HttpClient http = HttpClient.newHttpClient();
        private final JsonMapper json = JsonMapper.builder().build();
        private final URI url;

        Rpc(String url) {
            this.url = URI.create(url);
        }

        @Override
        public String code(String address) {
            return ask("eth_getCode", List.of(address, "latest"));
        }

        @Override
        public String storage(String address, String slot) {
            return ask("eth_getStorageAt", List.of(address, slot, "latest"));
        }

        @Override
        public String call(String to, String data) {
            return ask("eth_call", List.of(Map.of("to", to, "data", data), "latest"));
        }

        /** The result as text, or null when the node answered with an error (a reverted call). */
        private String ask(String method, List<Object> params) {
            try {
                String body = json.writeValueAsString(Map.of("jsonrpc", "2.0", "id", 1, "method", method, "params", params));
                HttpResponse<String> res = http.send(HttpRequest.newBuilder(url).header("content-type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
                JsonNode result = json.readTree(res.body()).path("result");
                return result.isMissingNode() || result.isNull() ? null : result.asString();
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }
}
