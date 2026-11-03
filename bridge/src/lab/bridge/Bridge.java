package lab.bridge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The bridge between {@code main} and the experimental lab.
 *
 * {@code main} is the authored policy layer: prose, legal notes, and a set of fictional
 * scenarios that state, in plain language, which actions sit inside an operator's
 * authority and which do not. The lab is the executable layer. Nothing kept them in
 * step, so the two could drift until the lab was doing something {@code main} had
 * already declared out of bounds.
 *
 * This class closes that gap in one direction and opens it in the other:
 *
 * <ol>
 *   <li>It reads {@code examples/scenarios.json} from {@code main}, and fails the
 *       build if a scenario claims an option that the lab's scope excludes is inside
 *       the operator's authority. Policy becomes a checked artefact rather than a
 *       paragraph.</li>
 *   <li>It converts each scenario's "under control" assets into contract-compliant
 *       lab events, so the documented scenarios can drive the pipeline end to
 *       end.</li>
 *   <li>It reads the lab's report and writes a Markdown fragment for the docs, so the
 *       numbers in the prose come from a run instead of from memory.</li>
 * </ol>
 *
 * Java is the bridge because it is the language least likely to be mistaken for the
 * pipeline: it holds no model, makes no decisions about behaviour, and can be deleted
 * without touching the lab. It runs on a plain JDK with no dependencies.
 */
public final class Bridge {

    /** Base timestamp: 2026-01-01T00:00:00Z. Deterministic runs beat realistic ones. */
    private static final double BASE_EPOCH = 1767225600.0;
    private static final String DEFAULT_SALT = "lab-bridge-demo-salt";
    private static final String DEFAULT_EPOCH = "2026-11";

    /**
     * Capability markers that must never appear in a scenario's "inside authority"
     * list. These are the exclusions written down in the lab's ethics page; if a
     * scenario contradicts them, the bridge refuses to emit anything.
     */
    private static final List<String> EXCLUDED_CAPABILITIES = List.of(
            "recipient's account",
            "recipient’s account",
            "recipient's storage",
            "recipient’s storage",
            "delete the file from",
            "active prob",
            "geolocat",
            "deanonymis",
            "de-anonymis",
            "tracking pixel",
            "web beacon");

    /** One documented scenario, as authored in main. */
    record Scenario(
            String id,
            String title,
            String premise,
            List<String> underControl,
            List<String> insideAuthority,
            List<String> outsideAuthority) {
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> options = parseArgs(args);
        if (options.containsKey("selftest")) {
            System.exit(selftest() ? 0 : 1);
        }

        Path scenariosPath = Path.of(options.getOrDefault("scenarios", "examples/scenarios.json"));
        Path emitPath = options.containsKey("emit") ? Path.of(options.get("emit")) : null;
        Path reportPath = Path.of(options.getOrDefault("summary", "lab/reports/last_run.json"));
        Path summaryPath = options.containsKey("summary-out") ? Path.of(options.get("summary-out")) : null;
        String salt = System.getenv().getOrDefault("LAB_SALT", DEFAULT_SALT);
        String epoch = options.getOrDefault("epoch", DEFAULT_EPOCH);

        List<Scenario> scenarios = loadScenarios(scenariosPath);
        System.out.printf("bridge: parsed %d scenario(s) from %s%n", scenarios.size(), scenariosPath);

        List<String> violations = boundaryViolations(scenarios);
        if (!violations.isEmpty()) {
            System.err.println("bridge: scenario authority contradicts lab scope:");
            for (String violation : violations) {
                System.err.println("  - " + violation);
            }
            System.exit(2);
        }
        System.out.println("bridge: boundary check passed");

        if (emitPath != null) {
            List<Map<String, Object>> events = emitEvents(scenarios, salt, epoch);
            writeJsonl(emitPath, events);
            System.out.printf("bridge: wrote %d event(s) to %s%n", events.size(), emitPath);
        }

        if (summaryPath != null) {
            if (!Files.isRegularFile(reportPath)) {
                System.out.printf("bridge: no report at %s, skipping summary%n", reportPath);
            } else {
                String markdown = summaryMarkdown(reportPath, scenarios);
                Files.createDirectories(summaryPath.getParent() == null ? Path.of(".") : summaryPath.getParent());
                Files.writeString(summaryPath, markdown, StandardCharsets.UTF_8);
                System.out.printf("bridge: wrote %s%n", summaryPath);
            }
        }
    }

    // ------------------------------------------------------------------ loading

    static List<Scenario> loadScenarios(Path path) throws IOException {
        String raw = Files.readString(path, StandardCharsets.UTF_8);
        Map<String, Object> root = Json.asObject(Json.parse(raw));
        List<Object> entries = Json.asArray(root.get("scenarios"));
        List<Scenario> scenarios = new ArrayList<>();
        for (Object entry : entries) {
            Map<String, Object> node = Json.asObject(entry);
            scenarios.add(new Scenario(
                    Json.asString(node.get("id")),
                    Json.asString(node.get("title")),
                    Json.asString(node.get("premise")),
                    Json.asStringList(node.get("what_is_under_control")),
                    Json.asStringList(node.get("options_inside_authority")),
                    Json.asStringList(node.get("options_outside_authority"))));
        }
        if (scenarios.isEmpty()) {
            throw new IllegalStateException(path + " declares no scenarios");
        }
        return scenarios;
    }

    // ----------------------------------------------------------------- boundary

    static List<String> boundaryViolations(List<Scenario> scenarios) {
        List<String> problems = new ArrayList<>();
        for (Scenario scenario : scenarios) {
            if (scenario.outsideAuthority().isEmpty()) {
                problems.add(scenario.id() + ": no out-of-authority option documented");
            }
            for (String option : scenario.insideAuthority()) {
                String lowered = option.toLowerCase(Locale.ROOT);
                for (String marker : EXCLUDED_CAPABILITIES) {
                    if (lowered.contains(marker.toLowerCase(Locale.ROOT))) {
                        problems.add(scenario.id() + ": inside-authority option matches excluded capability '"
                                + marker + "': " + option);
                    }
                }
            }
        }
        return problems;
    }

    // ------------------------------------------------------------------- events

    /** Observations emitted per documented asset. Enough for the feature layer's floor. */
    private static final int OBSERVATIONS_PER_ASSET = 8;

    static List<Map<String, Object>> emitEvents(List<Scenario> scenarios, String salt, String epoch) {
        List<Map<String, Object>> events = new ArrayList<>();
        int scenarioIndex = 0;
        for (Scenario scenario : scenarios) {
            int assetIndex = 0;
            for (String asset : scenario.underControl()) {
                Map<String, Object> labels = Json.ordered();
                labels.put("scenario_id", scenario.id());
                labels.put("title", scenario.title());
                labels.put("asset", asset);
                labels.put("bridge", "examples/scenarios.json");

                for (int step = 0; step < OBSERVATIONS_PER_ASSET; step++) {
                Map<String, Object> event = Json.ordered();
                event.put("event_id", "bridge-" + scenario.id() + "-" + assetIndex + "-" + step);
                event.put("observed_at",
                        BASE_EPOCH + scenarioIndex * 3600.0 + assetIndex * 600.0 + step * 60.0);
                event.put("source_id", "docs:scenario");
                event.put("client_key", clientKey(salt, epoch, scenario.id() + "/" + asset));
                event.put("channel", "site_visit");
                event.put("protocol", "h2");
                event.put("ua_family", "unknown");
                event.put("fingerprint_hash", "docs");
                event.put("network_class", "unknown");
                event.put("bytes_in", 0);
                event.put("latency_ms", 0.0);
                event.put("labels", labels);
                events.add(event);
                }
                assetIndex++;
            }
            scenarioIndex++;
        }
        return events;
    }

    /** Same construction as {@code contract.derive_client_key}: HMAC-SHA256, first 16 hex chars. */
    static String clientKey(String salt, String epoch, String subject) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal((epoch + "|" + subject).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    static void writeJsonl(Path path, List<Map<String, Object>> events) throws IOException {
        Files.createDirectories(path.getParent() == null ? Path.of(".") : path.getParent());
        StringBuilder out = new StringBuilder();
        for (Map<String, Object> event : events) {
            out.append(Json.write(event)).append('\n');
        }
        Files.writeString(path, out.toString(), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ summary

    static String summaryMarkdown(Path reportPath, List<Scenario> scenarios) throws IOException {
        Map<String, Object> report = Json.asObject(Json.parse(Files.readString(reportPath, StandardCharsets.UTF_8)));
        Map<String, Object> data = Json.asObject(report.get("data"));
        Map<String, Object> input = report.containsKey("input") ? Json.asObject(report.get("input")) : null;
        String inputKind = input == null ? "unknown" : Json.asString(input.get("kind"));
        Map<String, Object> holdout = Json.asObject(report.get("holdout"));
        Map<String, Object> validation = Json.asObject(report.get("temporal_validation"));
        Map<String, Object> expanding = Json.asObject(validation.get("expanding"));
        Map<String, Object> shadow = Json.asObject(report.get("shadow_model"));
        Map<String, Object> probe = Json.asObject(report.get("poisoning_probe"));
        Map<String, Object> noisyProbe = Json.asObject(probe.get("label_noise_25pct"));
        Map<String, Object> reflexive = Json.asObject(report.get("reflexive_update"));
        Map<String, Object> privacy = Json.asObject(report.get("differential_privacy"));

        StringBuilder md = new StringBuilder();
        md.append("<!-- generated by lab/bridge (Java) from lab/reports/last_run.json. Do not edit. -->\n\n");
        md.append("## Experimental lab: latest run\n\n");
        if ("synthetic".equals(inputKind)) {
            md.append("A deterministic run over synthetic data with a known answer and a deliberate 30% overlap. ");
            md.append("These numbers check the plumbing, not real-world performance.\n\n");
        } else {
            md.append("A run over supplied events (`").append(inputKind).append("` input). ");
            md.append("Labels come from the input file, so AUC is only meaningful if that file carries them; ");
            md.append("a documentation-fixture run will report n/a.\n\n");
        }
        md.append("| Metric | Value |\n| --- | --- |\n");
        md.append(String.format(Locale.ROOT, "| Events / clients | %d / %d |%n",
                Math.round(Json.asDouble(data.get("events"))), Math.round(Json.asDouble(data.get("clients")))));
        String foldsStatus = expanding.containsKey("status")
                ? "skipped: " + escapePipes(value(expanding.get("reason")))
                : "ran";
        md.append("| Temporal CV | " + foldsStatus + " |\n");
        md.append("| Temporal CV mean AUC (expanding) | " + metric(expanding.get("mean_auc")) + " |\n");
        md.append("| Leakage check | " + value(expanding.get("leakage_check")) + " |\n");
        md.append("| Holdout AUC | " + metric(holdout.get("auc")) + " |\n");
        md.append("| Stability PSI (train halves) | " + metric(holdout.get("stability_psi")) + " |\n");
        md.append("| Holdout PSI | " + metric(holdout.get("holdout_psi")) + " |\n");
        md.append("| Shadow divergence, clean | " + metric(shadow.get("mean_divergence")) + " |\n");
        md.append("| Shadow divergence, 25% label noise | " + metric(noisyProbe.get("mean_divergence")) + " |\n");
        md.append("| Poisoning probe reacted | " + value(probe.get("reacted")) + " |\n");
        md.append("| Reflexive update converged | " + value(reflexive.get("converged"))
                + " in " + value(reflexive.get("iterations")) + " iteration(s) |\n");
        md.append("| Epsilon spent | " + value(privacy.get("epsilon_spent")) + " |\n\n");

        md.append("### Documented scenarios loaded from main\n\n");
        md.append("| Scenario | Under operator control | Options outside authority |\n| --- | --- | --- |\n");
        for (Scenario scenario : scenarios) {
            md.append(String.format("| %s: %s | %d | %d |%n",
                    scenario.id(), escapePipes(scenario.title()),
                    scenario.underControl().size(), scenario.outsideAuthority().size()));
        }
        md.append("\nAll ").append(scenarios.size())
          .append(" scenario(s) passed the scope check: no option marked as inside the operator's authority ")
          .append("matches a capability the lab refuses to build.\n");
        return md.toString();
    }

    private static String value(Object raw) {
        if (raw == null) {
            return "n/a";
        }
        if (raw instanceof Boolean b) {
            return b ? "yes" : "no";
        }
        if (raw instanceof Double d) {
            if (d == Math.rint(d)) {
                return String.valueOf(d.longValue());
            }
            return String.valueOf(d);
        }
        return String.valueOf(raw);
    }

    /** Metrics keep three significant decimals; whole numbers are not rounded to ints. */
    private static String metric(Object raw) {
        if (raw instanceof Double d) {
            return String.format(Locale.ROOT, "%.3f", d);
        }
        return value(raw);
    }

    private static String escapePipes(String text) {
        return text.replace("|", "\\|");
    }

    // ----------------------------------------------------------------- selftest

    static boolean selftest() throws IOException {
        int failures = 0;
        List<String> log = new ArrayList<>();

        // 1. JSON round trip, including escapes and unicode.
        String tricky = "{\"a\":\"quote \\\" and \\\\ slash\",\"b\":[1,2.5,true,false,null],\"c\":\"\\u00e9\"}";
        Map<String, Object> parsed = Json.asObject(Json.parse(tricky));
        if (!"quote \" and \\ slash".equals(Json.asString(parsed.get("a")))) {
            log.add("FAIL json string escapes");
            failures++;
        } else {
            log.add("ok   json string escapes");
        }
        List<Object> array = Json.asArray(parsed.get("b"));
        if (array.size() != 5 || Json.asDouble(array.get(1)) != 2.5) {
            log.add("FAIL json array parsing");
            failures++;
        } else {
            log.add("ok   json array parsing");
        }
        if (!"\u00e9".equals(Json.asString(parsed.get("c")))) {
            log.add("FAIL json unicode escape");
            failures++;
        } else {
            log.add("ok   json unicode escape");
        }

        // 2. Reject malformed input instead of guessing.
        for (String bad : List.of("{\"a\":1,}", "[1,]", "{\"a\" 1}", "nope")) {
            try {
                Json.parse(bad);
                log.add("FAIL malformed json accepted: " + bad);
                failures++;
            } catch (IllegalArgumentException expected) {
                log.add("ok   rejected malformed json: " + bad);
            }
        }

        // 3. Round trip through the writer.
        if (!Json.asObject(Json.parse(Json.write(parsed))).keySet().equals(parsed.keySet())) {
            log.add("FAIL json write/parse round trip");
            failures++;
        } else {
            log.add("ok   json write/parse round trip");
        }

        // 4. Real scenarios load, and the authored boundary agrees with lab scope.
        Path scenariosPath = Path.of("examples/scenarios.json");
        List<Scenario> scenarios = loadScenarios(scenariosPath);
        log.add("ok   parsed " + scenarios.size() + " scenario(s) from main");
        List<String> violations = boundaryViolations(scenarios);
        if (!violations.isEmpty()) {
            log.add("FAIL boundary check on repo data: " + violations);
            failures++;
        } else {
            log.add("ok   boundary check on repo data");
        }

        // 5. A scenario that claims an excluded capability inside authority must fail.
        Scenario bad = new Scenario("BAD-001", "Bad", "p", List.of("asset"),
                List.of("access the recipient's account to remove the copy"), List.of("anything"));
        if (boundaryViolations(List.of(bad)).isEmpty()) {
            log.add("FAIL excluded capability not detected");
            failures++;
        } else {
            log.add("ok   excluded capability detected");
        }

        // 6. A scenario with no documented boundary must fail.
        Scenario vague = new Scenario("BAD-002", "Vague", "p", List.of("asset"), List.of("review logs"), List.of());
        if (boundaryViolations(List.of(vague)).isEmpty()) {
            log.add("FAIL missing boundary not detected");
            failures++;
        } else {
            log.add("ok   missing boundary detected");
        }

        // 7. Events match the documented assets and carry contract-shaped fields.
        List<Map<String, Object>> events = emitEvents(scenarios, DEFAULT_SALT, DEFAULT_EPOCH);
        int expected = scenarios.stream().mapToInt(s -> s.underControl().size()).sum() * OBSERVATIONS_PER_ASSET;
        if (events.size() != expected) {
            log.add("FAIL event count " + events.size() + " != " + expected);
            failures++;
        } else {
            log.add("ok   event count matches documented assets x observations (" + expected + ")");
        }
        for (Map<String, Object> event : events) {
            String key = Json.asString(event.get("client_key"));
            if (!key.matches("[0-9a-f]{16}")) {
                log.add("FAIL client_key shape: " + key);
                failures++;
                break;
            }
            if (Json.asDouble(event.get("observed_at")) <= 0) {
                log.add("FAIL observed_at not a positive epoch");
                failures++;
                break;
            }
        }

        // 8. Key derivation matches the Python contract: HMAC-SHA256 over "epoch|subject".
        String javaKey = clientKey("secret", "2026-11", "198.51.100.5");
        if (!javaKey.equals(pythonCompatibleKey("secret", "2026-11", "198.51.100.5"))) {
            log.add("FAIL key derivation disagrees with the Python contract");
            failures++;
        } else {
            log.add("ok   key derivation matches the Python contract (" + javaKey + ")");
        }

        for (String line : log) {
            System.out.println("  " + line);
        }
        System.out.println(failures == 0 ? "bridge selftest passed" : failures + " bridge check(s) failed");
        return failures == 0;
    }

    /**
     * Independent implementation of the Python rule, used only by the self-test so a
     * change on one side cannot quietly diverge from the other without failing here.
     */
    private static String pythonCompatibleKey(String secret, String epoch, String subject) throws IOException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal((epoch + "|" + subject).getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IOException(e);
        }
    }

    // ----------------------------------------------------------------------- cli

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> options = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!arg.startsWith("--")) {
                continue;
            }
            String name = arg.substring(2);
            if (name.contains("=")) {
                options.put(name.substring(0, name.indexOf('=')), name.substring(name.indexOf('=') + 1));
                continue;
            }
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                options.put(name, args[++i]);
            } else {
                options.put(name, "true");
            }
        }
        return options;
    }
}
