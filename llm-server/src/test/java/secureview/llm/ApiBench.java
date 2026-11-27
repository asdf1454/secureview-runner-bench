package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 외부 API(무료 Groq 등)로 정확도와 속도를 잰다. 키는 환경 변수 SR_LLM_BASE_URL, SR_LLM_MODEL, SR_LLM_API_KEY.
 *
 * owasp: OWASP Benchmark 4종류(SQL·명령어·경로·XSS)에서 진짜와 안전을 같은 수로 골라 PR 검토와 같은 순서
 * (상수 판정 → VerdictBatch)로 판정한다. 무료 한도(429)에 걸리면 알려 준 시간만큼 기다렸다 다시 보낸다.
 * 결과는 테스트 한 건마다 jsonl에 한 줄씩 붙이고, 다시 실행하면 이미 잰 테스트는 건너뛴다(하루 한도를 넘는 표본용).
 * 설명과 수정 방향은 만들지 않는다. 판정 정확도에 영향이 없고 토큰만 쓴다.
 *
 * large: 500줄 파일 하나를 PR 헝크 검토(/internal/review-hunk와 같은 코드, 예산 45초)로 반복 검토한다.
 * 한도에 걸려도 기다리지 않는다. 실제 PR 검토와 같게 재기 위해서다.
 *
 * 사용: ./mvnw -q test-compile exec:java -Dexec.classpathScope=test -Dexec.mainClass=secureview.llm.ApiBench
 *       -Dexec.args="owasp BenchmarkJava폴더 경고CSV폴더 결과.jsonl 종류별개수 제한분"
 *       -Dexec.args="large examples/Large500.java 반복횟수"
 */
public final class ApiBench {

    /** OWASP 분류 → CWE. 경고 CSV(warnings-분류.csv)는 docs/benchmark-constant.mjs가 FindSecBugs 결과로 만든다. */
    static final Map<String, Integer> CATEGORIES = new LinkedHashMap<>();

    static {
        CATEGORIES.put("sqli", 89);
        CATEGORIES.put("cmdi", 78);
        CATEGORIES.put("pathtraver", 22);
        CATEGORIES.put("xss", 79);
    }

    record Sample(String test, String category, boolean real, List<Integer> lines) {
    }

    /** 한도 때문에 제한 시간 안에 끝낼 수 없을 때. LlmException이 아니어야 StructuredLlm이 재요청하지 않는다. */
    static final class Stop extends RuntimeException {
        Stop(String message) {
            super(message);
        }
    }

    public static void main(String[] args) throws Exception {
        OpenAiCompatibleClient client = new OpenAiCompatibleClient(env("SR_LLM_BASE_URL"), System.getenv("SR_LLM_API_KEY"),
                env("SR_LLM_MODEL"), Duration.ofMinutes(2));
        switch (args[0]) {
            case "owasp" -> owasp(client, Path.of(args[1]), Path.of(args[2]), Path.of(args[3]),
                    Integer.parseInt(args[4]), Integer.parseInt(args[5]));
            case "large" -> large(client, Path.of(args[1]), Integer.parseInt(args[2]));
            default -> throw new IllegalArgumentException("owasp 또는 large");
        }
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + "을 설정하세요.");
        }
        return value;
    }

    // ---------- owasp ----------

    static void owasp(OpenAiCompatibleClient client, Path benchDir, Path csvDir, Path out, int perCategory, int minutes)
            throws IOException {
        long deadline = System.currentTimeMillis() + minutes * 60_000L;
        WaitOnLimit llm = new WaitOnLimit(client, deadline);
        VerdictBatch batch = new VerdictBatch(new VerdictService(llm));
        ContextExtractor extractor = new ContextExtractor();
        Path code = benchDir.resolve("src/main/java/org/owasp/benchmark/testcode");

        Files.createDirectories(out.toAbsolutePath().getParent());
        Set<String> done = new HashSet<>();
        for (JsonNode r : read(out)) {
            done.add(r.path("test").asText());
        }
        List<Sample> samples = sample(csvDir, perCategory);
        System.out.printf("표본 %d건, 이미 잰 것 %d건, 제한 %d분%n", samples.size(), done.size(), minutes);

        int measured = 0;
        for (Sample s : samples) {
            if (done.contains(s.test())) {
                continue;
            }
            if (System.currentTimeMillis() > deadline) {
                System.out.println("제한 시간이 지나 멈춤. 다음 실행에서 이어서 잰다.");
                break;
            }
            Map<String, Object> record;
            try {
                record = judge(s, Files.readString(code.resolve(s.test() + ".java")), batch, extractor, client, llm);
            } catch (Stop e) {
                System.out.println("멈춤: " + e.getMessage());
                break;
            } catch (LlmException e) {
                Throwable stop = e.getCause();
                if (stop instanceof Stop) {
                    System.out.println("멈춤: " + stop.getMessage());
                    break;
                }
                throw e;
            }
            Files.writeString(out, StructuredLlm.MAPPER.writeValueAsString(record) + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            measured++;
            System.out.printf("%d/%d %s %s %s → 경고 %s건, 상수 %s, 진짜 %s, 오탐 %s, 판정 못 함 %s, %s초, %s토큰%n",
                    done.size() + measured, samples.size(), s.test(), s.category(), s.real() ? "진짜" : "안전",
                    record.get("warnings"), record.get("constant"), record.get("tp"), record.get("fp"),
                    record.get("undecided"), record.get("sec"), record.get("tokens"));
        }
        String summary = summary(read(out), client.model(), samples.size());
        System.out.println(summary);
        Files.writeString(Path.of(out.toString().replaceAll("\\.jsonl$", "") + ".md"), summary, StandardCharsets.UTF_8);
    }

    /** 분류마다 진짜 half, 안전 half를 테스트 번호 전체에 고르게 뽑는다(앞 번호에 몰리지 않게). 분류를 번갈아 놓아 중간에 멈춰도 고르게 남는다. */
    static List<Sample> sample(Path csvDir, int perCategory) throws IOException {
        int half = perCategory / 2;
        List<List<Sample>> byCategory = new ArrayList<>();
        for (String category : CATEGORIES.keySet()) {
            Map<String, List<Integer>> lines = new TreeMap<>();
            Map<String, Boolean> real = new TreeMap<>();
            for (String row : Files.readAllLines(csvDir.resolve("warnings-" + category + ".csv"))) {
                String[] c = row.trim().split(",");
                if (c.length < 3) {
                    continue;
                }
                lines.computeIfAbsent(c[0], k -> new ArrayList<>()).add(Integer.parseInt(c[1]));
                real.put(c[0], Boolean.parseBoolean(c[2]));
            }
            List<Sample> reals = new ArrayList<>();
            List<Sample> safes = new ArrayList<>();
            lines.forEach((test, ls) -> (real.get(test) ? reals : safes).add(new Sample(test, category, real.get(test), ls)));
            List<Sample> picked = new ArrayList<>();
            List<Sample> r = spread(reals, half);
            List<Sample> f = spread(safes, half);
            for (int i = 0; i < Math.max(r.size(), f.size()); i++) {
                if (i < r.size()) {
                    picked.add(r.get(i));
                }
                if (i < f.size()) {
                    picked.add(f.get(i));
                }
            }
            byCategory.add(picked);
        }
        List<Sample> all = new ArrayList<>();
        int longest = byCategory.stream().mapToInt(List::size).max().orElse(0);
        for (int i = 0; i < longest; i++) {
            for (List<Sample> list : byCategory) {
                if (i < list.size()) {
                    all.add(list.get(i));
                }
            }
        }
        return all;
    }

    static <T> List<T> spread(List<T> items, int n) {
        if (items.size() <= n) {
            return items;
        }
        List<T> picked = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            picked.add(items.get((int) ((long) i * items.size() / n)));
        }
        return picked;
    }

    /** PR 검토(HunkReviewService)와 같은 순서: 상수면 LLM 없이 오탐, 나머지는 VerdictBatch. 시간 제한은 두지 않는다. */
    static Map<String, Object> judge(Sample s, String source, VerdictBatch batch, ContextExtractor extractor,
                                     OpenAiCompatibleClient client, WaitOnLimit llm) {
        int cwe = CATEGORIES.get(s.category());
        List<VerdictBatch.Item> items = new ArrayList<>();
        int constant = 0;
        for (int line : s.lines()) {
            if (ConstantArgs.isConstant(source, line, cwe)) {
                constant++;
            } else {
                Finding f = new Finding(s.test() + ":" + line, s.test() + ".java", line, line, "bench", cwe, "HIGH", "",
                        List.of("FindSecBugs"));
                items.add(new VerdictBatch.Item(f, extractor.extract(f, source)));
            }
        }
        long started = System.nanoTime();
        long slept = llm.sleptMillis();
        long tokens = client.tokensUsed();
        Map<String, Verdict> verdicts = items.isEmpty() ? Map.of() : batch.judgeAll(items, Duration.ofHours(12));
        double sec = Math.round(((System.nanoTime() - started) / 1e6 - (llm.sleptMillis() - slept)) / 100.0) / 10.0;

        int tp = 0;
        int fp = constant;
        int undecided = 0;
        for (Verdict v : verdicts.values()) {
            if (v.reason() != null && v.reason().contains("연결하지 못해")) {
                throw new Stop("LLM API에 연결하지 못함");
            }
            switch (v.result()) {
                case TRUE_POSITIVE -> tp++;
                case LIKELY_FALSE_POSITIVE -> fp++;
                case UNDETERMINED -> undecided++;
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("test", s.test());
        r.put("category", s.category());
        r.put("cwe", cwe);
        r.put("real", s.real());
        r.put("warnings", s.lines().size());
        r.put("constant", constant);
        r.put("tp", tp);
        r.put("fp", fp);
        r.put("undecided", undecided);
        r.put("filtered", fp == s.lines().size()); // 경고가 모두 오탐 추정일 때만 테스트를 걸러진 것으로 센다
        r.put("sec", sec);
        r.put("tokens", client.tokensUsed() - tokens);
        r.put("model", client.model());
        return r;
    }

    static List<JsonNode> read(Path out) throws IOException {
        List<JsonNode> records = new ArrayList<>();
        if (Files.exists(out)) {
            for (String line : Files.readAllLines(out, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    records.add(StructuredLlm.MAPPER.readTree(line));
                }
            }
        }
        return records;
    }

    /** 오탐 감소 = 안전 테스트 중 걸러진 비율, 재현율 = 진짜 테스트 중 남은 비율 (테스트 단위, 기존 측정과 같은 기준). */
    static String summary(List<JsonNode> records, String model, int planned) {
        StringBuilder b = new StringBuilder("## OWASP Benchmark 판정 (" + model + ")\n\n")
                .append("잰 테스트 ").append(records.size()).append(" / ").append(planned).append("건\n\n")
                .append("| 분류 | 오탐 감소 (안전 중 걸러짐) | 재현율 (진짜 중 남음) | LLM 없이 상수 처리 | 판정 못 한 경고 | LLM 쓴 테스트당 토큰 | LLM 쓴 테스트당 초 |\n")
                .append("|---|---|---|---|---|---|---|\n");
        List<String> rows = new ArrayList<>(CATEGORIES.keySet());
        rows.add("전체");
        for (String category : rows) {
            List<JsonNode> rs = records.stream()
                    .filter(r -> category.equals("전체") || category.equals(r.path("category").asText())).toList();
            long safes = rs.stream().filter(r -> !r.path("real").asBoolean()).count();
            long filtered = rs.stream().filter(r -> !r.path("real").asBoolean() && r.path("filtered").asBoolean()).count();
            long reals = rs.stream().filter(r -> r.path("real").asBoolean()).count();
            long kept = rs.stream().filter(r -> r.path("real").asBoolean() && !r.path("filtered").asBoolean()).count();
            long constant = rs.stream().filter(r -> r.path("constant").asInt() == r.path("warnings").asInt()).count();
            long undecided = rs.stream().mapToLong(r -> r.path("undecided").asLong()).sum();
            long warnings = rs.stream().mapToLong(r -> r.path("warnings").asLong()).sum();
            List<JsonNode> used = rs.stream().filter(r -> r.path("tokens").asLong() > 0).toList();
            long tokens = used.isEmpty() ? 0 : used.stream().mapToLong(r -> r.path("tokens").asLong()).sum() / used.size();
            double sec = used.isEmpty() ? 0 : used.stream().mapToDouble(r -> r.path("sec").asDouble()).sum() / used.size();
            b.append("| ").append(category)
                    .append(" | ").append(ratio(filtered, safes))
                    .append(" | ").append(ratio(kept, reals))
                    .append(" | ").append(constant).append("건")
                    .append(" | ").append(undecided).append(" / ").append(warnings)
                    .append(" | ").append(tokens)
                    .append(" | ").append(String.format("%.1f", sec)).append(" |\n");
        }
        return b.toString();
    }

    private static String ratio(long a, long b) {
        return b == 0 ? "-" : String.format("%d/%d (%.1f%%)", a, b, 100.0 * a / b);
    }

    /** 429(무료 한도)와 일시적인 5xx를 기다렸다 다시 보낸다. 기다린 시간은 처리 시간에서 뺀다. */
    static final class WaitOnLimit implements LlmClient {

        private static final Pattern WAIT = Pattern.compile(
                "try again in (?:(\\d+)h)?(?:(\\d+)m(?!s))?(?:([\\d.]+)s)?", Pattern.CASE_INSENSITIVE);
        private static final Pattern WAIT_MS = Pattern.compile("try again in ([\\d.]+)ms", Pattern.CASE_INSENSITIVE);
        private static final Pattern KIND = Pattern.compile("\\((TPM|TPD|RPM|RPD)\\)");
        private static final Pattern STATUS = Pattern.compile("응답 코드 (\\d{3})");

        private final LlmClient client;
        private final long deadline;
        private long slept;

        WaitOnLimit(LlmClient client, long deadline) {
            this.client = client;
            this.deadline = deadline;
        }

        long sleptMillis() {
            return slept;
        }

        @Override
        public String generateJson(String prompt) {
            return retry(() -> client.generateJson(prompt));
        }

        @Override
        public String generateJson(String prompt, JsonNode schema) {
            return retry(() -> client.generateJson(prompt, schema));
        }

        private String retry(Supplier<String> call) {
            int serverErrors = 0;
            while (true) {
                try {
                    return call.get();
                } catch (LlmUnavailableException e) {
                    throw e;
                } catch (LlmException e) {
                    String message = String.valueOf(e.getMessage());
                    Matcher status = STATUS.matcher(message);
                    int code = status.find() ? Integer.parseInt(status.group(1)) : 0;
                    long wait;
                    String why;
                    if (code == 429) {
                        wait = waitMillis(message);
                        Matcher kind = KIND.matcher(message);
                        why = "무료 한도 " + (kind.find() ? kind.group(1) : "");
                    } else if (code >= 500 && serverErrors++ < 3) {
                        wait = 10_000;
                        why = "서버 오류 " + code;
                    } else {
                        throw e;
                    }
                    if (System.currentTimeMillis() + wait > deadline) {
                        throw new Stop(why + ": " + wait / 1000 + "초를 기다리면 제한 시간을 넘음");
                    }
                    System.out.printf("  [%s] %.1f초 기다림%n", why, wait / 1000.0);
                    try {
                        Thread.sleep(wait);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new Stop("중단됨");
                    }
                    slept += wait;
                }
            }
        }

        /** Groq 429 본문의 "Please try again in 7.05s" / "2m30.5s" / "450ms". 못 읽으면 10초. 0.5초 여유를 둔다. */
        static long waitMillis(String message) {
            Matcher ms = WAIT_MS.matcher(message);
            if (ms.find()) {
                return (long) Double.parseDouble(ms.group(1)) + 500;
            }
            Matcher m = WAIT.matcher(message);
            if (m.find() && (m.group(1) != null || m.group(2) != null || m.group(3) != null)) {
                double sec = (m.group(1) == null ? 0 : Integer.parseInt(m.group(1)) * 3600)
                        + (m.group(2) == null ? 0 : Integer.parseInt(m.group(2)) * 60)
                        + (m.group(3) == null ? 0 : Double.parseDouble(m.group(3)));
                return (long) (sec * 1000) + 500;
            }
            return 10_000;
        }
    }

    // ---------- large ----------

    /** 500줄 파일의 "// warning" 줄마다 경고를 만들어 PR 헝크 검토와 같은 코드로 검토한다. 실행 사이에 1분 쉬어 분당 한도를 비운다. */
    static void large(OpenAiCompatibleClient client, Path file, int runs) throws Exception {
        String source = Files.readString(file);
        List<String> lines = source.lines().toList();
        List<AnalysisFinding> findings = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).contains("// warning")) {
                findings.add(new AnalysisFinding("bench", "F-" + (i + 1), "JAVA", "CWE-89", "SQL 인젝션", "HIGH",
                        "FindSecBugs", "SQL_INJECTION_JDBC", "", i + 1, file.getFileName().toString()));
            }
        }
        HunkReviewRequest request = new HunkReviewRequest("bench",
                new HunkReviewRequest.Hunk("large", file.getFileName().toString(), "java", "base", "head", 1, lines.size(), "",
                        List.of()),
                source, findings, (int) HunkReviewService.MAX_BUDGET.toSeconds());
        HunkReviewService service = new HunkReviewService(client, client.model(), HunkReviewService.MAX_BUDGET);
        System.out.printf("%s: %d줄, 경고 %d건, 예산 %d초, 모델 %s%n", file.getFileName(), lines.size(), findings.size(),
                HunkReviewService.MAX_BUDGET.toSeconds(), client.model());
        List<Long> times = new ArrayList<>();
        for (int run = 1; run <= runs; run++) {
            if (run > 1) {
                Thread.sleep(61_000);
            }
            long tokens = client.tokensUsed();
            long started = System.nanoTime();
            HunkReviewResponse response = service.review(request);
            long ms = (System.nanoTime() - started) / 1_000_000;
            times.add(ms);
            StringBuilder verdicts = new StringBuilder();
            int explained = 0;
            int suggested = 0;
            for (HunkReviewResponse.Finding f : response.findings()) {
                verdicts.append(f.line()).append('=').append(f.verdict()).append(' ');
                if ("TRUE_POSITIVE".equals(f.verdict()) && f.explanation() != null && !f.explanation().isBlank()) {
                    explained++;
                }
                if (f.suggestion() != null) {
                    suggested++;
                }
            }
            System.out.printf("%d회: %d ms, %d토큰, 설명 %d, 수정 방향 %d | %s%n", run, ms, client.tokensUsed() - tokens,
                    explained, suggested, verdicts.toString().trim());
        }
        times.sort(Long::compare);
        System.out.printf("중앙값 %d ms, 최소 %d ms, 최대 %d ms%n", times.get(times.size() / 2), times.get(0),
                times.get(times.size() - 1));
    }
}
