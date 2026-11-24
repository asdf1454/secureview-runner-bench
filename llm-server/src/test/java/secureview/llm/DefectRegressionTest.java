package secureview.llm;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/** docs/KNOWN_ISSUES.md에 기록했던 결함이 다시 나오지 않는지 확인한다. */
class DefectRegressionTest {

    private static final String SRC = "class A {\n  void f(String s) {\n    run(s);\n    run2(s);\n  }\n}\n";
    private static final String TP = "{\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[3],\"reason\":\"r\","
            + "\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}";
    private static final Verdict TP_VERDICT = new Verdict(Verdict.Result.TRUE_POSITIVE, 1, List.of(3), "r", null);

    private static Finding finding(int line, int cwe) {
        return new Finding("F-" + line, "A.java", line, line, "R", cwe, "HIGH", "m", List.of("t"));
    }

    private static CodeContext context() {
        return new ContextExtractor().extract(finding(3, 89), SRC);
    }

    // 1. 동시 요청
    @Test
    void concurrentExtractionReturnsCorrectFunction() throws Exception {
        StringBuilder big = new StringBuilder("class A {\n");
        for (int i = 0; i < 400; i++) {
            big.append("  void m").append(i).append("(int a) { int b = a + ").append(i).append("; }\n");
        }
        String source = big.append("}\n").toString();
        ContextExtractor extractor = new ContextExtractor();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<CodeContext>> futures = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                futures.add(pool.submit(() -> extractor.extract(finding(100, 89), source)));
            }
            for (Future<CodeContext> f : futures) {
                CodeContext c = f.get();
                assertTrue(c.wholeFunction());
                assertEquals(100, c.startLine());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // 2. 근거 줄의 null
    @Test
    void nullEvidenceLineIsRetriedInsteadOfCrashing() {
        FakeLlm llm = new FakeLlm("{\"externalInput\":false,\"source\":\"x\",\"evidenceLines\":[null]}",
                "{\"externalInput\":false,\"source\":\"x\",\"evidenceLines\":[3]}");

        Verdict v = new VerdictService(llm).judgeFacts(finding(3, 89), context());

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
        assertEquals(2, llm.prompts.size());
    }

    // 3. 파일 범위 밖 줄 번호
    @Test
    void lineBeyondFileUsesEndOfFileInsteadOfCrashing() {
        CodeContext c = new ContextExtractor().extract(finding(100, 89), SRC);

        assertFalse(c.wholeFunction());
        assertTrue(c.startLine() >= 1 && c.startLine() <= c.endLine() && c.endLine() <= 6);
    }

    @Test
    void negativeLineAndEmptySourceDoNotCrash() {
        assertDoesNotThrow(() -> new ContextExtractor().extract(finding(-100, 89), SRC));
        assertDoesNotThrow(() -> new ContextExtractor().extract(finding(5, 89), ""));
    }

    // 4. 심각도 없음
    @Test
    void missingSeverityIsJudgedLast() {
        Finding none = new Finding("none", "A.java", 3, 3, "R", 89, null, "m", List.of());
        FakeLlm llm = new FakeLlm(TP);

        Map<String, Verdict> out = new VerdictBatch(new VerdictService(llm)).judgeAll(List.of(
                new VerdictBatch.Item(none, context())), Duration.ofMinutes(1));

        assertEquals(Verdict.Result.TRUE_POSITIVE, out.get("none").result());
    }

    // 5. Ollama 꺼짐
    @Test
    void unavailableServerIsReportedAsSuchWithoutRetry() {
        int[] calls = {0};
        LlmClient down = prompt -> {
            calls[0]++;
            throw new LlmUnavailableException("연결 거부", null);
        };

        Verdict v = new VerdictService(down).judgeFacts(finding(3, 89), context());

        assertEquals(Verdict.Result.UNDETERMINED, v.result());
        assertTrue(v.reason().contains("Ollama"));
        assertEquals(1, calls[0], "연결 실패는 다시 시도해도 소용없다");
    }

    @Test
    void connectionRefusedBecomesUnavailableException() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        int port = server.getAddress().getPort();
        server.stop(0);
        OllamaClient client = new OllamaClient("http://localhost:" + port, "m", Duration.ofSeconds(2));

        assertThrows(LlmUnavailableException.class, () -> client.generateJson("p"));
    }

    @Test
    void qaAndFixReportUnavailableServerToCaller() {
        LlmClient down = prompt -> {
            throw new LlmUnavailableException("연결 거부", null);
        };

        assertThrows(LlmUnavailableException.class,
                () -> new QaService(down).ask(finding(3, 89), context(), TP_VERDICT, List.of(), "q"));
        assertThrows(LlmUnavailableException.class,
                () -> new FixService(down).propose(finding(3, 89), context(), TP_VERDICT, null));
    }

    // 6. 시간 제한
    @Test
    void budgetStopsCallAlreadyInProgress() {
        LlmClient slow = prompt -> {
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new LlmException("호출 중단", e);
            }
            return TP;
        };
        long started = System.nanoTime();

        Map<String, Verdict> out = new VerdictBatch(new VerdictService(slow)).judgeAll(List.of(
                new VerdictBatch.Item(finding(3, 89), context())), Duration.ofMillis(300));

        long elapsedMs = (System.nanoTime() - started) / 1_000_000;
        assertTrue(elapsedMs < 2000, "제한을 크게 넘지 않아야 한다: " + elapsedMs + " ms");
        assertEquals(Verdict.Result.UNDETERMINED, out.get("F-3").result());
        assertTrue(out.get("F-3").reason().contains("시간"));
    }

    // 7. 재사용한 판정의 근거 줄
    @Test
    void reusedVerdictIncludesItsOwnWarningLine() {
        ContextExtractor ex = new ContextExtractor();
        Finding first = finding(3, 89);
        Finding second = finding(4, 89);
        FakeLlm llm = new FakeLlm(TP);

        Map<String, Verdict> out = new VerdictBatch(new VerdictService(llm)).judgeAll(List.of(
                new VerdictBatch.Item(first, ex.extract(first, SRC)),
                new VerdictBatch.Item(second, ex.extract(second, SRC))), Duration.ofMinutes(1));

        assertEquals(1, llm.prompts.size());
        assertEquals(List.of(3), out.get("F-3").evidenceLines());
        assertEquals(List.of(3, 4), out.get("F-4").evidenceLines());
    }

    // 8. throws 변경
    @Test
    void fixThatChangesThrowsIsRetried() {
        FakeLlm llm = new FakeLlm("{\"code\":\"void f(String s) throws Exception { safe(s); }\",\"reason\":\"r\"}",
                "{\"code\":\"void f(String s) { safe(s); }\",\"reason\":\"r\"}");

        Fix fix = new FixService(llm).propose(finding(3, 89), context(), TP_VERDICT, null).orElseThrow();

        assertEquals(2, llm.prompts.size());
        assertFalse(fix.code().contains("throws"));
    }

    // 9. 수정 이유 없음
    @Test
    void fixWithoutReasonIsRetried() {
        FakeLlm llm = new FakeLlm("{\"code\":\"void f(String s) { safe(s); }\"}",
                "{\"code\":\"void f(String s) { safe(s); }\",\"reason\":\"안전한 호출로 변경\"}");

        Fix fix = new FixService(llm).propose(finding(3, 89), context(), TP_VERDICT, null).orElseThrow();

        assertEquals("안전한 호출로 변경", fix.reason());
    }

    // 10. 질의응답 줄 번호
    @Test
    void answerNamingLineOutsideCodeIsRetried() {
        FakeLlm llm = new FakeLlm("{\"answer\":\"라인 99에서 들어옵니다.\"}", "{\"answer\":\"2번 줄의 매개변수 s입니다.\"}");

        String answer = new QaService(llm).ask(finding(3, 89), context(), TP_VERDICT, List.of(), "q").orElseThrow();

        assertEquals("2번 줄의 매개변수 s입니다.", answer);
        assertTrue(llm.prompts.get(1).contains("99"));
    }

    @Test
    void qaPromptAsksForDeclarationLineOfParameters() {
        FakeLlm llm = new FakeLlm("{\"answer\":\"a\"}");

        new QaService(llm).ask(finding(3, 89), context(), TP_VERDICT, List.of(), "q");

        assertTrue(llm.prompts.get(0).contains("함수 선언 줄"));
    }
}
