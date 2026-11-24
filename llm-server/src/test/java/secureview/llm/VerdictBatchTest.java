package secureview.llm;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class VerdictBatchTest {

    private static final String TP = "{\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[16],\"reason\":\"r\","
            + "\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}";
    private static final String FP = "{\"externalInput\":false,\"source\":\"상수\",\"evidenceLines\":[16]}";

    private static VerdictBatch.Item item(String id, String severity, int start, int cwe) {
        Finding f = new Finding(id, "A.java", 16, 16, "R", cwe, severity, "m", List.of("t"));
        return new VerdictBatch.Item(f, new CodeContext("A.java", start, start + 9,
                List.of("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"), true, new TreeMap<>()));
    }

    @Test
    void judgesFactsOnlySoReportCanShowBeforeExplanations() {
        String facts = "{\"source\":\"name\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[16]}";
        FakeLlm llm = new FakeLlm(facts,
                "{\"reason\":\"문자열 연결\",\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}");
        VerdictService service = new VerdictService(llm);
        VerdictBatch.Item item = item("A", "HIGH", 10, 89);

        Verdict quick = new VerdictBatch(service).judgeAll(List.of(item), Duration.ofMinutes(1)).get("A");

        assertEquals(1, llm.prompts.size(), "목록 단계에서는 설명을 만들지 않는다");
        assertEquals(Verdict.Result.TRUE_POSITIVE, quick.result());
        assertNull(quick.explanation());

        Verdict explained = service.explain(quick, item.finding(), item.context());
        assertEquals("a", explained.explanation().attackExample());
    }

    @Test
    void explainLeavesFalsePositiveWithoutLlmCall() {
        FakeLlm llm = new FakeLlm();
        Verdict fp = new Verdict(Verdict.Result.LIKELY_FALSE_POSITIVE, 0, List.of(16), "r", null);
        VerdictBatch.Item item = item("A", "HIGH", 10, 89);

        assertSame(fp, new VerdictService(llm).explain(fp, item.finding(), item.context()));
        assertEquals(0, llm.prompts.size());
    }

    @Test
    void sameFunctionAndCweReusesTruePositive() {
        FakeLlm llm = new FakeLlm(TP);
        Map<String, Verdict> out = new VerdictBatch(new VerdictService(llm))
                .judgeAll(List.of(item("A", "HIGH", 10, 89), item("B", "HIGH", 10, 89)), Duration.ofMinutes(1));

        assertEquals(1, llm.prompts.size());
        assertEquals(Verdict.Result.TRUE_POSITIVE, out.get("B").result());
    }

    @Test
    void falsePositiveIsNotReusedBecauseAnotherWarningMayBeReal() {
        FakeLlm llm = new FakeLlm(FP, TP);
        Map<String, Verdict> out = new VerdictBatch(new VerdictService(llm))
                .judgeAll(List.of(item("A", "HIGH", 10, 89), item("B", "HIGH", 10, 89)), Duration.ofMinutes(1));

        assertEquals(2, llm.prompts.size());
        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, out.get("A").result());
        assertEquals(Verdict.Result.TRUE_POSITIVE, out.get("B").result());
    }

    @Test
    void differentCweInSameFunctionIsJudgedSeparately() {
        FakeLlm llm = new FakeLlm(TP, TP);
        new VerdictBatch(new VerdictService(llm))
                .judgeAll(List.of(item("A", "HIGH", 10, 89), item("B", "HIGH", 10, 79)), Duration.ofMinutes(1));

        assertEquals(2, llm.prompts.size());
    }

    @Test
    void highSeverityGoesFirstAndWarningsPastBudgetStayUndetermined() {
        AtomicLong now = new AtomicLong();
        List<String> order = new ArrayList<>();
        LlmClient slow = prompt -> {
            now.addAndGet(Duration.ofSeconds(30).toNanos());
            order.add(prompt);
            return TP;
        };
        Map<String, Verdict> out = new VerdictBatch(new VerdictService(slow), now::get).judgeAll(List.of(
                item("low", "LOW", 10, 89), item("med", "MEDIUM", 11, 89), item("high", "HIGH", 12, 89)),
                Duration.ofSeconds(50));

        assertEquals(Verdict.Result.TRUE_POSITIVE, out.get("high").result());
        assertEquals(Verdict.Result.TRUE_POSITIVE, out.get("med").result());
        assertEquals(Verdict.Result.UNDETERMINED, out.get("low").result());
        assertTrue(out.get("low").reason().contains("시간"));
        assertEquals(2, order.size());
    }

    @Test
    void llmFailureBecomesUndeterminedAndKeepsEveryWarning() {
        LlmClient down = prompt -> {
            throw new LlmException("연결 실패");
        };
        Map<String, Verdict> out = new VerdictBatch(new VerdictService(down))
                .judgeAll(List.of(item("A", "HIGH", 10, 89), item("B", "LOW", 30, 89)), Duration.ofMinutes(1));

        assertEquals(2, out.size());
        assertEquals(Verdict.Result.UNDETERMINED, out.get("A").result());
    }
}
