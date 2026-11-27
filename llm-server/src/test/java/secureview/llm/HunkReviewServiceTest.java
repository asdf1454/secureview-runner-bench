package secureview.llm;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** PR 헝크 하나에 걸린 정적 분석 경고들을 기존 판정 로직으로 판정한다. 줄 범위와 시간 예산을 지킨다. */
class HunkReviewServiceTest {

    private static final String SOURCE = """
            public class UserDao {
                private static final String TABLE = "users";

                public String find(String name) {
                    return "SELECT * FROM " + TABLE + " WHERE name = '" + name + "'";
                }

                public void all() {
                    String sql = "SELECT * FROM users";
                    statement.executeQuery(sql);
                }
            }
            """;
    private static final String FACTS_TP =
            "{\"source\":\"name 매개변수\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[4,5]}";
    private static final String EXPLAINED =
            "{\"explanation\":{\"summary\":\"요약\",\"risk\":\"위험\",\"attackExample\":\"' OR '1'='1\"}}";

    private static final HunkReviewRequest.Hunk HUNK = new HunkReviewRequest.Hunk("h1", "src/UserDao.java", "java",
            "base", "head", 4, 7, "@@ -3,2 +4,7 @@", List.of(new HunkReviewRequest.AddedLine(5, "return ...")));

    private static AnalysisFinding finding(String id, int line) {
        return new AnalysisFinding("pr", id, "JAVA", "CWE-89", "SQL 인젝션", "HIGH", "FindSecBugs",
                "SQL_INJECTION_JDBC", "m", line, "src/UserDao.java");
    }

    private static HunkReviewRequest request(Integer budgetSec, AnalysisFinding... findings) {
        return new HunkReviewRequest("pr-1", HUNK, SOURCE, List.of(findings), budgetSec);
    }

    private static HunkReviewService service(LlmClient llm) {
        return new HunkReviewService(llm, "m", Duration.ofSeconds(30));
    }

    @Test
    void truePositiveHasDesignDocFields() {
        HunkReviewResponse r = service(new FakeLlm(FACTS_TP, EXPLAINED)).review(request(null, finding("f1", 5)));

        assertEquals("h1", r.hunkId());
        HunkReviewResponse.Finding f = r.findings().get(0);
        assertEquals("h1:CWE-89:5", f.id());
        assertEquals("f1", f.findingId());
        assertEquals("CWE-89", f.cwe());
        assertEquals("HIGH", f.severity());
        assertEquals(5, f.line());
        assertEquals(5, f.endLine());
        assertEquals("SQL 인젝션", f.title());
        assertEquals("TRUE_POSITIVE", f.verdict());
        assertEquals("요약. 위험", f.explanation());
        assertEquals(List.of(4, 5), f.evidenceLines());
        assertNull(f.suggestion());
        assertEquals("m", f.model());
        assertTrue(f.latencySec() >= 0);
    }

    /** 댓글의 "수정 방향"은 S6 수정안의 이유를 쓴다. 수정 코드 자체는 재검증 전이라 내보내지 않는다. */
    @Test
    void truePositiveGetsSuggestionFromFixReason() {
        String fixed = "    public String find(String name) {\\n"
                + "        return \\\"SELECT * FROM \\\" + TABLE + \\\" WHERE name = ?\\\";\\n    }";
        FakeLlm llm = new FakeLlm(FACTS_TP, EXPLAINED, "{\"code\":\"" + fixed + "\",\"reason\":\"? 자리에 바인딩\"}");

        HunkReviewResponse.Finding f = service(llm).review(request(null, finding("f1", 5))).findings().get(0);

        assertEquals("? 자리에 바인딩", f.suggestion());
        assertEquals(3, llm.prompts.size());
    }

    @Test
    void falsePositiveGetsNoSuggestion() {
        FakeLlm llm = new FakeLlm("{\"source\":\"상수\",\"externalInput\":false,\"evidenceLines\":[5]}");

        HunkReviewResponse.Finding f = service(llm).review(request(null, finding("f1", 5))).findings().get(0);

        assertNull(f.suggestion());
        assertEquals(1, llm.prompts.size());
    }

    @Test
    void constantArgumentIsJudgedWithoutLlm() {
        FakeLlm llm = new FakeLlm();

        HunkReviewResponse r = service(llm).review(request(null, finding("f2", 10)));

        assertEquals("LIKELY_FALSE_POSITIVE", r.findings().get(0).verdict());
        assertTrue(llm.prompts.isEmpty());
    }

    @Test
    void lineOutsideHunkIsRejected() {
        InvalidLineException e = assertThrows(InvalidLineException.class,
                () -> service(new FakeLlm()).review(request(null, finding("f3", 11))));

        assertTrue(e.getMessage().contains("4~10"));
    }

    @Test
    void noFindingsMeansNoLlmCall() {
        FakeLlm llm = new FakeLlm();

        HunkReviewResponse r = service(llm).review(request(null));

        assertTrue(r.findings().isEmpty());
        assertTrue(llm.prompts.isEmpty());
    }

    @Test
    void zeroBudgetLeavesFindingsUndecided() {
        FakeLlm llm = new FakeLlm();

        HunkReviewResponse r = service(llm).review(request(0, finding("f1", 5)));

        assertEquals("UNDECIDED", r.findings().get(0).verdict());
        assertTrue(llm.prompts.isEmpty());
    }

    @Test
    void missingValuesAreRejected() {
        HunkReviewService s = service(new FakeLlm());

        assertThrows(IllegalArgumentException.class,
                () -> s.review(new HunkReviewRequest("pr", null, SOURCE, List.of(), null)));
        assertThrows(IllegalArgumentException.class,
                () -> s.review(new HunkReviewRequest("pr", HUNK, " ", List.of(), null)));
        assertThrows(IllegalArgumentException.class, () -> s.review(new HunkReviewRequest("pr",
                new HunkReviewRequest.Hunk("", "a", "java", "b", "h", 1, 1, "", List.of()), SOURCE, List.of(), null)));
    }

    /** 첫 호출에서 한 번 한도(429)에 걸린 뒤 정해 둔 응답을 돌려준다. waitMillis가 크면 매번 한도에 걸린다. */
    private static final class LimitedLlm implements LlmClient {
        private final FakeLlm answers;
        private final long waitMillis;
        private final boolean always;
        private long hits;

        LimitedLlm(long waitMillis, boolean always, String... answers) {
            this.answers = new FakeLlm(answers);
            this.waitMillis = waitMillis;
            this.always = always;
        }

        @Override
        public String generateJson(String prompt) {
            if (always || hits == 0) {
                hits++;
                throw new LlmRateLimitException("LLM API 사용 한도 초과 (429, TPM)", waitMillis);
            }
            return answers.generateJson(prompt);
        }

        @Override
        public long rateLimitHits() {
            return hits;
        }
    }

    @Test
    void waitsOnRateLimitThenJudgesAndReportsIt() {
        HunkReviewResponse r = service(new LimitedLlm(10, false, FACTS_TP, EXPLAINED)).review(request(null, finding("f1", 5)));

        assertEquals("TRUE_POSITIVE", r.findings().get(0).verdict());
        assertTrue(r.findings().get(0).explanation().startsWith("요약"), "설명도 한도 대기 뒤에 만든다");
        assertTrue(r.rateLimited());
    }

    @Test
    void givesUpOnLongRateLimitWithClearReason() {
        long started = System.nanoTime();
        HunkReviewResponse r = service(new LimitedLlm(StructuredLlm.MAX_LIMIT_WAIT_MILLIS + 1, true))
                .review(request(null, finding("f1", 5)));

        assertEquals("UNDECIDED", r.findings().get(0).verdict());
        assertTrue(r.findings().get(0).explanation().contains("사용 한도"), r.findings().get(0).explanation());
        assertTrue(r.rateLimited());
        assertTrue((System.nanoTime() - started) / 1_000_000 < 5_000, "하루 한도는 기다리지 않는다");
    }

    @Test
    void noRateLimitFlagWhenNotLimited() {
        assertFalse(service(new FakeLlm(FACTS_TP, EXPLAINED)).review(request(null, finding("f1", 5))).rateLimited());
    }
}
