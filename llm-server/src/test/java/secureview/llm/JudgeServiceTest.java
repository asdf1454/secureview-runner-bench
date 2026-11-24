package secureview.llm;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** API 명세 형식 A를 받아 형식 B를 돌려준다. 한 건당 제한 시간을 지킨다. */
class JudgeServiceTest {

    private static final String SOURCE = """
            public class UserDao {
                private static final String TABLE = "users";

                public String find(String name) {
                    return "SELECT * FROM " + TABLE + " WHERE name = '" + name + "'";
                }
            }
            """;
    private static final String FACTS_TP =
            "{\"source\":\"name 매개변수\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[4,5]}";
    private static final String EXPLAINED =
            "{\"explanation\":{\"summary\":\"요약\",\"risk\":\"위험\",\"attackExample\":\"' OR '1'='1\"}}";

    private static JudgeRequest request() {
        return request("CWE-89");
    }

    private static JudgeRequest request(String cwe) {
        return new JudgeRequest(new AnalysisFinding("job", "e91a", "JAVA", cwe, "SQL 인젝션", "HIGH", "FindSecBugs",
                "SQL_INJECTION_JDBC", "m", 5, "/work/job/UserDao.java"), SOURCE);
    }

    private static JudgeService service(LlmClient llm, Duration limit) {
        return new JudgeService(llm, "m", limit);
    }

    private static LlmClient slowAfter(int fastCalls, String... answers) {
        int[] calls = {0};
        return prompt -> {
            int call = calls[0]++;
            if (call >= fastCalls) {
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new LlmException("중단", e);
                }
            }
            return answers[Math.min(call, answers.length - 1)];
        };
    }

    @Test
    void truePositiveReturnsFormatB() {
        JudgeResponse r = service(new FakeLlm(FACTS_TP, EXPLAINED), Duration.ofSeconds(5)).judge(request());

        assertEquals("e91a", r.findingId());
        assertEquals("find", r.function().name());
        assertEquals(4, r.function().startLine());
        assertEquals(6, r.function().endLine());
        assertTrue(r.function().code().startsWith("    public String find"));
        assertEquals("TRUE_POSITIVE", r.llm().verdict());
        assertEquals(List.of(4, 5), r.llm().evidenceLines());
        assertEquals("요약. 위험", r.llm().explanation());
        assertEquals("' OR '1'='1", r.llm().attackExample());
        assertEquals("m", r.llm().model());
        assertTrue(r.llm().latencySec() >= 0);
    }

    @Test
    void falsePositiveHasReasonAndNoAttackExample() {
        JudgeResponse r = service(new FakeLlm("{\"source\":\"상수\",\"externalInput\":false,\"evidenceLines\":[5]}"),
                Duration.ofSeconds(5)).judge(request());

        assertEquals("LIKELY_FALSE_POSITIVE", r.llm().verdict());
        assertTrue(r.llm().explanation().contains("상수"));
        assertNull(r.llm().attackExample());
    }

    @Test
    void unknownFactsBecomeUndecidedWithReason() {
        JudgeResponse r = service(new FakeLlm("{\"source\":\"모름\",\"externalInput\":null,\"evidenceLines\":[]}"),
                Duration.ofSeconds(5)).judge(request());

        assertEquals("UNDECIDED", r.llm().verdict());
        assertTrue(r.llm().explanation().contains("판단할 수 없습니다"));
    }

    @Test
    void judgementOverLimitIsUndecidedButKeepsFunction() {
        JudgeResponse r = service(slowAfter(0, FACTS_TP), Duration.ofMillis(100)).judge(request());

        assertEquals("UNDECIDED", r.llm().verdict());
        assertTrue(r.llm().explanation().contains("시간"));
        assertEquals("find", r.function().name());
    }

    @Test
    void explanationOverLimitKeepsTruePositive() {
        JudgeResponse r = service(slowAfter(1, FACTS_TP), Duration.ofMillis(300)).judge(request());

        assertEquals("TRUE_POSITIVE", r.llm().verdict());
        assertEquals(List.of(4, 5), r.llm().evidenceLines());
        assertTrue(r.llm().explanation().contains("name 매개변수"));
        assertTrue(r.llm().explanation().contains("시간"));
        assertNull(r.llm().attackExample());
    }

    @Test
    void fieldLineEvidenceIsLeftOutBecauseScreenShowsOnlyTheFunction() {
        String facts = "{\"source\":\"s\",\"externalInput\":false,\"evidenceLines\":[2,5]}";

        JudgeResponse r = service(new FakeLlm(facts), Duration.ofSeconds(5)).judge(request());

        assertEquals(List.of(5), r.llm().evidenceLines());
    }

    @Test
    void warningLineIsUsedWhenAllEvidenceIsOutsideFunction() {
        String facts = "{\"source\":\"s\",\"externalInput\":false,\"evidenceLines\":[2]}";

        JudgeResponse r = service(new FakeLlm(facts), Duration.ofSeconds(5)).judge(request());

        assertEquals(List.of(5), r.llm().evidenceLines());
    }

    @Test
    void lineOutsideAnyFunctionStillReturnsFunctionObject() {
        JudgeRequest onField = new JudgeRequest(new AnalysisFinding("job", "f", "JAVA", "CWE-89", "t", "HIGH", "t",
                "r", "m", 2, "/work/job/UserDao.java"), SOURCE);

        JudgeResponse r = service(new FakeLlm("{\"source\":\"s\",\"externalInput\":false,\"evidenceLines\":[2]}"),
                Duration.ofSeconds(5)).judge(onField);

        assertEquals(JudgeService.NO_FUNCTION, r.function().name());
        assertEquals(1, r.function().startLine());
    }

    @Test
    void invalidCweIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> service(new FakeLlm(), Duration.ofSeconds(5)).judge(request("89")));
    }

    @Test
    void missingSourceCodeIsRejected() {
        JudgeRequest empty = new JudgeRequest(request().finding(), " ");

        assertThrows(IllegalArgumentException.class,
                () -> service(new FakeLlm(), Duration.ofSeconds(5)).judge(empty));
    }

    @Test
    void lineBelowOneIsRejected() {
        JudgeRequest bad = new JudgeRequest(new AnalysisFinding("job", "f", "JAVA", "CWE-89", "t", "HIGH", "t",
                "r", "m", 0, "/work/job/UserDao.java"), SOURCE);

        assertThrows(IllegalArgumentException.class,
                () -> service(new FakeLlm(), Duration.ofSeconds(5)).judge(bad));
    }
}
