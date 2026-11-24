package secureview.llm;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/** S6 수정안을 HTTP로 내주기 위한 변환: 형식 A 경고와 파일 전체를 받아, 재검증(형식 C 입력)에 그대로 쓸 값을 돌려준다. */
class FixApiServiceTest {

    private static final String SOURCE = """
            public class UserDao {
                private java.sql.Connection conn;

                public void find(String name) throws Exception {
                    conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
                }
            }
            """;
    private static final String FIXED = "    public void find(String name) throws Exception {\\n"
            + "        conn.prepareStatement(\\\"SELECT 1\\\").executeQuery();\\n    }";
    private static final String ANSWER = "{\"code\":\"" + FIXED + "\",\"reason\":\"바인딩으로 변경\"}";

    private static FixRequest request(String previousFailure) {
        return new FixRequest(new AnalysisFinding("job", "e91a", "JAVA", "CWE-89", "SQL 인젝션", "HIGH", "FindSecBugs",
                "SQL_INJECTION_JDBC", "m", 5, "/work/job/UserDao.java"), SOURCE, "name이 그대로 SQL에 들어감",
                previousFailure);
    }

    private static FixApiService service(LlmClient llm, Duration limit) {
        return new FixApiService(llm, "m", limit);
    }

    @Test
    void returnsFunctionRangeAndFixedCode() {
        FixResponse r = service(new FakeLlm(ANSWER), Duration.ofSeconds(5)).fix(request(null));

        assertEquals("e91a", r.findingId());
        assertEquals("find", r.function().name());
        assertEquals(4, r.function().startLine());
        assertEquals(6, r.function().endLine());
        assertTrue(r.fixedCode().contains("prepareStatement"));
        assertEquals("바인딩으로 변경", r.reason());
        assertEquals("m", r.model());
        assertTrue(r.latencySec() >= 0);
    }

    @Test
    void passesJudgeReasonAndPreviousFailureToTheModel() {
        FakeLlm llm = new FakeLlm(ANSWER);

        service(llm, Duration.ofSeconds(5)).fix(request("STILL_VULNERABLE"));

        assertTrue(llm.prompts.get(0).contains("name이 그대로 SQL에 들어감"));
        assertTrue(llm.prompts.get(0).contains("STILL_VULNERABLE"));
    }

    @Test
    void noUsableFixReturnsNullCodeWithReason() {
        FixResponse r = service(new FakeLlm("not json", "not json"), Duration.ofSeconds(5)).fix(request(null));

        assertNull(r.fixedCode());
        assertFalse(r.reason().isBlank());
        assertEquals("find", r.function().name());
    }

    @Test
    void overTimeLimitReturnsNullCode() {
        LlmClient slow = prompt -> {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new LlmException("중단", e);
            }
            return ANSWER;
        };

        FixResponse r = service(slow, Duration.ofMillis(100)).fix(request(null));

        assertNull(r.fixedCode());
        assertTrue(r.reason().contains("시간"));
    }

    @Test
    void missingSourceCodeIsRejected() {
        FixRequest bad = new FixRequest(request(null).finding(), " ", null, null);

        assertThrows(IllegalArgumentException.class, () -> service(new FakeLlm(), Duration.ofSeconds(5)).fix(bad));
    }
}
