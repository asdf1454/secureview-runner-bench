package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class LlmServicesTest {

    private static final Finding FINDING =
            new Finding("F-001", "UserDao.java", 16, 16, "SQL_INJECTION_JDBC", 89, "HIGH", "m", List.of("spotbugs"));
    private static final CodeContext CONTEXT = new CodeContext("UserDao.java", 14, 17,
            List.of("public ResultSet find(String name) {", "  Statement st = conn.createStatement();",
                    "  return st.executeQuery(\"...\" + name + \"'\");", "}"), true, new TreeMap<>());

    private static final String TRUE_POSITIVE = """
            {"externalInput":true,"sanitized":false,"confidence":0.9,"evidenceLines":[14,16],"reason":"r",
             "explanation":{"summary":"s","risk":"k","attackExample":"a"},"extra":"무시됨"}""";

    @Test
    void verdictAcceptsValidResponse() {
        FakeLlm llm = new FakeLlm(TRUE_POSITIVE);
        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(Verdict.Result.TRUE_POSITIVE, v.result());
        assertEquals(List.of(14, 16), v.evidenceLines());
        assertTrue(llm.prompts.get(0).contains("16|   return st.executeQuery"));
    }

    @Test
    void verdictRetriesWhenEvidenceOutOfRange() {
        String outOfRange = TRUE_POSITIVE.replace("[14,16]", "[99]");
        FakeLlm llm = new FakeLlm(outOfRange, TRUE_POSITIVE);
        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(Verdict.Result.TRUE_POSITIVE, v.result());
        assertEquals(2, llm.prompts.size());
        assertTrue(llm.prompts.get(1).contains("근거 라인 99이 코드 범위(14~17) 밖에 있음"));
    }

    @Test
    void verdictBecomesUndeterminedAfterRepeatedFailures() {
        FakeLlm llm = new FakeLlm("not json", "{\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[]}");
        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(Verdict.Result.UNDETERMINED, v.result());
        assertEquals(VerdictService.MAX_ATTEMPTS, llm.prompts.size());
    }

    @Test
    void verdictIsDecidedByRulesNotByLlmConclusion() {
        // LLM이 사실(상수 입력)과 모순되는 결론을 붙여도 규칙이 판정한다.
        String constant = "{\"source\":\"SELECT COUNT(*)\",\"externalInput\":false,\"sanitized\":false,"
                + "\"result\":\"TRUE_POSITIVE\",\"evidenceLines\":[16],\"reason\":\"SQL 인젝션 위험이 있습니다\"}";
        Verdict fromConstant = new VerdictService(new FakeLlm(constant)).judge(FINDING, CONTEXT);
        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, fromConstant.result());
        // 판정과 어긋나는 LLM 설명은 쓰지 않는다.
        assertFalse(fromConstant.reason().contains("위험이 있습니다"));
        assertTrue(fromConstant.reason().contains("상수"));
        assertEquals("", fromConstant.explanation().attackExample());

        String bound = "{\"externalInput\":true,\"sanitized\":true,\"sanitization\":\"setInt 바인딩\",\"evidenceLines\":[15]}";
        Verdict fromBound = new VerdictService(new FakeLlm(bound)).judge(FINDING, CONTEXT);
        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, fromBound.result());
        assertTrue(fromBound.reason().contains("setInt 바인딩"));

        String unknown = "{\"externalInput\":true,\"sanitized\":null}";
        assertEquals(Verdict.Result.UNDETERMINED,
                new VerdictService(new FakeLlm(unknown)).judge(FINDING, CONTEXT).result());
    }

    @Test
    void verdictRetriesWhenUndeterminedEvidenceOutOfRange() {
        String outOfRange = "{\"externalInput\":null,\"sanitized\":null,\"evidenceLines\":[99]}";
        String inRange = "{\"externalInput\":null,\"sanitized\":null,\"evidenceLines\":[16]}";
        FakeLlm llm = new FakeLlm(outOfRange, inRange);

        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(List.of(16), v.evidenceLines());
        assertEquals(2, llm.prompts.size());
    }

    @Test
    void undeterminedWithoutEvidenceHasEmptyEvidenceList() {
        Verdict v = new VerdictService(new FakeLlm("{\"externalInput\":null,\"sanitized\":null}")).judge(FINDING, CONTEXT);

        assertEquals(List.of(), v.evidenceLines());
    }

    @Test
    void fixCoversContextRangeAndPassesPreviousFailure() {
        Verdict tp = new Verdict(Verdict.Result.TRUE_POSITIVE, 0.9, List.of(16), "문자열 연결", null);
        FakeLlm llm = new FakeLlm("{\"code\":\"public ResultSet find(String name) { return safe(); }\",\"reason\":\"PreparedStatement 사용\"}");

        Optional<Fix> fix = new FixService(llm).propose(FINDING, CONTEXT, tp, "컴파일 오류: x");

        assertEquals(new Fix(List.of(14, 17), "public ResultSet find(String name) { return safe(); }", "PreparedStatement 사용", null), fix.orElseThrow());
        assertTrue(llm.prompts.get(0).contains("컴파일 오류: x"));
    }

    @Test
    void fixRefusesNonTruePositive() {
        Verdict fp = new Verdict(Verdict.Result.LIKELY_FALSE_POSITIVE, 0.5, List.of(16), "r", null);
        assertThrows(IllegalArgumentException.class,
                () -> new FixService(new FakeLlm()).propose(FINDING, CONTEXT, fp, null));
    }
}
