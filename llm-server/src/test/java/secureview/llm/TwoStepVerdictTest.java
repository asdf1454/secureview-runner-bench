package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/** 사실은 먼저 짧게 묻고, 설명은 진짜 취약점일 때만 따로 요청한다. */
class TwoStepVerdictTest {

    private static final Finding FINDING = new Finding("F", "A.java", 16, 16, "R", 89, "HIGH", "m", List.of("t"));
    private static final CodeContext CONTEXT = new CodeContext("A.java", 14, 17,
            List.of("a", "b", "c", "d"), true, new TreeMap<>());
    private static final String FACTS_TP =
            "{\"source\":\"name 매개변수\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[16]}";

    @Test
    void factPromptDoesNotAskForExplanation() {
        FakeLlm llm = new FakeLlm("{\"externalInput\":false,\"source\":\"상수\",\"evidenceLines\":[16]}");

        new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(1, llm.prompts.size(), "오탐 추정에는 설명 호출이 필요 없다");
        assertFalse(llm.prompts.get(0).contains("attackExample"));
    }

    @Test
    void truePositiveAsksExplanationWithFactInSecondCall() {
        FakeLlm llm = new FakeLlm(FACTS_TP,
                "{\"reason\":\"문자열 연결\",\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}");

        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(2, llm.prompts.size());
        assertTrue(llm.prompts.get(1).contains("attackExample"));
        assertTrue(llm.prompts.get(1).contains("name 매개변수"));
        assertEquals("문자열 연결", v.reason());
        assertEquals("a", v.explanation().attackExample());
    }

    @Test
    void failedExplanationKeepsTruePositiveWithFactAsReason() {
        FakeLlm llm = new FakeLlm(FACTS_TP, "not json", "{\"reason\":\"r\"}");

        Verdict v = new VerdictService(llm).judge(FINDING, CONTEXT);

        assertEquals(Verdict.Result.TRUE_POSITIVE, v.result());
        assertEquals("name 매개변수", v.reason());
        assertNull(v.explanation());
    }
}
