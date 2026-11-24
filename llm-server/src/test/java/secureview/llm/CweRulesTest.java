package secureview.llm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/** 외부 입력과 무관한 CWE는 위험 조건과 그것을 막는 코드를 따로 묻고, 규칙이 판정한다. */
class CweRulesTest {

    private static final CodeContext CONTEXT = new CodeContext("A.java", 14, 17,
            List.of("a", "b", "c", "d"), true, new TreeMap<>());
    private static final String EXPLAINED =
            ",\"reason\":\"r\",\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}";

    private static Finding finding(int cwe) {
        return new Finding("F-1", "A.java", 16, 16, "R", cwe, "HIGH", "m", List.of("t"));
    }

    private static Verdict judge(int cwe, String response) {
        return new VerdictService(new FakeLlm(response)).judge(finding(cwe), CONTEXT);
    }

    @ParameterizedTest
    @ValueSource(ints = {798, 120, 416, 476, 190, 134})
    void riskWithoutGuardIsTruePositiveEvenWhenValueIsConstant(int cwe) {
        Verdict v = judge(cwe, "{\"risk\":true,\"guard\":false,\"externalInput\":false,\"evidenceLines\":[16]" + EXPLAINED);

        assertEquals(Verdict.Result.TRUE_POSITIVE, v.result());
    }

    @ParameterizedTest
    @ValueSource(ints = {798, 120, 416, 476, 190, 134})
    void noRiskIsLikelyFalsePositiveWithDetail(int cwe) {
        Verdict v = judge(cwe, "{\"riskDetail\":\"위험 없음\",\"risk\":false,\"evidenceLines\":[15]}");

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
        assertTrue(v.reason().contains("위험 없음"));
        assertFalse(v.reason().contains("상수"));
    }

    @ParameterizedTest
    @ValueSource(ints = {798, 120, 416, 476, 190, 134})
    void guardedRiskIsLikelyFalsePositiveWithGuardDetail(int cwe) {
        Verdict v = judge(cwe, "{\"risk\":true,\"guardDetail\":\"먼저 검사함\",\"guard\":true,\"evidenceLines\":[15]}");

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
        assertTrue(v.reason().contains("먼저 검사함"));
    }

    @ParameterizedTest
    @ValueSource(ints = {798, 120, 416, 476, 190, 134})
    void unknownFactsAreUndetermined(int cwe) {
        assertEquals(Verdict.Result.UNDETERMINED,
                judge(cwe, "{\"riskDetail\":\"호출부 필요\",\"risk\":null}").result());
        assertEquals(Verdict.Result.UNDETERMINED,
                judge(cwe, "{\"riskDetail\":\"호출부 필요\",\"risk\":true,\"guard\":null}").result());
    }

    @ParameterizedTest
    @ValueSource(ints = {798, 120, 416, 476, 190, 134})
    void promptAsksCweSpecificQuestionsWithDetailBeforeAnswer(int cwe) {
        FakeLlm llm = new FakeLlm("{\"risk\":null}");

        new VerdictService(llm).judge(finding(cwe), CONTEXT);

        String prompt = llm.prompts.get(0);
        VerdictService.Condition q = VerdictService.CONDITIONS.get(cwe);
        assertTrue(prompt.contains(q.risk()));
        assertTrue(prompt.contains(q.guard()));
        assertFalse(prompt.contains("\"guard\": true 또는 false 또는 null"), "방어 코드가 없으면 false로 답하게 한다");
        assertTrue(prompt.indexOf("\"riskDetail\"") < prompt.indexOf("\"risk\""), "근거를 답보다 먼저 쓰게 한다");
    }

    @ParameterizedTest
    @ValueSource(ints = {89, 79, 78, 22})
    void taintCwesStillUseSourceAndSanitizerRules(int cwe) {
        FakeLlm llm = new FakeLlm("{\"externalInput\":false,\"source\":\"상수\",\"evidenceLines\":[16]}");

        Verdict v = new VerdictService(llm).judge(finding(cwe), CONTEXT);

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
        assertTrue(llm.prompts.get(0).contains("externalInput"));
        assertFalse(llm.prompts.get(0).contains("riskDetail"));
    }

    @Test
    void modelFailureIsRetriedThenBecomesUndetermined() {
        int[] calls = {0};
        LlmClient repeating = prompt -> {
            calls[0]++;
            throw new LlmException("Ollama 응답 코드 500: token repeat limit reached");
        };

        Verdict v = new VerdictService(repeating).judge(finding(89), CONTEXT);

        assertEquals(VerdictService.MAX_ATTEMPTS, calls[0]);
        assertEquals(Verdict.Result.UNDETERMINED, v.result());
    }

    @Test
    void modelFailureThenValidAnswerIsUsed() {
        int[] calls = {0};
        LlmClient flaky = prompt -> {
            if (calls[0]++ == 0) {
                throw new LlmException("Ollama 응답 코드 500");
            }
            return "{\"externalInput\":false,\"source\":\"상수\",\"evidenceLines\":[16]}";
        };

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, new VerdictService(flaky).judge(finding(89), CONTEXT).result());
    }
}
