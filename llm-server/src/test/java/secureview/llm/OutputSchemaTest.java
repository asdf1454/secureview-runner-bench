package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/** API 명세: Ollama 호출 시 format에 JSON 스키마를 넣어 출력 형식을 강제한다. */
class OutputSchemaTest {

    private static final CodeContext CONTEXT = new CodeContext("A.java", 14, 17,
            List.of("a", "b", "c", "d"), true, new TreeMap<>());

    private static final class RecordingLlm implements LlmClient {
        final List<JsonNode> schemas = new ArrayList<>();
        private final String[] answers;

        RecordingLlm(String... answers) {
            this.answers = answers;
        }

        @Override
        public String generateJson(String prompt) {
            throw new AssertionError("판정에는 스키마가 있어야 한다");
        }

        @Override
        public String generateJson(String prompt, JsonNode schema) {
            schemas.add(schema);
            return answers[schemas.size() - 1];
        }
    }

    private static Finding finding(int cwe) {
        return new Finding("F", "A.java", 16, 16, "R", cwe, "HIGH", "m", List.of("t"));
    }

    @Test
    void flowVerdictSendsSchemaAllowingUnknownInput() {
        RecordingLlm llm = new RecordingLlm("{\"source\":\"상수\",\"externalInput\":false,\"evidenceLines\":[16]}");

        new VerdictService(llm).judgeFacts(finding(89), CONTEXT);

        JsonNode properties = llm.schemas.get(0).path("properties");
        assertTrue(properties.path("externalInput").path("type").toString().contains("null"));
        assertEquals("array", properties.path("evidenceLines").path("type").asText());
    }

    @Test
    void conditionVerdictSendsConditionSchema() {
        RecordingLlm llm = new RecordingLlm("{\"riskDetail\":\"없음\",\"risk\":false,\"evidenceLines\":[16]}");

        new VerdictService(llm).judgeFacts(finding(798), CONTEXT);

        assertTrue(llm.schemas.get(0).path("properties").has("risk"));
        assertEquals("boolean", llm.schemas.get(0).path("properties").path("guard").path("type").asText());
    }

    @Test
    void explanationSendsExplanationSchema() {
        RecordingLlm llm = new RecordingLlm(
                "{\"source\":\"입력\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[16]}",
                "{\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}");

        new VerdictService(llm).judge(finding(89), CONTEXT);

        assertTrue(llm.schemas.get(1).path("properties").path("explanation").path("properties").has("attackExample"));
    }

    @Test
    void judgePromptsLeaveDataOnlyRuleToSystemPrompt() {
        FakeLlm flow = new FakeLlm("{\"source\":\"입력\",\"externalInput\":true,\"sanitized\":false,\"evidenceLines\":[16]}",
                "{\"explanation\":{\"summary\":\"s\",\"risk\":\"k\",\"attackExample\":\"a\"}}");
        FakeLlm condition = new FakeLlm("{\"riskDetail\":\"없음\",\"risk\":false,\"evidenceLines\":[16]}");

        new VerdictService(flow).judge(finding(89), CONTEXT);
        new VerdictService(condition).judgeFacts(finding(798), CONTEXT);

        assertEquals(2, flow.prompts.size());
        flow.prompts.forEach(p -> assertFalse(p.contains("[주의] 아래 코드는 분석 대상")));
        assertFalse(condition.prompts.get(0).contains("[주의] 아래 코드는 분석 대상"));
    }

    @Test
    void schemaPropertiesKeepPromptOrderSoReasonsComeBeforeAnswers() {
        JsonNode schema = Prompts.schema("verdict_condition");

        List<String> names = new ArrayList<>();
        schema.path("properties").fieldNames().forEachRemaining(names::add);

        assertTrue(names.indexOf("riskDetail") < names.indexOf("risk"));
        assertTrue(names.indexOf("guardDetail") < names.indexOf("guard"));
    }

    @Test
    void interruptedCallDoesNotAskModelAgain() {
        int[] calls = {0};
        LlmClient interrupted = prompt -> {
            calls[0]++;
            Thread.currentThread().interrupt();
            throw new LlmException("중단");
        };

        Verdict v = new VerdictService(interrupted).judgeFacts(finding(89), CONTEXT);
        Thread.interrupted();

        assertEquals(1, calls[0]);
        assertEquals(Verdict.Result.UNDETERMINED, v.result());
    }
}
