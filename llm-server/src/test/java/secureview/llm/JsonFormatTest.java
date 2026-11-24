package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 단계 사이 데이터는 JSON으로 주고받는다. 설명서 §5 예시 형식으로 읽고 쓸 수 있어야 한다. */
class JsonFormatTest {

    @Test
    void readsFindingFromManualExample() throws Exception {
        String json = """
                {"id": "F-001", "file": "src/UserDao.java", "startLine": 42, "endLine": 42,
                 "ruleId": "SQL_INJECTION_JDBC", "cwe": 89, "severity": "HIGH",
                 "message": "...", "tools": ["spotbugs-findsecbugs"], "extra": "무시됨"}""";

        Finding f = StructuredLlm.MAPPER.readValue(json, Finding.class);

        assertEquals("F-001", f.id());
        assertEquals(42, f.startLine());
        assertEquals(89, f.cwe());
        assertEquals(List.of("spotbugs-findsecbugs"), f.tools());
    }

    @Test
    void writesVerdictAndFixWithManualFieldNames() throws Exception {
        Verdict verdict = new Verdict(Verdict.Result.TRUE_POSITIVE, 0.8, List.of(38, 42), "r",
                new Verdict.Explanation("s", "k", "a"));
        Fix fix = new Fix(List.of(35, 50), "code", "reason", null);

        JsonNode v = StructuredLlm.MAPPER.valueToTree(verdict);
        JsonNode x = StructuredLlm.MAPPER.valueToTree(fix);

        assertEquals("TRUE_POSITIVE", v.path("result").asText());
        assertEquals(42, v.path("evidenceLines").get(1).asInt());
        assertEquals("a", v.path("explanation").path("attackExample").asText());
        assertEquals(35, x.path("functionRange").get(0).asInt());
        assertTrue(x.path("verification").isNull());
    }
}
