package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/** OWASP Benchmark에서 진짜 SQL 인젝션을 오탐으로 지운 3건(00033, 00037, 00100): LLM이 SQL에 맞지 않는 안전 처리를 근거로 댔다. */
class SanitizationClaimTest {

    private static final Finding SQL = new Finding("F", "A.java", 3, 3, "R", 89, "HIGH", "m", List.of("t"));

    private static CodeContext code(String... lines) {
        return new CodeContext("A.java", 1, lines.length, List.of(lines), true, new TreeMap<>());
    }

    private static String sanitizedBy(String how) {
        return "{\"source\":\"param\",\"externalInput\":true,\"sanitization\":\"" + how + "\",\"sanitized\":true,\"evidenceLines\":[3]}";
    }

    @Test
    void htmlEncodingIsNotSqlSanitization() {
        CodeContext c = code("String param = request.getParameter(\"x\");",
                "String sql = \"SELECT * FROM U WHERE N='\" + param + \"'\";",
                "jdbc.queryForRowSet(sql);");

        Verdict v = new VerdictService(new FakeLlm(sanitizedBy("ESAPI.encoder().encodeForHTML()로 이스케이프"))).judgeFacts(SQL, c);

        assertEquals(Verdict.Result.UNDETERMINED, v.result());
    }

    @Test
    void bindingDoesNotProtectConcatenatedInput() {
        CodeContext c = code("String param = request.getParameter(\"x\");",
                "String sql = \"SELECT * FROM U WHERE N=? AND P='\" + param + \"'\";",
                "PreparedStatement s = con.prepareStatement(sql); s.setString(1, \"foo\");");

        Verdict v = new VerdictService(new FakeLlm(sanitizedBy("PreparedStatement의 ? 자리에 setString으로 바인딩"))).judgeFacts(SQL, c);

        assertEquals(Verdict.Result.UNDETERMINED, v.result());
    }

    @Test
    void realBindingStaysFalsePositive() {
        CodeContext c = code("String param = request.getParameter(\"x\");",
                "String sql = \"SELECT * FROM U WHERE N=?\";",
                "PreparedStatement s = con.prepareStatement(sql); s.setString(1, param);");

        Verdict v = new VerdictService(new FakeLlm(sanitizedBy("PreparedStatement의 ? 자리에 setString으로 바인딩"))).judgeFacts(SQL, c);

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
    }

    @Test
    void htmlEncodingStillCountsForXss() {
        Finding xss = new Finding("F", "A.java", 3, 3, "R", 79, "HIGH", "m", List.of("t"));
        CodeContext c = code("String param = request.getParameter(\"x\");",
                "String out = ESAPI.encoder().encodeForHTML(param);",
                "response.getWriter().write(out);");

        Verdict v = new VerdictService(new FakeLlm(sanitizedBy("encodeForHTML로 이스케이프"))).judgeFacts(xss, c);

        assertEquals(Verdict.Result.LIKELY_FALSE_POSITIVE, v.result());
    }
}
