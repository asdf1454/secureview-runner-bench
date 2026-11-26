package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** API 명세의 내부 API: 인증, 정상 응답, 공통 에러 형식. */
class LlmServerTest {

    private static final String KEY = "test-key";
    private static final String BODY = """
            {"finding": {"jobId": "j", "findingId": "e91a", "language": "JAVA", "cwe": "CWE-89",
                         "title": "SQL 인젝션", "severity": "HIGH", "tool": "FindSecBugs",
                         "ruleId": "SQL_INJECTION_JDBC", "toolMessage": "m", "line": 2,
                         "sourcePath": "/work/j/A.java"},
             "sourceCode": "class A {\\n  String f(String n) { return n; }\\n}\\n"}""";
    private static final String FACTS = "{\"source\":\"상수\",\"externalInput\":false,\"evidenceLines\":[2]}";

    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private LlmServer server;

    private void start(LlmClient llm, BooleanSupplier up) throws Exception {
        server = new LlmServer(new JudgeService(llm, "m", Duration.ofSeconds(5)), "m", up, KEY);
        server.start("localhost", 0);
    }

    @AfterEach
    void stop() {
        server.stop();
    }

    private HttpResponse<String> post(String path, String key, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri(path)).POST(HttpRequest.BodyPublishers.ofString(body));
        if (key != null) {
            b.header("X-Internal-Key", key);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String key) throws Exception {
        return http.send(HttpRequest.newBuilder(uri(path)).header("X-Internal-Key", key).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private static JsonNode json(HttpResponse<String> response) throws Exception {
        return StructuredLlm.MAPPER.readTree(response.body());
    }

    @Test
    void judgeReturnsFormatB() throws Exception {
        start(new FakeLlm(FACTS), () -> true);

        HttpResponse<String> r = post("/internal/judge", KEY, BODY);

        assertEquals(200, r.statusCode());
        assertTrue(r.headers().firstValue("Content-Type").orElse("").contains("application/json"));
        JsonNode body = json(r);
        assertEquals("e91a", body.path("findingId").asText());
        assertEquals("f", body.path("function").path("name").asText());
        assertEquals("LIKELY_FALSE_POSITIVE", body.path("llm").path("verdict").asText());
        assertEquals(2, body.path("llm").path("evidenceLines").get(0).asInt());
        assertEquals("m", body.path("llm").path("model").asText());
        assertTrue(body.path("llm").has("latencySec"));
    }

    @Test
    void missingOrWrongKeyIsUnauthorized() throws Exception {
        start(new FakeLlm(), () -> true);

        for (String key : new String[] {null, "wrong"}) {
            HttpResponse<String> r = post("/internal/judge", key, BODY);
            assertEquals(401, r.statusCode());
            assertEquals("UNAUTHORIZED", json(r).path("error").asText());
            assertFalse(json(r).path("message").asText().isBlank());
        }
    }

    @Test
    void healthAlsoNeedsKey() throws Exception {
        start(new FakeLlm(), () -> true);

        assertEquals(401, get("/internal/health", "wrong").statusCode());
    }

    @Test
    void healthReportsModel() throws Exception {
        start(new FakeLlm(), () -> true);

        HttpResponse<String> r = get("/internal/health", KEY);

        assertEquals(200, r.statusCode());
        assertEquals("UP", json(r).path("status").asText());
        assertEquals("m", json(r).path("model").asText());
    }

    @Test
    void healthIsDownWhenModelCannotBeUsed() throws Exception {
        start(new FakeLlm(), () -> false);

        HttpResponse<String> r = get("/internal/health", KEY);

        assertEquals(503, r.statusCode());
        assertEquals("DOWN", json(r).path("status").asText());
    }

    /** 모델이 올라오기 전에 판정을 받으면 30초 제한이 모델 올리기를 끊어, 끝내 올라오지 못했다. */
    @Test
    void judgeIsRefusedAndHealthIsDownUntilModelIsLoaded() throws Exception {
        FakeLlm llm = new FakeLlm(FACTS);
        server = new LlmServer(new JudgeService(llm, "m", Duration.ofSeconds(5)), "m", () -> true, () -> false, KEY);
        server.start("localhost", 0);

        HttpResponse<String> judged = post("/internal/judge", KEY, BODY);

        assertEquals(503, judged.statusCode());
        assertEquals("INTERNAL_ERROR", json(judged).path("error").asText());
        assertTrue(llm.prompts.isEmpty(), "모델을 부르지 않는다");
        assertEquals(503, get("/internal/health", KEY).statusCode());
    }

    @Test
    void fixReturnsFunctionAndFixedCode() throws Exception {
        String answer = "{\"code\":\"  String f(String n) { return \\\"x\\\"; }\",\"reason\":\"상수로 변경\"}";
        server = new LlmServer(new JudgeService(new FakeLlm(), "m", Duration.ofSeconds(5)), "m", () -> true, KEY)
                .withFixes(new FixApiService(new FakeLlm(answer), "m", Duration.ofSeconds(5)));
        server.start("localhost", 0);

        HttpResponse<String> r = post("/internal/fix", KEY, BODY);

        assertEquals(200, r.statusCode());
        JsonNode body = json(r);
        assertEquals("e91a", body.path("findingId").asText());
        assertEquals("f", body.path("function").path("name").asText());
        assertEquals(2, body.path("function").path("startLine").asInt());
        assertTrue(body.path("fixedCode").asText().contains("return \"x\""));
        assertEquals("상수로 변경", body.path("reason").asText());
    }

    @Test
    void fixIsNotFoundWhenNotEnabled() throws Exception {
        start(new FakeLlm(), () -> true);

        assertEquals(404, post("/internal/fix", KEY, BODY).statusCode());
    }

    @Test
    void brokenJsonIsInvalidInput() throws Exception {
        start(new FakeLlm(), () -> true);

        HttpResponse<String> r = post("/internal/judge", KEY, "{");

        assertEquals(400, r.statusCode());
        assertEquals("INVALID_INPUT", json(r).path("error").asText());
    }

    @Test
    void missingFieldIsInvalidInput() throws Exception {
        start(new FakeLlm(), () -> true);

        HttpResponse<String> r = post("/internal/judge", KEY, "{\"finding\":{\"findingId\":\"f\"}}");

        assertEquals(400, r.statusCode());
        assertEquals("INVALID_INPUT", json(r).path("error").asText());
    }

    @Test
    void oversizedBodyIsRejected() throws Exception {
        start(new FakeLlm(), () -> true);

        HttpResponse<String> r = post("/internal/judge", KEY, "x".repeat(LlmServer.MAX_BODY_BYTES + 1));

        assertEquals(413, r.statusCode());
        assertEquals("FILE_TOO_LARGE", json(r).path("error").asText());
    }

    /** 본문을 다 읽기 전에 응답하고 닫으면 클라이언트는 413 대신 연결 끊김을 받는다. */
    @Test
    void muchLargerBodyStillGetsErrorResponse() throws Exception {
        start(new FakeLlm(), () -> true);

        HttpResponse<String> r = post("/internal/judge", KEY, "x".repeat(LlmServer.MAX_BODY_BYTES * 4));

        assertEquals(413, r.statusCode());
    }

    @Test
    void wrongMethodAndUnknownPathAreNotFound() throws Exception {
        start(new FakeLlm(), () -> true);

        assertEquals(404, get("/internal/judge", KEY).statusCode());
        assertEquals(404, get("/internal/other", KEY).statusCode());
        assertEquals("NOT_FOUND", json(get("/internal/judge", KEY)).path("error").asText());
    }

    @Test
    void unexpectedFailureHidesInternalMessage() throws Exception {
        server = new LlmServer(null, "m", () -> true, KEY);
        server.start("localhost", 0);

        HttpResponse<String> r = post("/internal/judge", KEY, BODY);

        assertEquals(500, r.statusCode());
        assertEquals("INTERNAL_ERROR", json(r).path("error").asText());
        assertFalse(r.body().contains("NullPointer"));
    }

    private static final String HUNK_BODY = """
            {"reviewId": "pr-1",
             "hunk": {"id": "h1", "filePath": "A.java", "language": "java", "baseSha": "b", "headSha": "h",
                      "newStartLine": 2, "newLineCount": 1, "patch": "@@ -1,0 +2,1 @@",
                      "addedLines": [{"line": 2, "code": "  String f(String n) { return n; }"}]},
             "sourceCode": "class A {\\n  String f(String n) { return n; }\\n}\\n",
             "findings": [{"jobId": "pr-1", "findingId": "e91a", "language": "JAVA", "cwe": "CWE-89",
                           "title": "SQL 인젝션", "severity": "HIGH", "tool": "FindSecBugs",
                           "ruleId": "SQL_INJECTION_JDBC", "toolMessage": "m", "line": %d, "sourcePath": "A.java"}],
             "budgetSec": 10}""";

    private void startWithHunks(LlmClient llm) throws Exception {
        server = new LlmServer(new JudgeService(llm, "m", Duration.ofSeconds(5)), "m", () -> true, KEY)
                .withHunkReview(new HunkReviewService(llm, "m", Duration.ofSeconds(5)));
        server.start("localhost", 0);
    }

    @Test
    void reviewHunkReturnsFindings() throws Exception {
        startWithHunks(new FakeLlm(FACTS));

        HttpResponse<String> r = post("/internal/review-hunk", KEY, HUNK_BODY.formatted(2));

        assertEquals(200, r.statusCode());
        JsonNode body = json(r);
        assertEquals("h1", body.path("hunkId").asText());
        assertEquals("h1:CWE-89:2", body.path("findings").get(0).path("id").asText());
        assertEquals("LIKELY_FALSE_POSITIVE", body.path("findings").get(0).path("verdict").asText());
    }

    @Test
    void reviewHunkRejectsLineOutsideHunk() throws Exception {
        startWithHunks(new FakeLlm());

        HttpResponse<String> r = post("/internal/review-hunk", KEY, HUNK_BODY.formatted(3));

        assertEquals(400, r.statusCode());
        assertEquals("INVALID_LINE", json(r).path("error").asText());
    }

    @Test
    void reviewHunkIsNotFoundWhenNotEnabled() throws Exception {
        start(new FakeLlm(), () -> true);

        assertEquals(404, post("/internal/review-hunk", KEY, HUNK_BODY.formatted(2)).statusCode());
    }
}
