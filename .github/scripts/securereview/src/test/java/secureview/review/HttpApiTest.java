package secureview.review;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

/** GitHub API와 llm-server를 흉내 낸 서버로 요청 형식과 응답 해석을 확인한다. */
class HttpApiTest {

    private HttpServer server;
    private final Map<String, String> bodies = new ConcurrentHashMap<>();
    private final Map<String, String> accepts = new ConcurrentHashMap<>();
    private final List<String> auth = new ArrayList<>();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getRawPath();
        String query = ex.getRequestURI().getQuery();
        bodies.put(path, new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        accepts.put(path, String.valueOf(ex.getRequestHeaders().getFirst("Accept")));
        auth.add(String.valueOf(ex.getRequestHeaders().getFirst("Authorization")) + "|"
                + ex.getRequestHeaders().getFirst("X-Internal-Key"));
        String accept = accepts.get(path);
        int status = 200;
        String out;
        if (path.equals("/repos/o/r/pulls/7") && accept.contains("diff")) {
            out = "diff --git a/A.java b/A.java";
        } else if (path.equals("/repos/o/r/pulls/7")) {
            out = "{\"head\":{\"sha\":\"abc\"}}";
        } else if (path.equals("/repos/o/r/contents/src/My%20A.java")) {
            out = "class A {}";
            assertEquals("ref=abc", query);
        } else if (path.startsWith("/repos/o/r/contents/")) {
            status = 404;
            out = "{\"message\":\"Not Found\"}";
        } else if (path.equals("/repos/o/r/pulls/7/comments") || path.equals("/repos/o/r/pulls/7/reviews")) {
            out = ex.getRequestMethod().equals("GET") ? "[{\"body\":\"old " + path.substring(path.lastIndexOf('/') + 1) + "\"}]" : "{}";
        } else if (path.equals("/internal/review-hunk")) {
            out = """
                    {"hunkId":"h","findings":[{"id":"h:CWE-89:2","cwe":"CWE-89","severity":"HIGH","line":2,
                     "title":"SQL","verdict":"TRUE_POSITIVE","confidence":0.9,"explanation":"설명",
                     "evidenceLines":[1,2],"suggestion":"바인딩"}],"rateLimited":true}""";
        } else {
            status = 404;
            out = "{}";
        }
        byte[] bytes = out.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private String url() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    @Test
    void gitHubReadsDiffHeadFileAndExistingBodies() {
        GitHubApi gh = new GitHubApi(url(), "o/r", 7, "tok");

        assertEquals("diff --git a/A.java b/A.java", gh.diff());
        assertEquals("abc", gh.headSha());
        assertEquals("class A {}", gh.file("src/My A.java", 100));
        assertNull(gh.file("src/My A.java", 3), "크기 제한을 넘으면 null");
        assertNull(gh.file("src/Missing.java", 100));
        assertEquals(List.of("old comments", "old reviews"), gh.existingBodies());
        assertTrue(auth.get(0).startsWith("Bearer tok|"));
    }

    @Test
    void gitHubPostsReviewOnHeadCommit() throws Exception {
        new GitHubApi(url(), "o/r", 7, "tok").postReview("abc", "요약",
                List.of(new PrReviewer.InlineComment("src/A.java", 2, "본문")));

        JsonNode body = SarifReader.MAPPER.readTree(bodies.get("/repos/o/r/pulls/7/reviews"));
        assertEquals("abc", body.path("commit_id").asText());
        assertEquals("COMMENT", body.path("event").asText());
        assertEquals("요약", body.path("body").asText());
        JsonNode c = body.path("comments").get(0);
        assertEquals("src/A.java", c.path("path").asText());
        assertEquals(2, c.path("line").asInt());
        assertEquals("RIGHT", c.path("side").asText());
    }

    @Test
    void llmGetsFormatAFindingsAndBudget() throws Exception {
        Hunk hunk = DiffParser.parse("""
                diff --git a/src/A.java b/src/A.java
                --- a/src/A.java
                +++ b/src/A.java
                @@ -1,1 +1,2 @@
                 class A {
                +  void f(String n) { q(n); }
                """, 1 << 16).get(0);
        Warning w = new Warning("src/A.java", 2, "CWE-89", "HIGH", "SQL_INJECTION_JDBC", "SQL", "msg", "SpotBugs");

        LlmApi llm = new LlmApi(url(), "k");
        assertFalse(llm.rateLimited());
        List<PrReviewer.Reviewed> r = llm.review("abc", hunk, "class A {}", List.of(w), 30);

        assertTrue(llm.rateLimited());
        assertEquals("TRUE_POSITIVE", r.get(0).verdict());
        assertEquals(List.of(1, 2), r.get(0).evidenceLines());
        assertEquals("바인딩", r.get(0).suggestion());
        JsonNode sent = SarifReader.MAPPER.readTree(bodies.get("/internal/review-hunk"));
        assertEquals(30, sent.path("budgetSec").asInt());
        assertEquals(hunk.id(), sent.path("hunk").path("id").asText());
        assertEquals(2, sent.path("hunk").path("addedLines").get(0).path("line").asInt());
        JsonNode f = sent.path("findings").get(0);
        assertEquals("CWE-89", f.path("cwe").asText());
        assertEquals(2, f.path("line").asInt());
        assertEquals("src/A.java", f.path("sourcePath").asText());
        assertTrue(auth.get(auth.size() - 1).endsWith("|k"));
    }

    @Test
    void errorMessageHasStatusButNoToken() {
        GitHubApi gh = new GitHubApi(url(), "o/r", 8, "secret-token");

        Http.Failure e = assertThrows(Http.Failure.class, gh::diff);

        assertEquals(404, e.status);
        assertFalse(e.getMessage().contains("secret-token"));
    }
}
