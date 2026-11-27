package secureview.review;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** llm-server의 POST /internal/review-hunk를 부른다. 경고는 API 명세 형식 A로 넘긴다. */
final class LlmApi implements PrReviewer.Llm {

    private final Http http = new Http();
    private final String baseUrl;
    private final String key;

    private boolean rateLimited;

    @Override
    public boolean rateLimited() {
        return rateLimited;
    }

    LlmApi(String baseUrl, String key) {
        this.baseUrl = baseUrl;
        this.key = key;
    }

    @Override
    public List<PrReviewer.Reviewed> review(String reviewId, Hunk hunk, String source, List<Warning> warnings,
                                            int budgetSec) {
        ObjectNode body = SarifReader.MAPPER.createObjectNode().put("reviewId", reviewId);
        ObjectNode h = body.putObject("hunk").put("id", hunk.id()).put("filePath", hunk.filePath())
                .put("language", "java").put("headSha", reviewId)
                .put("newStartLine", hunk.newStartLine()).put("newLineCount", hunk.newLineCount())
                .put("patch", hunk.patch());
        ArrayNode added = h.putArray("addedLines");
        hunk.addedLines().forEach(a -> added.addObject().put("line", a.line()).put("code", a.code()));
        body.put("sourceCode", source).put("budgetSec", budgetSec);
        ArrayNode findings = body.putArray("findings");
        for (Warning w : warnings) {
            findings.addObject().put("jobId", reviewId).put("findingId", hunk.id().substring(0, 12) + ":" + w.ruleId()
                            + ":" + w.line()).put("language", "JAVA").put("cwe", w.cwe()).put("title", w.title())
                    .put("severity", w.severity()).put("tool", w.tool()).put("ruleId", w.ruleId())
                    .put("toolMessage", w.message()).put("line", w.line()).put("sourcePath", hunk.filePath());
        }

        // 서버는 budgetSec 안에서 끝내므로, 응답을 받는 여유 시간을 더해 기다린다.
        String text = http.send("POST", URI.create(baseUrl + "/internal/review-hunk"),
                Map.of("X-Internal-Key", key, "Content-Type", "application/json"), body.toString(),
                Duration.ofSeconds(budgetSec + 30L));
        JsonNode response;
        try {
            response = SarifReader.MAPPER.readTree(text);
        } catch (Exception e) {
            throw new IllegalStateException("LLM 서버 응답 JSON을 읽지 못했습니다.");
        }
        rateLimited |= response.path("rateLimited").asBoolean(false);
        List<PrReviewer.Reviewed> results = new ArrayList<>();
        for (JsonNode f : response.path("findings")) {
            List<Integer> evidence = new ArrayList<>();
            f.path("evidenceLines").forEach(n -> evidence.add(n.asInt()));
            results.add(new PrReviewer.Reviewed(f.path("id").asText(), f.path("cwe").asText(), f.path("severity").asText(),
                    f.path("line").asInt(), f.path("title").asText(), f.path("verdict").asText("UNDECIDED"),
                    f.path("explanation").asText(""), evidence,
                    f.path("suggestion").isTextual() ? f.path("suggestion").asText() : null));
        }
        return results;
    }
}
