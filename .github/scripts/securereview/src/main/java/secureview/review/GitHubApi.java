package secureview.review;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** GitHub REST API로 PR diff·파일을 읽고 리뷰를 단다. */
final class GitHubApi implements PrReviewer.GitHub {

    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private final Http http = new Http();
    private final String api;
    private final String repo;
    private final int number;
    private final String token;
    private String headSha;

    /** @param api 보통 https://api.github.com (GITHUB_API_URL) */
    GitHubApi(String api, String repo, int number, String token) {
        this.api = api;
        this.repo = repo;
        this.number = number;
        this.token = token;
    }

    @Override
    public String diff() {
        return get("/repos/" + repo + "/pulls/" + number, "application/vnd.github.v3.diff");
    }

    @Override
    public String headSha() {
        if (headSha == null) {
            headSha = json(get("/repos/" + repo + "/pulls/" + number, "application/vnd.github+json"))
                    .path("head").path("sha").asText();
        }
        return headSha;
    }

    /** checkout된 작업 폴더는 merge 커밋이라 diff 줄 번호와 다를 수 있다. 그래서 head 커밋의 파일을 API로 받는다. */
    @Override
    public String file(String path, int maxBytes) {
        String encoded = String.join("/", java.util.Arrays.stream(path.split("/"))
                .map(p -> URLEncoder.encode(p, StandardCharsets.UTF_8).replace("+", "%20")).toList());
        try {
            String text = get("/repos/" + repo + "/contents/" + encoded + "?ref=" + headSha(), "application/vnd.github.raw");
            return text.getBytes(StandardCharsets.UTF_8).length > maxBytes ? null : text;
        } catch (Http.Failure e) {
            if (e.status == 404) {
                return null;
            }
            throw e;
        }
    }

    @Override
    public List<String> existingBodies() {
        List<String> bodies = new ArrayList<>();
        for (String kind : List.of("comments", "reviews")) {
            for (int page = 1; ; page++) {
                JsonNode items = json(get("/repos/" + repo + "/pulls/" + number + "/" + kind + "?per_page=100&page=" + page,
                        "application/vnd.github+json"));
                items.forEach(i -> bodies.add(i.path("body").asText("")));
                if (items.size() < 100) {
                    break;
                }
            }
        }
        return bodies;
    }

    @Override
    public void postReview(String headSha, String body, List<PrReviewer.InlineComment> comments) {
        ObjectNode review = SarifReader.MAPPER.createObjectNode()
                .put("commit_id", headSha).put("event", "COMMENT").put("body", body);
        ArrayNode list = review.putArray("comments");
        comments.forEach(c -> list.addObject().put("path", c.path()).put("line", c.line()).put("side", "RIGHT")
                .put("body", c.body()));
        http.send("POST", URI.create(api + "/repos/" + repo + "/pulls/" + number + "/reviews"),
                headers("application/vnd.github+json"), review.toString(), TIMEOUT);
    }

    private String get(String path, String accept) {
        return http.send("GET", URI.create(api + path), headers(accept), null, TIMEOUT);
    }

    private Map<String, String> headers(String accept) {
        return Map.of("Authorization", "Bearer " + token, "Accept", accept, "X-GitHub-Api-Version", "2022-11-28",
                "Content-Type", "application/json");
    }

    private static JsonNode json(String text) {
        try {
            return SarifReader.MAPPER.readTree(text);
        } catch (Exception e) {
            throw new IllegalStateException("GitHub 응답 JSON을 읽지 못했습니다.", e);
        }
    }
}
