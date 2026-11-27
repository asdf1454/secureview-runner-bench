package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * OpenAI 형식 /chat/completions를 호출한다. OpenAI, GitHub Models, Ollama(/v1)가 모두 이 형식을 받는다.
 * baseUrl은 버전 경로까지 포함한다(예: https://api.openai.com/v1, http://localhost:11434/v1).
 */
public final class OpenAiCompatibleClient implements LlmClient {

    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private final URI uri;
    private final String apiKey;
    private final String model;
    private final Duration timeout;
    private final AtomicLong tokens = new AtomicLong();

    /** @param apiKey 없으면 null 또는 빈 문자열(팀 PC의 Ollama처럼 키가 필요 없는 경우) */
    public OpenAiCompatibleClient(String baseUrl, String apiKey, String model, Duration timeout) {
        this.uri = URI.create(baseUrl + "/chat/completions");
        this.apiKey = apiKey;
        this.model = model;
        this.timeout = timeout;
    }

    @Override
    public String generateJson(String prompt) {
        return post(List.of(message("user", prompt)), Map.of("type", "json_object"));
    }

    @Override
    public String generateJson(String prompt, JsonNode schema) {
        return post(List.of(message("system", Prompts.system()), message("user", prompt)),
                Map.of("type", "json_schema", "json_schema", Map.of("name", "result", "schema", schema)));
    }

    /**
     * 짧은 요청을 한 번 보내 모델을 메모리에 올린다. Ollama /v1은 요청이 와야 모델을 올리므로,
     * 서버 시작 때 호출하지 않으면 첫 판정이 30초 제한에 걸린다. 외부 API에서는 토큰 몇 개만 쓴다.
     */
    public void warmUp() {
        generateJson("Reply with JSON {\"ok\":true}");
    }

    public String model() {
        return model;
    }

    /** 지금까지 응답의 usage.total_tokens 합계. 무료 API 한도(분당·하루 토큰)를 가늠할 때 쓴다. */
    public long tokensUsed() {
        return tokens.get();
    }

    private static Map<String, String> message(String role, String content) {
        return Map.of("role", role, "content", content);
    }

    private String post(List<Map<String, String>> messages, Map<String, Object> responseFormat) {
        Map<String, Object> body = Map.of(
                "model", model,
                "messages", new ArrayList<>(messages),
                "temperature", 0.1,
                "response_format", responseFormat);
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(StructuredLlm.MAPPER.writeValueAsString(body)));
            if (apiKey != null && !apiKey.isBlank()) {
                request.header("Authorization", "Bearer " + apiKey);
            }
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new LlmException("LLM API 응답 코드 " + response.statusCode() + ": " + response.body());
            }
            JsonNode json = StructuredLlm.MAPPER.readTree(response.body());
            tokens.addAndGet(json.path("usage").path("total_tokens").asLong());
            return json.path("choices").path(0).path("message").path("content").asText();
        } catch (IOException e) {
            throw new LlmUnavailableException("LLM API 호출 실패 (주소와 응답 시간 확인): " + uri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException("LLM API 호출 중단", e);
        }
    }
}
