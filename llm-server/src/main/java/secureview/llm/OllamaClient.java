package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/** Ollama /api/generate를 직접 호출한다. 출력은 JSON 고정, temperature 0.1(계획서: 0~0.2). */
public final class OllamaClient implements LlmClient {

    public static final String DEFAULT_MODEL = "qwen2.5-coder:7b";

    /** 작업 사이에 모델이 내려가지 않게 하는 시간. 내려가면 다음 판정이 모델 올리기를 기다리다 30초 제한에 걸린다. */
    static final String KEEP_ALIVE = "24h";
    /**
     * 입력 한도(토큰). 넘치면 Ollama가 프롬프트를 경고 없이 잘라 버린다. 기본값 4096에서는 긴 150줄 함수(5577토큰)가 2050토큰으로 잘렸다.
     * 값이 바뀌면 모델을 다시 올리므로 모든 요청에 같은 값을 쓴다.
     */
    static final int NUM_CTX = 8192;

    /** 기본값은 첫 요청에 HTTP/2 업그레이드를 시도하는데, 모델이 이미 올라와 있으면 warmUp이 응답을 받지 못하고 멈췄다. */
    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private final URI uri;
    private final String model;
    private final Duration timeout;

    public OllamaClient(String baseUrl, String model, Duration timeout) {
        this.uri = URI.create(baseUrl + "/api/generate");
        this.model = model;
        this.timeout = timeout;
    }

    public OllamaClient() {
        this("http://localhost:11434", DEFAULT_MODEL, Duration.ofMinutes(2));
    }

    /** 모델을 메모리에 미리 올린다(실측 약 18초). 서버 시작 때 한 번 호출하면 첫 작업이 그만큼 빨라진다. */
    public void warmUp() {
        post(Map.of("model", model, "stream", false, "keep_alive", KEEP_ALIVE, "options", Map.of("num_ctx", NUM_CTX)));
    }

    @Override
    public String generateJson(String prompt) {
        return post(generateBody(prompt, "json"));
    }

    @Override
    public String generateJson(String prompt, JsonNode schema) {
        Map<String, Object> body = generateBody(prompt, schema);
        body.put("system", Prompts.system());
        return post(body);
    }

    private Map<String, Object> generateBody(String prompt, Object format) {
        return new HashMap<>(Map.of(
                "model", model,
                "prompt", prompt,
                "format", format,
                "stream", false,
                "keep_alive", KEEP_ALIVE,
                "options", Map.of("temperature", 0.1, "num_ctx", NUM_CTX)));
    }

    public String model() {
        return model;
    }

    /** Ollama가 응답하고 이 모델이 설치되어 있으면 true. */
    public boolean available() {
        try {
            HttpRequest request = HttpRequest.newBuilder(uri.resolve("/api/tags"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return false;
            }
            for (JsonNode installed : StructuredLlm.MAPPER.readTree(response.body()).path("models")) {
                if (model.equals(installed.path("name").asText())) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private String post(Map<String, Object> body) {
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(StructuredLlm.MAPPER.writeValueAsString(body)))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new LlmException("Ollama 응답 코드 " + response.statusCode() + ": " + response.body());
            }
            return StructuredLlm.MAPPER.readTree(response.body()).path("response").asText();
        } catch (IOException e) {
            throw new LlmUnavailableException("Ollama 호출 실패 (실행 여부와 응답 시간 확인): " + uri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException("Ollama 호출 중단", e);
        }
    }
}
