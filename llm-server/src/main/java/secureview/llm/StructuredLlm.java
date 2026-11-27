package secureview.llm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Optional;
import java.util.function.Function;

/**
 * LLM에 JSON을 요청하고, 형식·내용 검사를 통과할 때까지 최대 maxAttempts번 묻는다.
 * 다시 물을 때는 이전 응답의 문제를 프롬프트에 붙인다. 통신·생성 실패도 같은 방식으로 다시 시도한다.
 */
final class StructuredLlm {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /** 사용 한도(429)에 걸렸을 때 기다렸다 다시 보내는 최대 횟수와, 이보다 오래 기다려야 하면 포기하는 시간(하루 한도 등). */
    static final int MAX_LIMIT_WAITS = 3;
    static final long MAX_LIMIT_WAIT_MILLIS = 60_000;

    private final LlmClient client;
    private final int maxAttempts;

    StructuredLlm(LlmClient client, int maxAttempts) {
        this.client = client;
        this.maxAttempts = maxAttempts;
    }

    /**
     * @param problemOf 응답 내용 검사. 문제가 없으면 null, 있으면 LLM에게 돌려줄 설명.
     * @return 모든 시도가 실패하면 empty
     */
    <T> Optional<T> ask(String prompt, Class<T> type, Function<T, String> problemOf) {
        return ask(prompt, null, type, problemOf);
    }

    /** @param schema 출력 형식을 강제할 JSON 스키마. null이면 일반 JSON */
    <T> Optional<T> ask(String prompt, JsonNode schema, Class<T> type, Function<T, String> problemOf) {
        String current = prompt;
        int limitWaits = 0;
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            String problem;
            try {
                String json = schema == null ? client.generateJson(current) : client.generateJson(current, schema);
                T value = MAPPER.readValue(json, type);
                problem = value == null ? "응답이 비어 있음" : problemOf.apply(value);
                if (problem == null) {
                    return Optional.of(value);
                }
            } catch (JsonProcessingException e) {
                problem = "JSON 형식이 맞지 않음: " + e.getOriginalMessage();
            } catch (LlmUnavailableException e) {
                throw e;
            } catch (LlmRateLimitException e) {
                // 한도는 응답 내용의 문제가 아니므로 시도 횟수에 넣지 않고, 알려 준 시간만큼 기다렸다 같은 요청을 다시 보낸다.
                // 하루 한도처럼 오래 기다려야 하면 바로 포기한다. 기다리는 중에 시간 예산이 끝나면 호출자가 끊는다.
                if (limitWaits++ >= MAX_LIMIT_WAITS || e.waitMillis() > MAX_LIMIT_WAIT_MILLIS) {
                    throw e;
                }
                try {
                    Thread.sleep(e.waitMillis());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return Optional.empty();
                }
                attempt--;
                continue;
            } catch (LlmException e) {
                if (Thread.currentThread().isInterrupted()) {
                    return Optional.empty(); // 시간 제한으로 끊긴 호출은 다시 묻지 않는다.
                }
                // 모델이 같은 토큰을 반복해 중단되는 경우 등. 끝까지 실패하면 호출자가 판정 불가로 처리한다.
                problem = "응답 생성이 실패함. 같은 말을 반복하지 말고 짧게 답하라.";
            }
            current = prompt + "\n\n[이전 응답의 문제] " + problem + "\n이 문제를 고쳐서 JSON만 다시 출력하라.";
        }
        return Optional.empty();
    }
}
