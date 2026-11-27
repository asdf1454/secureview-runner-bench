package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;

/** LLM 호출 계약. 나중에 Spring AI·LangChain4j로 바꿔도 이 인터페이스만 구현하면 된다. */
public interface LlmClient {

    /** 프롬프트를 보내고 JSON 문자열 응답을 받는다. 통신 실패 시 {@link LlmException}. */
    String generateJson(String prompt);

    /** 출력 형식을 JSON 스키마로 강제한다. 스키마를 지원하지 않는 구현은 일반 JSON으로 받는다. */
    default String generateJson(String prompt, JsonNode schema) {
        return generateJson(prompt);
    }

    /** 지금까지 사용 한도(429)에 걸린 횟수. 한도가 없는 구현(Ollama)은 0. */
    default long rateLimitHits() {
        return 0;
    }
}
