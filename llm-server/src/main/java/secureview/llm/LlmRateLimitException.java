package secureview.llm;

/** LLM API가 사용 한도(429)로 거절함. waitMillis는 API가 알려 준 대기 시간(모르면 추정값). */
public class LlmRateLimitException extends LlmException {

    private final long waitMillis;

    public LlmRateLimitException(String message, long waitMillis) {
        super(message);
        this.waitMillis = waitMillis;
    }

    public long waitMillis() {
        return waitMillis;
    }
}
