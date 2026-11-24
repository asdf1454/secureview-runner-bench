package secureview.llm;

/** Ollama 서버에 닿지 못했거나 응답 시간을 넘긴 경우. 같은 요청을 바로 다시 보내도 소용없으므로 재요청하지 않는다. */
public class LlmUnavailableException extends LlmException {

    public LlmUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
