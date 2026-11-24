package secureview.llm;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/** 정해 둔 응답을 차례로 돌려주고, 받은 프롬프트를 기록하는 테스트용 LLM. */
final class FakeLlm implements LlmClient {

    final List<String> prompts = new ArrayList<>();
    private final Deque<String> responses;

    FakeLlm(String... responses) {
        this.responses = new ArrayDeque<>(List.of(responses));
    }

    @Override
    public String generateJson(String prompt) {
        prompts.add(prompt);
        return responses.removeFirst();
    }
}
