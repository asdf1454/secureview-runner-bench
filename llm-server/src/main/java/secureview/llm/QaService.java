package secureview.llm;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * S8 질의응답: 선택한 취약점 하나에 대한 사용자 질문에 답한다.
 * 화면(강민재 님)이 대화 기록을 들고 있다가 질문마다 넘긴다. 이 클래스는 상태를 갖지 않는다.
 */
public final class QaService {

    static final int MAX_ATTEMPTS = 2;
    /** 프롬프트에 넣는 최근 대화 수. 한 번에 넣을 수 있는 컨텍스트에 한계가 있어 오래된 대화는 뺀다. */
    static final int MAX_HISTORY = 4;
    private static final Pattern LINE_REFERENCE = Pattern.compile("라인\\s*(\\d+)|(\\d+)\\s*번\\s*(?:줄|라인)");

    public record Turn(String question, String answer) {
    }

    record Response(String answer) {
    }

    private final StructuredLlm llm;

    public QaService(LlmClient client) {
        this.llm = new StructuredLlm(client, MAX_ATTEMPTS);
    }

    /**
     * @return 답변. LLM 응답이 끝내 검사를 통과하지 못하면 empty.
     * @throws LlmUnavailableException Ollama 서버에 닿지 못한 경우
     */
    public Optional<String> ask(Finding finding, CodeContext context, Verdict verdict,
                                List<Turn> history, String question) {
        String prompt = Prompts.render("qa", Map.of(
                "line", String.valueOf(finding.startLine()),
                "cwe", Prompts.cwe(finding.cwe()),
                "result", verdict.result().name(),
                "reason", String.valueOf(verdict.reason()),
                "history", recent(history),
                "question", question,
                "code", context.numbered()));
        return llm.ask(prompt, Response.class, r -> problemOf(r, context))
                .map(Response::answer);
    }

    private static String problemOf(Response r, CodeContext context) {
        if (r.answer() == null || r.answer().isBlank()) {
            return "answer가 비어 있음";
        }
        Matcher lines = LINE_REFERENCE.matcher(r.answer());
        while (lines.find()) {
            String number = lines.group(1) != null ? lines.group(1) : lines.group(2);
            if (number.length() > 9 || !context.contains(Integer.parseInt(number))) {
                return "라인 " + number + "은 코드에 없는 번호임. 코드 앞에 붙은 번호만 쓸 것";
            }
        }
        return null;
    }

    private static String recent(List<Turn> history) {
        if (history.isEmpty()) {
            return "없음";
        }
        return history.subList(Math.max(0, history.size() - MAX_HISTORY), history.size()).stream()
                .map(t -> "질문: " + t.question() + "\n답변: " + t.answer())
                .collect(Collectors.joining("\n"));
    }
}
