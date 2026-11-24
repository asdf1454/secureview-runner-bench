package secureview.llm;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * S6 수정안 생성. TRUE_POSITIVE 판정에만 쓴다.
 * S7 재검증이 실패하면 그 실패 이유를 previousFailure로 넘겨 다시 호출한다(계획서: 최대 2회).
 */
public final class FixService {

    static final int MAX_ATTEMPTS = 2;

    /** CWE별 수정 방법. 없으면 7B 모델이 String.format으로 형태만 바꾸거나 없는 메서드를 지어냈다. */
    static final Map<Integer, String> METHODS = Map.of(
            89, "값을 문자열에 이어 붙이지 말고 PreparedStatement의 ? 자리에 setString 등으로 바인딩한다.",
            79, "출력 전에 입력의 & < > \" ' 를 String.replace로 HTML 엔티티(&amp; &lt; &gt; &quot; &#39;)로 바꾼다. String.format은 안전 처리가 아니다.",
            78, "입력이 정규식 [A-Za-z0-9._-]+ 와 맞지 않으면 IllegalArgumentException을 던지고, 쉘(sh -c)을 쓰지 않고 new ProcessBuilder(명령, 인자...)로 인자를 따로 넘긴다. String.format은 안전 처리가 아니다.",
            22, "기준 폴더 Path를 정해 base.resolve(입력).normalize()로 만든 뒤 startsWith(base)가 아니면 SecurityException을 던진다. 기준 폴더가 코드에 없으면 입력에 .. 이나 경로 구분자가 있을 때 거부한다.",
            798, "문자열 상수 대신 System.getenv(\"이름\")으로 값을 읽고, null이면 IllegalStateException을 던진다. 함수 밖 상수 선언은 고치지 않는다.",
            120, "버퍼 크기를 넘지 않게 snprintf나 strncpy에 sizeof(버퍼)를 넘기고 끝에 '\\0'을 넣는다. gets는 fgets로 바꾼다.",
            416, "free한 뒤 포인터에 NULL을 넣고, 사용하기 전에 NULL을 검사한다. 사용 코드를 지우지 않는다. 사용이 끝난 뒤로 free를 옮길 수 있으면 옮긴다.",
            476, "역참조 전에 NULL을 검사하고, NULL이면 함수의 반환형에 맞는 오류 값을 돌려준다.",
            134, "형식 문자열을 고정하고 입력은 인자로 넘긴다. 예: printf(\"%s\", msg). 출력 내용과 대상은 바꾸지 않는다.",
            190, "연산 전에 자료형의 최댓값(INT_MAX, UINT_MAX 등)과 비교해 넘칠 값이면 오류 값을 돌려준다. 검사와 연산에 쓰는 자료형을 맞춘다.");

    record Response(String code, String reason) {
    }

    private final StructuredLlm llm;

    public FixService(LlmClient client) {
        this.llm = new StructuredLlm(client, MAX_ATTEMPTS);
    }

    /** @param previousFailure 이전 수정안의 재검증 실패 이유. 첫 시도면 null. */
    public Optional<Fix> propose(Finding finding, CodeContext context, Verdict verdict, String previousFailure) {
        if (verdict.result() != Verdict.Result.TRUE_POSITIVE) {
            throw new IllegalArgumentException("수정안은 TRUE_POSITIVE 판정에만 생성한다: " + verdict.result());
        }
        String prompt = Prompts.render("fix", Map.of(
                "cwe", Prompts.cwe(finding.cwe()),
                "method", METHODS.getOrDefault(finding.cwe(), "안전한 API나 검증으로 고친다."),
                "reason", String.valueOf(verdict.reason()),
                "startLine", String.valueOf(context.startLine()),
                "endLine", String.valueOf(context.endLine()),
                "previousFailure", previousFailure == null ? "없음" : previousFailure,
                "code", context.numbered()));
        return llm.ask(prompt, Response.class, r -> r.reason() == null || r.reason().isBlank()
                        ? "reason이 비어 있음"
                        : FixValidator.problemOf(context, r.code()))
                .map(r -> new Fix(List.of(context.startLine(), context.endLine()), r.code(), r.reason(), null));
    }
}
