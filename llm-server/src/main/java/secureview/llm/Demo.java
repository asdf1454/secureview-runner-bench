package secureview.llm;

import com.fasterxml.jackson.databind.ObjectWriter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 실제 Ollama로 S4 → S5 → S8 → S6 흐름을 한 번 돌려 보는 실행 예제.
 * 사용법: Demo <소스 파일> <경고 라인> <CWE 번호>
 */
public final class Demo {

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("사용법: Demo <소스 파일> <경고 라인> <CWE 번호>");
            System.exit(1);
        }
        Path file = Path.of(args[0]);
        int line = Integer.parseInt(args[1]);
        Finding finding = new Finding("F-001", file.toString(), line, line,
                "DEMO", Integer.parseInt(args[2]), "HIGH", "데모용 경고", List.of("demo"));

        OllamaClient llm = new OllamaClient();
        long warmUpStarted = System.nanoTime();
        llm.warmUp();
        System.out.println("== 모델 미리 올리기 (" + (System.nanoTime() - warmUpStarted) / 1_000_000 + " ms)");
        ObjectWriter out = StructuredLlm.MAPPER.writerWithDefaultPrettyPrinter();

        CodeContext context = new ContextExtractor().extract(finding, Files.readString(file));
        System.out.println("== S4 컨텍스트 (" + context.startLine() + "~" + context.endLine()
                + (context.wholeFunction() ? ", 함수 전체" : ", ±30줄 조각") + ")");
        System.out.println(context.numbered());

        long started = System.nanoTime();
        Verdict verdict = new VerdictService(llm).judge(finding, context);
        System.out.println("\n== S5 판정 (" + (System.nanoTime() - started) / 1_000_000 + " ms)");
        System.out.println(out.writeValueAsString(verdict));

        started = System.nanoTime();
        String question = "이 입력은 어디서 들어오나요?";
        String answer = new QaService(llm).ask(finding, context, verdict, List.of(), question).orElse("(답변 실패)");
        System.out.println("\n== S8 질의응답 (" + (System.nanoTime() - started) / 1_000_000 + " ms)");
        System.out.println("질문: " + question + "\n답변: " + answer);

        if (verdict.result() != Verdict.Result.TRUE_POSITIVE) {
            return;
        }
        System.out.println("\n== S6 수정안");
        System.out.println(out.writeValueAsString(new FixService(llm).propose(finding, context, verdict, null).orElse(null)));
    }
}
