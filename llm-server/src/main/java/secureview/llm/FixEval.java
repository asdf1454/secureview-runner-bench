package secureview.llm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * S6 수정안 일괄 확인. 소스의 "// expect: TRUE_POSITIVE" 줄마다 수정안을 만들어 사전 검사 통과 수와 코드를 출력한다.
 * 컴파일과 경고 해소 확인은 S7 몫이라 여기서 하지 않는다.
 * 사용법: FixEval <소스 파일> <CWE 번호>
 */
public final class FixEval {

    private static final Pattern LABEL = Pattern.compile("\\s*//\\s*expect:\\s*([A-Z_]+)\\s*$");

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        int cwe = Integer.parseInt(args[1]);
        List<String> lines = Files.readAllLines(file);
        StringBuilder source = new StringBuilder();
        for (String line : lines) {
            Matcher m = LABEL.matcher(line);
            source.append(m.find() ? line.substring(0, m.start()) : line).append('\n');
        }

        ContextExtractor extractor = new ContextExtractor();
        FixService service = new FixService(new OllamaClient());
        int passed = 0;
        int total = 0;
        for (int i = 0; i < lines.size(); i++) {
            Matcher m = LABEL.matcher(lines.get(i));
            if (!m.find() || !m.group(1).equals("TRUE_POSITIVE")) {
                continue;
            }
            int line = i + 1;
            total++;
            Finding finding = new Finding("F-" + line, file.toString(), line, line, "R", cwe, "HIGH", "m", List.of("eval"));
            Verdict verdict = new Verdict(Verdict.Result.TRUE_POSITIVE, 1, List.of(line), "이 라인에 취약점이 있음", null);
            long started = System.nanoTime();
            Optional<Fix> fix = service.propose(finding, extractor.extract(finding, source.toString()), verdict, null);
            passed += fix.isPresent() ? 1 : 0;
            System.out.printf("--- 라인 %d (%d ms) %s%n%s%n", line, (System.nanoTime() - started) / 1_000_000,
                    fix.isPresent() ? "통과" : "실패", fix.map(Fix::code).orElse(""));
        }
        System.out.printf("사전 검사 통과 %d/%d%n", passed, total);
    }
}
