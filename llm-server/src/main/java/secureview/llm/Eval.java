package secureview.llm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * S5 판정 일괄 평가(초기판). 소스의 "// expect: 판정" 주석을 정답으로 삼고, 그 줄마다 경고를 만들어 판정한다.
 * 라벨 주석은 LLM에 보내기 전에 지운다.
 * 사용법: Eval <소스 파일> <CWE 번호> [반복 횟수]
 */
public final class Eval {

    private static final Pattern LABEL = Pattern.compile("\\s*//\\s*expect:\\s*([A-Z_]+)\\s*$");

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("사용법: Eval <소스 파일> <CWE 번호> [반복 횟수]");
            System.exit(1);
        }
        Path file = Path.of(args[0]);
        int cwe = Integer.parseInt(args[1]);
        int repeat = args.length > 2 ? Integer.parseInt(args[2]) : 1;

        Map<Integer, Verdict.Result> expected = new TreeMap<>();
        StringBuilder source = new StringBuilder();
        List<String> lines = Files.readAllLines(file);
        for (int i = 0; i < lines.size(); i++) {
            Matcher m = LABEL.matcher(lines.get(i));
            if (m.find()) {
                expected.put(i + 1, Verdict.Result.valueOf(m.group(1)));
                source.append(lines.get(i), 0, m.start());
            } else {
                source.append(lines.get(i));
            }
            source.append('\n');
        }

        ContextExtractor extractor = new ContextExtractor();
        VerdictService service = new VerdictService(new OllamaClient());
        int correct = 0;
        int total = 0;
        int realTotal = 0;
        int realKept = 0;
        int falseTotal = 0;
        int falseFiltered = 0;
        for (Map.Entry<Integer, Verdict.Result> e : expected.entrySet()) {
            for (int r = 0; r < repeat; r++) {
                int line = e.getKey();
                Finding finding = new Finding("F-" + line, file.toString(), line, line,
                        "SQL_INJECTION", cwe, "HIGH", "SQL 인젝션 가능성", List.of("eval"));
                long started = System.nanoTime();
                Verdict v = service.judge(finding, extractor.extract(finding, source.toString()));
                boolean ok = v.result() == e.getValue();
                correct += ok ? 1 : 0;
                total++;
                // 설명서 §9 제안대로 '오탐 추정'만 걸러진 것으로 세고, '판정 불가'는 남은 경고로 센다.
                boolean filtered = v.result() == Verdict.Result.LIKELY_FALSE_POSITIVE;
                if (e.getValue() == Verdict.Result.TRUE_POSITIVE) {
                    realTotal++;
                    realKept += filtered ? 0 : 1;
                } else {
                    falseTotal++;
                    falseFiltered += filtered ? 1 : 0;
                }
                System.out.printf("%s 라인 %3d  기대 %-21s 결과 %-21s %6d ms  %s%n", ok ? "O" : "X", line,
                        e.getValue(), v.result(), (System.nanoTime() - started) / 1_000_000, v.reason());
            }
        }
        System.out.printf("정답률 %d/%d, 오탐 감소 %d/%d, 재현율 유지 %d/%d%n",
                correct, total, falseFiltered, falseTotal, realKept, realTotal);
    }
}
