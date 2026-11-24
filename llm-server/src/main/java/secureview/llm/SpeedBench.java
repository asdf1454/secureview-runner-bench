package secureview.llm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 처리 속도 측정: S4 추출과 S5 일괄 판정 시간을 반복해 재고 중앙값을 낸다. S0~S3과 화면 표시 시간은 포함하지 않는다.
 * 소스에서 "// warning"이 붙은 줄마다 경고를 만든다.
 * 사용법: SpeedBench <소스 파일> <CWE 번호> <반복 횟수> <제한 초>
 */
public final class SpeedBench {

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        int cwe = Integer.parseInt(args[1]);
        int runs = Integer.parseInt(args[2]);
        Duration budget = Duration.ofSeconds(Long.parseLong(args[3]));

        String source = Files.readString(file);
        List<String> lines = source.lines().toList();
        ContextExtractor extractor = new ContextExtractor();
        OllamaClient llm = new OllamaClient();
        llm.warmUp();
        VerdictService service = new VerdictService(llm);
        VerdictBatch batch = new VerdictBatch(service);

        List<Long> times = new ArrayList<>();
        for (int run = 1; run <= runs; run++) {
            long started = System.nanoTime();
            List<VerdictBatch.Item> items = new ArrayList<>();
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).contains("// warning")) {
                    Finding f = new Finding("F-" + (i + 1), file.toString(), i + 1, i + 1, "R", cwe, "HIGH", "m", List.of("bench"));
                    items.add(new VerdictBatch.Item(f, extractor.extract(f, source)));
                }
            }
            Map<String, Verdict> verdicts = batch.judgeAll(items, budget);
            long ms = (System.nanoTime() - started) / 1_000_000;
            times.add(ms);
            long tp = verdicts.values().stream().filter(v -> v.result() == Verdict.Result.TRUE_POSITIVE).count();
            long fp = verdicts.values().stream().filter(v -> v.result() == Verdict.Result.LIKELY_FALSE_POSITIVE).count();
            System.out.printf("%d회: %d줄, 경고 %d건, %d ms, 진짜 취약점 %d, 오탐 추정 %d, 판정 불가 %d%n",
                    run, lines.size(), items.size(), ms, tp, fp, items.size() - tp - fp);
        }
        Collections.sort(times);
        System.out.printf("중앙값 %d ms, 최소 %d ms, 최대 %d ms%n", times.get(times.size() / 2), times.get(0), times.get(times.size() - 1));
    }
}
