package secureview.llm;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OWASP Benchmark 경고 전체에 {@link ConstantArgs}만 돌려 본다 (LLM 없음).
 * 한 테스트에 경고가 여럿이면 모두 상수로 판정될 때만 그 테스트를 걸러진 것으로 센다 (채점은 테스트 단위).
 * 입력: 한 줄에 "테스트 이름, 경고 줄, 정답(true=진짜)"인 CSV. docs/benchmark-constant.mjs가 만든다.
 * 사용: ./mvnw -q test-compile exec:java -Dexec.classpathScope=test -Dexec.mainClass=secureview.llm.ConstantArgsBench
 *       -Dexec.args="BenchmarkJava폴더 경고.csv [CWE=89] [--missed]"
 */
public final class ConstantArgsBench {

    public static void main(String[] args) throws Exception {
        Path code = Path.of(args[0], "src/main/java/org/owasp/benchmark/testcode");
        int cwe = args.length > 2 && args[2].matches("\\d+") ? Integer.parseInt(args[2]) : 89;
        boolean showMissed = List.of(args).contains("--missed");
        Map<String, Boolean> real = new LinkedHashMap<>();
        Map<String, Boolean> filtered = new LinkedHashMap<>();
        for (String row : Files.readAllLines(Path.of(args[1]))) {
            String[] c = row.split(",");
            if (c.length < 3) {
                continue;
            }
            int line = Integer.parseInt(c[1]);
            boolean constant = ConstantArgs.isConstant(Files.readString(code.resolve(c[0] + ".java")), line, cwe);
            real.put(c[0], Boolean.parseBoolean(c[2]));
            filtered.merge(c[0], constant, Boolean::logicalAnd);
        }
        int reals = 0, safes = 0, realFiltered = 0, safeFiltered = 0;
        for (Map.Entry<String, Boolean> e : real.entrySet()) {
            boolean f = filtered.get(e.getKey());
            if (e.getValue()) {
                reals++;
                if (f) {
                    realFiltered++;
                    System.out.println("진짜인데 상수로 판정: " + e.getKey());
                }
            } else {
                safes++;
                if (f) {
                    safeFiltered++;
                } else if (showMissed) {
                    System.out.println("놓친 안전: " + e.getKey());
                }
            }
        }
        System.out.printf("CWE-%d 안전 %d건 중 LLM 없이 오탐 처리: %d건 (%.1f%%)%n", cwe, safes, safeFiltered, 100.0 * safeFiltered / safes);
        System.out.printf("CWE-%d 진짜 %d건 중 잘못 판정: %d건%n", cwe, reals, realFiltered);
    }
}
