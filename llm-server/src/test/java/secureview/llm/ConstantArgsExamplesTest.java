package secureview.llm;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** 직접 만든 Java 평가 예제(CWE-89, 78, 22, 79)에서 상수 추적이 진짜 취약점을 하나도 오탐으로 보지 않는지 확인한다. */
class ConstantArgsExamplesTest {

    @Test
    void noTruePositiveExampleIsJudgedConstant() throws Exception {
        List<String> wrong = new ArrayList<>();
        int constants = 0;
        for (Map.Entry<String, Integer> example : Map.of("examples/SqlCases.java", 89, "examples/cwe/Cwe89Injection.java", 89,
                "examples/cwe/Cwe78.java", 78, "examples/cwe/Cwe22.java", 22, "examples/cwe/Cwe79.java", 79).entrySet()) {
            String file = example.getKey();
            List<String> lines = Files.readAllLines(Path.of(file));
            String source = String.join("\n", lines.stream().map(l -> l.replaceAll("//\s*expect:.*$", "")).toList());
            for (int i = 0; i < lines.size(); i++) {
                if (!lines.get(i).contains("expect:")) {
                    continue;
                }
                if (ConstantArgs.isConstant(source, i + 1, example.getValue())) {
                    constants++;
                    if (lines.get(i).contains("TRUE_POSITIVE")) {
                        wrong.add(file + ":" + (i + 1));
                    }
                }
            }
        }
        assertEquals(List.of(), wrong);
        System.out.println("상수로 판정된 예제 경고: " + constants);
    }
}
