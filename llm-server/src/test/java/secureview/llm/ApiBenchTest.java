package secureview.llm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiBenchTest {

    @Test
    void waitsOnLimitThenSucceeds() {
        AtomicInteger calls = new AtomicInteger();
        LlmClient limited = prompt -> {
            if (calls.incrementAndGet() == 1) {
                throw new LlmRateLimitException("LLM API 사용 한도 초과 (429, TPM)", 510);
            }
            return "{}";
        };
        ApiBench.WaitOnLimit llm = new ApiBench.WaitOnLimit(limited, System.currentTimeMillis() + 60_000);
        assertEquals("{}", llm.generateJson("p"));
        assertEquals(2, calls.get());
        assertEquals(510, llm.sleptMillis());
    }

    @Test
    void stopsWhenWaitPassesDeadlineAndKeepsOtherErrors() {
        LlmClient daily = prompt -> {
            throw new LlmRateLimitException("LLM API 사용 한도 초과 (429, TPD)", 30 * 60_000);
        };
        assertThrows(ApiBench.Stop.class,
                () -> new ApiBench.WaitOnLimit(daily, System.currentTimeMillis() + 60_000).generateJson("p"));
        LlmClient bad = prompt -> {
            throw new LlmException("LLM API 응답 코드 400: bad request");
        };
        assertThrows(LlmException.class,
                () -> new ApiBench.WaitOnLimit(bad, System.currentTimeMillis() + 60_000).generateJson("p"));
    }

    @Test
    void samplesEvenlyAndAlternatesCategories(@TempDir Path dir) throws Exception {
        for (String c : ApiBench.CATEGORIES.keySet()) {
            StringBuilder csv = new StringBuilder();
            for (int i = 0; i < 20; i++) {
                csv.append(c).append(i).append(",10,").append(i % 2 == 0).append('\n');
            }
            csv.append(c).append("0,12,true\n"); // 한 테스트에 경고 두 줄
            Files.writeString(dir.resolve("warnings-" + c + ".csv"), csv);
        }
        List<ApiBench.Sample> samples = ApiBench.sample(dir, 4);
        assertEquals(16, samples.size());
        assertEquals(List.of("sqli", "cmdi", "pathtraver", "xss"),
                samples.subList(0, 4).stream().map(ApiBench.Sample::category).toList());
        assertEquals(List.of(10, 12), samples.get(0).lines());
        assertEquals(8, samples.stream().filter(ApiBench.Sample::real).count());
        assertEquals(List.of(0, 5), ApiBench.spread(List.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9), 2));
    }

    @Test
    void summaryCountsPerTest() throws Exception {
        String summary = ApiBench.summary(List.of(
                StructuredLlm.MAPPER.readTree("{\"category\":\"sqli\",\"real\":false,\"warnings\":1,\"constant\":1,\"undecided\":0,\"filtered\":true,\"tokens\":0,\"sec\":0}"),
                StructuredLlm.MAPPER.readTree("{\"category\":\"sqli\",\"real\":true,\"warnings\":2,\"constant\":0,\"undecided\":1,\"filtered\":false,\"tokens\":3000,\"sec\":1.5}")),
                "m", 2);
        assertTrue(summary.contains("| sqli | 1/1 (100.0%) | 1/1 (100.0%) | 1건 | 1 / 3 | 3000 | 1.5 |"), summary);
    }
}
