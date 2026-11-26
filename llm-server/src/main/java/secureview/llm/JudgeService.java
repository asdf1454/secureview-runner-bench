package secureview.llm;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * API 명세의 경고 한 건 처리: 형식 A를 받아 S4, S5를 거쳐 형식 B를 돌려준다.
 * 판정이 제한 시간을 넘으면 UNDECIDED다. 판정이 끝났는데 설명만 늦으면 진짜 취약점을 놓치지 않도록 판정을 유지한다.
 * 모델은 한 번에 하나만 돌리므로 요청은 도착 순서대로 처리하고, 기다린 시간도 제한 시간에 포함한다.
 */
public final class JudgeService {

    public static final Duration TIME_LIMIT = Duration.ofSeconds(30);
    static final String NO_FUNCTION = "(함수 없음)";

    private final ContextExtractor extractor = new ContextExtractor();
    private final VerdictService verdicts;
    private final String model;
    private final Duration limit;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "llm-worker");
        thread.setDaemon(true);
        return thread;
    });

    public JudgeService(LlmClient client, String model, Duration limit) {
        this.verdicts = new VerdictService(client);
        this.model = model;
        this.limit = limit;
    }

    /** @throws IllegalArgumentException 필수 값이 없거나 형식이 틀린 요청 */
    public JudgeResponse judge(JudgeRequest request) {
        long started = System.nanoTime();
        if (request.finding() == null) {
            throw new IllegalArgumentException("finding이 없습니다.");
        }
        if (request.sourceCode() == null || request.sourceCode().isBlank()) {
            throw new IllegalArgumentException("sourceCode가 없습니다.");
        }
        Finding finding = request.finding().toFinding();
        CodeContext context = extractor.extract(finding, request.sourceCode());

        // 위험한 호출의 인자가 공격자가 바꿀 수 없는 값뿐인 것을 코드로 계산할 수 있으면 LLM에 묻지 않는다 (ConstantArgs 참고)
        Verdict verdict = ConstantArgs.isConstant(request.sourceCode(), finding.startLine(), finding.cwe())
                ? constantArgs(finding)
                : within(started, () -> verdicts.judgeFacts(finding, context))
                .orElseGet(() -> Verdict.undetermined(
                        "제한 시간(" + limit.toSeconds() + "초) 안에 LLM 판정을 끝내지 못했습니다."));
        if (verdict.result() == Verdict.Result.TRUE_POSITIVE) {
            Verdict judged = verdict;
            verdict = within(started, () -> verdicts.explain(judged, finding, context)).orElse(judged);
        }

        return new JudgeResponse(finding.id(),
                new JudgeResponse.Function(
                        extractor.functionName(finding, request.sourceCode()).orElse(NO_FUNCTION),
                        context.startLine(), context.endLine(), String.join("\n", context.lines())),
                new JudgeResponse.Llm(verdictName(verdict), evidence(verdict, finding, context),
                        explanation(verdict), attackExample(verdict), model, secondsSince(started)));
    }

    static Verdict constantArgs(Finding finding) {
        String why = "위험한 호출에 들어가는 값이 상수로만 만들어져 공격자가 바꿀 수 없습니다. (LLM 없이 코드로 계산한 판정)";
        return new Verdict(Verdict.Result.LIKELY_FALSE_POSITIVE, 1.0, List.of(finding.startLine()), why,
                new Verdict.Explanation("오탐으로 추정됩니다.", why, ""));
    }

    private Optional<Verdict> within(long started, Callable<Verdict> call) {
        long remaining = limit.toNanos() - (System.nanoTime() - started);
        if (remaining <= 0) {
            return Optional.empty();
        }
        Future<Verdict> future = worker.submit(call);
        try {
            return Optional.of(future.get(remaining, TimeUnit.NANOSECONDS));
        } catch (TimeoutException e) {
            future.cancel(true);
            return Optional.empty();
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (ExecutionException e) {
            throw new LlmException("판정 실패", e.getCause());
        }
    }

    /** 내부 값 UNDETERMINED를 명세 값 UNDECIDED로 바꾼다. */
    static String verdictName(Verdict verdict) {
        return verdict.result() == Verdict.Result.UNDETERMINED ? "UNDECIDED" : verdict.result().name();
    }

    /** 화면은 함수 코드만 보여 주므로 함수 밖 필드 줄은 뺀다. 판정의 근거가 함수 밖뿐이면 경고 줄을 쓴다. */
    private static List<Integer> evidence(Verdict verdict, Finding finding, CodeContext context) {
        List<Integer> inFunction = verdict.evidenceLines().stream()
                .filter(line -> line >= context.startLine() && line <= context.endLine())
                .toList();
        boolean decided = verdict.result() != Verdict.Result.UNDETERMINED;
        return inFunction.isEmpty() && decided ? List.of(finding.startLine()) : inFunction;
    }

    static String explanation(Verdict verdict) {
        return switch (verdict.result()) {
            case TRUE_POSITIVE -> verdict.explanation() == null
                    ? verdict.reason() + " (자세한 설명은 시간 제한 또는 생성 실패로 만들지 못했습니다.)"
                    : sentence(verdict.explanation().summary()) + " " + verdict.explanation().risk();
            case LIKELY_FALSE_POSITIVE, UNDETERMINED -> verdict.reason();
        };
    }

    /** 모델이 요약을 마침표 없이 쓰면 다음 문장과 붙어 읽기 어렵다. */
    private static String sentence(String text) {
        return text.endsWith(".") ? text : text + ".";
    }

    private static String attackExample(Verdict verdict) {
        if (verdict.explanation() == null || verdict.explanation().attackExample() == null
                || verdict.explanation().attackExample().isBlank()) {
            return null;
        }
        return verdict.explanation().attackExample();
    }

    private static double secondsSince(long started) {
        return Math.round((System.nanoTime() - started) / 100_000_000.0) / 10.0;
    }
}
