package secureview.llm;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 경고 한 건의 수정안(S6)을 만든다. 형식 A와 파일 전체를 받아 함수 범위와 수정 코드를 돌려준다.
 * 진짜 취약점으로 판정된 경고에만 부른다. 제한 시간을 넘기거나 쓸 만한 수정안이 없으면 fixedCode가 null이다.
 */
public final class FixApiService {

    public static final Duration TIME_LIMIT = Duration.ofSeconds(60);

    private final ContextExtractor extractor = new ContextExtractor();
    private final FixService fixes;
    private final String model;
    private final Duration limit;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "llm-fix-worker");
        thread.setDaemon(true);
        return thread;
    });

    public FixApiService(LlmClient client, String model, Duration limit) {
        this.fixes = new FixService(client);
        this.model = model;
        this.limit = limit;
    }

    /** @throws IllegalArgumentException 필수 값이 없거나 형식이 틀린 요청 */
    public FixResponse fix(FixRequest request) {
        long started = System.nanoTime();
        if (request.finding() == null) {
            throw new IllegalArgumentException("finding이 없습니다.");
        }
        if (request.sourceCode() == null || request.sourceCode().isBlank()) {
            throw new IllegalArgumentException("sourceCode가 없습니다.");
        }
        Finding finding = request.finding().toFinding();
        CodeContext context = extractor.extract(finding, request.sourceCode());
        Verdict verdict = new Verdict(Verdict.Result.TRUE_POSITIVE, 0, List.of(finding.startLine()),
                request.reason() == null || request.reason().isBlank() ? "취약점으로 판정됨" : request.reason(), null);
        FixResponse.Function function = new FixResponse.Function(
                extractor.functionName(finding, request.sourceCode()).orElse(JudgeService.NO_FUNCTION),
                context.startLine(), context.endLine());

        Future<Optional<Fix>> call = worker.submit(
                () -> fixes.propose(finding, context, verdict, request.previousFailure()));
        try {
            Optional<Fix> fix = call.get(limit.toNanos(), TimeUnit.NANOSECONDS);
            return fix.map(f -> new FixResponse(finding.id(), function, f.code(), f.reason(), model, secondsSince(started)))
                    .orElseGet(() -> new FixResponse(finding.id(), function, null,
                            "사전 검사를 통과하는 수정안을 만들지 못했습니다.", model, secondsSince(started)));
        } catch (TimeoutException e) {
            call.cancel(true);
            return new FixResponse(finding.id(), function, null,
                    "제한 시간(" + limit.toSeconds() + "초) 안에 수정안을 만들지 못했습니다.", model, secondsSince(started));
        } catch (InterruptedException e) {
            call.cancel(true);
            Thread.currentThread().interrupt();
            return new FixResponse(finding.id(), function, null, "수정안 생성이 중단되었습니다.", model,
                    secondsSince(started));
        } catch (ExecutionException e) {
            if (e.getCause() instanceof LlmUnavailableException unavailable) {
                throw unavailable;
            }
            throw new LlmException("수정안 생성 실패", e.getCause());
        }
    }

    private static double secondsSince(long started) {
        return Math.round((System.nanoTime() - started) / 100_000_000.0) / 10.0;
    }
}
