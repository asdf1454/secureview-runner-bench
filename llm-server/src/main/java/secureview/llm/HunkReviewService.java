package secureview.llm;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * PR 헝크 하나에 걸린 정적 분석 경고들을 판정한다. 판정 로직은 /internal/judge와 같다(상수 판정, VerdictBatch).
 * 시간은 경고 한 건이 아니라 요청의 budgetSec(PR 전체 예산 중 남은 시간)로 묶는다. 심각도가 높은 경고부터 판정하고,
 * 남은 시간으로 진짜 취약점의 설명과 수정 방향(S6 수정안의 이유)을 만든다.
 * 시간이 모자라면 판정은 UNDECIDED, 설명은 판정 사유로 대신하고 수정 방향은 null이다.
 */
public final class HunkReviewService {

    /** 교수님께 약속한 처리 시간 목표(합계 45초)를 PR 한 번의 최대 예산으로 쓴다. */
    public static final Duration MAX_BUDGET = Duration.ofSeconds(45);

    private final ContextExtractor extractor = new ContextExtractor();
    private final LlmClient client;
    private final VerdictService verdicts;
    private final VerdictBatch batch;
    private final FixService fixes;
    private final String model;
    private final Duration maxBudget;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "hunk-explain");
        thread.setDaemon(true);
        return thread;
    });

    /** @param maxBudget 요청 한 번에 쓸 수 있는 최대 시간. budgetSec가 없거나 더 크면 이 값을 쓴다 */
    public HunkReviewService(LlmClient client, String model, Duration maxBudget) {
        this.client = client;
        this.verdicts = new VerdictService(client);
        this.batch = new VerdictBatch(verdicts);
        this.fixes = new FixService(client);
        this.model = model;
        this.maxBudget = maxBudget;
    }

    /** @throws IllegalArgumentException 필수 값이 없거나 형식이 틀린 요청. 경고 줄이 헝크 밖이면 {@link InvalidLineException} */
    public HunkReviewResponse review(HunkReviewRequest request) {
        long started = System.nanoTime();
        long limitHits = client.rateLimitHits();
        HunkReviewRequest.Hunk hunk = request.hunk();
        if (hunk == null || hunk.id() == null || hunk.id().isBlank()) {
            throw new IllegalArgumentException("hunk.id가 없습니다.");
        }
        if (request.sourceCode() == null || request.sourceCode().isBlank()) {
            throw new IllegalArgumentException("sourceCode가 없습니다.");
        }
        List<AnalysisFinding> requested = request.findings() == null ? List.of() : request.findings();
        int first = hunk.newStartLine();
        int last = first + hunk.newLineCount() - 1;

        Map<String, AnalysisFinding> originals = new LinkedHashMap<>();
        Map<String, Verdict> judged = new LinkedHashMap<>();
        Map<String, CodeContext> contexts = new LinkedHashMap<>();
        List<VerdictBatch.Item> toLlm = new ArrayList<>();
        for (AnalysisFinding original : requested) {
            Finding finding = original.toFinding();
            if (finding.startLine() < first || finding.startLine() > last) {
                throw new InvalidLineException("경고 " + finding.id() + "의 line " + finding.startLine()
                        + "이 헝크 범위(" + first + "~" + last + ") 밖입니다.");
            }
            CodeContext context = extractor.extract(finding, request.sourceCode());
            originals.put(finding.id(), original);
            contexts.put(finding.id(), context);
            if (ConstantArgs.isConstant(request.sourceCode(), finding.startLine(), finding.cwe())) {
                judged.put(finding.id(), JudgeService.constantArgs(finding));
            } else {
                judged.put(finding.id(), null);
                toLlm.add(new VerdictBatch.Item(finding, context));
            }
        }

        Duration budget = budget(request.budgetSec());
        if (!toLlm.isEmpty()) {
            judged.putAll(batch.judgeAll(toLlm, budget));
        }

        // 설명을 모든 진짜 취약점에 먼저 만들고, 남은 시간으로 수정 방향을 만든다. 댓글에는 설명이 더 중요하다.
        Map<String, Verdict> explained = new LinkedHashMap<>();
        judged.forEach((id, v) -> {
            Finding finding = originals.get(id).toFinding();
            explained.put(id, v.result() != Verdict.Result.TRUE_POSITIVE ? v
                    : within(started, budget, () -> verdicts.explain(v, finding, contexts.get(id)), v));
        });
        Map<String, String> suggestions = new LinkedHashMap<>();
        explained.forEach((id, v) -> {
            if (v.result() == Verdict.Result.TRUE_POSITIVE) {
                Finding finding = originals.get(id).toFinding();
                suggestions.put(id, within(started, budget, () -> fixes.propose(finding, contexts.get(id), v, null)
                        .map(Fix::reason).orElse(null), null));
            }
        });

        List<HunkReviewResponse.Finding> results = new ArrayList<>();
        for (Map.Entry<String, Verdict> entry : explained.entrySet()) {
            AnalysisFinding original = originals.get(entry.getKey());
            Finding finding = original.toFinding();
            Verdict verdict = entry.getValue();
            results.add(new HunkReviewResponse.Finding(
                    hunk.id() + ":" + original.cwe() + ":" + finding.startLine(), finding.id(), original.cwe(),
                    original.severity(), finding.startLine(), finding.endLine(), original.title(),
                    JudgeService.verdictName(verdict), verdict.confidence(), JudgeService.explanation(verdict),
                    evidence(verdict, finding), suggestions.get(entry.getKey()), model, secondsSince(started)));
        }
        // 서버 전체의 횟수라 동시에 다른 요청이 한도에 걸려도 true가 될 수 있다. PR 검토는 헝크를 하나씩 보내므로 문제없다.
        return new HunkReviewResponse(hunk.id(), results, client.rateLimitHits() > limitHits);
    }

    private Duration budget(Integer budgetSec) {
        if (budgetSec == null) {
            return maxBudget;
        }
        Duration asked = Duration.ofSeconds(Math.max(0, budgetSec));
        return asked.compareTo(maxBudget) < 0 ? asked : maxBudget;
    }

    /** 남은 예산 안에서 work를 실행한다. 시간이 없거나, 넘기거나, 실패하면 fallback. 판정은 이미 끝났으므로 결과를 버리지 않는다. */
    private <T> T within(long started, Duration budget, Callable<T> work, T fallback) {
        long remaining = budget.toNanos() - (System.nanoTime() - started);
        if (remaining <= 0) {
            return fallback;
        }
        Future<T> call = worker.submit(work);
        try {
            return call.get(remaining, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            call.cancel(true);
            return fallback;
        } catch (InterruptedException e) {
            call.cancel(true);
            Thread.currentThread().interrupt();
            return fallback;
        } catch (ExecutionException e) {
            return fallback;
        }
    }

    /** 판정했는데 근거 줄이 없으면 경고 줄을 근거로 둔다. 댓글이 가리킬 줄이 있어야 한다. */
    private static List<Integer> evidence(Verdict verdict, Finding finding) {
        boolean decided = verdict.result() != Verdict.Result.UNDETERMINED;
        return verdict.evidenceLines().isEmpty() && decided ? List.of(finding.startLine()) : verdict.evidenceLines();
    }

    private static double secondsSince(long started) {
        return Math.round((System.nanoTime() - started) / 100_000_000.0) / 10.0;
    }
}
