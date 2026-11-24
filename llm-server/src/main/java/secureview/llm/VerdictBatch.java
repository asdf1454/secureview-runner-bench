package secureview.llm;

import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;

/**
 * 경고 목록 전체를 정해진 시간 안에서 판정한다 (처리 속도 목표용). 설명은 만들지 않으며, 리포트를 보여 준 뒤
 * {@link VerdictService#explain}으로 채운다.
 * 심각도가 높은 경고부터 판정하고, 시간이 지나면 나머지는 지우지 않고 UNDETERMINED로 남긴다.
 * 같은 함수·같은 CWE에서 이미 진짜 취약점이 나왔으면 LLM을 다시 부르지 않는다.
 * 오탐 추정은 재사용하지 않는다. 같은 함수의 다른 줄은 진짜 취약점일 수 있기 때문이다.
 */
public final class VerdictBatch {

    public record Item(Finding finding, CodeContext context) {
    }

    private final VerdictService service;
    private final LongSupplier nanoTime;

    public VerdictBatch(VerdictService service) {
        this(service, System::nanoTime);
    }

    VerdictBatch(VerdictService service, LongSupplier nanoTime) {
        this.service = service;
        this.nanoTime = nanoTime;
    }

    /** @return Finding id → 판정. 입력한 경고가 모두 들어 있다. */
    public Map<String, Verdict> judgeAll(List<Item> items, Duration budget) {
        long started = nanoTime.getAsLong();
        Map<String, Verdict> judged = new HashMap<>();
        Map<String, Verdict> truePositives = new HashMap<>();
        ExecutorService worker = Executors.newSingleThreadExecutor();

        try {
            List<Item> ordered = items.stream()
                    .sorted(Comparator.comparingInt((Item i) -> severityRank(i.finding().severity())))
                    .toList();
            for (Item item : ordered) {
                String function = item.context().file() + ":" + item.context().startLine() + ":"
                        + item.context().endLine() + ":" + item.finding().cwe();
                Verdict reusable = truePositives.get(function);
                Verdict verdict;
                if (reusable != null) {
                    verdict = withOwnLine(reusable, item.finding());
                } else {
                    long remaining = budget.toNanos() - (nanoTime.getAsLong() - started);
                    verdict = remaining <= 0 ? timedOut() : judgeWithin(worker, item, remaining);
                    if (verdict.result() == Verdict.Result.TRUE_POSITIVE) {
                        truePositives.put(function, verdict);
                    }
                }
                judged.put(item.finding().id(), verdict);
            }
        } finally {
            worker.shutdownNow();
        }

        Map<String, Verdict> inInputOrder = new LinkedHashMap<>();
        items.forEach(i -> inInputOrder.put(i.finding().id(), judged.get(i.finding().id())));
        return inInputOrder;
    }

    /** 진행 중인 호출도 남은 시간이 지나면 끊는다. */
    private Verdict judgeWithin(ExecutorService worker, Item item, long remainingNanos) {
        Future<Verdict> call = worker.submit(() -> service.judgeFacts(item.finding(), item.context()));
        try {
            return call.get(remainingNanos, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            call.cancel(true);
            return timedOut();
        } catch (InterruptedException e) {
            call.cancel(true);
            Thread.currentThread().interrupt();
            return timedOut();
        } catch (ExecutionException e) {
            throw new LlmException("판정 실패: " + e.getCause().getMessage(), e.getCause());
        }
    }

    private static Verdict timedOut() {
        return Verdict.undetermined("처리 시간 제한으로 LLM 검토를 하지 못했습니다.");
    }

    /** 재사용한 판정에도 이 경고 자신의 줄을 근거로 넣는다. 화면이 해당 줄을 강조할 수 있어야 한다. */
    private static Verdict withOwnLine(Verdict verdict, Finding finding) {
        TreeSet<Integer> evidence = new TreeSet<>(verdict.evidenceLines());
        evidence.add(finding.startLine());
        return new Verdict(verdict.result(), verdict.confidence(), List.copyOf(evidence),
                verdict.reason(), verdict.explanation());
    }

    private static int severityRank(String severity) {
        if (severity == null) {
            return 3;
        }
        return switch (severity) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            case "LOW" -> 2;
            default -> 3;
        };
    }
}
