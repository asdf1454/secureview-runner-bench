package secureview.llm;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * S5 LLM 판정·설명.
 * LLM은 사실만 답하고, 판정은 {@link #decide}의 규칙이 내린다.
 * 7B 모델은 사실을 맞게 답하고도 마지막 판정에서 그 사실과 모순되는 답을 내는 경우가 있었기 때문이다.
 * 묻는 사실은 CWE 종류에 따라 다르다.
 * - 입력 흐름형(89, 79, 78, 22): 외부 입력이 안전 처리 없이 위험한 호출에 닿는가
 * - 조건형(798, 120, 416, 476, 190, 134): 위험 조건이 있는가, 그것을 막는 코드가 있는가. 비밀번호는 상수인 것 자체가 위험 조건이다
 * 형식이 틀리거나 근거 라인이 코드 범위를 벗어나면 다시 묻고, 그래도 실패하면 UNDETERMINED(판정 불가).
 */
public final class VerdictService {

    static final int MAX_ATTEMPTS = 2;

    /** 조건형 CWE에서 LLM에게 묻는 두 가지 사실. */
    record Condition(String risk, String guard) {
    }

    static final Map<Integer, Condition> CONDITIONS = Map.of(
            134, new Condition(
                    "경고 라인의 형식 문자열 인자(printf의 첫 인자, sprintf의 둘째 인자)가 변수인가? \"%s\" 같은 문자열 상수이면 false.",
                    "그 변수에 코드 안의 고정 문자열만 들어가는가?"),
            798, new Condition(
                    "경고 라인에서 쓰는 비밀번호·키·토큰이 코드(필드 포함)에 문자열 상수로 직접 적혀 있는가? 매개변수, 환경 변수, 설정 파일에서 오면 false.",
                    "그 값이 실제 인증이나 암호화에 쓰이지 않는 값인가?"),
            120, new Condition(
                    "경고 라인의 복사나 쓰기가 고정 크기 버퍼로 들어가고, 입력 길이가 코드에서 고정되어 있지 않은가?",
                    "경고 라인 전에 길이를 검사해 넘치면 벗어나거나, 호출의 크기 인자가 대상 버퍼 크기 이하로 제한되는가?"),
            416, new Condition(
                    "경고 라인 앞의 실행 경로에 같은 포인터를 free하는 코드가 있고 경고 라인이 그 포인터를 사용하는가? 경고 라인이 free 호출 자체이고 그 앞에 free가 없으면 false.",
                    "그 free와 경고 라인 사이에 포인터에 새 값을 대입하는가?"),
            476, new Condition(
                    "경고 라인이 역참조하는 포인터가 malloc, fopen처럼 NULL을 돌려줄 수 있는 호출의 결과이거나 NULL일 수 있는 값인가? 지역 변수의 주소(&x)면 false.",
                    "경고 라인 전에 그 포인터를 NULL 검사해서 NULL이면 벗어나는가?"),
            190, new Condition(
                    "경고 라인이나 그 앞의 크기 계산 정수 연산(곱셈, 덧셈)에 매개변수처럼 값이 정해지지 않은 변수가 들어가는가? 모두 작은 상수면 false.",
                    "연산 전에 범위를 검사해서 넘칠 값이면 벗어나는가?"));

    /** LLM 응답. Boolean의 null은 "코드만으로 알 수 없음". */
    record Response(String source, Boolean externalInput, String sanitization, Boolean sanitized,
                    String riskDetail, Boolean risk, String guardDetail, Boolean guard,
                    double confidence, List<Integer> evidenceLines, String reason,
                    Verdict.Explanation explanation) {
    }

    record Explained(String reason, Verdict.Explanation explanation) {
    }

    private final StructuredLlm llm;

    public VerdictService(LlmClient client) {
        this.llm = new StructuredLlm(client, MAX_ATTEMPTS);
    }

    /** 판정과 설명을 한 번에 얻는다. */
    public Verdict judge(Finding finding, CodeContext context) {
        return explain(judgeFacts(finding, context), finding, context);
    }

    /** 설명 없이 판정만 얻는다. 건당 약 8초라 리포트 목록을 먼저 보여 줄 때 쓴다. 설명은 {@link #explain}으로 나중에 채운다. */
    public Verdict judgeFacts(Finding finding, CodeContext context) {
        boolean condition = CONDITIONS.containsKey(finding.cwe());
        String prompt = condition ? conditionPrompt(finding, context) : Prompts.render("verdict", Map.of(
                "file", finding.file(),
                "line", String.valueOf(finding.startLine()),
                // 경고 메시지·규칙 이름은 넣지 않는다. 넣으면 LLM이 코드 대신 그 문구를 근거로 든다.
                "cwe", Prompts.cwe(finding.cwe()),
                "code", context.numbered()));
        try {
            return llm.ask(prompt, Prompts.schema(condition ? "verdict_condition" : "verdict"), Response.class,
                            r -> problemOf(r, condition, context))
                    .map(r -> {
                        String wrong = finding.cwe() == 89 ? wrongSqlSanitization(r, context) : null;
                        return wrong != null ? Verdict.undetermined(wrong) : toVerdict(r, condition);
                    })
                    .orElseGet(() -> Verdict.undetermined("LLM 응답이 형식·근거 검사를 통과하지 못함"));
        } catch (LlmUnavailableException e) {
            return Verdict.undetermined("Ollama 서버에 연결하지 못해 LLM 검토를 하지 못했습니다. 실행 여부를 확인하세요.");
        }
    }

    /** 설명은 시간이 오래 걸리므로 진짜 취약점에만 따로 요청한다. 실패해도 판정은 그대로 둔다. */
    public Verdict explain(Verdict verdict, Finding finding, CodeContext context) {
        if (verdict.result() != Verdict.Result.TRUE_POSITIVE || verdict.explanation() != null) {
            return verdict;
        }
        String prompt = Prompts.render("explain", Map.of(
                "line", String.valueOf(finding.startLine()),
                "cwe", Prompts.cwe(finding.cwe()),
                "fact", String.valueOf(verdict.reason()),
                "code", context.numbered()));
        try {
            return llm.ask(prompt, Prompts.schema("explain"), Explained.class,
                            e -> e.explanation() == null || e.explanation().summary() == null ? "explanation이 비어 있음" : null)
                    .map(e -> new Verdict(verdict.result(), verdict.confidence(), verdict.evidenceLines(),
                            e.reason() == null ? verdict.reason() : e.reason(), e.explanation()))
                    .orElse(verdict);
        } catch (LlmUnavailableException e) {
            return verdict;
        }
    }

    private static String conditionPrompt(Finding finding, CodeContext context) {
        return Prompts.render("verdict_condition", Map.of(
                "file", finding.file(),
                "line", String.valueOf(finding.startLine()),
                "cwe", Prompts.cwe(finding.cwe()),
                "risk", CONDITIONS.get(finding.cwe()).risk(),
                "guard", CONDITIONS.get(finding.cwe()).guard(),
                "code", context.numbered()));
    }

    /**
     * LLM의 설명 문장은 판정과 어긋날 수 있다(상수 쿼리를 오탐으로 판정해 놓고 "위험하다"고 쓰는 등).
     * 그래서 진짜 취약점일 때만 LLM 설명을 쓰고, 나머지는 LLM이 답한 사실로 설명을 만든다.
     */
    static Verdict toVerdict(Response r, boolean condition) {
        Verdict.Result result = decide(r, condition);
        List<Integer> evidence = r.evidenceLines() == null ? List.of() : r.evidenceLines();
        return switch (result) {
            case TRUE_POSITIVE -> new Verdict(result, r.confidence(), evidence,
                    r.reason() != null ? r.reason() : condition ? r.riskDetail() : r.source(), r.explanation());
            case LIKELY_FALSE_POSITIVE -> {
                String why = safeReason(r, condition);
                yield new Verdict(result, r.confidence(), evidence, why,
                        new Verdict.Explanation("오탐으로 추정됩니다.", why, ""));
            }
            case UNDETERMINED -> new Verdict(result, r.confidence(), evidence, unknownReason(r, condition), null);
        };
    }

    private static String safeReason(Response r, boolean condition) {
        if (condition) {
            return Boolean.TRUE.equals(r.guard())
                    ? "위험한 경로를 막는 코드가 있습니다. (" + r.guardDetail() + ")"
                    : "취약점이 되는 조건이 코드에서 확인되지 않습니다. (" + r.riskDetail() + ")";
        }
        return Boolean.FALSE.equals(r.externalInput())
                ? "위험한 호출에 들어가는 값이 코드에 직접 적힌 상수라 공격자가 바꿀 수 없습니다. (" + r.source() + ")"
                : "외부 입력이 위험한 호출에 닿기 전에 안전하게 처리됩니다. (" + r.sanitization() + ")";
    }

    private static String unknownReason(Response r, boolean condition) {
        return condition
                ? "주어진 코드만으로는 취약점 조건을 판단할 수 없습니다. (" + r.riskDetail() + ")"
                : "주어진 코드만으로는 외부 입력이 들어오는지, 안전하게 처리되는지 판단할 수 없습니다. (" + r.source() + ")";
    }

    /** SQL 문자열 상수 뒤에 변수를 이어 붙이는 코드. 예: "... PASSWORD='" + param */
    private static final Pattern SQL_CONCAT =
            Pattern.compile("(?i)\"[^\"]*\\b(select|insert|update|delete|where)\\b[^\"]*\"\\s*\\+\\s*[A-Za-z_]");

    /**
     * SQL 인젝션에서 LLM이 "안전하게 처리된다"고 댄 근거가 SQL에 맞지 않으면 이유를, 맞으면 null을 돌려준다.
     * OWASP Benchmark에서 진짜 취약점을 오탐으로 지운 3건이 모두 이 경우였다:
     * HTML 인코딩을 SQL 처리로 착각했고, 쿼리에 ?가 있지만 입력을 문자열로 이어 붙인 코드를 바인딩으로 착각했다.
     * 확실하지 않으므로 진짜 취약점이 아니라 판정 불가로 돌려 경고를 남긴다.
     */
    static String wrongSqlSanitization(Response r, CodeContext context) {
        if (!Boolean.TRUE.equals(r.externalInput()) || !Boolean.TRUE.equals(r.sanitized()) || r.sanitization() == null) {
            return null;
        }
        String how = r.sanitization().toLowerCase();
        if (how.contains("html")) {
            return "HTML 인코딩은 SQL 인젝션을 막지 못해 오탐으로 볼 수 없습니다. (" + r.sanitization() + ")";
        }
        boolean binding = how.contains("prepared") || how.contains("setstring") || how.contains("바인딩") || how.contains("?");
        if (binding && context.lines().stream().anyMatch(l -> SQL_CONCAT.matcher(l).find())) {
            return "쿼리 문자열에 변수를 이어 붙이므로 바인딩만으로는 안전하지 않습니다. (" + r.sanitization() + ")";
        }
        return null;
    }

    static Verdict.Result decide(Response r, boolean condition) {
        if (condition) {
            if (Boolean.FALSE.equals(r.risk())) {
                return Verdict.Result.LIKELY_FALSE_POSITIVE;
            }
            if (Boolean.TRUE.equals(r.risk()) && r.guard() != null) {
                return r.guard() ? Verdict.Result.LIKELY_FALSE_POSITIVE : Verdict.Result.TRUE_POSITIVE;
            }
            return Verdict.Result.UNDETERMINED;
        }
        // 입력 흐름형: 상수만 닿거나 안전 처리를 거치면 오탐 추정, 외부 입력이 그대로 닿으면 진짜 취약점, 모르면 판정 불가.
        if (Boolean.FALSE.equals(r.externalInput())) {
            return Verdict.Result.LIKELY_FALSE_POSITIVE;
        }
        if (Boolean.TRUE.equals(r.externalInput()) && r.sanitized() != null) {
            return r.sanitized() ? Verdict.Result.LIKELY_FALSE_POSITIVE : Verdict.Result.TRUE_POSITIVE;
        }
        return Verdict.Result.UNDETERMINED;
    }

    /** 판정(진짜 취약점/오탐 추정)에는 근거 라인이 필수이고, 근거 라인은 판정 불가일 때도 실제 코드 범위 안에 있어야 한다. */
    static String problemOf(Response r, boolean condition, CodeContext context) {
        boolean noEvidence = r.evidenceLines() == null || r.evidenceLines().isEmpty();
        if (noEvidence) {
            return decide(r, condition) == Verdict.Result.UNDETERMINED ? null : "evidenceLines가 비어 있음";
        }
        for (Integer line : r.evidenceLines()) {
            if (line == null) {
                return "evidenceLines에 빈 값이 있음";
            }
            if (!context.contains(line)) {
                return "근거 라인 " + line + "이 코드 범위(" + context.startLine() + "~" + context.endLine() + ") 밖에 있음";
            }
        }
        return null;
    }
}
