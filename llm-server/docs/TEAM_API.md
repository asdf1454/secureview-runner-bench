# LLM 모듈 연동 안내

담당: 유환민. 웹 서버는 아래 **내부 HTTP API**로 호출한다. 수정안(S6)과 질의응답은 명세에 API가 없어 아직 Java 호출만 가능하다.

## 내부 HTTP API (API 명세 기준)

```bash
SR_INTERNAL_KEY=비밀값 ./mvnw -q compile exec:java "-Dexec.mainClass=secureview.llm.LlmServer"
```

PowerShell에서는 먼저 `$env:SR_INTERNAL_KEY = '비밀값'`을 실행하고, 같은 `./mvnw` 명령을 실행한다.

| 환경 변수 | 기본값 | 뜻 |
|---|---|---|
| `SR_INTERNAL_KEY` | 없음 (필수) | `X-Internal-Key` 헤더 값 |
| `SR_LLM_HOST` | `127.0.0.1` | 받을 주소. 배포 때 Tailscale 주소로 설정 |
| `SR_LLM_PORT` | `8081` | 받을 포트. 명세에 정해지지 않아 임시로 정함 |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 주소 |

- `POST /internal/judge`: 요청은 `{"finding": 형식 A, "sourceCode": "파일 전체"}`, 응답은 형식 B.
- `GET /internal/health`: 정상이면 200 `{"status":"UP","model":"qwen2.5-coder:7b"}`. Ollama가 꺼졌거나 모델이 없으면 503 `{"status":"DOWN",...}`.
- 모델을 메모리에 올리는 동안에는 `health`가 503 `DOWN`이고 `judge`도 503을 돌려준다. `health`가 `UP`이 된 뒤에 업로드를 받는다. 메모리가 부족한 PC에서는 3분 넘게 걸린 적이 있다.
- 모든 요청에 `X-Internal-Key`가 필요하다. 없거나 틀리면 401 `UNAUTHORIZED`.
- 에러는 명세의 `{"error","message"}` 형식이다: 400 `INVALID_INPUT`, 404 `NOT_FOUND`, 413 `FILE_TOO_LARGE`(본문 4MB 초과), 500 `INTERNAL_ERROR`.

### 연결 확인 (웹 서버 담당용)

LLM 서버를 켠 뒤 `llm-server` 폴더에서 아래 두 명령을 실행한다. PowerShell에서는 `curl` 대신 `curl.exe`를 쓴다.

```bash
curl -H "X-Internal-Key: 비밀값" http://127.0.0.1:8081/internal/health
```

```bash
curl -H "X-Internal-Key: 비밀값" -H "Content-Type: application/json" --data-binary @examples/judge-request.json http://127.0.0.1:8081/internal/judge
```

- `examples/judge-request.json`은 형식 A 경고 1건과 `examples/UserDao.java` 전체를 담은 요청 예시다. 16번 줄은 진짜 취약점이라 `TRUE_POSITIVE`가 나와야 한다.
- 응답은 측정 PC(RTX 2050)에서 약 20초 걸린다. 웹 서버의 호출 제한 시간은 명세대로 40초로 둔다.
- 한글이 들어가므로 요청과 응답은 UTF-8로 주고받는다.

### 웹 서버에 저장할 때의 대응 (backend의 `Finding`)

| 형식 B | 저장 호출 |
|---|---|
| `function.name`, `startLine`, `endLine`, `code` | `finding.setFunction(name, startLine, endLine, code)` |
| `llm.verdict` | `Verdict.valueOf(verdict)`. 값 세 가지가 backend의 `Verdict`와 같다 |
| `llm.evidenceLines`, `explanation`, `attackExample`, `model` | `finding.setJudgement(verdict, evidenceLines, explanation, attackExample, model)` |
| `llm.latencySec` | 저장할 칸 없음. 로그용 |

- `attackExample`은 `null`일 수 있다 (오탐 추정, 판정 불가, 설명 지연).
- 호출에 실패하거나 40초를 넘기면 명세대로 1회 재시도하고, 그래도 실패하면 그 경고를 `UNDECIDED`로 저장한다.
- 경고는 한 건씩 차례로 보낸다. 심각도가 높은 것부터 보낸다.

### 수정안 API (12월 범위, 명세에 아직 없음)

`POST /internal/fix`: 진짜 취약점으로 판정된 경고의 수정안을 만든다. 주소와 형식은 임시이며 명세에 넣을 때 바뀔 수 있다.

```json
{"finding": { "형식 A 객체 하나": "..." }, "sourceCode": "파일 전체",
 "reason": "판정 때 받은 설명 (없어도 됨)", "previousFailure": "이전 수정안의 재검증 실패 이유 (첫 시도면 null)"}
```

```json
{"findingId": "e91a...", "function": {"name": "find", "startLine": 14, "endLine": 17},
 "fixedCode": "public ResultSet find(String name) ...", "reason": "바인딩으로 변경",
 "model": "qwen2.5-coder:7b", "latencySec": 12.1}
```

- `function`과 `fixedCode`는 재검증(형식 C 입력)에 그대로 넣는다.
- 제한 시간(60초)을 넘기거나 사전 검사를 통과하는 수정안이 없으면 `fixedCode`가 `null`이고 `reason`에 이유가 들어간다.
- 재검증이 실패하면 실패 이유를 `previousFailure`에 넣어 다시 요청한다. 설명서 기준 최대 2회.

### 명세에 없거나 명세와 다른 동작 (팀 확인 필요)

| 항목 | 동작 | 이유 |
|---|---|---|
| 30초 초과 | 판정이 30초를 넘으면 `UNDECIDED`. 판정은 끝났는데 **설명만 늦으면 `TRUE_POSITIVE` 유지**, `attackExample`은 `null` | 명세대로 모두 `UNDECIDED`로 바꾸면 찾아낸 진짜 취약점을 잃는다 |
| `explanation` | 설명이 늦으면 판정 근거와 함께 "자세한 설명을 만들지 못했다"는 문장이 들어간다 | 화면이 빈 칸을 보여 주지 않도록 |
| `attackExample` | 오탐 추정, 판정 불가, 설명 지연이면 `null` | 공격 예시가 없다 |
| `evidenceLines` | 함수 밖 필드 줄은 응답에서 뺀다. 판정 근거가 함수 밖뿐이면 경고 줄을 넣는다 | 화면은 함수 코드만 보여 준다 |
| `function.name` | 함수를 찾지 못하면 `(함수 없음)`. 이때 `function`은 경고 줄 ±30줄 범위다. 150줄 넘는 함수도 범위는 ±30줄 | DB `function_name`이 NULL 허용으로 적혀 있지 않다 |
| 동시 요청 | 모델은 한 번에 한 건만 돌린다. 기다린 시간도 30초에 포함한다 | 웹 서버는 경고를 한 건씩 차례로 보내야 한다 |
| 경고 순서 | 서버가 경고를 받은 순서대로 처리한다 | 심각도 높은 경고부터 보내야 시간이 모자랄 때 중요한 경고가 먼저 끝난다 |
| 코드로 계산한 판정 (v1.2.0) | Java의 CWE-89·78·22·79에서 위험한 호출의 값이 상수로만 만들어지면 LLM 없이 `LIKELY_FALSE_POSITIVE`. `explanation`에 "LLM 없이 코드로 계산한 판정"이 들어가고, `model`에는 그대로 모델 이름이 나간다 | 형식 B에 "규칙으로 판정"을 나타낼 칸이 없다. 화면에서 구분하려면 칸을 추가할지 정해야 한다 |

명세의 "같은 함수·같은 CWE 재사용"과 전체 시간 제한은 건별 호출에는 적용되지 않는다. 아래 `VerdictBatch`는 Java로 직접 호출할 때만 쓰인다.

## Java 직접 호출 (수정안, 질의응답)

Spring에 묶이지 않은 Java 17 코드라 `@Bean`으로 등록하거나 `new`로 만들어 쓸 수 있다.

### 준비

1. Ollama를 실행하고 모델을 받는다: `ollama pull qwen2.5-coder:7b`
2. 서버 시작 때 `warmUp()`을 한 번 호출한다. 약 18초 걸리고, 호출하지 않으면 첫 판정이 그만큼 느려진다.

```java
OllamaClient llm = new OllamaClient();
llm.warmUp();
ContextExtractor extractor = new ContextExtractor();
VerdictService verdicts = new VerdictService(llm);
VerdictBatch batch = new VerdictBatch(verdicts);
FixService fixes = new FixService(llm);
QaService qa = new QaService(llm);
```

### 단계별 호출

#### 묶음 판정: S3 → S4 → S5 (HTTP API를 쓰면 필요 없음)

```java
List<VerdictBatch.Item> items = findings.stream()
        .map(f -> new VerdictBatch.Item(f, extractor.extract(f, sourceOf(f.file()))))
        .toList();
Map<String, Verdict> result = batch.judgeAll(items, Duration.ofSeconds(40));
```

- 입력한 경고가 결과에 모두 들어 있다. LLM은 경고를 지우지 않는다.
- 심각도 `HIGH`, `MEDIUM`, `LOW` 순서로 판정한다. 제한 시간이 지난 경고와 LLM 호출에 실패한 경고는 `UNDETERMINED`가 된다.
- 시간이 지나면 진행 중인 호출도 끊는다. Ollama에 연결하지 못하면 판정 불가와 함께 그 이유를 `reason`에 담는다.
- 40초는 예시다. 1분에서 S0~S3과 화면 표시 시간을 뺀 값을 넣는다. 경고 5건도 40초에 걸릴 수 있어 5번째가 판정 불가로 남을 수 있다.
- 이 단계에서는 `explanation`이 비어 있다. 건당 약 8초(RTX 2050 기준)라 리포트 목록을 먼저 보여 줄 수 있다.
- 설명은 리포트를 보여 준 뒤 채운다: `verdict = verdicts.explain(verdict, finding, context)` (진짜 취약점 건당 약 25초, 그 외에는 LLM을 호출하지 않음)

#### 수정안 (채무진): S6 ↔ S7 (12월)

```java
Optional<Fix> fix = fixes.propose(finding, context, verdict, null);
// S7 실패 시 실패 이유를 넘겨 다시 요청한다. 최대 2회.
Optional<Fix> retry = fixes.propose(finding, context, verdict, "컴파일 오류: ...");
```

- `TRUE_POSITIVE`가 아니면 `IllegalArgumentException`이 발생한다.
- `functionRange`의 `[시작, 끝]` 줄을 `code`로 통째로 교체한다. `verification`은 S7이 채운다.
- `FixValidator`는 문법, 함수 개수, 선언 유지만 본다. 컴파일과 경고 해소는 S7에서 확인해야 한다.
- `context.wholeFunction()`이 `false`면 함수가 아니라 ±30줄 조각을 교체하는 수정안이다.

#### 질의응답 (강민재): S8 (명세에 API 없음)

```java
List<QaService.Turn> history = new ArrayList<>(); // 화면이 경고별로 보관
Optional<String> answer = qa.ask(finding, context, verdict, history, "이 입력은 어디서 들어오나요?");
answer.ifPresent(a -> history.add(new QaService.Turn(question, a)));
```

- 답변이 비어 있으면 두 번 시도해 실패한 경우다. 다시 질문하도록 안내한다.
- 모델 생성 실패는 다시 시도한 뒤 빈 값으로 돌려준다.
- Ollama에 연결하지 못하거나 응답 시간을 넘기면 `LlmUnavailableException`을 던진다. `FixService`도 같다.

## Java 직접 호출 시 화면 표시 규칙

HTTP API 응답에는 `confidence`가 없고, 판정 불가 값은 `UNDECIDED`다.

- `confidence`는 LLM이 스스로 낸 값이라 화면에 보여 주지 않는다.
- `LIKELY_FALSE_POSITIVE`는 지우지 않고 접어서 보여 준다.
- `UNDETERMINED`는 `explanation`이 `null`이다. `TRUE_POSITIVE`도 설명 생성에 실패하면 `null`일 수 있다.

## Java 직접 호출 데이터 형식

HTTP API 형식은 API 명세의 형식 A, B를 따른다. 아래는 내부 클래스 형식이다.

```json
{
  "finding": {"id": "F-001", "file": "src/UserDao.java", "startLine": 42, "endLine": 42,
              "ruleId": "SQL_INJECTION_JDBC", "cwe": 89, "severity": "HIGH",
              "message": "...", "tools": ["spotbugs-findsecbugs"]},
  "verdict": {"result": "TRUE_POSITIVE", "confidence": 0.8, "evidenceLines": [38, 42], "reason": "...",
              "explanation": {"summary": "...", "risk": "...", "attackExample": "..."}},
  "fix": {"functionRange": [35, 50], "code": "...", "reason": "...", "verification": null}
}
```

`severity`는 `HIGH`, `MEDIUM`, `LOW`, `cwe`는 숫자로 넘겨 주어야 한다. 대상 CWE 10종 외의 번호는 입력 흐름형 규칙으로 판정한다.
