# llm-server (LLM 서버) — 유환민

Ollama + qwen2.5-coder:7b로 경고 1건을 판정해서 **형식 B**를 돌려주는 서버.

- 만들 API: `POST /internal/judge`, `GET /internal/health` (`docs/api.md` "모듈 간 통신")
- 입력: 형식 A 1건 + `sourceCode`(파일 전체) / 출력: 형식 B
- Ollama 호출 시 `format`에 JSON 스키마를 넣어 출력 형식 강제
- 업로드 코드는 구분자로 감싸 **데이터로만** 넘기기 (프롬프트 인젝션 방지)
- 판정 값은 `TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` / `UNDECIDED` 세 가지만. 그 외는 버리고 `UNDECIDED`
- Ollama 포트(11434)는 이 PC 안에서만 열어둔다

---

## 구현: sr-llm: SecuReview LLM 모듈 (S4~S6, S8 질의응답)

담당: 유환민. Spring 없이 순수 Java 17 모듈로 만들어, 나중에 Spring Boot 골격에 끼워 넣는다.

| 문서 | 내용 |
|---|---|
| [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) | **연결 전에 꼭 읽을 것.** 남은 문제와 고친 결함 |
| [docs/PROGRESS.md](docs/PROGRESS.md) | 전체 작업 정리, 버전별 변경, 그래프 |
| [docs/TEAM_API.md](docs/TEAM_API.md) | 팀원용 호출 방법 |
| [docs/LLM_REPORT.md](docs/LLM_REPORT.md) | 보고서·발표용 측정 결과와 피드백 대응 |
| [CHANGELOG.md](CHANGELOG.md) | 버전별 변경 기록 |
| [docs/eval/](docs/eval/) | 버전별 평가 원본 기록 |

### 구성

| 단계 | 클래스 | 하는 일 |
|---|---|---|
| S4 | `ContextExtractor`, `CFunctionFinder` | 경고 라인을 포함한 함수 전체 추출. 판단할 수 없거나 150줄 초과면 ±30줄 |
| S5 | `VerdictService`, `VerdictBatch` | 판정과 설명. 일괄 판정은 심각도 순서와 시간 제한 적용 |
| S6 | `FixService`, `FixValidator` | TRUE_POSITIVE만 수정안 생성. 사전 검사 후 S7 실패 이유를 받아 재생성 |
| S8 | `QaService` | 선택한 경고에 대한 질문에 답변 |
| 서버 | `LlmServer`, `JudgeService` | API 명세의 내부 API. 형식 A를 받아 형식 B를 돌려줌, 한 건당 30초 제한 |
| 공통 | `OllamaClient`, `StructuredLlm` | Ollama 호출, JSON 스키마 강제, 파싱, 재요청 |
| 측정 | `Eval`, `SpeedBench`, `FixEval` | 판정 정확도, 처리 시간, 수정안 확인 |

프롬프트는 `src/main/resources/prompts/*.txt`에 있다.

`AnalysisFinding`, `JudgeRequest`, `JudgeResponse`는 API 명세 형식이다. `Finding`, `Verdict`, `Fix`는 모듈 내부 형식이다.

### 처음 실행

1. JDK 17과 [Ollama](https://ollama.com)를 설치한다. `JAVA_HOME`은 JDK 17을 가리켜야 한다.
2. 모델을 받는다 (4.7GB). RAM은 8GB 이상을 권장한다.

```bash
ollama pull qwen2.5-coder:7b
```

팀 서버 기준은 Ubuntu 24.04 LTS다(API 명세 "기준 환경"). Ubuntu에서는 `sudo apt install openjdk-17-jdk`로 JDK 17을 설치하고, Ollama는 공식 사이트의 Linux 설치 안내를 따른다. 저장소나 zip이 실행 권한을 잃었으면 `chmod +x mvnw`를 먼저 실행한다.

첫 실행 때는 Maven과 라이브러리를 내려받으므로 인터넷이 필요하다. 처리 시간은 PC 사양에 따라 달라진다.

### 실행

```bash
./mvnw test
```

실제 모델로 데모 실행 (Windows는 `run-demo.cmd` 더블클릭). 인자는 파일, 경고 줄, CWE 번호다. 16번 줄은 위험한 코드, 22번과 26번 줄은 안전한 코드다.

```bash
./mvnw -q compile exec:java "-Dexec.args=examples/UserDao.java 16 89"
```

판정 평가와 속도 측정:

```bash
./mvnw -q compile exec:java "-Dexec.mainClass=secureview.llm.Eval" "-Dexec.args=examples/SqlCases.java 89 1"
```

```bash
./mvnw -q compile exec:java "-Dexec.mainClass=secureview.llm.SpeedBench" "-Dexec.args=examples/Large500.java 89 10 40"
```

LLM 서버 실행 (PowerShell, 호출 방법은 [docs/TEAM_API.md](docs/TEAM_API.md)):

```powershell
$env:SR_INTERNAL_KEY = '비밀값'
./mvnw -q compile exec:java "-Dexec.mainClass=secureview.llm.LlmServer"
```

OpenAI 형식 API(OpenAI, GitHub Models, Ollama `/v1`)로 실행하려면 아래 변수를 더 설정한다. `SR_LLM_API_KEY`는 키가 필요 없는 Ollama에서는 비워 둔다.

```powershell
$env:SR_LLM_PROVIDER = 'openai'
$env:SR_LLM_BASE_URL = 'http://localhost:11434/v1'
$env:SR_LLM_MODEL = 'qwen2.5-coder:7b'
$env:SR_LLM_API_KEY = ''
```

Ollama `/v1`은 요청마다 입력 한도와 모델 유지 시간을 정할 수 없다. 그대로 두면 입력 한도가 4096토큰이라 긴 함수가 잘리고, 5분 동안 요청이 없으면 모델이 내려가 다음 판정이 30초 제한에 걸린다. Ollama를 켜기 전에 아래 두 변수를 설정한다.

```powershell
$env:OLLAMA_CONTEXT_LENGTH = '8192'
$env:OLLAMA_KEEP_ALIVE = '24h'
ollama serve
```

`./mvnw` 명령은 PowerShell과 Bash에서 같다. `-D` 옵션은 전체를 따옴표로 감싸야 한다. 따옴표가 없으면 PowerShell이 옵션을 잘라 `Unknown lifecycle phase` 오류가 난다.

Windows PowerShell에서 한글이 깨지면 먼저 아래 두 줄을 실행한다.

```powershell
chcp 65001
$env:MAVEN_OPTS = '-Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8'
```

### 버전 보기

버전별 변경은 [CHANGELOG.md](CHANGELOG.md)에 있다. 버전별 Git 태그(v0.1.0~v1.1.2)는 원래 개발 저장소 asdf1454/secureview-llm(비공개)에 있고, 이 저장소에는 v1.1.2 내용이 들어 있다.
