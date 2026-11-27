# 외부 API 측정 (groq-bench 워크플로)

- `owasp/warnings-*.csv`: OWASP Benchmark(커밋 a452b3a)에 FindSecBugs 1.14.0을 돌려 얻은 경고. 한 줄에 "테스트,경고 줄,정답(true=진짜)". team-local `docs/benchmark-constant.mjs`로 만들었다.
- `results/owasp-모델.jsonl`: 테스트 한 건에 한 줄. 다시 실행하면 이미 잰 테스트는 건너뛴다.
- `results/owasp-모델.md`: 지금까지의 요약 표.
- `results/large500-모델.md`: 500줄 파일 PR 검토 반복 결과.

채점은 테스트 단위다. 경고가 모두 오탐 추정이면 "걸러짐"이다.
- 오탐 감소 = 안전 테스트 중 걸러진 비율
- 재현율 = 진짜 테스트 중 남은 비율

판정은 PR 검토와 같은 순서(상수 판정 → LLM 묶음 판정)다. 설명과 수정 방향은 정확도와 무관해 만들지 않는다.
무료 한도(429)에 걸리면 Groq가 알려 준 시간만큼 기다리고, 그 시간은 처리 시간에서 뺀다.

멈추려면 Actions → groq-bench → ⋯ → Disable workflow.
