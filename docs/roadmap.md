# 구현 계획과 완료 기준

기준: [Quarkslab 연구](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)의
`graph → recon → slicing → analysis → triage → poc → chain → exploit`.
현재 graph/recon/slicing/analysis/triage/poc/chain/impact의 bounded 첫 버전이 연결되어 있다.
Clang·Go·Solidity·Python 추출, 정적 근거, 원인별 triage, PoC 검토, 격리 worker,
수정 전후 판정, build matrix, chain과 단계별 impact를 합성 fixture에서 검증했다.
이 저장소의 **합성 fixture 기반 첫 버전**의 필수 gate는 모두 실행했다. 마지막 M5에서
같은 최종 도구 조건으로 세 언어의 반복 품질·비용을 비교했지만, 일반적인 우위는 입증되지 않았다.
호출 관계는 실행 조건·데이터 흐름·공격자 노출을 증명하지 않는다.

현재 확인 상태(2026-10-13): 원문의 graph/recon/slicing/analysis/triage/poc/chain/impact에
대응하는 bounded 계약과 fixture 흐름을 연결했고, Go HTTP의 격리된 수정 전후 사례를 실행했다.
recon 제안 입력은 근거 함수의 확인된 호출 상태와 미해결 호출을 byte 예산 안에 포함하고,
제외된 호출을 coverage에 남긴다. 이는 원문의 관계 기반 조사에 가까워진 입력 보강이며
계획의 순위 정확도나 실제 호출 실행을 입증하지 않는다.
두 primitive의 실제 연결·단계별 영향 기록을 현재 검증기로 다시 확인했고, compiler matrix도
새 격리 worker 네 개에서 실제 실행해 두 build case의 독립 판정을 확인했다.
이후 별도로 승인한 최종 M5 평가에서 Go·Python·Solidity의 두 arm을 각각 두 번 실행해
12개 run·6개 pair가 모두 완료됐다. 59회 시도 중 인용 실패 2회는 수정 응답과 함께 보존했다.
Go는 양쪽 모두 양성을 놓쳤고, Python은 graph/recon 2/2·lexical 1/2, Solidity는 양쪽
모두 2/2였다. 음성은 각 arm에서 6/6 통과했다. 호출 수는 graph/recon이 24회,
lexical이 35회였지만 token·시간 이득은 언어별로 엇갈렸다. 결과와 제한은
[실모델 평가 기록](model-evaluation.md)에 있다.

## Go milestone: graph → recon → 관계 기반 입력

원문의 graph를 전부 복제하기 전에 하나의 Go 조사 사례를 끝까지 연결한다.
순서는 **필요한 graph 보강 + M1 → M2 → 다른 언어 → 정적 분석·triage 보강 → 동적 검증**이다.
언어 확장과 audit 흐름 구현을 별도 축으로 관리한다.

### G0.1: 조사에 필요한 근거만 보강

- Go 타입·필드를 포함한 선언, 패키지 전역 값 선언, import 문맥의 위치와 참조 관계를 기록한다.
- 함수 값이 호출 인자로 전달되는 사실을 타입 정보로 기록한다. callback 전달은 실행 간선이 아니다.
- 함수와 선언의 ID·소스 위치를 공통 계약으로 검증한다. 기존 v2와 v1 조회를 유지한다.
- 인터페이스·함수 변수의 구현체, 전역 초기화 실행, reflection과 taint를 추측으로 연결하지 않는다.

### M1: 근거를 가진 조사 계획

- 첫 버전은 연구자가 제공한 가설·출발 함수·보안 주석을 strict JSON 계약으로 입력한다.
  자동으로 전체 threat model을 발견하는 기능으로 표시하지 않는다.
- `recon.json`은 graph identity, source hash, 컴포넌트, 출발점, 원문 근거,
  관련 함수·통제 후보·미해결 호출·외부 호출·조사 순서를 보존한다.
- Go 표준 HTTP handler 등록은 타입으로 식별된 API와 함수 인자에서 근거를 얻는다.
  등록 사실만으로 서버 실행·외부 노출·인증 우회를 확정하지 않는다.
- 주석의 원문 위치를 검증하되 보안 의미는 조사 가설로 유지한다.
  통제 코드의 존재만으로 경로를 안전하다고 분류하거나 탐색을 중단하지 않는다.

### M2: 한 가설의 다중 파일 입력과 실행 연결

- 출발 함수, 명시한 조사 근거, 직접 호출로 연결된 함수, 참조 선언을 순서대로 묶는다.
- 직렬화한 `source_slice`에 고정 byte 예산을 적용한다. prompt·응답·triage 후보를 포함한 총 token 상한은 아니다.
  빠진 함수·선언·호출 근거와 미해결 경계를 기록한다.
- `plan`과 `run`이 같은 입력 생성기를 사용한다. graph/recon 없이 기존 줄 slice도 유지한다.
- analysis·triage에 다중 파일 입력을 제공하고 각 파일·줄·원문 인용을 검증한다.
- cache identity에 graph, recon, 실제 slice를 포함한다. 소스·설정 변경 시 재사용을 거절한다.
- coverage는 제공한 고유 소스 줄과 누락 내역이며 보안 검토 완료·taint 도달 증명이 아니다.

### 이번 milestone 완료 조건

1. Go fixture에서 등록 진입점 → 다른 패키지의 처리 → 민감 연산을 연결한다.
2. 통제 후보가 있는 경로와 없는 경로의 소스를 모두 보존한다. 취약점 확정은 하지 않는다.
3. 타입·필드 정의와 미해결 interface/callback이 조사 입력 또는 명시적 누락 내역에 남는다.
4. 예산 초과, 거짓 인용, 다른 함수의 근거, 변경된 source/config/artifact를 거절하거나 누락으로 기록한다.
5. replay로 분석·triage·후보 대기·추가 호출 없는 재개를 확인한다.
6. 동일 소스 byte 예산의 lexical baseline과 필요한 근거 포함 여부를 비교한다.
   실제 모델 탐지율·비용 개선으로 일반화하지 않는다.

## 전체 단계 상태와 완료 gate

여기서 `완료`는 이 저장소의 bounded 첫 버전과 합성 fixture 완료를 뜻한다. 운영 대상에서의
취약점 발견률이나 영향 증명까지 일반화하지 않는다.

| 단계 | 상태 | 현재 근거 | 남은 한계 |
| --- | --- | --- | --- |
| G0/G1 graph | 완료 | 공통 graph v2와 Clang·Go·Solidity·Python 추출; 파일/패키지 호출, 상속·modifier, import와 미해결 관계 검사 | 동적 binding·reflection·프록시/배포 관계는 미해결로 보존 |
| M1/Q1/R1 recon | 완료 | 연구자 가설, 등록/visibility/정적 역할과 제한된 graph/source 질의를 source identity에 결합 | 전체 자동 threat model과 계획 우선순위 품질 평가는 범위 밖 |
| M2 slicing | 완료 | 동일 입력 생성기의 bounded 다중 파일 slice, 누락·예산·cache identity 검사 | 제공 범위를 넘어선 실행·데이터 흐름은 추론하지 않음 |
| A1/A2 analysis | 완료 | 호출 근거와 Semgrep role/taint 분리, source-backed 함수 모델과 한 차례 두 번째 정적 분석 | 타 언어 정적 모델과 함수 간 taint는 선택적 확장 |
| T1 triage | 완료 | 원인·수정 가설별 그룹과 후보별 기각·불확실·반증·입력 gap 보존 | 의미 정확도는 M5 실모델 평가 대상 |
| M3/P1 validation | 완료 | 별도 검토된 PoC 자료, digest-pinned 격리 worker, 실패/timeout/cleanup, 설정별 build matrix | 운영 대상별 harness·oracle 품질은 별도 연구자 검토 필요 |
| M4 judgment | 완료 | 실행 성공과 재현 구분, 실제 진입점 관찰, 동일 case 수정 전후와 열린 근거 판정 | 합성 결과를 외부 대상의 안전성으로 승격하지 않음 |
| C1 chain | 완료 | 두 validated primitive의 원본 증거 재검산, 연구자 검토와 실제 격리 연결·음성 대조군 | 운영 대상의 인과관계는 별도 계측 필요 |
| I1 impact | 완료 | source/PoC/review에 묶인 단계별 checkpoint와 속성 oracle로 합성 영향 관찰 | 운영 공격 자동화나 일반적인 exploitability 주장이 아님 |
| M5 benchmark | 완료: 반복 측정 | 동일 snapshot/라벨/상한의 Go·Python·Solidity 각 2개 완료 pair, 원본 시도·token·시간·실패 보존 | 작은 합성 사례에서 일반적인 품질·비용 우위는 입증되지 않음 |

완료 근거는 아래 단계별 기록과 [실모델 평가 기록](model-evaluation.md)에 있다. 핵심 실행
산출물은 compiler matrix의 `runs/matrix-docker.pWXauy/`, chain/impact의
`runs/chain-impact-docker-20261013/`, Go HTTP의 `runs/go-http-demo.5mJ4az/`다.
M5의 최종 승인 실험은 `runs/model-eval-prospective.yEMrOO/`에 있고 세부 결과는
[실모델 평가 기록](model-evaluation.md)에 있다.

이 상태표는 [원문 연구](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)와
동등한 실전 성과를 뜻하지 않는다. 원문은 대규모 C 대상에서 자동 recon으로 304개 slice를
만들고, 알려진 모델과 agent 제안 모델의 두 차례 taint 분석, ASan과 실제 진입 경로의 PoC,
두 primitive의 연결 및 연구자 개입을 거친 RCE까지 보고했다. 여기서는 자동 threat model과
순위 품질, C/C++의 두 차례 taint, 운영 대상의 계측·PoC 정확도, 연구자 검토 시간 절감을
검증하지 않았다. 준비한 M5 실험도 언어당 합성 양성·음성 하나를 두 번 비교하는 범위다.
따라서 M5의 반복 측정 완료는 이 첫 버전의 비교 근거가 갖춰졌다는 뜻이며, 원문 규모나
실제 대상의 탐지율·효율·영향까지 입증하는 것은 아니다.

graph·recon·slice의 사실 생성은 재현 가능하게, agent 판단은 근거와 함께 검토 가능하게 만든다.
기존 parser/analyzer를 활용하며 별도 범용 taint 엔진·graph DB·agent framework는 구현하지 않는다.
실제 감사와 유료 모델 실행은 개발 fixture 검증과 별도다. chain/impact는 아래 후속 단계에서
검증된 근거와 연구자 점검을 가진 harness 기능으로 구현하며, 자동 운영 공격 실행을 의미하지 않는다.


## 검증 기록 — 2026-10-11

Go G0.1·M1·M2 첫 버전의 위 여섯 완료 조건을 fixture와 replay로 확인했다.

- `make check`: Ruff lint/format 통과, 69개 테스트 통과. Go helper와 fixture의 `gofmt` 변경 없음.
- `make demo`: 기존 줄 입력 분석·triage와 재개 유지, 재개 시 4개 응답 재사용.
- `make demo-review`: 4개 패키지·5개 소스 파일에서 함수 9개, 호출 위치 19개,
  선언 문맥 9개를 추출하고 3개 조사 가설을 연결했다. 함수 없는 타입 패키지도 컴포넌트에 남는다.
- 관계 기반 입력은 각각 9,766 / 11,825 / 9,944 byte로 16,000 byte 한도 안에 들었고,
  interface/callback의 미해결 호출 2개를 유지했다. replay 분석·triage 6회 후 재개는
  추가 호출 없이 응답 6개를 재사용했다.
- 동일 예산의 lexical 첫 slice와 필요한 다중 파일 근거 포함 여부를 테스트로 비교했다.
  예산 누락, 잘못된 원문/함수 위치, Unicode 문자와 물리적 줄 구분, source/config/artifact 변경도 검증했다.
- wheel을 offline으로 빌드·설치한 별도 경로에서 패키지에 포함된 Go helper·schema·prompt를 사용해
  graph → recon → analysis/triage → resume를 확인했다. 배포 파일에 cache/run 산출물이 없음을 확인했다.

확인 범위는 로컬 macOS/arm64와 예제 저장소다. 실제 모델 호출, 탐지율·token 비용 비교,
동적 재현, 원격 CI는 실행하지 않았다. replay의 판정은 기록된 응답이며 취약점 입증이 아니다.
이 기록 이후 Solidity와 Python 추출기 및 공통 recon 연결을 구현했다.


## G1 Solidity 완료 범위

- 기존 공통 v2 schema 유지, 기존 Clang/Go/v1 조회 유지.
- solc-js 0.8.30 AST의 선언 ID·타입 정보와 byte 위치에서 함수/modifier·context를 추출.
- base/C3 순서·override 근거, modifier 적용 순서/placeholder·본문 호출을 보존.
- modifier의 symbolic CFG를 기존 metadata로 보존: 조건·전후 실행·생략/반복·중첩·return/revert·loop.
- graph 조회/보고서와 bounded agent slice에 flow 제공; 누락/미해결/상한 초과를 명시.
- 비가상 내부·상속·internal library 호출을 파일/scope 간 연결.
- 외부 interface/contract/self/library 호출은 선언 ID만 보존하고 내부 도달 탐색에서 제외.
- virtual/super·함수 값·저수준 호출·assembly는 사유를 가진 미해결 경계로 유지.
- 공통 recon → 다중 파일 slice → replay triage → resume 연결을 테스트로 확인.

첫 버전은 0.8.30과 호환되는 pragma 및 입력된 소스만 지원한다. remapping·프로젝트 build 설정,
자동 Solidity 노출 recon, 배포 binding·EVM 검증은 후속 작업이다. compiler 오류 시 batch 전체를 제외한다.


Solidity 검증 기록 (2026-10-11): `make check`의 전체 80개 테스트 통과(신규 Solidity 11개),
Ruff lint/format 통과. 기존 replay·Go demo-review와 Solidity demo 모두 실행했다.
Solidity fixture의 4개 파일에서 함수/modifier 13개, 호출/적용 15개, context 13개를 추출했다.
Node preload·대상 script 미실행, 외부 import 차단, 오류 batch 제외와 다중 상속/alias/overload/
virtual/super/외부·저수준 호출/함수 값/UTF-8 위치를 검증했다.
설치된 wheel에서도 graph → recon → slice → replay triage → resume를 실행했다.
조사 입력은 11,638 byte였고 재개는 추가 호출 없이 응답 2개를 재사용했다.
package/lock 기반 compiler 준비 명령을 npm cache로 offline 재실행했으며,
배포 wheel에 helper 3개 파일이 포함되고 node_modules/cache/run이 제외된 것을 확인했다.
기존 공통 graph schema는 이전 wheel과 byte 단위로 동일하다.
실제 모델·EVM 실행·원격 CI는 검증하지 않았다.

Modifier flow 보강 완료 기준:
- 공통 schema 유지와 이전 artifact 호환, CFG endpoint·소스/호출 참조·적용 순서 검증.
- 정상 body 생략, 2회/4회 반복, modifier 순서를 바꾼 전후 실행, 안쪽 modifier 및 body return 후 복귀.
- if/else·require/assert·revert, loop/break/continue와 구조상 무상한 반복을 별도로 검증.
- virtual·opaque expression/assembly와 확장 예산 초과에서 안전 판정이나 횟수를 꾸며내지 않음.
- 동일 입력 graph 재현, 원문 동반 slice와 byte 예산에 따른 flow 누락, replay/resume 회귀 검증.
실행 경로 만족 여부·인자/상태 흐름·modifier의 실제 통제 효과와 EVM 검증은 후속 단계다.

Modifier flow 검증 기록 (2026-10-11): 전체 `make check` 100개 통과(추가 20개),
Solidity 관련 31개 통과, Ruff lint/format 통과. `make demo`, `make demo-review`의
replay/resume와 확장된 `make demo-solidity` 모두 실행했다. modifier fixture의 2개 파일에서
36개 함수/modifier와 59개 호출/적용을 추출했다. 공통 graph schema는 변경하지 않았다.
기존 Solidity replay는 모든 호출과 flow를 포함하도록 명시적인 24,000 byte 입력에서 검증했다.
기본 16,000 byte 제한은 유지하며 부족한 호출·flow는 coverage에 기록하는 경로도 검증했다.
실제 모델·EVM 실행·원격 CI는 이번에도 검증하지 않았다.


## G1 Python 완료 범위

- 공통 graph v2 schema 유지; CLI의 `--language python` 및 단일 언어 자동 감지 추가.
- 표준 AST의 위치·선언·lexical/import binding에서 함수·메서드·중첩/async 함수와 호출을 추출.
- 여러 파일/모듈, import 별칭·상대 경로·재수출·재귀 및 `src/`/namespace layout을 연결.
- 호출과 import 근거를 구분: 재수출의 중간 `__init__.py`를 context 참조로 분석 입력에 포함.
- 콜백/객체 메서드/계산된 callable은 미해결, 중복 binding/경로는 ambiguous, 외부는 external.
- 조건부 선언/import·decorator·wildcard·재대입·정의 시점 대입·직접 attribute/global/nonlocal
  쓰기를 보수적으로 처리하며 이유와 `callee=null`을 유지.
- 파일·모듈 조회, 실패한 로컬 모듈/순환 import·UTF-8/CRLF 위치·동일 입력 재현을 테스트로 확인.
- 격리된 `python -I`에 소스 JSON만 전달: 대상/import/setup/config/PYTHONPATH 미실행,
  기존 timeout/output cap과 파일/AST 크기 상한 유지.
- 공통 recon → 다중 파일 slice → replay triage → resume를 추가 의존성 없이 검증.

Python 검증 기록 (2026-10-11): `make check`의 전체 **117개 테스트 통과**(Python 신규 17개),
Ruff lint/format 통과. `make demo-python`에서 5개 파일의 함수 7개·호출 12개를 추출했다.
확정 호출 7개, 미해결 4개, 외부 1개이며 파일/모듈 간 연결은 각각 5개다.
공통 graph schema는 변경하지 않았다. 기본 16,000 byte에서 재수출 근거와 미해결 호출을
포함한 slice 및 replay/resume(2회 응답 재사용)를 검증했다.
import root는 대상의 `.`과 `src/`로 한정하며 `configuration_verified=false`다.
module/class 초기화·정의 시점 호출·lambda 본문, 동적 import/메서드/상속/descriptor의 런타임
대상 해석은 후속 범위다. 실제 모델·동적 재현·원격 CI는 실행하지 않았다.

2026-10-13 자체 소스 규모 점검: `src`를 import root로 지정해 이 저장소의 Python
33개 파일·12,275행을 실행 없이 파싱했다. 로컬 한 번의 CLI 실행은 0.74초였고 함수
221개, 호출 위치 5,216개, 확정 호출 938개, 파일 간 간선 86개를 기록했다.
`extractors/go_helper/main.go`가 미지원 언어로 남아 전체 coverage는 `partial`이다.
패키지 디렉터리 `src/agent_audit_harness`를 잘못 root로 지정하면 `__init__.py`가
실패하고 파일 간 간선이 6개로 줄어드는 것을 확인해, 이 입력은 graph 생성 전에
명시적으로 거절하도록 했다. 올바른 부모 root는 같은 소스에서 간선 86개를 만든다.
이는 작은 로컬 Python 사례의 설정·규모 점검이며 원문의 대규모 C 대상 성능 근거는 아니다.
이후 A1과 T1의 첫 근거 연동·원인 기준 triage를 구현했다. 다음 구현 축은 M3의 격리 검증 worker이며
자동 노출 adapter와 더 넓은 데이터 흐름 분석도 남아 있다.

## A1 정적 분석 연동 완료 범위

- Semgrep CE 1.180.0의 native core, wheel/hash lock, 대상 config 없는 filtered snapshot 분석.
- 공통 graph v2 schema 유지; 별도 `static.json` v1로 graph/source·엔진/runtime·rule identity 결합.
- source/sink/sanitizer의 패턴 관찰과 실제 엔진 taint 결과 분리; 선언한 모델/가정 보존.
- source·sink·중간 변수의 원문·byte/줄 위치·source hash·함수·호출 참조 검증.
- 함수/파일 간 호출, unknown callback, 없는 trace·parse/timeout/스캔 누락을 gap으로 기록.
- graph/recon 입력에 원문과 함께 정적 결과 첨부; byte 예산 누락 및 checkpoint identity 유지.
- Python/Go 실제 taint, 상수 음성 대조군, 모델 sanitizer와 위 실패 경계, replay/resume 검증.

첫 모델은 Python `input → os.system`과 Go `os.Getenv → exec.Command("sh", "-c", ...)`이다.
함수 내부 보고만 소비하며 구조 호출을 taint 연결로 합성하지 않는다. sanitizer는 모델의 가정이고
미해결 호출을 통한 보수적 전파는 partial이다. taint 보고가 runtime binding·노출·취약점 확정을
의미하지 않는다. Solidity/C++ adapter, 함수 간 분석·통제의 효과 입증·실모델 평가는 후속 범위다.
원문의 결정적인 분석 코어를 agent에 공급하는 단계에 해당하며 전체 감사 흐름의 완성은 아니다.

A1 검증 기록 (2026-10-11): `make check` **144개 통과**(정적 분석 신규 27개),
Ruff lint/format 통과. `make setup-static`을 준비된 캐시에서 offline으로 다시 실행했다.
`make demo`의 기존 replay/resume와 `make demo-static`의 실제 CE → replay/resume를 확인했다.
정적 fixture에서 역할 관찰 8개·taint 보고 2개·분석 경계 2개를 보존했고,
재개는 새 agent 호출 없이 응답 2개를 재사용했다. graph v2 schema는 변경하지 않았다.
CI에 엔진 준비와 demo를 연결했지만 원격 CI는 실행하지 않았다. 확인 환경은 로컬 macOS/arm64다.
대상 프로그램·실모델·동적 worker는 실행하지 않았다.

## T1 원인 기준 triage·반증 정리 완료 범위 — 2026-10-12

- 기존 slice별 triage 호출에 공통 원인 invariant/통제 근거와 수정 strategy/수정 위치를 추가했다.
  agent가 제안한 원인과 수정은 가설이며 harness가 보안 의미를 확정하지 않는다.
- 원인·수정·반증·근거가 있는 보류 주장의 원문/줄/UTF-8 byte column을 검증하고 source hash를 붙인다.
  후보 ID가 빠지거나 중복/외부 ID가 있으면 거절하며 유효한 응답만 checkpoint에 저장한다.
- 모든 slice를 처리한 뒤 원인 label, 통제 인용/hash, 수정 전략과 수정 인용/hash가 일치할 때만
  `clusters.json`으로 병합한다. CWE/name/sink만 같으면 합치지 않는다. 추가 모델 호출은 없다.
- `root_cause=null`은 단독 그룹이다. 기각에는 원문 반증, 불확실에는 미해결 주장을 요구한다.
  자료가 없으면 evidence=null로 남긴다. 그룹은 mixed 판정을 허용하고 모든 개별 결과를 보존한다.
- `findings.json`에는 반증/보류 주장과 harness가 보존한 `input_gaps`를 남긴다.
  전체 recon의 unknown/external call·unlinked annotation, 선택한 static gap·modifier gap,
  slice 누락 수와 coverage 참조는 agent 응답으로 지워지지 않는다. 원본 artifact도 run에 저장한다.
- 기각 후보는 대기열에서만 제외하며 전체 findings와 cluster 회원에는 남는다.
  생성 결과/그룹 ID의 재개 결정성과 실패 시 오래된 clusters 제거를 검증했다.

검증: `make check` **181개 통과**(이 단계 신규 37개), Ruff lint/format 통과.
`make demo`, `make demo-review`, `make demo-static` 및 각각 4/6/2개 응답의 재사용을 확인했다.
Go의 3개 후보는 2개 그룹으로 묶였다. 공통 executor/수정 지점을 가진 그룹의 needs_validation과
rejected를 각각 유지하고, 기각 반증 2개와 별도 uncertain 후보의 unknown call 2개를 보존했다.
Python의 byte 제한으로 빠진 callback static gap, Solidity의 미제공 modifier gap도 원본 참조로 유지했다.
공통 graph v2는 변경하지 않았고 대상 프로그램·실모델·동적 worker·원격 CI는 실행하지 않았다.

이전 `decisions` triage 응답/실행은 새 계약과 호환되지 않으며 새 출력 디렉터리가 필요하다.
정확한 label/인용 일치가 필요한 보수적 병합이므로 표현이 다른 동일 원인은 남을 수 있다.
전역 의미 triage/순위 평가와 원인·반증의 효과 입증은 실모델 benchmark 및 동적 증거가 필요하다.
이후 M3의 폐기 가능한 격리 validation worker 첫 버전을 구현했다.

## M3 격리 validation worker 완료 범위 — 2026-10-12

- 완료된 review 대기열의 한 후보와 대상 밖의 strict recipe를 연결했다. 모델의 계획 설명을
  자동 실행하지 않으며 호스트에서는 신뢰한 Docker 제어 코드와 폐기 타이머만 실행한다.
- 후보 원문·review/source hash를 확인한 명시적 파일 snapshot, 준비된 immutable image ID,
  recipe/schema/worker identity와 원래 반증·미해결 근거를 보존한다.
- 실행 전에 실제 Docker 정책을 검증한다. 외부 network·host credential·홈/socket 전달 차단,
  비특권 UID·capability 제거·기본 seccomp·읽기 전용 입력/root와 제한된 tmpfs를 사용한다.
- CPU·메모리/swap·PID·scratch·wall time·stdout/stderr 상한을 강제한다.
  nonzero/OOM/timeout/output limit·Docker/제거 실패와 미확인 실행 상태를 구분한다.
- 정상·실패·중단 시 컨테이너를 제거한다. controller 강제 종료에도 독립 타이머가 해당 job만
  제거하고 별도 기록을 남긴다. Docker가 없거나 정책을 적용하지 못하면 호스트 대체 실행 없이 실패한다.
- CLI·schema·예제·offline 정책 테스트와 실제 Docker integration 테스트를 함께 추가했다.
  결과는 별도 artifact이며 공통 graph 계약, triage와 `confirmed_findings=0`을 유지한다.

실제 Docker의 9개 테스트에서 credential 미주입·외부 연결 차단·읽기 전용 입력/root,
CPU/RAM/PID 설정, 실제 OOM·fork/scratch 한도, nonzero·timeout·로그 초과와 증거 hash를 확인했다.
controller를 SIGKILL한 사례에서도 컨테이너가 제거되고 미확인 최종 상태가 보존됐다.
준비된 로컬 Debian bookworm-slim만 사용했으며 이미지 pull이나 실제 대상 감사는 수행하지 않았다.

검증: `make check` Ruff lint/format 통과, **253개 통과·9개 Docker test skip**.
위 opt-in 실제 Docker 테스트는 별도 실행하여 **9개 모두 통과**했다.
`make demo`는 기존 응답 4개를 재사용했고 `make demo-validation`은 replay 후보를 실제 worker에서
실행해 `completed`, exit 0, cleanup `removed`와 containment 로그를 남겼다.
확인 환경은 로컬 macOS/arm64·Linux Docker 28.3.2·cgroup v2다. 원격 CI와 실모델은 실행하지 않았다.

이후 재현 oracle·entry point 관찰·수정 전후 비교와 검토 가능한 승격 기준의 M4 첫 버전을 구현했다.
언어별 build/sanitizer matrix와 배포/영향 검증은 남아 있다. 임의 exit 0을 취약점 입증으로 취급하지 않는다.
Docker daemon/kernel/image 신뢰 경계, 텍스트 파일 입력 제한과 secret 자동 정제 부재는 남는다.

## M4 validation 판정·승격 기준 완료 범위 — 2026-10-12

- 선택적인 oracle을 기존 recipe v1에 추가했다. 기존 graph/triage 계약과 oracle 없는 recipe는 유지한다.
  source 원문·별도 검증 코드·실제 요청 invocation을 확인하고 관찰 조건을 실행 전에 hash에 고정한다.
- `judge`는 worker result/파일 hash·source manifest·실제 정책·종료 상태를 재검사한다.
  코드를 실행하거나 모델을 호출하지 않는다. 실패·미완성/상충/변조 결과를 보류/실패로 보존한다.
- 실행 성공, 명시적 음성, 재현, 불확실, validated를 구분한다. 관찰은 stream/완전한 줄의
  정확한 일치·유일성·entry → outcome → completion 순서에 근거한다. 직접 호출/정적 간선은 진입점 증명이 아니다.
- 동일 review/후보·검증 코드/입력/oracle/명령·자원/image/worker/engine에서 source 복사본만 바꾼다.
  before/after hash·원본·실제 실행 소스를 보존하고 명시적 수정 후 음성과 진입점 도달을 요구한다.
- 기존 불확실·반증·unknown/external/static/modifier gap·입력 누락을 issue ID로 유지한다.
  predeclared resolution의 요구 단계가 통과해야 해소되고 원래 근거·이유·관찰 참조는 남는다.
  연결되지 않은 issue는 모든 실행이 성공해도 승격을 막는다.
- 위 gate가 모두 통과하면 별도 judgment에서 validated/eligible을 기록한다.
  원래 후보·cluster·worker·analysis metrics를 바꾸지 않으며 전체 서비스 안전이나 배포 영향을 주장하지 않는다.

예제는 정상 CLI dispatcher로 guest 요청을 보내고 private-record 응답을 관찰한다.
같은 검증 코드로 source 복사본의 authorization을 수정하면 진입점 도달 후 DENIED를 관찰한다.
기존 미해결 주장 두 개는 각각 진입점·수정 비교 근거로 해소하며 전체 주장도 보존한다.
oracle/harness와 resolution의 의미는 연구자가 검토한다. 자동 계측, 운영 배포 진입점,
전체 입력에 대한 수정 완전성, exploit 영향과 실모델 benchmark는 후속 범위다.

검증: `make check` Ruff lint/format 통과, **326개 통과·11개 실제 Docker test skip**.
신규 판정 계약 테스트 73개와 별도 실제 Docker **11개 통과**(기존 worker 9개 + 판정 2개).
마지막 판정 변경 후 실제 판정 2개를 다시 통과했다. `make demo`는 기존 응답 4개를 재사용했다.
`make demo-judgment`에서 수정 전 guest의 DATA 응답과 수정 후 DENIED를 관찰하고,
진입점/수정 비교로 미해결 2개를 해소해 validated/eligible을 기록했다.
이전 containment worker 기록은 별도 `judge`에서 execution_only/승격 불가로 확인했다.
원본 source·기존 triage·worker 결과는 유지했고 결과/증거/판정 코드 hash와 issue별 관찰 참조를 검증했다.
확인 환경은 로컬 macOS/arm64·Linux Docker 28.3.2다. 실모델·운영 대상 감사·원격 CI는 실행하지 않았다.

## Go HTTP 단일 사례 연결 — 2026-10-12

`examples/go-http-target`에서 `/private`의 등록과 handler → service → store 호출을
Go 그래프로 추출한다. 연구자가 제공한 가설을 recon에 묶고 다중 파일 slice를 replay
분석·triage에 전달한다. 구조적 근거만으로는 후보를 `uncertain`으로 유지하며 표준 라이브러리
외부 호출 두 개와 실제 요청·수정 확인 필요성을 각각 issue로 보존한다.

같은 review의 후보에 대해 worker가 정상 Go 서버를 격리된 컨테이너에서 빌드·기동한다.
네트워크는 차단하고 컨테이너 내부 loopback의 실제 HTTP GET만 사용한다. 수정 전 guest 요청은
`HTTP 200`·`DATA private-record`, handler 내부 진입 표시를 관찰했다. 같은 검증 코드와 설정으로
handler 복사본만 바꾼 수정 후에는 `HTTP 403`·`DENIED`를 관찰했다. source, 응답, 로그의
해시는 worker와 별도 판정 기록에 남는다. 각 issue의 해소 이유는 이 요청에 대한 관찰로만 한정한다.
`judge`는 재현·진입점·비교·명시된 issue 해소를 통과한 이 사례를 `validated`로 기록했다.

이 예제는 분리되어 있던 graph/review와 worker/judgment의 연결을 검증한다. 가설·replay 응답·
검증 코드·oracle·수정 내용은 여전히 사람이 제공한다. 운영 서비스 노출이나 범용 자동 탐지율,
다른 입력에 대한 수정 효과는 입증하지 않는다.

검증: `make check`는 Ruff와 offline 테스트 **329개 통과·실제 Docker 13개 skip**,
`make demo`는 기존 replay 응답 4개를 재사용했다. Go HTTP 전용 테스트는 준비된 Go 이미지로
**5개 통과**(그래프·recipe의 offline 3개, 실제 Docker 2개). `make demo-go-http`도
수정 전후 worker 모두 정상 종료·컨테이너 제거 후 `validated/eligible`을 확인했다.
별도 실제 Docker 실패 사례에서는 `/missing`이 404를 돌려 handler 진입 근거가 없으므로
승격되지 않았다. 결과는 로컬 macOS/arm64와 Linux Docker 엔진에서 얻었다.

## 연구와의 차이 및 다음 완료 기준 — 2026-10-12

현재 단계별 계약은 연결되어 있지만 가설·replay·검증 코드·수정 내용은 사람이 제공한다.
agent의 제한된 근거 조회와 대상 고유 함수 모델을 반영한 두 번째 taint 분석을 구현했다.
등록/정적 역할에 근거한 조사 계획 제안과 외부 후보의 독립 검증 진입도 연결했다.
PoC 코드 제안·연구자 검토·설정별 build 비교, 검증된 primitive의 연결·영향 측정은 아직 필요하다. 첫 버전의 테스트 통과를
전체 workflow 완성 또는 실제 모델의 탐지 성능으로 해석하지 않는다.

| 순서 | 작업 | 확인할 결과 |
| --- | --- | --- |
| H1 | 판정 입력과 build 문맥 보강 | 대상 로그/응답이 oracle 줄로 소비되지 않음; admin 성공 대조군; 검토 graph/config 불일치의 사전 거절 |
| Q1 | agent의 제한된 추가 조사 | agent가 resolve/reachable/원문 조회를 구조화해 요청; core만 처리; 조회/byte/call 예산과 원문·미해결·실패 기록; checkpoint 재사용 |
| A2 | 대상 고유 분석 모델 제안과 재분석 | agent의 source/sink 제안에 원문 근거·제한된 모델 계약을 요구; 고정 CE로 두 번째 분석; 첫 결과와 새 결과·gap 보존; 임의 rule/code 실행 금지 |
| R1 | 근거를 가진 recon 확장 | 발견한 등록·입력 경계로 계획을 제안; 노출/통제는 가설로 유지; 누락과 조사 순위 근거 기록; 연구자 계획도 그대로 입력 가능 |
| P1 | PoC 제안·독립 단계 진입과 build 비교 | 가져온 후보도 source/triage/oracle 계약으로 연결; 검증 코드 제안과 연구자 검토를 기록; 적용된 설정별 격리 실행·실제 진입·음성 대조군 비교 |
| C1 | 검증된 후보의 연결 가설 | validated artifact만 입력; 두 primitive의 순서·상태·전제·미해결 근거 기록; 독립 재현과 연결 재현 구분 |
| I1 | 영향 검증의 단계별 기록 | 측정할 속성·실험·성공/실패 gate와 연구자 점검을 고정; 합성 fixture에서 관찰로 gate를 통과; 개별 재현을 실제 영향으로 자동 승격하지 않음 |
| M5 | 효율과 품질 평가 | 동일 사례/예산의 baseline 비교 실행기와 결과; tokens·시간·누락·판정 지표; replay 값과 실제 모델 측정 구분; 측정한 병목에만 병렬화 |

원문의 `graph → recon → slicing → analysis → triage → poc → chain → exploit` 전체 흐름을
위 단계로 유지한다. 연구자 점검은 artifact에 연결하고 단계별로 시작·중단·재개할 수 있어야 한다.
추가 언어와 범용 framework보다 Q1/A2/R1의 조사·분석 loop를 먼저 구체화했다. 다음 순서는 P1이다.

H1 구현 범위:
- 두 supplied harness에서 출력과 판정 신호를 구분하고 전체 응답의 정확한 일치를 검사한다.
  admin 요청이 정상 동작해야 guest 요청 결과를 판정한다. CLI 원래 bytes/base64와 Go 응답의
  인용 escape를 보존하고, 대상 출력 속 판정·진입·완료 문자열은 해당 관찰을 대신하지 않는다.
- graph가 있는 review는 보존된 graph를 schema/hash/target/source index로 검사하고
  `input_config` 해시를 실제 설정과 비교한다. recipe 갱신이나 설정의 recipe 제외로 우회하지 않는다.
  graph 없는 기존 lexical review와 기존 oracle 계약은 유지한다.
- config 변경·review graph 누락/변조·위조 문자열·NUL·모든 요청 차단 수정과 정상 사례를 검증한다.
  임의 harness의 계측 의미, 운영 인증, 모든 입력과 build 설정의 수정 완전성은 별도 검증이다.

H1 검증: `make check` Ruff lint/format 통과, **336개 통과·실제 Docker 18개 skip**.
`tests/test_go_http.py`와 `tests/test_judgment_docker.py`는 준비된 로컬 Go/Debian 이미지로
**19개 통과**(offline 10개, 실제 Docker 9개). config 실패는 Docker 제어 호출 없이 기록됐다.
실제 실행에서 위조 판정/진입/완료 문자열, NUL 응답과 모든 요청 차단 수정이 승격되지 않았고,
정상 수정은 guest 거절·admin 성공을 관찰했다. source 원본과 기존 후보 판정은 보존됐다.
`make demo`는 응답 4개를 재사용했다. image pull·운영 대상 감사·유료 모델·원격 CI는 실행하지 않았다.
`make demo-go-http`와 `make demo-judgment`의 새 실행도 수정 전후 worker가 모두 완료·폐기되고
`validated/eligible`을 기록했다. 로컬 기록은 각각 `runs/go-http-demo.pnb0Um`과
`runs/judgment-demo.UWjApb`다. 이 판정은 supplied fixture의 guest/admin 요청에 한정한다.

## Q1 제한된 추가 조사 구현 — 2026-10-12

- 공통 graph v2 유지. analysis에 선택적인 strict requests를 추가해 기존 candidates 응답도 받는다.
  resolve/reachable/source만 허용하며 제공된 원문만 후보·원인·수정·반증 인용에 사용할 수 있다.
- 검증된 in-memory graph/source를 조회한다. source는 200개 물리적 줄까지, 구조 조회는
  정의·호출 위치의 원문을 함께 제공한다. 조회가 taint·노출·실행 증명으로 바뀌지 않는다.
- 기본 slice당 조회 4회/제공 payload 16,000 byte, 상한 32회/65,536 byte. 실패한 조회도 횟수를
  소비하고, 답변이 크면 전체를 생략하며 원문을 임의로 자르지 않는다. 기본 slice와 bookkeeping은
  별도이며 전체 token 예산은 아니다. 추가 analysis는 global call cap과 기존 timeout을 적용한다.
- 원래 slice와 query checkpoint·누적 응답·예산·coverage를 함께 보존한다. query 실패/누락과
  추가 호출의 미해결·외부 관계는 input gaps로 triage/judgment에 남긴다. 초기 누락은 지우지 않는다.
- cache identity는 소스·graph·prompt/schema·provider/model과 조회 코드·예산을 포함한다.
  성공 응답/조회는 재사용하고 실제 시도별 raw response·오류 기록은 재시도에도 보존한다.

Go HTTP 예제의 초기 handler slice에 없던 `cmd/server/main.go`와 listener/Serve 근거를 조회한다.
없는 Authenticate selector는 unavailable로 남겨 후보를 uncertain으로 유지한다. 이는 기록된
replay 응답으로 조사 절차를 검증한 것이며 agent의 자동 발견 성능을 증명하지 않는다.
다음 단계는 A2의 source-backed 대상 고유 모델 제안과 두 번째 정적 분석이다.

Q1 검증: `make check` Ruff lint/format 통과, **352개 통과·실제 Docker 18개 skip**.
추가 조사 신규 테스트 **16개 통과**: 다중 파일 원문/typed graph·미해결 dispatch·ambiguous selector,
UTF-8 누적 byte/조회/call 한도, 제외된 파일/대상 미실행, 인용 범위, cache 변조·재개,
timeout과 시도별 실패 기록, triage/judgment의 query gap 보존을 확인했다.
`make demo-investigation`은 24,000 byte 예산에서 4개 요청 중 3개 근거를 제공하고
없는 selector 1개를 보존했다. 제공 payload는 16,979 byte였고 재개는 agent 응답 3개와
query checkpoint 1개를 추가 실행 없이 재사용했다. 기록은 `runs/investigation-demo.XktJ4G`다.
`make demo`의 기존 분석/triage도 재개에서 응답 4개를 재사용했다.

제공된 원문의 외부 호출을 모두 보존하면서 기존 Go HTTP 후보에 ServeMux 등록 API의 gap이
추가됐다. 이 API의 일반적인 안전을 주장하지 않고, 해당 guest 요청이 등록 handler에 도달한
관찰로만 해소하도록 두 frozen recipe를 보강했다. 준비된 로컬 Go 이미지의
`tests/test_go_http.py` **14개 통과**(offline 10개, 실제 Docker 4개)로 정상 전후 비교와
위조 문자열·wrong route·deny-all 차단을 다시 확인했다. 실제 모델·운영 감사·원격 CI는 실행하지 않았다.

Q1 검수 보강 — 2026-10-12:
- 초기 가설 밖의 함수를 resolve/reachable로 읽으면 static gap이 빠지고, source로 읽으면
  미해결 호출·static/modifier gap이 빠지는 사례를 회귀 테스트에서 먼저 재현했다.
- 추가 조회는 제공된 줄과 겹치는 함수의 ID, 요청한 줄의 호출 사실과 알려진 gap 참조를
  byte 예산 안에서 전달한다. 부분 원문도 해당 함수의 알려진 한계를 지우지 않는다.
  원문 밖 참조를 인용 가능한 소스·전체 함수 검토·taint 연결로 취급하지 않는다.
- triage는 초기 가설과 추가 함수의 gap을 합치고 judgment의 미해결 issue로 보존한다.
  초기 slice와 누락 기록은 유지하며 재개 identity에 gap 선택 코드도 포함한다.
- Go 조사 예제의 명시적 예산은 근거 증가에 맞춰 32,000 byte로 조정했다. 기본값은 16,000 byte다.
  24,000 byte에서는 세 번째 조회를 전체 생략하고 추가 query gap을 보존하는 경로도 검증한다.
- Python dynamic sink의 한 줄 조회를 기록한 replay를 추가하고 `make demo-static`에 연결했다.
  Solidity 부분 원문의 modifier gap과 Go 원문 조회의 unknown dispatch도 공통 계약으로 확인한다.

보강 검증: `make check` Ruff lint/format 통과, **359개 통과·실제 Docker 18개 skip**.
신규 회귀 7개에서 세 조회 방식의 static/dispatch gap, 부분 Solidity 원문의 modifier gap,
agent prompt·후보·재개 보존 및 static/modifier 미해결 issue의 승격 차단을 확인했다.
기존 Go 조회 테스트도 원문 조회와 24,000 byte 전체 생략 사례를 보강했다.
`make demo`, `make demo-investigation`, `make demo-static` 모두 통과했다.
Go 예제는 32,000 byte 중 24,832 byte를 제공하고 없는 selector 1개를 보존했다.
Python `query-review`는 한 줄과 gap 참조에 1,802 byte를 사용해 uncertain 후보를 유지했고,
재개에서 agent 응답 3개와 query checkpoint 1개를 새 실행 없이 재사용했다.
기록은 `runs/investigation-demo.qpcCgB`, `runs/static-demo.QUEAcT/query-review`다.
이 검수 보강에서는 실제 Docker·실모델·운영 대상 감사·원격 CI를 실행하지 않았다.
당시 다음 단계였던 A2 구현은 아래에 기록한다.

## A2 대상 함수 모델과 두 번째 정적 분석 — 2026-10-12

원문의 첫 taint 분석 → agent가 발견한 read/stream/allocation 등 대상 vocabulary → 두 번째 분석
순서를 기존 Q1 조사 loop에 연결했다. 첫 범위는 Python·Go의 call-return source와 whole-call sink다.

- 공통 graph v2 유지. strict `analysis.model_proposals`는 제공된 함수 원문·byte column,
  graph 함수 ID·역할 이유·가정을 요구한다. candidates/requests와 동시에 받지 않고 slice당
  한 번·최대 4개다. 코어만 resolved 호출에서 제한된 ASCII dotted `name(...)` 패턴을 생성한다.
- 역할당 8개 표기·총 16개 rule. 없는 함수/지원하지 않는 Unicode·generic 호출/예산·ID 충돌은
  명시적 gap이며 알려진 함수의 틀린 인용과 임의 패턴·rule·코드는 엔진 실행 전에 거절한다.
- 같은 고정 CE/core/runtime/adapter/normalizer로 두 번째 분석한다. 첫 `static.json`을 보존하고
  모델 계획·생성 rules·새 static/raw 결과·실패·attempt·checkpoint를 `models/<slice>/`에 남긴다.
  모델·rules·raw·source·identity가 변한 cache는 거절하며 성공한 재개는 CE를 다시 실행하지 않는다.
- 새 source/sink match가 해당 graph의 resolved 함수 호출에 유일하게 대응하지 않으면 binding gap을
  보존한다. wrapper 의미·공격자 통제·인자 역할·실제 노출·함수 간 흐름은 증명된 사실로 바꾸지 않는다.
- 새 근거는 slice byte 예산 안에서 전달한다. 상세 누락은 별도 context 파일, agent에는 요약·참조를
  제공한다. 나중에 원문을 추가 조회해도 이전 누락은 남는다. 기존 static gap과 새 model/static gap은
  triage·judgment의 issue로 보존하며 수정 전후 비교가 통과해도 미해소 issue가 승격을 막는다.
- Python·Go의 실제 정적 분석 fixture, 모델 제안 replay, `make demo-models`와 CI 단계를 추가했다.
  외부 대상 실행·유료 모델 호출·임의 generated command는 포함하지 않는다.

A2 검증: `make check` Ruff lint/format 통과, **406개 통과·실제 Docker 18개 skip**.
새 모델 테스트 **45개**는 실제 CE의 Python·Go 두 번째 분석, 상수 음성 대조군, 동적 callback,
동명 함수 가림, unsupported 표기, 예산, 잘못된 인용·rule, 엔진 identity, timeout·재시도,
변조된 checkpoint/rules/raw와 조회 이후에도 누락이 남는 경우를 확인한다. 기존 judgment 테스트에
model/model-static issue 두 종류를 더해 수정 비교가 통과해도 승격되지 않는 경우를 확인했다.

`make demo-models`의 기록은 `runs/models-demo.lepTVJ`다. 첫 taint는 두 언어 모두 0개,
새 taint는 Python 3개·Go 2개이고 모두 partial이다. 상수 sink에는 새 taint가 없으며
Go fixture의 exec.Command는 실행을 준비하는 호출이라 실제 명령 실행의 증거가 아니다.
새 agent 데이터는 각각 11,338/13,065 byte로 16,000 byte 한도 안이다. context별 상세 누락
3개와 기본 조회 byte 예산에서 생긴 omission 1개를 보존하며 후보는 uncertain이다.
각 언어의 재개는 응답 4개·query 1개·model checkpoint 1개를 재사용했다.
`make demo`, `make demo-static`, `make demo-investigation`도 통과했다. 실제 모델·Docker·
운영 대상 감사·원격 CI는 이번 검증에서 실행하지 않았다.

당시 계획한 R1은 기존 연구자 계획 입력을 유지하면서, graph의 등록 사실·입력 경계를 근거로 조사 계획을
제안하고 우선순위 이유·미해결·누락을 남기는 단계다. 노출과 통제의 효과는 가설로 유지한다.
첫 관찰 가능한 범위와 완료 조건은 다음과 같다.

1. 기존 Go HTTP 등록 사실과 Python·Go static 역할 근거를 제한된 recon 입력으로 공급한다.
2. 제안한 진입 함수·입력 경계·조사 이유를 기존 graph ID와 제공된 원문에 연결하고 검증한다.
   실제 외부 노출·통제 효과·실행 경로는 추정으로 확정하지 않는다.
3. 우선순위 이유·미해결·byte 누락을 보존하고, 검증된 제안을 기존 research-plan/recon/slicing으로
   연결한다. 사람이 제공한 계획의 기존 경로도 유지한다.
4. 정상 등록, 없는 함수, 거짓 인용, 등록과 노출의 혼동, 예산 초과·실패·재개를 fixture/replay로 검증한다.

이후 P1의 검증 코드 제안·연구자 검토·독립 진입·build 비교, C1 연결 가설, I1 영향 측정과
M5의 실제 품질/비용 비교는 아직 필요하다. A2는 인자별 모델·sanitizer·함수 간 taint나
실제 모델의 탐지 성능을 검증한 단계가 아니다.

## R1 근거에 연결한 조사 계획 제안 — 2026-10-12

원문의 recon이 등록·입력 경계를 찾고 조사 범위를 정하는 역할을, 현재 지원한 사실 범위에서
agent 제안으로 연결했다. 기존 `recon --spec`도 유지한다.

- Go의 typed direct HandleFunc 등록과 선택적 Python/Go static 역할·함수 원문을 공급한다.
  기본 입력 data는 16,000 byte(1,024..64,000)이며 fact와 전체 함수 원문이 함께 들어갈 때만
  제공한다. 자세한 누락은 context/coverage에 보존하고 agent에는 요약·참조를 전달한다.
- 제안은 제공한 graph 함수 ID, 그 함수의 등록/source fact, entry 원문·UTF-8 byte column,
  우선순위·조사 이유·미해결을 요구한다. 알려지지 않은 함수·fact, 잘못된 함수 근거/column,
  거짓 인용·노출 확인 필드는 거절한다. 우선순위와 통제·노출의 의미는 가설이다.
- 기존 연구 계획의 선택적 selection/proposal_origin으로 연결한다. 첫 exposure 미확인,
  input 누락·미선택 entry·static 한계·모든 unresolved는 recon/slice와 `recon_gap_ids`에 남는다.
  judgment는 수정 비교가 통과해도 미해소 recon issue로 승격을 막는다.
- `run`은 원래 graph/source/static과 input byte 한도에서 context를 재계산해 hash와 fact/entry
  대응을 검사한다. 원래 fact·전체 누락은 `recon-context.json`으로 보존한다. source 인용과
  checksum이 맞더라도 다른 함수의 fact로 바꾼 계획은 거절한다. 정적 근거로 만든 계획에는
  원래 static artifact가 필요하다. 나중에 static을 추가해도 초기 누락을 지우지 않는다.
- 제안 기본 시도는 1회·상한 16회이며 실패/timeout도 횟수를 소비한다. 시도별 raw/prompt/실패와
  manifest를 보존하고 재개는 명시적으로 상한을 늘리거나 성공 checkpoint를 재사용한다.
  source/graph/static·provider/model·prompt/schema·코드·예산, 저장된 입력·raw/reply·계획/결과를
  확인한다. 실패한 재개 다음에도 결과 identity와 변조 검사가 유지된다.
- 빈 제안은 no_hypotheses로 기록하며 recon을 만들지 않는다. 전체 threat model·노출·안전이
  확인된 상태가 아니다. 일반적인 등록 wrapper·타 router·Solidity/C++ 노출 adapter와 계획 품질은
  이 첫 범위 밖이며 수동 계획 경로는 모든 기존 graph 언어에서 유지한다.

R1 검증: `make check` Ruff lint/format 통과, **460개 통과·실제 Docker 18개 skip**.
신규 recon 테스트 **53개**로 실제 Python/Go graph와 CE 근거, 제안 → slicing/triage,
우선순위·source/fact binding, 거짓 근거·원문 변경, 부분/전체 byte 누락·빈 제안, timeout/시도 한도,
raw·입력·계획·결과 변조와 다시 만든 checksum, 원래 static 누락/변경, 재개를 확인했다.
기존 judgment에 recon issue를 추가해 수정 비교 성공만으로 승격되지 않는 경우도 확인했다.

`make demo-recon`의 최종 기록은 `runs/recon-demo.DrQyhx`다. Python의 역할 fact 8개/6,027 byte와
Go의 등록 fact 3개/4,628 byte에서 각각 계획 1개/3개를 제안했다. 복사한 recon context는 원본과
동일하며 후보에는 각각 recon gap 5개, 4개씩이 남았다. 재개는 recon 응답을 한 번씩 재사용하고
기존 분석/triage 응답은 Python 2개·Go 6개를 재사용했다. Go 기각·불확실·검증 대기와 mixed cluster도
보존했다. `make demo`, `make demo-models`의 재분석/재개도 통과했다. 모두 기록된 agent 응답이며
실제 모델·Docker·운영 감사·원격 CI는 이번 단계에서 실행하지 않았다.

R1 Solidity 보강: solc AST에 이미 있는 구현 함수의 `public`/`external` visibility를
`entry_visibility` 사실과 정의 원문·UTF-8 byte 위치로 bounded recon 입력에 전달한다.
`function`·`receive`·`fallback`만 시작점 후보로 제시하며 constructor·internal·본문 없는
선언은 제외한다. 다른 함수의 fact를 붙인 제안은 거절하고 byte 예산의 생략, 미선택 시작점,
배포·프록시·호출자 미확인을 보존한다. 합성 Vault의 별도 파일 상속 modifier 사례에서
기록된 계획 제안→slice→triage와 실패·재개를 검증했다. 소스 visibility는 배포된 진입점의
증거가 아니며 생성된 public getter와 상속 후 selector·프록시 binding은 여전히 미해결이다.
CLI replay에서는 visibility fact 3개에서 가설 2개를 만들고 후보 1개를 `needs_validation`으로
남겼다. 원본의 `deployment_unverified` 등 recon gap 6개가 후보 입력에 유지됐다.
입력 예산에서 빠진 recon fact는 불투명한 ID만 남기지 않고 종류·함수 ID·파일·줄·byte column·
소스 hash를 `coverage.json`에 기록한다. agent 프롬프트에는 기존대로 누락 수와 참조만 전달한다.

다음 작업은 P1의 PoC 제안·검토·독립 진입·build 비교다. 첫 완료 조건은 다음과 같다.

1. 외부에서 가져온 후보도 source/triage identity와 반증·미해결·gap을 검증해 입력한다.
2. 검증 코드·관찰 조건 제안은 자료로 저장하고 실행하지 않는다. 연구자 검토를 정확한
   후보·소스·제안 hash에 연결하고 제안 자체가 승인 또는 취약점 확정이 되지 않게 한다.
3. 검토한 recipe·준비한 이미지로만 기존 worker/oracle을 사용한다. 실제 진입점과 양성/음성
   대조군, 적용한 설정별 전후 비교와 미해결 해소를 기록하고 원래 근거는 보존한다.
4. 잘못된 source/검토 identity·미검토 제안·직접 함수 검사·설정 불일치·실패/timeout과
   정상 경로·독립 진입/재개를 fixture로 검증한다. 대상/제안 명령의 host 실행·암묵적 image 준비는 없다.

C1 연결 가설, I1의 단계별 영향 관찰과 M5의 실제 품질/시간/token 비교는 계속 남아 있다.

## P1-1 외부 후보의 독립 검증 진입 — 2026-10-12

원문은 연구자가 자기 후보를 넣어 triage/PoC부터 시작할 수 있어야 한다고 설명한다.
`import-review`로 기존 analysis/recon agent를 다시 실행하지 않고 source-backed 외부 후보를
공통 triage·queue와 기존 `validate`/`judge`에 연결했다. **P1의 첫 조건을 완료했으며 P1 전체는 진행 중이다.**

- strict import 계약은 filtered source index hash, 최대 32개·각 200줄의 fragment/hash,
  최대 8개 후보, 모든 후보의 triage 결정과 외부 gap을 요구한다. spec/output은 대상 밖에 두고
  새 output만 허용한다. 기본 원문 data 한도는 16,000 byte(1,024..64,000)다.
- 공통 analysis·triage의 원문 인용과 UTF-8 byte column 검사를 재사용한다. source/hypothesis별
  canonical 후보 ID와 source hash를 확인하며 중복·잘못된 인용·판정·원인/수정 근거·누락된 결정을 거절한다.
  기존 원인·수정 grouping과 mixed/기각/불확실·반증·미해결을 보존한다. 기각 후보도 findings에 남긴다.
- 원본 `import-input.json`을 검사 전에 저장하고 실패를 manifest에 기록한다. 완료 직전
  spec/source/graph/static을 재검사하고 identity에 원본·계약·검사 코드·입력 예산을 포함한다.
  spec의 명령/승격 필드는 허용하지 않고 validation_plan과 대상 AGENTS/코드는 자료로만 처리한다.
- optional graph/static은 원래 artifact로 보존한다. fragment와 겹치는 함수에서 core가
  context_function_ids를 계산해 전체 알려진 미해결/외부 호출·modifier 한계·정적 gap을 남긴다.
  제공하지 못한 정적 근거는 항목별 omission과 omitted_counts에 남긴다. 가설 ID가 없어도
  `hypothesis_id=null`로 누락을 기록하도록 공통 static attachment의 오류를 수정했다.
  공통 graph 계약은 이번 단계에서 변경하지 않았다.
- 외부 gap의 원문 근거와 자동 진입점 미확인 gap은 import-gaps.json/import_gap_ids로 연결한다.
  기존 judgment가 이를 issue로 보존하며 비교 성공만으로 해결하지 않는다. 합성 fixture의
  별도 frozen recipe는 정상 CLI 요청·admin 양성 대조군·guest 수정 전후와 명시적 issue 해소를 선언한다.
  imported verdict와 review/worker 기록은 승격 결과로 덮어쓰지 않는다.

검증: `make check` Ruff lint/format 통과, **503개 통과·실제 Docker 18개 skip**.
신규 intake 테스트 **42개**와 기존 judgment의 import gap 사례를 추가했다.
정상/실패 raw·identity, 엄격한 계약·경로/예산·인용·소스/spec 변경·기존 출력 보존,
가설별 ID·mixed cluster·반증·빈 결과, 실제 Python graph/CE의 원문/byte 누락,
Go 미해결 호출·Solidity modifier gap을 확인했다. 기존 FakeDocker 제어 응답 fixture로
import → worker → 수정 비교/issue 판정과 해소 조건 누락·timeout·실패·변경 source의 승격 거절을 검증했다.
실제 Docker 격리·진입점 실행을 새로 검증했다는 뜻은 아니다.

`make demo-intake`는 `runs/intake-demo.39uugG`에 합성 후보와 부분 Python 가져오기를 기록했다.
둘 다 model/validation 호출·확정 건수는 0이며 uncertain 후보 1개·import gap 2개를 보존했다.
Python은 1줄 입력에서도 unresolved call 1개·static gap 1개·미공급 정적 항목 2개를 남겼다.
`make demo`의 replay/reuse도 `runs/demo.mcDkKU`에서 통과했다. CI 명령을 추가했으나 원격 CI,
실제 모델·Docker·운영 감사는 이번 단계에서 실행하지 않았다. 가져오기는 재개 대신 새 output을 요구한다.

P1-2의 검증 코드·관찰 조건 제안과 연구자 검토는 다음 완료 기준으로 진행했다:

1. 완료된 review의 후보/source/graph와 원문 예산을 확인해 기존 bounded agent/replay로
   PoC 제안을 받고 코드·관찰·필요 설정·미해결을 자료로 보존한다. 거짓 source/후보와 임의 승격을 거절한다.
2. 연구자 검토 artifact를 정확한 후보·review/source·제안 hash에 묶고 승인/기각/수정 요청을 보존한다.
   agent 제안이 자기 자신을 승인하지 못하게 하며 검토 기록은 취약점 확정이 아니다.
3. 명시적으로 검토한 코드와 frozen oracle만 strict recipe의 별도 입력으로 공급해 기존 worker에 연결한다.
   대상/제안 코드의 host 실행·암묵적 image 준비 없이 미검토·변경된 제안/검토·timeout/실패와 정상 경로를 검증한다.
4. 제안 시도/실패·예산·identity·raw/checkpoint와 재개를 검증하고 기존 수동 supplied-harness 경로를 유지한다.

그 뒤 P1-3에서 적용된 build 설정별 전후 비교를 묶고, C1·I1·M5를 진행한다.

## P1-2 PoC 제안과 별도 연구자 검토 — 2026-10-12

원문의 PoC agent와 연구자 checkpoint에 대응하는 자료 제안·검토 경계를 구현했다.
**P1-2의 위 네 조건은 완료했으며 P1 전체와 전체 연구 workflow는 아직 진행 중이다.**
공통 graph 계약·원래 triage·수동 supplied-harness 경로는 유지한다.

- `poc`는 완료된 review/queue의 canonical 후보와 filtered source index·graph/static·설정·저장 원문을
  대조한다. 기존 agent/replay로 코드·absolute container argv·frozen oracle·requirements·unresolved를
  strict 자료로 받고 후보의 byte 인용·입력/attachment hash·관찰/issue 참조를 확인한다.
  후보/source 오인·자기 승인/승격·제안 단계의 target replacement를 거절한다.
- context는 기본 16,000 byte(1,024..64,000)이며 source 범위는 최대 32개·각 200줄이다.
  큰 기존 범위는 원문을 잃지 않고 나누고, 추가 조사 후보는 현재 source에서 인용을 확인한 뒤
  제한된 주변 범위를 보충한다. budget 초과는 거절한다. 다중 파일·Go 설정과 전체 알려진
  소유 함수의 미해결 호출/static gap·omission, 원래 후보·반증·gap과 core issue ID를 공급한다.
- 기본 1회(최대 16회) 시도를 호출 전에 기록한다. 실패도 예산을 사용하며 raw/prompt/failure와
  checkpoint를 남긴다. 재개는 context/source/provider/prompt/schema/tool identity, 원본 응답·
  checkpoint·저장 proposal/recipe를 대조한다. 완료 직전에 source/context를 다시 확인한다.
- `poc-review`는 완료한 제안·현재 근거·raw/checkpoint를 대조한 뒤 별도 운영자의
  approve/reject/request_changes와 reviewer/rationale를 기록한다. 후보·review·queue·전체 source index·
  proposal·recipe hash에 묶는다. 기각/수정 요청은 제안을 남기되 recipe를 만들지 않는다.
  agent는 이 결정을 생성하지 못한다. reviewer는 로컬 선언이며 hash는 신원 인증/서명이 아니다.
- worker는 explicit approved `--poc-review`가 있어야 `poc/` text attachment를 받는다.
  각 attachment 64 KiB·전체 128 KiB, 경로·credential·hash·target 입력 충돌을 검사하고
  readonly snapshot에만 쓴다. frozen harness는 target fix로 교체할 수 없다. 전체 source index와
  설정 변경, 코드/관찰/검토 변조를 Docker 호출 전에 거절한다. 이미지/의존성을 암묵적으로 준비하지 않는다.
- proposal/receipt·원래 candidate를 worker evidence와 judgment에 보존한다. PoC의 새 미해결도
  독립 issue로 남고 timeout/process/cleanup 실패에 지워지지 않는다. 기존 판정의 실제 진입점·
  고정 oracle·전후 비교·issue 해소 gate를 재사용한다. 다른 검토 기록의 전후 run은 비교하지 않는다.
  exit zero, 직접 함수 호출 또는 승인만으로 취약점을 승격하지 않는다.

검증: `make check` Ruff lint/format 통과, **568개 통과·실제 Docker 18개 skip**.
새 `tests/test_poc.py` **65개**는 정상 경로와 잘못된 인용/ID/self-approval/input/attachment/관찰,
UTF-8 byte 예산·call 한도·timeout 재개, provider/context 변경, raw/checkpoint/proposal 변조,
별도 검토 결정·미검토와 원문/설정 변경, target shadow/harness replacement 거절을 확인한다.
실제 Go 다중 파일/config와 부분 Python graph/CE context를 검사했다.
worker/판정 연결은 기존 FakeDocker 제어 응답 fixture로 전후 비교, 실제 진입점 부재·direct_call,
PoC 미해결 보존·timeout/실패/cleanup·artifact 변조·다른 검토의 비교 거절을 검증했다.
실제 Docker 격리·대상 실행·취약점 재현을 새로 검증했다는 뜻은 아니다.

`make demo-poc`는 `runs/poc-demo.I6KYAv`에 recorded 제안 1회·cache reuse와 `offline-fixture` 합성
검토 기록을 남겼다. 후보는 uncertain이며 worker 실행은 0이다. 실제 연구자 승인이나 모델 결과가 아니다.
`make demo-intake`는 `runs/intake-demo.QMkpyJ`, `make demo`는 `runs/demo.RBkAXR`에서 통과했다.
README·설계/개발 문서·AGENTS·CI의 실행 목록을 갱신했다. 원격 CI·실모델·실제 Docker·운영 감사는
이번 단계에서 실행하지 않았다. 기존 모든 변경은 그대로 두며 commit/push는 이번 작업 범위에 없다.

P1-3의 적용된 build 설정별 비교는 다음 완료 기준으로 진행했다:

1. 검토한 후보/source/PoC/oracle을 그대로 유지하는 bounded matrix spec을 정의한다.
   case별 immutable 준비 이미지·명시한 설정·원문 근거를 기록하고 target/build 명령은 host에서 실행하지 않는다.
2. 각 case 안에서 설정을 실제로 적용했음을 관찰하고 동일 조건의 수정 전후 worker/판정을 묶는다.
   설정 이름이나 제안자의 주장만으로 적용을 인정하지 않는다. 다른 설정 간 결과는 비교 성공으로 합치지 않는다.
3. 미적용/미확인 설정, 누락/실패/timeout/대조군 실패·미해결을 case별로 남기고
   통과한 case가 다른 case의 gap을 지우지 않게 한다. original triage·receipt·raw worker evidence를 유지한다.
4. 오프라인 fixture로 정상/설정 불일치·미적용·실패/timeout·변조와 예산 한도를 검증한다.
   실제 실행은 명시적인 isolated 경로와 사전 준비한 이미지가 있을 때만 한다.

그 뒤 **C1 validated 후보 간 연결 가설**, **I1 단계별 영향 관찰**, **M5 동일 조건의 품질/시간/token 비교**를
진행한다. 현재 이 세 단계를 완료했다고 주장하지 않는다.

## P1-3 설정별 적용 관찰과 전후 비교 — 2026-10-12

원문은 `WITH_VERBOSE_WINPR_ASSERT=OFF` 같은 build 조건과 ASan 관찰로 정적 가설의
적용 범위를 확인했다. 그에 대응해 **위 네 조건의 bounded build matrix 구현을 완료했다.**
P1의 독립 진입·자료 제안·별도 검토·설정별 비교 경계는 갖췄으며, 실제 대상 품질 평가와
C1·I1·M5를 포함한 전체 목표는 계속 진행 중이다. 공통 graph 계약은 바꾸지 않았다.

- PoC/recipe의 optional `configurations`는 최대 4개의 ID/settings·target 원문과 frozen harness
  build/invocation 인용·서로 다른 runtime observation을 요구한다. `validate --configuration`은
  선택 ID를 literal argument로 추가하며 create/policy/worker reader가 같은 명령을 검사한다.
  선택 누락·미선언/중복과 변경된 코드·관찰/승인은 실행 전에 거절한다. 기존 단일 recipe도 유지한다.
- `prepare-matrix`는 승인한 recipe/receipt/proposal·fixed recipe와 원본 strict spec을 복사해
  hash와 target/review/tool identity를 고정한다. 현재 source/context를 대조하며 모든 선언 case와
  명시한 immutable image를 정확히 한 번 요구한다. 준비는 target/build command를 실행하지 않는다.
- `validate-matrix`에서만 최대 8회 worker를 순서대로 호출한다. 호출 전에 시도를 기록하고 실패도
  예산을 사용한다. frozen 입력을 매번 확인하고 raw worker/참조·모든 case를 보존한다.
  cleanup 실패·실행 시작/terminal 상태 미확인·controller 중단·입력 변경에는 나머지를 시작하지 않는다.
  자동 image 준비·host fallback·묵시적 재시작/재개는 없다.
- judge는 실제 target 속성의 고정 observation이 선택 case에 맞고 유일하며 outcome보다 앞선지
  확인한다. 이름/요청 옵션 echo·누락/중복·다른 case 관찰·잘못된 순서는 적용을 인정하지 않는다.
  source/invocation proof와 관찰을 issue 해소 참조에 연결한다. 전후 ID/image/source/approval/oracle,
  비교 조건과 실제 진입점·재현·수정·미해결 해소가 필요하다. 다른 case는 비교하지 않는다.
- `judge-matrix`는 보존된 preparation/execution/worker만 읽고 case별 기존 judge를 재사용한다.
  설정 미확인·없거나 잘못된 run·실패·미재현과 원래 candidate/검토/issue/참조를 남긴다.
  `validated_cases`와 모든 선언 case의 관찰 완료 여부인 `coverage_complete`를 분리한다.
  통과한 case가 다른 case의 gap을 지우거나 negative 결과가 안전성을 의미하지 않는다.

합성 C fixture는 `__OPTIMIZE__`의 활성/비활성과 `AUDIT_GUARD` 값을 compiled target에서 보고하고,
고정 probe는 guest/admin 정상 요청과 정확한 출력 byte를 비교한다. release에서는 guard가 꺼져
수정 전 재현·수정 후 미재현, guarded에서는 처음부터 미재현인 기록을 별도로 판정했다.
관찰은 최적화 활성 여부만 확인하며 정확한 `-O2` 단계/전체 build·배포 설정을 증명하지 않는다.
source anchor가 수정 후에 이동하면 재검토가 필요하다. compiler별 자동 설정 추출/계측은 없다.

검증: `make check` Ruff lint/format 통과, **608개 통과·실제 Docker 19개 skip**.
새 matrix 테스트 **38개**는 FakeDocker 응답으로 정상/설정 누락·불일치·중복·순서·대조군,
전후 case 분리·예산·raw/approval/recipe/source 변조·timeout/process/정책·cleanup·unknown state,
controller 중단·worker 사이 입력 변경과 재시작 거절을 확인했다. 별도 준비한 compiler image를
명시하는 실제 Docker 통합 테스트 한 개를 추가했으나 실행하지 않았다.
실제 C 프로그램을 host에서 compile/execute하거나 Docker 격리를 새로 증명한 것은 아니다.

후속 실제 검증(2026-10-13): 이미 준비된 digest-pinned Go 이미지
`sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee`에 포함된
`/usr/bin/cc`로 `test_real_isolated_compiler_matrix` **1개가 통과**했다. 별도 pull/build는 없었다.
`runs/matrix-docker.pWXauy/test_real_isolated_compiler_ma0/`에 네 worker와 실제 출력·정책·
판정을 보존했다. release는 optimization 활성/guard 0을 관찰하고 수정 전 재현·수정 후 차단,
guarded는 optimization 비활성/guard 1에서 처음부터 차단이었다. 모든 admin 요청은 성공했다.
`coverage_complete=true`, `validated_cases=[release]`이며 guarded의 미재현도 별도 남았다.
각 worker는 network none·readonly root·128 MiB·32 pids·cap drop ALL·한 개 input mount를
확인했고 실행/폐기까지 완료됐다. host는 컨트롤러만 실행했다. 최초 sandbox 내 실행은
Docker 접속 권한 부족으로 engine 단계에서 끝났으며 네 기록 모두 execution_attempted=false,
cleanup=not_created로 `runs/matrix-docker.oQQfr2/`에 보존했다. credential 제거 환경의 두
socket 모두 차단됨을 확인한 후, 컨트롤러 접근 권한으로 별도의 새 matrix를 실행한 것이다.
같은 matrix의 재개/자동 재시작은 없었다. 이 테스트의 PoC 승인은 합성 선언이며 운영 검토가 아니다.

회귀 검사에서 기존 trusted tool의 출력 한도 검사 중 `PermissionError`가 정리 단계에서 원래 오류를
덮는 사례가 한 번 발생했다. 단독 검사와 60회 반복에서는 재현되지 않았다. signal 거절 뒤 100ms 안에
종료를 확인한 경우에만 기존 오류를 유지하고, 종료 미확인은 permission 실패로 남기도록 shared helper를
보완했다. 자연 종료 확인/미확인 두 경계 테스트가 통과했다. OS의 권한 오류 발생 원인은 특정하지 않았다.

`make demo-matrix`는 `runs/matrix-demo.eWFj5F`에서 두 missing case, coverage false와 validated 0을
남겼다. 합성 image ID/검토이며 실제 worker/model/compile 실행은 0이다.
`make demo`는 `runs/demo.WZ64au`, `make demo-poc`는 `runs/poc-demo.Cn1i4c`에서 통과했다.
계약·prompt/replay·README·설계/개발 문서·AGENTS·CI를 함께 갱신했다. 원격 CI·유료 모델·실제 Docker와
운영 감사는 이번 단계에서 실행하지 않았다. commit/push는 수행하지 않았다.

다음은 **C1: 검증된 후보의 연결 가설**이다. 완료 기준:

1. promotion gate를 통과한 immutable judgment와 원래 source/worker/조건을 확인한다.
   rejected/uncertain/실패/미해결/미재현을 연결의 확정 primitive로 받지 않으며 원래 기록은 보존한다.
2. 두 primitive의 순서·입출력 상태·전제·source 근거와 남은 gap을 strict 연결 가설로 기록한다.
   source/graph의 구조적 관계와 실행/데이터 흐름 proof를 분리하고 누락된 관계를 만들지 않는다.
3. 연구자 검토와 frozen 연결 실험/관찰 기준을 기존 isolated worker에 연결한다.
   개별 재현 두 개와 실제 상태 전달을 관찰한 연결 재현을 구분한다. 연결이 곧 영향 입증은 아니다.
4. 정상 연결과 순서/상태/조건 불일치·미검증 입력·변조·반증/미해결·실패/timeout을 offline fixture로
   검증한다. 그 뒤 I1의 단계별 영향 관찰과 M5의 동일 사례/예산 비교를 진행한다.

C1-1/2 구현: `prepare-chain`은 두 `validated` 판정을 원본 worker에서 재계산하고
동일 대상/review/image/설정 ID와 설정값, 겹치는 source snapshot, 서로 다른 후보 ID를 검사한다.
strict `chain-hypothesis.json`에 순서, 상태 전달 가정, 양쪽 source 인용, 전제·반증·미해결을
보존한다. 개별 재현 두 개와 연결 관찰을 분리해 `connection: unobserved`로 남긴다.
합성 FakeDocker fixture의 정상 가설과 순서/인용/누락/변조/비승격 입력 거절을 검사한다.
이것만으로 연결 재현은 아니다. C1-3/4는 두 번째 후보용 승인 PoC와 별도 chain 연구자 검토를
가설에 바인딩하고, 기존 `validate` worker의 고정 harness로만 연결 실험을 실행하도록 했다.
`judge-chain`은 원본 가설/검토/worker를 다시 확인하고 첫 진입·출력·입력·둘째 진입·재현·완료의
단일 stream 순서 및 정규 base64 원래 byte 동일성을 판정한다. 미해결 전제는 연구자가 명시적으로
실험 gate에 연결한 것만 해소하고, 반증/남은 gap은 `observed_with_open_issues`로 남긴다.
순서·값 불일치, 누락·중복, 미재현, 실패·timeout, 미승인·변조를 offline FakeDocker fixture로
검사한다. 연결은 영향 입증이 아니며, 합성 harness의 실제 Docker 실행과 실모델·운영 대상 검증은
수행하지 않았다. 다음은 **I1 단계별 영향 관찰**과 **M5 동일 조건 성능/품질 비교**다.

후속 C1 보강: 승인 harness에 잘못된 상태를 쓰는 대조 호출과 정확한 거부 응답 관찰을 추가했다.
`judge-chain`은 재현 뒤 대조군 거부가 완료 전에 한 번 관찰되지 않으면
`state_dependence_unverified`로 연결 승격을 막는다. FakeDocker 정상/대조군 수락 테스트와
준비된 immutable 로컬 이미지의 실제 격리 실행을 확인했다. 기존 `judgment-target` 예제는
전달된 역할값과 무관하게 데이터를 반환하므로 실제 실행에서는 대조군도 수락했고,
`connected`가 아닌 `not_observed`로 판정됐다. 이 상태 독립 예제는 연결 성공 사례가 아니다.

후속 C1 실제 정상 사례: 별도 분기인 guest 토큰 누출과 guest 토큰 교환 결함을 가진
`chain-linked-target`을 추가했다. 각 결함에 대해 별도 source 후보, 진입점 oracle, 초점 수정과
admin 대조군을 고정하고 준비된 로컬 이미지의 격리 worker에서 각각 수정 전 재현·수정 후
미재현으로 `validated`를 얻었다. 승인된 결합 harness의 다섯 번째 worker는 첫 응답의 token
byte를 두 번째 guest 요청에 전달하고 secret 응답을 관찰했다. 잘못된 token은 거부됐으며
`judge-chain`은 `connected`, `impact_validated: false`를 기록했다. 테스트용 승인 선언과
합성 shell 사례이므로 운영 대상의 취약점 연결·영향 입증이나 모델 품질 평가는 아니다.

원문에서 `chain`은 검증된 두 primitive가 결합 가능한지 묻는 단계이며, FreeRDP 사례에서도
이 시점의 RCE는 가능성이지 입증이 아니었다. 이 구현도 `connected`를 검토한 격리 실험의
전달 관찰로만 정의하고 `impact_validated: false`를 유지한다. 실제 영향 판정은 원문의
`exploit`처럼 별도 gate와 연구자 점검이 필요하다.

다음 **I1** 완료 기준:

1. `validated` primitive 또는 `connected` chain의 원본 근거를 재검증한 뒤, 연구자가 측정할
   보안 속성·위협 문맥·대조군·성공/실패 조건과 단계 순서를 별도 artifact로 승인한다.
2. 각 단계의 관찰은 기존 격리 worker의 고정 recipe/PoC와 연결하고, 진입·상태/primitive·통제
   실험·속성 변화·완료를 따로 기록한다. 단계 누락/역순·실행 실패·timeout·반증은 다음 단계로
   승격하지 않으며 raw evidence와 연구자 중단/재개 지점을 보존한다.
3. 합성 정상·음성·불확실 fixture로 `실행 성공 ≠ 재현 ≠ 연결 ≠ 영향`을 검증한다. 실제 운영
   대상 공격이나 유료 모델 호출 없이 reproducible offline 경로를 먼저 완성한다.

I1-1 구현: `impact-review`는 validated primitive 또는 connected chain의 원본 판정/worker를
재검증하고 researcher가 지정한 보안 속성·위협 문맥·성공/실패 정의·대조군·최대 8개 gate를
source 및 별도 승인된 PoC에 바인딩한다. 최소 setup/primitive/control/impact 순서를 요구하고
각 단계의 recipe·실제 entrypoint·관찰 marker·source 인용과 열린 가정/해소 선언을 보존한다.
검토 artifact는 worker를 실행하지 않으며 영향 판정을 내리지 않는다. primitive와 chain 정상 입력,
순서/인용/중복/비승인/미승격 입력 거절을 offline fixture로 검사한다.
I1-2 구현: `impact-step`은 원본 review/validated 입력/이전 checkpoint 및 supplied worker를
재검증한다. 고정 stage의 후보·recipe·PoC 승인·image·source/설정과 진입/결과/완료/cleanup을
확인한 뒤 명시적 연구자 `approve`가 있는 통과 gate만 전진한다. 실패·timeout·역순·변조·
잘못된 worker는 attempt로 보존하고 같은 단계에 멈춘다. `retry`는 새 worker를 최대 세 번
허용하며 `reject`는 중단한다. 마지막 gate 후에도 열린 가정/반증이 남으면
`observed_with_open_issues`이고, 모두 명시적 단계에 해소된 때만 해당 실험 속성에 대해
`impact_observed`가 된다. primitive/chain 입력, 정상 네 단계, 음성 control, 재시도·중단·
timeout·증거 변조·열린 근거를 offline FakeDocker fixture로 검사했다.
이 시점에는 실제 Docker 영향 측정은 수행하지 않았다.

후속 I1 실제 합성 실험: `chain-linked-target`의 두 primitive를 격리 Docker worker에서
각각 검증하고 `connected` chain을 얻은 뒤, 승인된 별도 PoC로 setup·guest 토큰 누출·
admin 및 잘못된 토큰 control·guest 보호 기록 획득을 네 worker에서 순서대로 측정했다.
최종 응답 원본 byte는 base64로 raw 로그에 보존하고 정확한 `ENTRY redeem` 및
`SECRET vault-record`와 일치하는지 테스트에서 확인했다. checkpoint는
`reproduced → reproduced → not_reproduced → reproduced`, `impact_observed`를 기록한다.
순서 위반은 진행되지 않는다. 이 승인은 테스트용 합성 선언이며 운영 대상의 영향이나
실모델 탐지 품질을 입증하지 않는다. 다음은 **M5 동일 사례·예산의 실모델 반복 평가**다.

완료 근거 재검수(2026-10-13): `runs/chain-impact-docker-20261013/linked-chain0/`의
chain을 원본 두 primitive/worker/승인 자료에서 재계산했고 `connected`·impact false가
저장 결과와 일치했다. 별도 impact review와 네 stage의 checkpoint도 재검증해
`complete/impact_observed`·impact true·next_stage_index 4를 확인했다.
원본 worker 9개는 모두 completed/cleanup removed였고 현지 Docker에도 audit-validation
컨테이너가 남지 않았다. 새 target/model 실행 없이 원본을 검증했고 읽기 전용 감사 결과는
`runs/chain-completion-audit.json`에 남겼다. 연구 원문 단계의 계약·합성 실행 근거는 연결되어
있지만 운영 대상의 품질이나 M5 반복 완료 기준은 이 기록으로 충족하지 않는다.

M5-1 구현: `benchmark-replay`는 연구자가 source 위치·CWE와 함께 선언한 positive/negative
정답을 원문에 대조한 뒤, 같은 대상과 호출·slice·조회 상한으로 lexical baseline과 선택적
graph/recon candidate를 각각 새 run에서 실행한다. source snapshot이 달라지면 비교를 실패로
남긴다. `benchmark.json`에 label별 후보 유지·누락·정상 대조군 오탐과 미포함 위치, 원본
metrics/coverage/hash, 로컬 경과 시간, 미보고 token의 `null`을 보존한다. C 예제 정상·누락·
오탐·실패와 Go graph 대 lexical fixture로 offline 절차를 검증했다. Go의 빈 lexical replay와
기록된 graph replay의 차이는 정해 둔 응답의 차이이며 실제 모델 성능 향상이 아니다.
남은 M5는 동일 모델·동일 예산의 실측 호출, token/시간/오탐·미탐의 반복 측정과 병목이
관찰될 때만 적용할 병렬화다. 개발 요청만으로 유료 모델 실행을 시작하지 않는다.

M5-2 구현: `benchmark-runs`는 이미 완료된 두 `run` artifact를 읽기 전용으로 비교한다.
동일 target/source snapshot·계약·도구·예산을 요구하고 Codex 기록은 같은 model/CLI/config
선언까지 대조한다. fresh 성공 호출의 reply checksum·원본 응답·프롬프트 사본·시간·token 집계와
findings/queue/metrics 일치를 확인한다. 누락 사용량은 호출별 coverage로 남기고, cache hit·실패 시도가 섞인 시간
비교를 거절한다. replay 정상·변조·불일치와 가짜 Codex identity의 부분 사용량을 offline
fixture로 검사했다. provider identity와 정답은 로컬 선언이므로 실측 모델 성능 주장에는
보호된 원본 run과 반복 평가가 추가로 필요하다. 이 단계에서 모델을 호출하지 않았다.

M5-3 구현: `benchmark-summary`는 독립된 pair 비교 2~16개를 다시 계산하고, source/truth,
모델·graph/recon/static 설정과 예산이 반복마다 같은지 확인한다. run 재사용·보고서/원본 변조·
설정 불일치는 거절한다. label별 판정 횟수와 candidate−baseline 차이의 중앙값·범위를
기록한다. token 사용량이 불완전한 pair가 있으면 token 분포를 비워 둔다. offline replay와
가짜 Codex usage fixture로 정상·실패·누락을 검사했다. 실제 모델의 반복 측정과 원문 연구의
성능/영향 재현은 아직 없으며 병렬화할 병목도 측정되지 않았다.

M5-4 구현: 같은 설정 상한만으로 입력 비용이 같다고 보지 않도록, 반복 요약에 원본 호출의
analysis/triage 프롬프트 byte·성공 호출 시간과 검증 대기 후보 수를 추가했다. 각 prompt와
저장된 시도 사본이 다른 경우 요약을 거절한다. 동일 replay의 2회 요약, 변조 prompt, token
미보고를 offline fixture로 확인했다. 이 수치는 모델 token/가격이나 실제 연구자 검토 시간을
대신하지 않으며, 병렬화 여부는 실측 병목을 얻은 뒤 판단한다.

M5 실측 전 사전 점검: Go 정답 사례의 동일 소스 복사본과 양성·음성 라벨 2개를 고정했다.
`plan`의 상대 target 경로에서 graph 입력을 잘못 거절하던 문제를 고쳤고, 실제 호출 상한을
과소 표시하던 값을 기본 호출 수와 보수적 최대 호출 수로 분리했다. slice 8개·16 KiB·
조회 1회·전체 호출 16회로 동일하게 설정하면 lexical은 5개 slice/최대 15회,
graph/recon은 3개 slice/최대 9회로 계획된다. `benchmark-replay`와 `benchmark-runs`는
기록된 응답으로 통과했다. 이는 비교 절차의 점검 결과이며, 모델의 탐지 품질·token 사용량·
가격이나 graph의 우월성을 측정한 결과는 아니다. 실제 반복 호출과 더 넓은 정답 사례,
관찰된 병목에 따른 병렬화 판단은 아직 남아 있다.

Python 교차 언어 점검: 기존 `static-target`의 직접 입력→shell sink와 상수 명령 대조군을
양성·음성 정답으로 고정하고, 두 함수에 대한 graph/recon 입력과 기록된 응답을 비교했다.
두 라벨의 source 포함과 판정 보존을 테스트로 확인했다.

Solidity 교차 언어 점검: 별도 합성 Vault의 소유자만 전체 잔액을 전송한다는 정책 아래,
gate가 없는 `releaseA`와 상속한 `ownerOnly`를 적용한 `releaseB`를 양성·음성 정답으로
고정했다. graph에서 파일 간 modifier 적용과 `require` 참/거짓 분기, 외부 전송 호출을
확인하고, 두 라벨의 graph/recon 입력 포함과 replay 판정 보존을 테스트했다. 이는
정책에 대한 조사 후보의 정답이며 배포·EVM 실행·금전 영향의 증거가 아니다. Go/Python/
Solidity는 별도 평가 단위이므로 합쳐서 탐지율을 주장하지 않는다.

세 언어의 고정 소스·라벨·호출 예산과 replay 프롬프트 비용 사전 점검은
[`docs/model-evaluation.md`](model-evaluation.md)에 기록했다. Go graph/recon은 lexical보다
analysis 호출 수가 적었지만 프롬프트 byte가 컸다. 실제 token/시간과 후보 품질을 측정하기
전에는 graph의 효율 우위를 주장하지 않는다.
계측한 JSON 들여쓰기 비용을 줄여 동일한 파싱 입력으로 세 언어 replay를 다시 생성했다.
graph/recon 전체 프롬프트 byte는 Go 94,617→80,417, Python 23,117→20,677,
Solidity 33,467→28,097로 줄었다. `benchmark-runs`가 새 원본·프롬프트 일치를 확인했다.
`pipeline.py`를 도구 identity에 포함해 형식 변경 전후의 run을 같은 도구 버전으로 비교하지
않는다. 이 절감은 byte 수치이며 모델 token·탐지 정확도의 개선 증거는 아니다.

P1-Go 연결 보강: Go HTTP 그래프·recon·analysis/triage의 후보에서 PoC proposal과 별도
합성 연구자 승인을 거쳐 worker·before/after 판정까지 같은 source/graph identity로 연결했다.
기존 slice에 없는 서버 진입 파일과 supplied harness는 `--support-file`로 명시한다. 최대
16개·256 KiB의 현재 reviewed source만 입력 hash로 추가하고, 중복·미검토 파일 또는 검토 후
소스 변경은 agent 호출/worker 실행 전에 거절한다. Go PoC replay와 FakeDocker 정상·변경
거절 테스트는 단계 간 계약을 확인한다. FakeDocker 로그는 실제 HTTP 요청·취약점 재현의
근거가 아니다. 실제 Docker/실모델 반복 품질 측정은 여전히 남아 있다.

같은 Go PoC의 승인 recipe와 수정 후 사본을 로컬의 digest-pinned Go 이미지에서 실제
격리 실행했다. 컨테이너 내부 HTTP 요청에서 guest는 수정 전 `200/private-record`, 수정 후
`403/DENIED`였고 admin 대조군은 유지됐다. `judge`는 이 합성 fixture 요청에 한해
`validated/eligible`을 기록했다. 명시적 로컬 Unix Docker socket으로 전체 Go HTTP 테스트
**17개 통과**를 확인했으며, 잘못된 경로·위조 marker·전체 차단 수정은 승격되지 않았다.
PoC의 `offline-fixture` 승인은 테스트용 선언이고 운영 연구자의 검토를 대체하지 않는다.
실제 모델 품질·다른 대상의 chain/impact 동적 관찰은 아직 검증하지 않았다.

M5 오프라인 평가 준비를 새 체크아웃에서도 재현할 수 있도록 `make demo-model-evaluation`을
추가했다. 커밋된 Go·Python·Solidity 소스와 정답에서 새 graph/recon·replay run·`benchmark-runs`
결과를 만들고 도구 식별자·라벨 coverage·프롬프트 byte를 `summary.json`에 남긴다.
lexical 응답은 의도적으로 빈 후보이므로 이 비교는 실행 경로·입력 범위의 사전 점검이며
모델의 탐지 정확도나 graph의 우월성을 측정하지 않는다.

실모델 평가 전 `plan`을 새 고정 입력에 다시 적용해 Go lexical/graph 최대 15/9회,
Python과 Solidity 각각 6/6회를 확인했다. 비교군의 설정을 맞추면서 Go run당 15회,
Python·Solidity run당 6회로 낮췄다. 두 반복의 엄격한 상한은 총 108회 시도이며,
token·금액 상한은 아니다. 축소한 상한으로 오프라인 리허설을 다시 통과했다.

M5 GPT-6 Luna 탐색 실행(2026-10-13): 모델용 strict JSON schema가 선택 필드와
`const` 타입을 거부하던 오류를 고쳐 원본·정규화 응답을 별도로 보존하고, adapter 코드를
도구 identity에 포함했다. 고정 대상 비교 run 8개 중 4개 완료·4개 인용 위치 검증 실패였다.
Go 첫 pair는 양쪽 모두 완료돼 lexical 12회/69.189초/입력 190,789 token,
graph/recon 6회/49.059초/101,092 token을 기록했다. 원래 대표 행·CWE 기준으로는
lexical만 양성 라벨을 유지했다. graph 후보는 진입점을 대표 행으로 택했지만 검증된
원인 근거는 sink 정답 행을 인용했다. 원인 근거 일치는 별도 보조 지표로 남겨 사후에
1차 점수를 바꾸지 않는다. Python 첫 pair, Solidity 첫 pair와 Go 둘째 pair는 최소
한 arm이 실패해 반복 비교를 만들 수 없었다. Solidity의 완료된 graph 후보는
`CWE-862`·함수 선언 행으로 제시돼 고정된 `CWE-284`·전송 행 라벨과 달랐다.
파일 끝을 넘긴 모델 source 조회도 gap으로 남았다. 이 실험은 graph의 탐지 우위나
일반화 증거가 아니다. 다음 gate는 인용 오류를 줄이는 입력/재시도 설계와 실패 시도까지
계산하는 비교, 파일 길이 안내, 사전 고정된 후보·원인·CWE 채점이다. 세부 기록은
[`docs/model-evaluation.md`](model-evaluation.md)에 있다.

M5 인용/조회 진단 보강: analysis에는 해당 slice의 indexed 파일별 최종 행 번호를
전달하고, triage에는 행 앞 공백을 포함한 `column=1` 인용을 권장한다. 원문 인용
검증과 `invalid_source_range` 거절은 유지했다. 새 오프라인 replay와 `make demo`가
통과했고 Go 실모델 진단 pair도 양쪽 완료됐다. lexical 11회/45.442초/입력
151,063 token, graph/recon 5회/30.163초/84,875 token이었다. 대표 행·CWE의
1차 점수는 이전 Go pair처럼 lexical만 양성을 유지했고 graph의 원인 근거는
정답 sink 행을 인용했다. 이번 graph 조회는 파일 끝을 넘지 않았지만 모호한
selector가 별도 gap으로 남았다. 한 pair에서 인용 실패가 없었던 것은 개선의
재현성 증거가 아니다. 앞서 승인한 12개 유료 run 상한을 소진했으므로 추가 모델
반복은 별도 범위 지정 후 진행한다. 다음 gate는 실패 run의 원본 token·시간을
누락하지 않는 집계와, 후보 대표 위치·원인 근거·CWE 동등성 규칙을 사전 고정한
다언어 반복 평가다.

M5 실패 시도 비용 계측: `benchmark-attempts`가 완료·실패·미확정 Codex run을
재실행하지 않고 manifest, 원본 event, 성공 reply, 실패 기록을 대조한다.
원본 사용량이 빠진 시도는 `null`/coverage로 남기고 시간 누락은 `unknown`으로
보존한다. 정상·검증 실패·HTTP 400·변조·미확정 입력을 offline 테스트와 실제
저장 run에 적용했다. 승인된 12개 유료 run의 65회 시도 중 완료된 turn 63회에
대해서만 입력 token 971,369개가 보고됐다. 저장된 호출 시간 합계는 357.870초로
graph/recon 준비와 provider 외부 시간을 제외한다. 2회는 사용량이 보고되지 않아
총 비용을 확정할 수 없다. 다음 gate는 위치/CWE 채점 규칙을 사전 고정하고,
Go·Python·Solidity의 완료된 두 pair씩을 확보해 실패율·전체 비용까지 비교하는 것이다.

M5 채점 규칙 고정: 대표 위치·CWE와 미기각 판정을 1차 후보 유지로,
검증된 원인 근거의 정답 인용을 2차 지표로 분리했다. 반복 요약은 두 횟수를
정답별로 따로 남긴다. 기각 후보의 원인 인용은 1차 점수가 아니며 CWE 동등성은
사후에 넓히지 않는다. 실패 pair의 호출·사용량은 `benchmark-attempts`로 따로
보존한다. 다언어 완료 pair와 실제 비용 비교는 아직 남아 있다.

M5 실패 원인 계측: 저장된 실패 응답 4건을 현재 검증기에 오프라인 대조해
인용 행 2건·UTF-8 byte 열 2건의 불일치를 확인했다. 새 run의 인용 검증 실패는
고정 코드와 원본 응답을 함께 보존하고 `benchmark-attempts`에서 횟수를 집계한다.
이전 run의 오류 코드는 추정하지 않는다. 재시도나 추가 유료 호출은 수행하지 않았다.

M5 제한된 인용 수정: 명시적인 `--repair-citations` 옵션에서만 logical call당 한 번
수정 요청한다. 거절 응답·오류 코드·원본 hash를 고정하고 같은 검증기를 다시 적용한다.
호출 상한 전에 준비된 수정은 재개할 수 있지만, 이미 시작한 수정은 실패/중단 후 자동
반복하지 않는다. 호출·스키마 오류는 자동 재시도하지 않는다. 비교 보고서와 반복 요약은
최초 실패까지 포함한 token·시간·프롬프트 byte를 집계하고, 실제 성공 시도와 실패 원문의
변조를 거절한다. analysis 행·triage byte 열 수정, 상한/재개, 재실패, transport 오류,
반복 집계와 미확정 시도의 보존을 offline 검사했다. 실모델 개선 효과는 아직 검증하지 않았다.

M5 인용 수정 옵션의 추가 실측(2026-10-13): 별도 승인한 `gpt-6-luna` 평가 12개 run을
고정된 세 언어/두 arm/두 반복으로 순차 실행했다. 68회 시도에서 8개 run 완료·4개 인용
재실패였고, 실패 시도 10건·미확정 0건과 모든 시도의 보고 사용량/시간을 보존했다.
수정 요청 6건 중 2건이 통과했지만 두 응답 모두 Solidity 후보 철회여서 정확한 인용 수정
성공으로 보지 않는다. Go·Python의 첫 pair만 비교 가능했고 양쪽 graph/recon의 호출 수는
적었지만 입력 token은 늘었다. 두 번째 pair들은 한 arm이 실패했고 Solidity는 두 pair 모두
불완전하므로 반복 요약을 생성하지 않았다. **M5 다언어 반복 평가 gate는 미충족**이다.
원본 `runs/model-eval-repair.tjM9VK/`와 수치는 [실모델 평가 기록](model-evaluation.md)에 남겼다.
다음 관찰 가능한 milestone은 실패 필드의 위치와 제한된 원문을 제공하는 인용 수정 피드백,
후보 철회/실제 인용 수정의 별도 계측과 저장 실패 응답의 오프라인 회귀다.
새 유료 평가 없이 이 경계를 먼저 구현·검증하며 현재 결과에서 병렬화를 추가하지 않는다.

M5 오류 필드와 수정 결과 보강: 위 실패 원문 10건을 `examples/citation-failure-cases.json`에
소스 fragment/오류 코드와 함께 고정했다. analysis 후보, triage 원인/수정/반증/미해결,
대상 함수 모델의 근거까지 JSON 필드 경로를 붙인다. 수정 feedback은 실제 제공한 fragment의
주변 3행·4 KiB와 첫 정확한 UTF-8 byte 열만 제공하고, 입력 밖/큰 행을 명시적으로 생략한다.
원문 검증·호출 상한·1회 수정 제한을 유지한다. accepted 응답의 인용-only 변경·후보 철회·
기타 내용 변경을 나누고, metrics/보고서/attempt 비용 계측에 failed/pending/unknown도 남긴다.
이전 68회 시도의 읽기 전용 재집계는 후보 철회 2건·수정 실패 4건으로 원본 관찰과 일치했다.
다언어 반복 평가 gate는 여전히 미충족이며 이 코드의 실모델 효과는 별도 실험이 필요하다.

최종 검사: `make check`에서 Ruff lint/format과 **726개 테스트 통과·23개 skip**을
확인했다. 집중 검사 163개, `make demo`의 fresh/resume, 인용 수정 replay CLI와
`make demo-model-evaluation`도 통과했다. 새 preflight는
`runs/model-eval-preflight.ZH4c4l/`, 도구 hash는
`852e274c8916d3353d5921da0935086ab5e18f6144ebbe217b43bbf742fbc442`다.
소스·모델·채점·예산과 12개 실행 순서를 고정한 다음 실험의 `protocol.json`을
`runs/model-eval-feedback.c645kqlr/`에 준비했고 사용자 승인 후 순차 실행했다. 68회 시도에서
9개 run 완료·3개 실패, 실패 시도 8건·미확정 0건이었다. 인용 수정 요청 5건 중 2건이
통과했지만 모두 `reply_revised`였고 `citation_corrected`는 0건이었다. 완료 pair는 Go 2개와
Solidity 1개다. Go graph/recon은 두 번 모두 호출과 입력 token을 줄였으나 양성 유지는
1/2로 lexical의 2/2보다 낮았고, 음성 통과는 2/2로 lexical의 1/2보다 높았다. Solidity는
양쪽 모두 양성을 놓쳤고 Python은 lexical 실패로 완료 pair가 없다. 따라서 비용 감소만
Go 합성 fixture에서 반복됐으며 **M5 다언어 반복 평가 gate는 계속 미충족**이다. 전체 결과는
[`docs/model-evaluation.md`](model-evaluation.md)와 run의 `observations.json`에 보존했다.

M5 다중 인용 피드백 보강: 실패 run을 대조한 결과 한 응답의 첫 인용만 피드백해 다음
잘못된 인용에서 재실패하고, 수정 응답이 새 잘못된 인용을 추가하는 사례가 있었다. 기존
검증 기준과 logical call당 1회 상한을 유지하면서 analysis·triage 응답의 인용 오류를 최대
8개 함께 기록한다. 각 오류에는 supplied fragment 안의 동일 quote 시작 위치만 최대 8개
제공하며 자동으로 행·열을 바꾸지 않는다. 다중 analysis 인용을 한 번에 수정하는 성공 경로,
여러 triage byte 열 실패, 초과/원문 경계를 offline 검사했다. 이 변경 이후 실모델 호출은
수행하지 않은 상태에서 새 `make demo-model-evaluation`은
`runs/model-eval-preflight.8KZtd9/`에 source·graph/recon·정답 비교를 만들었고 도구 hash
`71e59876f654514357e0e31f5d6699931b50897717949cf33bfbe6bf5eda2cb0`를 기록했다.
같은 12개 run·108회 시도 상한의 후속 프로토콜은
`runs/model-eval-batch-feedback.qz1odqas/protocol.json`에 고정한 뒤 별도 승인으로 실행했다.
75회 시도에서 9개 run 완료·3개 실패, 실패 시도 6건·미확정 0건이었다. 인용 실패 6건의
수정 결과는 `citation_corrected` 1건·`reply_revised` 4건·`pending` 1건이었지만 정확한 수정
한 건이 속한 Python run도 뒤 단계에서 cap을 소진했다. 완료 pair는 Go 2개와 Solidity 1개다.
Go graph/recon은 호출을 두 번 모두 11→7로 줄였으나 입력 token 차이는 -2,840/+5,206,
기록 시간 차이는 +4.050/+2.636초였다. 검증된 원인 근거는 두 번 모두 정답 sink를 인용했지만
후보 대표 위치가 HTTP 입력 행이어서 사전 고정한 1차 양성 점수는 0/2였고 lexical은 2/2였다.
Python은 완료 pair가 없고 Solidity 완료 pair는 양쪽 모두 양성을 놓쳤다. 따라서 다중 피드백도
완료율과 M5 다언어 gate를 개선하지 못했으며 graph/recon의 일반적인 효율 우위는 입증되지 않았다.
전체 수치와 해석은 [실모델 평가 기록](model-evaluation.md)에 보존했다.
대표 행 하나의 채점이 입력 행·함수 선언에 붙은 후보를 놓치는 한계가 드러나,
새 truth에서만 `accepted_locations`를 최대 4개 사전 선언하도록 보강했다. 각 위치의
원문·CWE와 사례 간 중복을 검사하고 사례당 한 번만 채점한다. 이전 실험은 단일 위치
정답과 점수를 유지하며, 새 위치 계약의 실모델 효과는 아직 측정하지 않았다.
다음 평가를 위해 기존 실모델 응답에 쓰이지 않은 Go·Python·Solidity 합성 입력과
양성·음성 truth를 별도로 고정했다. `make demo-model-evaluation-prospective`로 세
언어의 graph/recon 관계·source-backed 위치·양쪽 slice 포함과 오프라인 비교를
확인했다. 인용 수정과 조회가 모두 필요한 경우까지 arm당 상한을 18/12/12로 잡아
두 반복·두 arm의 최대 호출 시도는 168회다. 이 preflight는 빈 응답을 사용했고
실모델 효과는 측정하지 않았다. 새 소스·계획·정답의 복사본과 hash, 실행 순서는
`runs/model-eval-prospective.yEMrOO/protocol.json`에 승인 전 상태로 다시 고정했다.
이전 `SNIzAy` 입력은 recon 도구 변경으로 식별자가 달라져 실행 전에 대체했다.
초기 준비본은 음성 대조군의 대체 위치를 빠뜨려 유료 실행 전에 철회했다.
근거와 범위는 [평가 기록](model-evaluation.md)에 있다.

Agent I/O 경계 보강: 실모델 평가 artifact를 검수하며 최종 JSON의 기존 128 KiB 제한과 달리
Codex event/stderr가 timeout까지 무제한 기록되고 replay loader에도 파일 수·byte 제한이 없음을
확인했다. Codex event/stderr를 stream별 8 MiB에서 process group 종료하고, replay를 regular
JSON 최대 128개·개별 128 KiB·합계 8 MiB로 제한해 symlink를 거절한다. 정상 adapter와
timeout·로그 초과·replay 네 경계를 offline 검사했다.
`run`과 비용 보고의 상한도 공통 128회로 맞춰, 실행 후 `benchmark-attempts`가 읽지 못하는
설정을 CLI와 programmatic 진입에서 거절한다.
CI는 기존 unit/integration 외에 누락됐던 `demo-python`, `demo-benchmark`,
`demo-model-evaluation`도 실행해 공개된 오프라인 추출·비교·preflight 배선을 확인한다.
최종 로컬 검사는 `make check` **731개 통과·23개 skip**, 집중 검사 92개와 `make demo`,
`demo-python`, `demo-benchmark`, `demo-model-evaluation` 통과다.

2026-10-13 현재 코드에서 준비된 digest-pinned Go 이미지를 사용해 `make demo-go-http`를
다시 실행했다. `runs/go-http-demo.5mJ4az/`의 격리 로그에는 guest가 수정 전
`200/DATA private-record`, 수정 후 `403/DENIED`, admin은 양쪽에서
`200/DATA private-record`로 기록됐다. 두 worker는 network `none`·read-only root·capability
제거·1 GiB/64 pids 정책을 확인하고 컨테이너를 제거했다. `judge`는 이 합성 요청에 한해
`validated/eligible`을 기록했다. 같은 로컬 이미지로 `tests/test_go_http.py`의 실제 Docker
정상·음성 사례 **17개가 통과**했다. 외부 대상의 품질이나 실모델 평가를 뜻하지 않는다.

M5 최종 반복 평가(2026-10-13): 별도로 승인한 고정 신규 입력에서 `gpt-6-luna`로
Go·Python·Solidity의 lexical/graph+recon을 각각 두 번 순차 실행했다. 12개 run과
언어별 2개 pair가 모두 완료됐고, 59회 호출 시도 중 인용 실패 2회는 수정 후 완료,
미확정은 0회였다. 양성 유지 lexical→graph/recon은 Go 0/2→0/2, Python 1/2→2/2,
Solidity 2/2→2/2였고 음성은 양쪽 모두 6/6 통과했다. graph/recon의 호출 수는
35→24로 적었지만 언어별 token·시간은 엇갈렸다. `runs/model-eval-prospective.yEMrOO/`
안의 `execution-result.json`, 여섯 comparison, 세 summary와 12개 attempt 보고서를
재검산했다. 이로써 **합성 첫 버전의 M5 반복 측정 gate는 충족**하지만, 원문 수준의
탐지율·일반적 효율·실제 대상 결과는 입증하지 않는다. 최종 변경 기준 `make check`는
739개 통과·23개 skip, `make demo`와 `make demo-recon`도 통과했다.

후속 정밀화 D1→R1→G1→V1(2026-10-13): [세부 계획과 완료 기준](research-fidelity-plan.md)에
따라 엄격 점수를 유지한 위치/CWE 진단, 진입 사실→정적 역할의 예산 제한 직접 호출 경로,
Go 직접 호출 인자→매개변수 근거와 `go-http-file-selection` 역할 규칙을 구현했다.
동일 소스의 상수 파일명 대조군·미해결 dispatch·누락/변조를 검사했다.
`make check`는 744개 통과·23개 skip이며 `make demo`, `demo-go`, `demo-recon`도 통과했다.
별도 승인된 `gpt-6-luna` Go 적응적 2쌍 평가는 원본 실패 1건을 보존한 새 프로토콜에서
4 run·21회 시도로 완료했다. 엄격 양성 0/2→0/2, 음성 2/2→2/2였고 graph arm은
`CWE-73` 후보 2개를 남겼으나 두 번 모두 대표 위치가 사전 라벨 밖이었다.
호출 수 12→9와 달리 입력 token·기록 시간은 증가했다. 이 작은 후속 실험으로
탐지·비용 개선을 주장하지 않는다. [평가 기록](model-evaluation.md)에 원본과 한계를 보존했다.

후속 Go 값 경로 gate(2026-10-13): 대표 위치를 위험 동작으로 고정하는 analysis 계약과
단순 scalar 호출 반환값→매개변수→파일 열기의 제한된 경로를 Go graph/recon/slice에
연결했다. 분기·재대입·주소 이탈·클로저·변환·가변 값·간접 호출은 미해결로 두고,
다중 패키지·상수 음성·예산 누락을 테스트했다. 최종 코드에서 `make check`는
751개 통과·23개 skip, `make demo`, `demo-go`, `demo-recon`도 통과했다.
새 합성 Go fixture의 최종 코드 재실행은 lexical/graph/static-value의 엄격 양성이
각각 1/2, 2/2, 2/2이고 음성은 모두 2/2였다. 이는 앞선 첫 실행에서 lexical
2/2, graph 1/2, static-value 2/2였던 것과 다르다. 모델 출력 변동성과 같은
fixture 재사용 때문에 일반적인 개선이나 값 경로 단독 기여는 입증되지 않았다.
세부 원본·비용은 [평가 기록](model-evaluation.md)에 남겼다.
별개인 기존 Go HTTP 합성 fixture는 준비된 로컬 이미지의 격리 worker로 다시 실행해
`runs/go-http-demo.rJ9Luj/`에서 실제 등록 진입점 요청·수정 전후·정리와
`judge`의 `validated` gate를 확인했다. 이번 파일 선택 모델 평가의 동적 재현은 아니다.

후속 실제 진입점 gate(2026-10-13): 모델 평가 입력은 그대로 두고 별도
`examples/go-file-selection-target`에 일반 HTTP server와 고정 요청 harness를 공급했다.
`web.Download → relay.Fetch → storage.Open → os.ReadFile(key)` 후보는
`storage/files.go:6`·`CWE-73`을 인용한다. 준비된 로컬 Go 이미지에서
`make demo-go-file-selection`을 실행한 `runs/go-file-selection-demo.tHck3v/`의
수정 전 private 요청은 `200/DATA private-record`, 후보 소스의 허용 목록 수정 후
같은 요청은 `404/unavailable`이었다. 공개 파일과 상수 notice 요청은 양쪽 모두
`200`과 기대 본문을 유지했다. 두 worker는 격리 정책 확인·컨테이너 제거까지 완료했고
`judge`는 이 합성 사례에 한해 `validated/eligible`을 기록했다. 하네스 해시 변경은
실행 전 거절되며, `make check`는 753개 통과·24개 skip, 실제 Docker 집중 테스트는
3개 통과했다. 이는 사용자가 제공한 격리 이미지와 fixture의 재현 근거이며,
모델이 새 사례를 발견했거나 외부 저장소에서 같은 결과를 낸 증거는 아니다.

값 경로 분리 평가(2026-10-13): 기존 파일 선택 입력에서 정적 역할은 그대로 두고
Go 인자 출처·전달 metadata만 제거한 arm과 full arm을 두 번 비교했다.
`runs/go-value-ablation-20261013/`의 완료된 4 run은 양성·상수 음성 모두
양쪽 2/2였고, 실패 포함 호출은 static-only/full 10/6회였다. 인용 실패 1회와
모델 출력 전에 거절된 로컬 sandbox 초기화 1회를 분리 보존했다. 이 입력은 이전
모델 응답을 본 뒤 재사용한 적응적 사례라 일반 효과의 근거가 아니다.

새 Go 합성 홀드아웃에서는 `os.Getenv → dispatch.Start → runner.Build →
exec.Command("sh", "-c", value)`와 고정 문자열 대조군을 모델 실행 전에
`examples/go-eval-holdout-truth.json`에 고정했다. lexical/static-only/full을
각각 2회 실행한 `runs/go-holdout-20261013/`은 6 run·29회 시도에서 실패·
미확정 0회였다. 세 arm의 엄격 양성·음성은 모두 2/2였다. 호출 합계는
14/8/7회이나 static-only→full의 반복별 호출 차이는 +1/-2회로 일관되지 않았다.
정답은 쉘 명령 **구성 후보**이고 실행·공격자 환경 제어는 검증되지 않았다.
원본 시도와 반복 보고는 [평가 기록](model-evaluation.md)에 있다.
따라서 현재 측정으로 Go 값 경로의 탐지 개선이나 비용 우위를 확정할 수 없고,
측정된 Go 미탐 유형도 없다.

언어별 값 근거 첫 gate(2026-10-13): Python은 공통 graph v2의 직접 호출
인자→매개변수, 직선형 출처, 정적 source/sink와 연결된 제한된 recon 값 경로를
추가했다. 파일 간 `input → worker.execute → os.system`과 직접 sink,
상수 대조군, 분기·재대입 unknown, 위조된 출처 거절을 검증한다. Solidity는
확정된 직접 내부 호출의 인자 원문·대상 매개변수와 매개변수/literal 출처만
추가했다. 외부·virtual·super 호출은 전달 관계로 승격하지 않고 복합식 출처는
unknown이다. Solidity 정적 역할 adapter와 source→sink 값 경로는 아직 없다.
두 언어의 그래프 사실은 실행이나 공격자 제어의 증명이 아니다.

다음 gate는 제3자가 작성한 미관측 저장소와 고정된 평가 기준에서 반복 측정하고,
Solidity에는 별도로 선언한 source/sink 역할·상수/미해결 대조군을 마련한 뒤
지원 가능한 구문 경로만 연결하는 것이다. 조건·동적 호출이나 저장소 설정의
실제 의미는 별도 검증 근거가 없으면 unknown으로 유지한다.
현재 코드에서 `make check`는 757개 통과·24개 skip이며 `make demo`,
`demo-python`, `demo-solidity`, `demo-static`, `demo-recon`이 통과했다.

DeFiHackLabs 실사례 첫 진단(2026-10-13): [평가 프로토콜과 UniLend 파일럿](defihacklabs-evaluation.md)에
사건 앵커, 피해 구현 원문 검증, 실제 graph 추출 결과와 미채점 이유를 기록했다.
PoC 대신 피해 구현 7개 파일을 읽기 전용으로 분석했고 91개 함수·306개 호출을
추출했다. 그래프는 소각→건전성 검사→전송과 검사 내부의 잔액 조회를 연결하지만
상태 효과는 판정하지 않는다. Solidity 정적 adapter가 없으므로 현재는 탐지 점수를
내지 않는다. 이 실사례의 실패 원인을 기준으로 한 번에 한 근거 계층씩 보강한다.
