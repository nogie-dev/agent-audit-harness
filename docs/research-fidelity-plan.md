# 연구 흐름 정밀화 계획

기준은 [Quarkslab의 graph → recon → slicing → analysis → triage → PoC → chain → exploit 연구](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)다. 기존 [로드맵](roadmap.md)의 합성 fixture 첫 버전은 연결·측정을 마쳤다. 이 계획은 그 결과에서 확인한 **탐지 진단과 관계 근거의 빈틈**을 좁히는 다음 개발 범위다. 외부 대상을 감사하거나 원문의 RCE 결과를 재현하는 계획은 아니다.

## 관찰과 완료 기준

고정 Go 평가의 4개 run은 모두 요청값으로 파일을 선택할 수 있다는 후보를 냈지만 `CWE-22`를 붙였다. 사전 선언한 정답은 `CWE-73`이고, 엄격 채점은 경로·행·CWE가 모두 같아야 양성으로 센다. graph/recon 후보 둘은 source→sink를 원문으로 설명하고 `needs_validation`으로 남았으나 엄격 점수는 0/2였다. lexical은 파일별 slice와 사용할 수 없는 graph 조회 때문에 두 번 모두 `uncertain`이었다. 원래 점수·정답·원본 응답은 유지한다.

이 단계의 완료는 아래 네 gate가 **각각 관찰 가능한 결과**를 남기는 것이다. 측정 통과를 일반적 탐지 우위로 해석하지 않는다.

| 순서 | 구현 범위 | 완료 증거 | 명시적 경계 |
| --- | --- | --- | --- |
| D1 평가 진단 | 기존 엄격 점수와 별도로 위치만 일치한 후보, CWE만 다른 후보, 원인 근거가 정답 위치를 인용한 후보를 읽기 전용 보고 | 저장된 Go run에서 엄격 0/2는 불변이고 분류/대표 위치 차이를 구분; 음성·기각·중복 테스트 | CWE 동등성이나 취약성 판정은 자동 추정하지 않음 |
| R1 recon 관계 | 공급된 entry 사실과 정적 source/sink/sanitizer 역할 사이의 **확정된 직접 호출 경로**를 byte 예산 안에서 제시 | 다중 파일 경로, 통제 후보, 미해결/예산 누락을 Go·Python fixture로 검사 | 경로는 데이터 흐름·노출·통제 효과가 아님 |
| G1 Go 전달 사실 | 타입으로 확정된 직접 호출에서 호출 인자와 피호출자 매개변수의 위치·표현식을 연결 | 다른 파일/패키지의 인자 전달과 상수 대조군, interface/function-value 미해결, 소스 변경 거절 | 인자 전달은 taint 증명이나 실행 간선 추가가 아님 |
| V1 확대 검증 | 기존 Go 양성·음성 사례와 새 전달 사실을 오프라인으로 재검사하고, 필요하면 고정한 새 입력에서 제한된 실모델 비교 | `make check`, 관련 demo, 고정 source/truth/도구 hash·호출 상한, 원본 시도/실패/비용 기록 | 작은 합성 표본; 실제 대상의 발견률·영향 주장 금지 |

## 구현 순서와 변경 경계

1. D1은 `benchmark.py`의 기존 `score_run` 결과에 **추가 진단 필드**를 둔다. 엄격 label 수와 기존 `benchmark-summary` 결과를 바꾸지 않는다. 후보의 대표 위치와 `root_cause.evidence` 위치를 분리하고, CWE가 다른 경우 실제 출력값을 그대로 기록한다. 저장된 예전 report는 재계산해서 읽되 원본을 고치지 않는다. 동일 위치·다른 CWE와 동일 CWE·다른 위치의 정상/실패 테스트를 먼저 넣는다.
2. R1은 `recon_proposal.py`의 기존 facts/functions/calls 입력을 재사용한다. 정적 역할이 붙은 함수까지의 확정된 call ID 경로만 계산하고, 예산에 빠진 관계와 경로를 알 수 없는 역할을 `coverage.json`에 남긴다. 새 관계는 prompt에서 구조 사실로만 설명한다. 모델 제안은 여전히 원문 인용·entry 사실 검사를 거친다. 원래 공통 graph 계약은 바꾸지 않는다.
3. G1은 `extractors/go_helper/main.go`가 이미 사용하는 typed AST에서 실제 call argument의 좁은 사실을 추출한다. 직접 확정된 내부 호출과 매개변수 index가 맞는 경우만 대응시키고, 동적 dispatch는 미해결로 유지한다. 추출한 표현식과 위치는 graph call의 Go metadata에 넣어 기존 schema/조회/다른 언어를 유지한다. downstream slice는 기존 call metadata를 그대로 전달한다. 타입 정보·byte 위치·소스 hash를 테스트하고 원문 실행은 하지 않는다.
4. V1은 Go의 양성 요청값 전달과 상수 파일명 대조군, 거짓 interface 연결을 함께 확인한다. 기존 격리 Go HTTP 수정 전후 관찰은 별도 실행 증거로 유지한다. 모델 호출이 필요한 경우 먼저 입력·정답·채점·순서·최대 run/시도를 새 프로토콜에 고정하고 `gpt-6-luna`를 사용한다. 이전 M5 정답이나 run을 소급 변경하지 않는다.

각 gate마다 책임 코드·계약/프롬프트·fixture·성공/실패 테스트를 함께 바꾼다. 대상 코드는 호스트에서 실행하지 않는다. 기본 검사는 오프라인이며 `make check`와 영향을 받는 demo를 통과시킨 뒤 다음 gate로 이동한다. 모델 평가가 실패해도 원본과 비용을 보존하고, 실패를 새 입력으로 바꾸어 숨기지 않는다.

## 실행 결과와 다음 연구 경계

2026-10-13 현재 D1·R1·G1·V1의 **구현·검증 gate는 완료**했다. 이는 합성 입력의
근거 연결과 반복 측정 완료를 뜻하며, 외부 저장소의 발견률이나 원문의 RCE 연구 결과와
동등하다는 뜻은 아니다.

| Gate | 확인한 결과 | 남은 한계 |
| --- | --- | --- |
| D1 | 이전 Go 2쌍의 엄격 양성은 양쪽 0/2로 유지. lexical 후보 2개는 대표 위치만 맞고 CWE-22, graph/recon 후보 2개는 정답 원인 위치를 인용했지만 CWE-22. 음성·기각·잘못된 hash와 옛 보고서 호환 검사 통과 | 진단은 판정 승격이 아니며 새 모델 응답의 위치 선택은 여전히 흔들림 |
| R1 | Python의 `entry.across_files → worker.execute`와 Go의 `Selected → ReadSelected` 확정 호출 경로를 공급. Go source/sink 역할은 각각 정적 모델이며 파일 간 taint 결과는 0. 관계 부재·예산 누락 보존 | 단일 최단 경로, 256쌍 상한; 데이터 전달·통제 효과·실제 진입은 별도 근거 필요 |
| G1 | Go의 `store.ReadSelected(name)`에서 `name → name string` 인자/매개변수 사실과 상수 대조군 기록. interface/function-value는 미해결, 메서드·generic 등은 gap. source hash·byte 위치·변조 거절 검사 통과 | 호출 하나의 구문 사실이며 값의 출처를 함수 간 전파하지 않음 |
| V1 | `make check` 744 pass·23 skip, `make demo`, `make demo-go`, `make demo-recon` 통과. 별도 고정 Go 후속 평가 4 run/21회 호출 시도, 미확정 0 | 후속 평가는 이전 실패를 본 뒤 설계한 적응적 합성 실험; 개선 효과를 한 요소에 귀속할 수 없음 |

후속 평가의 엄격 양성은 lexical 0/2, graph+recon+static 0/2로 그대로였다.
graph arm은 `CWE-73` 후보를 2/2 만들었지만 두 번 모두 후보 대표 위치를 사전 허용하지 않은
HTTP 입력 행에 두었다. 한 번은 정답 sink를 원인 근거로 인용했다. 음성 대조군은 양쪽 2/2 통과했다.
호출은 12→9로 감소했으나 실패 1회까지 포함한 입력 token은 182,192→242,279,
기록된 호출 시간은 54.357→63.477초였다. 이 결과는 비용 우위나 엄격 탐지 개선을
보이지 않는다. 원본·프로토콜·비용 근거는 [실모델 평가 기록](model-evaluation.md)에 있다.

이후 gate에서 새 합성 입력의 대표 위치를 먼저 고정하고 정적 역할과 Go 값 경로를
분리 비교했다. Go 값 경로와 Python의 제한된 구문 경로, Solidity의 직접 인자 전달
사실 및 합성 HTTP 예제의 격리된 전후 검증을 구현했다. 제3자 미관측 저장소의
반복 평가와 Solidity 정적 역할·source→sink 경로는 남아 있다. 현재 결과만으로
지원 언어 전체의 보안감사 완성이나 실제 대상 취약점 재현을 선언하지 않는다.

## 후속 순차 gate: 대표 위치와 Go 값 경로

1. **위치 계약:** analysis 후보의 대표 위치는 입력 수집 행이 아니라 안전성이
   문제되는 동작 또는 빠진 검사의 지배를 받는 동작이다. source와 원인 근거는
   별도로 인용한다. 기존 truth와 점수는 변경하지 않는다. 새 미관측 fixture는
   이 규칙에 따라 모델 호출 전에 양성·음성 위치와 CWE를 고정한다.
2. **좁은 Go 값 경로:** typed AST의 단순 scalar 대입·매개변수 전달을 source/sink
   역할 근거에 연결한다. 분기, 루프, 재대입, 가변 값, 동적 호출과 준비되지 않은
   정적 역할은 경로 부재/unknown으로 남긴다. 다중 패키지 경로와 상수·분기·재대입
   대조군을 테스트한다. graph v2를 유지하고 recon의 선택적 사실로 전달한다.
3. **독립 평가:** 새 소스·정답·도구 hash·실행 상한을 먼저 동결한 뒤 lexical,
   graph+recon, graph+recon+static/value 세 arm을 동일 모델로 비교한다.
   엄격 점수, 후보 철회, 음성, 호출·token·시간·실패 비용을 모두 보존한다.
   합성 결과가 실제 대상 탐지율이나 비용 우위를 입증하지는 않는다.

2026-10-13 실행: 대표 위치 계약을 analysis prompt에 반영했고, 새 Go fixture의
`storage/files.go:6` 파일 열기를 양성 대표 위치, 10행의 상수 파일 열기를 음성으로
고정했다. Go typed AST는 단순 scalar의 호출 반환값·매개변수 출처를 기록하고,
정적 역할과 연결한 제한된 다중 패키지 경로를 recon 및 analysis slice에 넣는다.
분기·재대입·주소 이탈·클로저·변환·가변 값·간접 호출은 경로를 합성하지 않는다.
16KB에서 경로가 빠지면 `value_flow_input_omitted`를 남기고, 20KB에서 공급되는
것을 테스트했다. `make check` 751개 통과·23개 skip, `make demo`, `demo-go`,
`demo-recon` 통과. 새 fixture에서는 대상 코드나 build script를 실행하지 않았다.

모델 입력을 보기 전에 고정한 첫 3-arm 프로토콜은
`runs/model-eval-go-value-20261013/`에, 주소 이탈 등의 경계를 보수화한 최종
코드의 새 도구 hash와 재실행은 `runs/model-eval-go-value-20261013-v2/`에 보존했다.
첫 프로토콜은 6 run·38회 시도(인용 실패 4회)에서 엄격 양성 lexical 2/2,
graph+recon 1/2, static/value 2/2였다. 최종 코드 재실행은 같은 소스·truth의
6 run·33회 시도(실패 0회)에서 각각 1/2, 2/2, 2/2였고 음성은 모든 arm에서
2/2 통과했다. 두 실행의 차이와 작은 표본은 결과 변동성을 보여준다.
최종 코드의 호출 수는 lexical/graph/static-value 순서로 18/8/7회, 실패 포함
입력 token은 269,520/173,940/153,484개였다. static 역할과 값 경로를 같은
arm에 넣었으므로 어느 요소가 모델 응답을 바꿨는지 분리할 수 없다. 실제 진입점
검증은 **기존 Go HTTP 합성 fixture**에서 `runs/go-http-demo.rJ9Luj/`의 격리 worker를
새로 실행했다. 준비된 digest 고정 로컬 이미지에서 수정 전/후 HTTP 요청, 정리,
`judge`의 `validated`·진입점·수정 비교 gate를 통과했다. 이는 이번 새 파일 선택
fixture의 동적 재현이나 외부 저장소 검증은 아니다. 미관측 저장소의 반복 평가도
별도 gate다.

파일 선택의 실제 진입점은 모델 평가 입력과 별도인
`examples/go-file-selection-target`에서 확인했다. 동일한 공급 HTTP harness가
private·public·상수 notice 요청을 수정 전후 격리 worker에 보냈고, 후보 파일
`storage/files.go`만 허용 목록으로 교체했다. `runs/go-file-selection-demo.tHck3v/`에서
private 200→404, 공개·notice 200 유지, 두 worker 정리와 `judge`의
`validated/eligible`을 확인했다. 동결된 모델 평가의 독립성은 주장하지 않으며,
정적 역할과 값 경로의 개별 효과 및 미관측 입력 평가는 다음 gate로 남는다.

이후 static-only/full 분리 비교와 새 Go 쉘 명령 합성 입력의 lexical/
static-only/full 2회 반복까지 실행했다. 기존 파일 선택은 양쪽 엄격 양성·
음성 2/2, 새 합성 입력은 세 arm 모두 2/2였다. 새 입력의 static-only→full
호출 차이가 반복별 +1/-2회라 값 경로의 안정적인 개선을 주장하지 않는다.
`runs/go-value-ablation-20261013/`과 `runs/go-holdout-20261013/`에
사전 고정 프로토콜·시도·비교·해시를 보존했다. 이 단계에서는 새 Go 분기/동적
호출을 억지로 해결할 근거가 없다.

이어 Python은 공통 graph v2에서 단순 직선형 출처와 직접 인자→매개변수 사실을
추출하고, 기존 정적 역할과 정확히 연결되는 source→sink 구문 경로를 recon에
전달했다. 파일 간 경로·상수 대조군·분기/재대입 unknown과 변조 거절을 테스트했다.
Solidity는 직접 내부 호출의 인자/매개변수 사실과 매개변수·literal 출처까지만
추출한다. 외부·virtual·super와 복합 표현식은 해결하지 않는다. 정적 역할
adapter가 없으므로 Solidity source→sink 경로는 생성하지 않는다. 이 경계와
제3자 미관측 저장소의 반복 평가는 다음 작업이다.
