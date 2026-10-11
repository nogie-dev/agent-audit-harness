# 구현 계획과 완료 기준

기준: [Quarkslab 연구](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)의
`graph → recon → slicing → analysis → triage → poc → chain → exploit`.
현재 M0, G0와 Go의 G0.1·M1·M2 첫 버전, G1의 Solidity 추출기가 구현되어 있다.
호출 관계는 실행 조건·데이터 흐름·공격자 노출을 증명하지 않는다.

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

## 이후 단계

현재 M1은 연구자가 제공한 계획을 근거에 연결한다. 자동 노출 탐색·위협 모델 생성·우선순위 추정은
아직 구현하지 않았으며 실제 사례에서 필요를 확인해 M1을 확장한다.

| 단계 | 구현 | 완료 조건 |
| --- | --- | --- |
| G1 | Solidity 추출기·공통 recon 연결 완료; Python 추출기와 언어별 노출 adapter 예정 | 공통 계약 유지; 상속·modifier·외부 호출, import·동적 호출의 사실과 미해결 경계 검증 |
| A1 | 기존 analyzer의 정적 분석 연동 | source/sink·통제·taint·패턴 결과에 provenance와 한계를 보존; 호출 간선을 taint로 취급하지 않음 |
| T1 | 원인 기준 triage와 반증 | 같은 broken control·수정 방법을 공유하는 후보만 묶고 반증과 보류 근거를 보존 |
| M3 | 격리된 validation worker | 호스트 실행 없음; network·credential·자원 제한, build matrix·source hash, 실패·timeout 기록 |
| M4 | 결과 승격과 reachability | 직접 함수 재현과 실제 entry point를 구분; 수정 전 실패·수정 후 성공과 검토할 증거 묶음 |
| M5 | benchmark와 필요한 병렬화 | 동일 예산으로 token·시간·오탐·미탐 측정; 관찰된 병목에만 concurrency 추가 |

graph·recon·slice의 사실 생성은 재현 가능하게, agent 판단은 근거와 함께 검토 가능하게 만든다.
기존 parser/analyzer를 활용하며 별도 범용 taint 엔진·graph DB·agent framework는 구현하지 않는다.
실제 감사, 유료 모델 실행, chain/exploit 연구는 이번 milestone에 포함하지 않는다.


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
이 기록 이후 Solidity 추출기와 공통 recon 연결을 구현했다. 다음 언어는 Python이다.


## G1 Solidity 완료 범위

- 기존 공통 v2 schema 유지, 기존 Clang/Go/v1 조회 유지.
- solc-js 0.8.30 AST의 선언 ID·타입 정보와 byte 위치에서 함수/modifier·context를 추출.
- base/C3 순서·override 근거, modifier 적용 순서/placeholder·본문 호출을 보존.
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
