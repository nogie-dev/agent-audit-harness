# Agent 개발 환경

## 빠른 반복

`make setup`으로 lockfile 기반 환경을 설치하고 `make check`로 로컬 검증한다.
개발 의존성은 pytest와 Ruff다. 런타임 추가 의존성은 agent 출력의 신뢰 경계를 검사하는 jsonschema 하나다.
graph DB, agent SDK, queue 서버와 웹 UI는 현재 단계에 필요하지 않다.
호출 구조 작업에는 분석 언어에 따라 Clang, Go 또는 Node.js가 필요하다.
`make setup-go`는 helper의 고정 의존성(x/tools 0.30.0, x/mod 0.23.0, x/sync 0.11.0)을 준비한다.
`make setup-solidity`는 locked solc-js 0.8.30을 `.cache/solidity-extractor`에 준비한다.
`make demo-graph`/`make demo-go`/`make demo-solidity`로 실제 compiler 경로를 검증한다.
처음에는 graph를 만들고 `resolve`/`reachable`로 구조를 확인한다.
`make demo-review`는 graph → source-backed recon → 다중 파일 slice → replay → resume을 검증한다.
`plan`/`run`에 `--graph`와 `--recon`을 함께 제공하면 관계 기반 입력을 사용한다.

`AGENTS.md`는 코드 책임, 실행 명령과 유지할 계약만 담는다.
agent가 매 작업마다 전체 설계 문서를 읽지 않도록 자세한 내용은 docs에 분리했다.
파일과 schema는 package에 포함되므로 editable 설치와 wheel 설치에서 같은 계약을 사용한다.
Go helper의 소스·go.mod·go.sum도 wheel에 포함하며 로컬 toolchain으로 컴파일한다.
Solidity helper의 JS·package/lock도 포함하되 node_modules는 배포하지 않는다.
wheel 설치에서도 실행 디렉터리의 `.cache/solidity-extractor`에 같은 lock으로 npm 의존성을 준비해야 한다.
추출은 이 캐시를 읽기만 한다. 대상 디렉터리 내부에 compiler 캐시를 둘 수 없다.

외부 Go 의존성이 있는 모듈은 분석 전에 다운로드 범위를 검토하고 명시적으로 캐시를 준비한다.
추출 명령은 이를 자동으로 수행하지 않는다. 루트 캐시는 harness 실행 디렉터리 기준이다.

```sh
# 신뢰한 모듈의 의존성을 준비하는 별도 단계; 대상 프로그램은 실행하지 않음
audit_go_cache="$PWD/.cache/go-extractor"
cd /path/to/module
GOENV=off GOTOOLCHAIN=local GOWORK=off GOPACKAGESDRIVER=off \
  GOMODCACHE="$audit_go_cache/mod" GOCACHE="$audit_go_cache/build" go mod download
```

분석은 항상 `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`,
`GOWORK=off`, `GOPACKAGESDRIVER=off`, `GOFLAGS=-mod=readonly`를 사용한다.
helper 준비 시에는 설치된 Go 캐시의 로컬 archive proxy를 재사용할 수 있다.
비어 있는 캐시는 분석 중 네트워크로 채우지 않는다. 타입 오류/없는 의존성이 있는 패키지는
실패로 기록하고 해당 패키지의 함수·호출을 전부 제외한다. 정상 패키지는 그대로 조회할 수 있다.
대상 자체가 실행 디렉터리이면 캐시는 출력 디렉터리의 부모에 둔다.

프로젝트 Codex 설정 원본은 `config/codex-dev.toml`이다.
`.codex/config.toml`에도 같은 개발 기본값을 설치한다. 모델은 사용자가 선택한 기본값을 유지하고,
프로젝트 파일 수정과 로컬 테스트에 맞는 workspace-write 설정을 사용한다.
Codex는 신뢰한 프로젝트의 설정만 읽는다. 적용은 다음 세션에서 확인한다.
이는 [프로젝트 설정의 공식 동작](https://learn.chatgpt.com/docs/config-file/config-basic)에 따른다.
감사 runtime의 설정은 `agents.py`에서 별도로 전달하므로 개발 설정을 공유하지 않는다.

## 작업 요청 템플릿

```text
목표: <한 가지 관찰 가능한 동작>
완료 조건: <입력 → 기대 결과, 실패 경계 한 가지>
범위: <수정할 모듈/계약, 영향받는 호출자>
검증: <관련 pytest 선택자와 make check>
제외: <이번 작업에서 구현하지 않을 다음 단계>
```

하나의 요청에서 orchestration, analyzer, worker와 UI를 동시에 확장하지 않는다.
먼저 기존 ownership을 찾고 수정할 계약에 연결된 fixture를 읽는다.
상태를 변경하는 코드에는 오류 경계의 회귀 사례를 넣고, 검증이 끝나면 그 milestone을 마친다.
추가 agent나 provider는 실제 병목과 측정 결과가 있을 때 도입한다.

## Model 없이 prompt와 계약 변경하기

1. `prompts/<stage>.md`와 관련 schema를 읽는다.
2. 바뀐 계약에 맞춰 `examples/replay/`와 관련 test를 수정한다.
3. `make check`로 출력 형식, evidence, resume, budget 경계를 검증한다.
4. `audit-harness run ... --replay ... --output runs/new-contract`로 새 실행을 만든다.
5. 실모델 품질 평가는 별도의 고정된 benchmark 작업으로 실행한다.

계약을 바꾼 후 기존 `runs/demo`에서 resume하면 입력 변경으로 거절되는 것이 정상이다.
기존 evidence를 지우는 대신 새 output 디렉터리를 사용한다.

## 복구와 상태 확인

`manifest.json`이 실행 상태의 기준이다. `failed`인 실행에서는 마지막 성공 응답이 남고,
최종 보고서를 만들지 않는다. 같은 입력과 provider/model로 `--resume`하면 완료된 단계를 재사용한다.
한도가 소진되면 `--max-calls`를 늘릴 수 있다. 실패한 시도도 누적 횟수에 포함된다.

동일 실행의 동시 쓰기는 `.lock`으로 막는다. 정상 종료와 처리 가능한 오류에서는 해제한다.
프로세스를 강제 종료하면 lock이 남을 수 있으므로 기록된 PID가 실제로 종료됐는지 확인한 뒤 제거한다.
동일 PID가 재사용될 수 있으므로 숫자만으로 프로세스를 종료하지 않는다.

## 검증 범위

graph test는 실제 Clang으로 교차 파일 관계, file-local 함수 분리, C++ overload,
헤더/macro의 위치, 재귀 종료, unevaluated 제외, callback·virtual·중복 정의의 미해결 상태를 검사한다.
compilation DB의 원래 프로그램은 실행하지 않으며 define 입력과 parse 실패 coverage를 검증한다.
Clang이 없으면 해당 integration test는 skip하므로 graph 지원 검증으로 보고하지 않는다.

Go test는 실제 `go/packages`로 교차 파일·패키지·import 별칭·메서드·generic·재귀와
파일/패키지 resolve를 검사한다. 인터페이스/함수 변수의 미해결 표시, go/defer,
literal의 호출 소유권, unevaluated 표현, 실패 패키지, build 조건/test 제외를 검증한다.
driver/GOFLAGS를 주입한 상황에서도 대상 init/generator를 실행하지 않는지 확인한다.
공통 계약 v2는 schema·source 위치·endpoint·요약 관계·checksum을 검사하고 v1 조회를 유지한다.
선언 context·참조 관계·함수 인자도 endpoint를 검증한다. 함수 인자 전달은 실행 간선이 아니다.
Go가 없으면 integration test가 skip하므로 CI는 Go와 helper 의존성을 먼저 준비한다.

`tests/test_solidity_graph.py`는 실제 solc로 상속/C3 순서·override·modifier 적용 및 본문,
파일 간 내부/library 호출·alias/using/overload·외부/저수준/함수 값/assembly 경계를 검사한다.
오류가 있는 batch의 부분 AST 제외, 외부 import 차단, Node preload 및 프로젝트 script 미실행,
UTF-8 byte 위치·동일 줄 다른 함수 인용 거절, 공통 recon/slice/replay 재개도 확인한다.
Node 또는 준비된 compiler가 없으면 skip하므로 CI는 `make setup-solidity`를 먼저 실행한다.

`tests/test_recon.py`는 handler 등록, 타입·필드·전역 선언, 통제 후보가 있는/없는 경로,
미해결 호출, 고정 직렬화 byte 예산, 고유 줄 coverage, 원문·source/config/artifact 변경 거절,
replay 재개를 확인한다. lexical 비교는 fixture의 동일 한도에서 근거 포함 여부만 검증한다.
실제 탐지율·토큰 비용·전체 저장소 threat-model 정확도는 검증하지 않는다.

offline test는 실제 소스와 인용 대응, strict schema, byte 분할, 중복·후보 ID,
false-positive triage, 부분 coverage, 재개·호출 cap·cache 손상·동시 실행을 검증한다.
Codex adapter는 로컬 가짜 CLI로 stdin, 제한 설정, 별도 cwd, 환경변수 필터,
오류와 timeout, 제한이 무시될 때 호출 거절을 검사한다.
실제 설치된 CLI의 feature 제한 사전 확인도 모델 호출 없이 검사했다.
이는 Codex 서비스의 실제 동작이나 보안 격리 검증이 아니다.

`make doctor`는 Clang/Go를 포함한 도구 존재와 Docker daemon 상태를 확인한다.
현재 Docker CLI는 존재하지만 daemon은 실행되지 않은 환경에서 개발할 수 있다.
동적 worker 구현 전에는 Docker가 필요하지 않다.
