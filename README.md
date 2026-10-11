# Agent Audit Harness

감사 대상의 **함수·파일·패키지 간 호출 구조를 먼저 정리**하고, 그 위에서 agent 분석을 진행하는 harness입니다.
C/C++의 Clang, Go의 타입 추출기, Solidity의 solc AST 추출기가 같은 그래프 계약과 조회 코드를 사용합니다.
Go와 Solidity에서는 연구자가 지정한 가설을 graph와 원문에 연결하고, 관계 기반 다중 파일 입력으로
analysis·triage를 실행할 수 있습니다. taint와 동적 검증은 다음 단계입니다.

[Quarkslab 글](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)을
검토했습니다. 구조 평가와 구현 범위는 [설계 문서](docs/architecture.md)에 있습니다.

## 바로 개발하기

macOS/Linux에서 Python 3.12와 `uv`가 필요합니다. 저장소 루트에서 실행합니다.

```sh
make setup
make setup-go
make setup-solidity
make check
make demo-graph
make demo-go
make demo-solidity
make demo-review
make demo
make doctor
```

`make demo-graph`는 실제 Clang으로 교차 파일 호출 예제를 파싱합니다. 결과 위치를 출력합니다.
`make demo-go`는 실제 Go 타입 정보로 3개 패키지·4개 파일의 호출 구조를 추출합니다.
Go 지원에는 로컬 Go 1.23 이상이 필요하며 현재 검증한 버전은 1.25.1입니다.
`make setup-go`는 고정된 추출기 의존성을 내려받는 준비 단계입니다.
`make demo`는 별도의 C 예제와 기록된 응답으로 기존 agent 골격을 검증합니다.
그래프 추출과 replay 검증은 네트워크, 모델 호출, 빌드 스크립트 또는 대상 프로그램 실행이 없습니다.
의도적으로 넣은 오탐 하나를 제외하고, 검증이 필요한 후보 하나를 남기는 흐름을 확인합니다.
반복 실행은 완료된 단계의 응답을 재사용합니다. 각 demo는 새 결과 디렉터리를 만들며 위치를 출력합니다.

## 먼저 호출 구조 정리하기

C/C++ 대상은 Python 환경 외에 설치된 `clang`이 필요합니다. Clang은 syntax 분석만 수행합니다.

Go 대상은 루트에 `go.mod`가 있는 단일 모듈을 지정합니다.
Go 소스는 LF/CRLF 줄바꿈을 지원하고 단독 CR은 명시적으로 거절합니다.

```sh
export UV_CACHE_DIR="$PWD/.cache/uv"
uv run --locked audit-harness graph build examples/go-target --language go --output runs/go-example
uv run --locked audit-harness graph resolve runs/go-example/graph.json audit.example/graph/parser
uv run --locked audit-harness graph resolve runs/go-example/graph.json app/entry.go
uv run --locked audit-harness graph reachable runs/go-example/graph.json Entry --files
uv run --locked audit-harness graph reachable runs/go-example/graph.json Dynamic
```

`Entry`는 `app/entry.go`, `app/stage.go`, `parser/parse.go`, `shared/normalize.go`에 도달합니다.
import 별칭·다른 파일의 함수·구체 타입 메서드·generic·재귀를 타입 정보로 연결합니다.
`Dynamic`의 인터페이스와 callback은 `status=unresolved`, `callee=null`로 표시하고
`dispatch`와 `reason`에 원인을 남깁니다. 구현 후보를 추측해 간선을 만들지 않습니다.
Go의 `scope`는 전체 패키지 경로이며 `scope_calls`가 패키지 사이의 확정된 호출을 요약합니다.
`go`/`defer` 호출은 `execution=concurrent`/`deferred`로 표시합니다.
Go graph는 타입·필드가 포함된 선언, 패키지 전역 값, import 문맥을 `contexts`로 기록합니다.
함수의 `context_ids`와 선언의 `references`는 실행 간선과 별개인 원문 의존성입니다.
함수 인자 전달은 `function_arguments`로 기록하며 callback의 실제 실행을 확정하지 않습니다.

Go 추출은 인덱싱된 소스와 `go.mod`/`go.sum`의 임시 복사본에서 `go/packages`를 사용합니다.
helper를 컴파일하며, 패키지 로더는 타입 확인을 위해 의존성 export data를 컴파일할 수 있습니다.
대상 프로그램·`init`·generator·test를 실행하지 않습니다. 사용자 GOFLAGS/driver 설정을 제거하고,
cgo·workspace·자동 toolchain 전환·의존성 다운로드를 끕니다.
호스트 OS/architecture의 기본 build 조건만 분석하며 test/tag로 제외된 파일과 타입 오류는 coverage에 남깁니다.
workspace·중첩 모듈·로컬 replace는 명시적으로 거절합니다. 외부 의존성은 사전에
`.cache/go-extractor/mod`에 준비해야 하며 방법은 [개발 문서](docs/development.md)에 있습니다.
표준 라이브러리/외부 패키지 호출은 `external`로 표시합니다.
embedded asset과 assembly는 snapshot에 포함하지 않으므로 해당 입력이 필요한 패키지는 불완전할 수 있습니다.

지원 언어가 함께 있으면 `--language`를 지정합니다. 단일 지원 언어는 자동 감지합니다.

```sh
export UV_CACHE_DIR="$PWD/.cache/uv"

uv run audit-harness graph build examples/graph-target --output runs/graph-example
uv run audit-harness graph resolve runs/graph-example/graph.json entry
uv run audit-harness graph resolve runs/graph-example/graph.json parser.c
uv run audit-harness graph reachable runs/graph-example/graph.json entry --files

# 실제 프로젝트의 파싱 설정 사용; 빌드 명령 자체를 실행하지 않음
uv run audit-harness graph build /path/to/source \
  --compilation-database /path/to/source/build/compile_commands.json \
  --output runs/target-structure
```

예제 `entry`의 도달 파일은 `entry.c`, `parser.c`입니다. 두 파일에 있는 같은 이름의
`static helper`는 별도 함수로 식별합니다. `callback_entry`의 callback은 `unresolved`로 남고
`dispatch=indirect`로 표시됩니다.
결과의 `graph.json`에는 함수 정의·시그니처·매개변수·위치, 호출 위치와 provenance,
파일·패키지 간 호출, 파싱 설정·실패·미지원 범위가 저장됩니다. `report.md`는 사람이 읽는 요약입니다.
`resolve`는 호출자·피호출자를 보여주고, `reachable`은 확정된 직접 호출만 따라갑니다.
같은 함수 이름이 여러 개이면 조회 결과의 함수 ID를 사용합니다.
출력은 대상 밖의 새 디렉터리에만 저장하며, 기존 결과를 덮어쓰지 않습니다.

`compile_commands.json`이 대상 루트에 있으면 자동 사용합니다. 없으면 Clang 기본 설정으로
파싱하며 `configuration_verified=false`로 표시합니다. 기존 DB에서는 include·define·undefine·
language·standard 옵션만 복사하고, 나머지 옵션은 기록합니다. 실행 파일·플러그인·response file·
shell 명령을 재실행하지 않습니다. 외부 include 경로는 거절하므로 의존성 헤더를 대상 안에 준비해야 합니다.
시스템 기본 헤더는 로컬 toolchain을 사용합니다. 여러 build 설정은 하나를 선택한 DB가 필요합니다.
파싱 실패와 미지원 파일은 coverage에 남으며, 실패한 TU의 부분 AST로 관계를 만들지 않습니다.
`parsed`는 선택된 TU의 syntax 파싱 상태이며 전체 호출 관계가 해결됐다는 뜻이 아닙니다.

## Solidity 호출 구조

Node.js와 npm이 필요합니다. `make setup-solidity`는 package lock에 고정한 solc-js **0.8.30**과
의존성을 실행 디렉터리의 `.cache/solidity-extractor`에 준비합니다. 설치 스크립트를 실행하지 않습니다.
추출은 준비된 compiler에 소스 내용만 제공하며 의존성 다운로드·대상 빌드/배포를 하지 않습니다.

```sh
make setup-solidity
make demo-solidity
uv run --locked audit-harness graph build examples/solidity-target --language solidity --output runs/solidity-example
uv run --locked audit-harness graph resolve runs/solidity-example/graph.json Wallet.sol:Wallet
uv run --locked audit-harness graph reachable runs/solidity-example/graph.json entry
uv run --locked audit-harness graph reachable runs/solidity-example/graph.json invokeVirtual
```

`scope`는 `파일:컨트랙트`이며 free function은 파일을 사용합니다. 상속 header와 타입·상태 변수·
pragma/import는 기존 `contexts`에 저장하고, 함수 metadata의 `base_contract_ids`,
`linearized_base_ids`, `overrides`로 상속 순서와 재정의 관계를 보존합니다.
modifier는 `kind=modifier`인 함수 노드이며 적용은 `dispatch=modifier` 간선으로 기록합니다.
적용 순서와 `_` 개수도 보존하지만 modifier의 실행 순서·반복·통제 효과를 증명하지는 않습니다.

| 관계 | 그래프 처리 |
| --- | --- |
| 비가상 내부 함수·상속 함수·internal library | `resolved`; 파일·scope 간 요약과 reachable에 포함 |
| modifier 적용 | 비가상 구현에만 `resolved`; modifier 본문의 호출도 조회 |
| virtual·super | `unresolved`; 후보 `declaration_id`와 사유 보존 |
| interface/contract·`this` 외부 호출·public library | `external`, `callee=null`; 선언 ID는 보존하되 내부 도달 탐색에서 제외 |
| 함수 값·저수준 call/delegatecall/staticcall·assembly | `unresolved`; 구현/주소/selector 또는 opaque 경계 기록 |

현재 지원은 0.8.30과 호환되는 pragma와 입력된 `.sol` 파일에 한정합니다.
Foundry/Hardhat 설정·remapping을 자동으로 읽지 않으며 외부 import의 filesystem fallback을 차단합니다.
필요한 의존성 소스는 인덱싱 가능한 대상 디렉터리에 준비해야 합니다.
컴파일 오류가 있으면 batch 전체의 부분 AST를 제외하고 coverage에 실패를 남깁니다.
`configuration_verified=false`는 배포용 빌드 설정을 확인하지 않았다는 뜻입니다.
initializer 실행·암묵적 base constructor·modifier control flow는 확장하지 않습니다.
소스는 최대 256개, compiler 과정 timeout은 기본 30초, 도구 출력은 최대 64 MiB입니다.
`recon`/`plan`/`run --graph ... --recon ...`은 공통 계약으로 동일하게 사용할 수 있습니다.
Solidity 진입 함수의 노출·배포 정보를 자동으로 발견하는 adapter는 아직 없습니다.

## Graph에서 조사 입력으로 연결하기

`examples/go-review-plan.json`은 연구자가 제공한 세 가설의 예제입니다.
등록된 handler, 통제 후보가 있는/없는 경로, 구현체를 모르는 interface/callback을 다룹니다.
`recon`은 함수 식별과 실제 원문 인용을 검증하고 입력 순서를 보존합니다.
보안 주석의 의미, 서버 실행·외부 노출, taint 경로를 자동으로 입증하지는 않습니다.

```sh
uv run --locked audit-harness graph build examples/go-review-target --language go --output runs/review-graph
uv run --locked audit-harness recon examples/go-review-target \
  --graph runs/review-graph/graph.json --spec examples/go-review-plan.json --output runs/review-recon
uv run --locked audit-harness plan examples/go-review-target \
  --graph runs/review-graph/graph.json --recon runs/review-recon/recon.json --slice-bytes 16000
uv run --locked audit-harness run examples/go-review-target \
  --graph runs/review-graph/graph.json --recon runs/review-recon/recon.json \
  --replay examples/go-review-replay --output runs/review-run
```

출발 함수·조사 주석·등록 근거·관련 함수·참조 선언을 묶고, 직렬화한 `source_slice`에 byte 한도를 적용합니다.
빠진 함수·선언·호출·주석과 미검토 가설은 `coverage.json`에 기록합니다.
총 prompt·triage 후보·응답까지 포함한 token/금액 상한은 아닙니다.
Go 표준 `http.HandleFunc`/`ServeMux.HandleFunc`의 직접 함수 등록만 현재 확인합니다.
wrapper·함수 변수·전역 초기화의 등록·다른 router는 자동으로 해석하지 않습니다.
입력 계획의 계약은 `src/agent_audit_harness/schemas/research-plan.json`입니다.
`recon.json`은 이 계획과 graph에서 재계산해 검증하며, source/config가 바뀌면 graph부터 다시 만듭니다.

`make demo-review`는 새 디렉터리에서 위 연결과 추가 호출 없는 재개를 한 번에 확인합니다.
기록된 응답을 사용하므로 실제 모델이 가설을 발견·기각했다는 실험은 아닙니다.

## 줄 단위 agent 입력 실행하기

```sh
export UV_CACHE_DIR="$PWD/.cache/uv"

# 기존 줄 단위 입력의 범위와 최대 호출 수 확인; 호출 그래프 조회와 별개
uv run audit-harness plan examples/demo-target --max-slices 2

# 기록된 응답으로 전체 흐름 검증
uv run audit-harness run examples/demo-target \
  --replay examples/replay --output runs/demo --resume

# Codex 연동: 사용할 모델을 명시하고, 대상 밖에 결과 디렉터리 지정
uv run audit-harness run /path/to/source \
  --codex --model YOUR_AVAILABLE_MODEL \
  --max-slices 8 --max-calls 16 --timeout 180 --output runs/my-run

# 실패한 실행도 같은 입력으로 재개 가능; 필요하면 누적 호출 한도를 늘림
uv run audit-harness run /path/to/source \
  --codex --model YOUR_AVAILABLE_MODEL \
  --output runs/my-run --resume --max-calls 20
```

Codex 실행에는 로그인된 CLI와 해당 옵션을 지원하는 버전이 필요합니다.
선택한 소스가 모델 서비스에 전달되고 계정 사용량을 소비합니다.
기존 사용자 설정을 읽지 않으므로 사용자 정의 모델 provider 설정은 지원하지 않습니다.
모델, CLI 버전, 소스, prompt, schema 또는 slice 설정이 바뀌면 새 결과 디렉터리를 사용합니다.
기본 최대 호출 수는 16회이고 timeout은 호출당 180초입니다. 이것은 토큰·금액 상한이 아닙니다.

## 실행 산출물

| 파일 | 용도 |
| --- | --- |
| `manifest.json` | 입력 식별자, 실행 상태, 실패 유형, 누적 호출 시도 수 |
| `index.json` / `slices.json` | 파일 hash와 실제 agent 입력 범위 |
| `graph.json` / `recon.json` | 관계 기반 실행에서 사용한 그래프와 근거를 가진 조사 계획 |
| `calls/<slice>.<stage>/` | prompt, 응답, checksum, 시간; Codex 사용 시 원시 이벤트와 오류 로그 |
| `coverage.json` | 선택한 줄과 제외된 파일·미검토 범위 |
| `findings.json` | 오탐을 포함한 모든 triage 결과 |
| `validation-queue.json` | 추가 검증이 필요한 후보와 불확실한 후보 |
| `metrics.json` / `report.md` | 실행 지표와 읽을 수 있는 보고서 |

`complete`는 선택한 범위의 분석과 triage 완료를 뜻합니다. 보안감사 전체 완료를 뜻하지 않습니다.
실제 취약점 확인 수와 동적 검증 실행 수는 현재 항상 0입니다.

## 개발 안내

- [구조 분석과 효율성 평가](docs/architecture.md)
- [agent 개발 방법과 검증 명령](docs/development.md)
- [다음 구현 단계와 완료 조건](docs/roadmap.md)
- [agent가 먼저 읽는 작업 규칙](AGENTS.md)

graph/recon을 제공하지 않은 실행은 파일 이름 순서의 연속된 줄 묶음을 사용합니다.
현재 graph는 C/C++와 Go의 정적 호출 구조를 지원합니다. 함수 포인터·가상 호출은 미해결로 남기며,
생성자·암묵적인 소멸자·template·link 조건의 전체 해석과 taint는 지원하지 않습니다.
호출 도달 관계만으로 공격자 입력의 도달 가능성을 주장하지 않습니다.
자동 threat model·노출 우선순위 추정, Python·Solidity 추출기,
Go의 points-to·reflection·패키지 전역 initializer 실행 관계는 아직 구현하지 않았습니다.
UTF-8 소스만 읽으며, 제외 디렉터리·symlink·큰 파일·긴 줄은 coverage에 기록합니다.
`.gitignore`를 해석하거나 소스에 들어 있는 비밀정보를 자동 제거하지는 않습니다.

Codex 호출은 별도 임시 작업 디렉터리와 제한된 도구 설정을 사용합니다.
CLI의 read-only 설정은 호스트 읽기 격리나 VM 경계를 보장하지 않습니다.
원시 소스·응답·로그는 민감한 자료일 수 있으므로 실행 결과를 기본 Git 제외 대상으로 두었습니다.
동적 검증 worker를 구현하기 전에는 이 harness가 생성한 검증 계획을 실행하지 않습니다.
