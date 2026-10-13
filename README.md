# Agent Audit Harness

감사 대상의 **함수·파일·패키지 간 호출 구조를 먼저 정리**하고, 그 위에서 agent 분석을 진행하는 harness입니다.
C/C++의 Clang, Go의 타입 추출기, Solidity의 solc AST, Python의 표준 AST 추출기가
같은 그래프 계약과 조회 코드를 사용합니다.
Go·Solidity·Python에서는 연구자가 지정한 가설을 graph와 원문에 연결하고, 관계 기반 다중 파일 입력으로
analysis·triage를 실행할 수 있습니다. Go HTTP 등록·Solidity의 소스상 공개 함수·Python/Go 정적 역할 근거로 agent가 조사 계획을
제안할 수도 있습니다. Python·Go는 Semgrep CE의 정적 근거와 함수 내부 taint를
별도로 첨부하고, agent가 원문에 근거해 제안한 source·sink 함수로 두 번째 분석을 할 수 있습니다.
명시적인 검증 recipe는 격리된 Docker worker에서 실행합니다.
PoC 코드·관찰 조건은 agent가 자료로 제안하고, 별도의 연구자 검토를 거쳐 worker에 공급할 수 있습니다.
Go·Python은 지원되는 직선형 표현식과 직접 호출에서 제한된 구문상 값 경로를
기록합니다. Solidity는 직접 호출의 인자→매개변수 사실까지만 기록합니다.
검증 결과는 실행 전에 선언한 관찰 조건,
실제 진입점 도달과 수정 전후 비교, 미해결 근거를 검사해 별도 판정으로 승격할 수 있습니다.
triage는 공통 원인·수정 위치를 원문에 연결해 후보를 묶고, 각 후보의 기각·불확실 판정,
반증과 미해결 근거를 보존합니다.

[Quarkslab 글](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)을
검토했습니다. 구조 평가와 구현 범위는 [설계 문서](docs/architecture.md)에 있습니다.

현재 graph → recon → slicing → analysis → triage → PoC → chain → impact의 bounded 첫
버전이 연결되어 있습니다. 네 언어의 구조 추출과 합성 fixture의 격리된 수정 전후·build
matrix·chain·단계별 impact를 검증했습니다. 완료 범위와 운영 대상에 일반화할 수 없는 경계는
[로드맵의 상태표](docs/roadmap.md#전체-단계-상태와-완료-gate)에 정리했습니다.
합성 fixture 기반 첫 버전의 M5도 완료했습니다. 새 고정 입력에서 Go·Python·Solidity의
lexical과 graph/recon을 각각 두 번 비교해 12개 run·6개 pair가 모두 완료됐습니다.
graph/recon의 호출 시도는 35회에서 24회로 줄었지만, Go 양성은 양쪽 모두 놓쳤고
언어별 token·시간 결과는 엇갈렸습니다. [평가 기록](docs/model-evaluation.md)에
원본 시도와 한계를 정리했습니다. 일반적인 탐지 품질·비용 우위나 운영 대상의
취약점 발견률은 입증하지 않았습니다. 오프라인 입력 준비는
`make demo-model-evaluation-prospective`로 재현할 수 있습니다.
이후 Go의 호출 인자 전달·제한된 값 경로와 정적 역할·recon 관계를 보강했습니다.
구현 범위와 미해결 조건은 [정밀화 계획](docs/research-fidelity-plan.md)에 있습니다.
새 합성 Go 입력의 최종 코드 재평가에서 graph와 static/value arm은 엄격 양성
각 2/2, lexical은 1/2였지만, 작은 동일 fixture의 반복이며 일반적인 탐지 개선이나
값 경로 단독 효과를 입증하지 않습니다. 원본·비용은 [평가 기록](docs/model-evaluation.md)에 있습니다.
이후 static-only/full 분리 비교와 모델에 처음 공급한 별도 Go 합성 입력의 3-arm
반복에서 각 arm의 양성·음성은 모두 2/2였습니다. 값 경로의 안정적인 추가 효과는
관찰되지 않았습니다. 파일 선택 예제는 격리된 실제 HTTP 요청의 수정 전후와
상수 대조군을 확인했습니다. Python은 제한된 값 경로, Solidity는 직접 인자 전달
사실을 공통 graph v2에 추가했습니다. 제3자 미관측 저장소 평가는 남아 있습니다.
DeFiHackLabs의 UniLend 사례를 피해 구현 원문과 분리해 읽기 전용으로 점검한 첫
진단 결과와 채점 조건은 [실사례 평가 기록](docs/defihacklabs-evaluation.md)에 있습니다.

## 바로 개발하기

macOS/Linux에서 Python 3.12와 `uv`가 필요합니다. 저장소 루트에서 실행합니다.

```sh
make setup
make setup-go
make setup-solidity
make setup-static
make check
make demo-graph
make demo-go
make demo-solidity
make demo-python
make demo-static
make demo-models
make demo-recon
make demo-intake
make demo-poc
make demo-matrix
make demo-review
make demo
make demo-benchmark
make demo-model-evaluation
make demo-model-evaluation-prospective
make doctor
```

`make demo-graph`는 실제 Clang으로 교차 파일 호출 예제를 파싱합니다. 결과 위치를 출력합니다.
`make demo-go`는 실제 Go 타입 정보로 3개 패키지·4개 파일의 호출 구조를 추출합니다.
`make demo-python`은 5개 파일의 import 별칭·상대 import·재수출과 미해결 호출을 추출합니다.
`make demo-static`은 실제 Semgrep CE로 역할·taint·미해결 경계를 추출하고 replay/resume까지 확인합니다.
`make demo-models`는 Python·Go wrapper의 모델 제안, 실제 CE 재분석과 기존 근거·재개 보존을 확인합니다.
`make demo-recon`은 제공된 근거로 계획을 제안하고 조사 순서·미해결·누락을 slicing/triage에 전달합니다.
`make demo-intake`는 외부 후보와 부분 Python 원문에서 검증 대기열·정적 근거 누락을 보존합니다.
`make demo-poc`는 기록된 PoC 제안·재개와 합성 검토 기록의 결합을 확인합니다. 모델이나 worker는 실행하지 않습니다.
`make demo-matrix`는 설정별 입력을 고정하고 미실행 case를 그대로 보고합니다. 모델·컴파일·Docker 실행은 없습니다.
Go 지원에는 로컬 Go 1.23 이상이 필요하며 현재 검증한 버전은 1.25.1입니다.
`make setup-go`는 고정된 추출기 의존성을 내려받는 준비 단계입니다.
`make demo`는 별도의 C 예제와 기록된 응답으로 기존 agent 골격을 검증합니다.
`make demo-benchmark`는 같은 C 소스·예산·정답 위치로 두 offline replay 실행을 비교합니다.
`make demo-model-evaluation`은 Go·Python·Solidity의 고정 예제로 graph/recon과 replay 비교를 새 `runs/` 디렉터리에 재생성합니다. 빈 lexical 응답은 배선 점검용이며 모델 성능 비교가 아닙니다.
GPT-6 Luna 합성 대상 탐색 결과와 실패·비교 한계는 [`docs/model-evaluation.md`](docs/model-evaluation.md)에 기록했습니다.
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

## Python 호출 구조

추가 의존성 설치 없이 harness의 Python으로 [표준 AST](https://docs.python.org/3/library/ast.html)를
파싱합니다. 대상은 import root(패키지의 부모 디렉터리), 또는 `src/` layout의 프로젝트 루트입니다.
예를 들어 이 저장소는 `src`를 지정하며 `src/agent_audit_harness`를 직접 지정하면
패키지 루트가 빠져 추출을 거절합니다.
`.`과 `src/`를 소스 import root로 취급하며 같은 모듈명이 둘에 있으면 `ambiguous`로 남깁니다.
프로젝트 설정·`sys.path`·환경의 `PYTHONPATH`로 root를 추측하지 않습니다.

```sh
make demo-python
uv run --locked audit-harness graph build examples/python-target --language python --output runs/python-example
uv run --locked audit-harness graph resolve runs/python-example/graph.json auditpkg.worker
uv run --locked audit-harness graph reachable runs/python-example/graph.json app.entry --files
uv run --locked audit-harness graph reachable runs/python-example/graph.json app.dynamic
```

`app.entry`는 `auditpkg.ops.stage`, `auditpkg.worker.run`과 같은 파일의 `helper`,
`auditpkg.shared.normalize`로 연결됩니다. import 별칭, 상대 import, `__init__.py` 재수출,
중첩 함수·재귀·async 함수 선언을 기록합니다. `scope`는 dotted module 이름이며
확정된 호출을 기존 `file_calls`/`scope_calls`로 요약합니다. import·전역 값·class header는
기존 `contexts`에 저장하므로 recon과 다중 파일 입력도 같은 경로를 사용합니다.

콜백·객체 메서드·계산된 호출 대상은 `unresolved`, 중복 선언·모듈 경로는 `ambiguous`,
인덱스 밖 import와 builtin은 `external`이며 모두 `callee=null`입니다.
파싱 실패한 로컬 모듈을 외부 함수나 확정 간선으로 바꾸지 않습니다.
조건부 선언/import, 이름 재대입, decorator와 wildcard import도 확정 간선을 만들지 않습니다.
직접 발견된 global/nonlocal·모듈 attribute 쓰기는 보수적으로 처리합니다.

최대 256개 Python 파일을 임시 소스 JSON으로 전달하고 `python -I`에서 파싱합니다.
대상 import·프로그램·`setup.py`·설정 파일을 실행하거나 의존성을 설치하지 않습니다.
파싱 실패, 미지원 파일, 제외 입력은 coverage에 남습니다. `configuration_verified=false`이며
`parsed`는 문법 파싱 상태입니다. 함수 본문 내 호출을 정적으로 연결한 결과는 실행 증명이 아닙니다.
메서드/상속/descriptor·함수 값 전파, 동적 import와 실행 중 binding 변경은 분석하지 않습니다.
module/class 초기화·함수 정의 시점 표현식·lambda 본문의 실행 관계는 생략합니다.
async 호출은 coroutine 실행을 증명하지 않으며 generator comprehension의 내부 호출은 `deferred`입니다.
다른 소스 root나 Python 버전, 실제 런타임 설정의 검증은 후속 범위입니다.
직접 호출의 인자→매개변수와 단순 직선형 함수의 출처는 선택적 그래프 metadata로
확인할 수 있습니다. Python 정적 source/sink 역할과 맞는 경우 recon이 제한된
구문상 값 경로를 제공하지만, 조건 분기·재대입·동적 호출은 unknown으로 남기며
실제 오염 전파나 취약성을 입증하지 않습니다.

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
적용 순서와 `_` 개수를 보존하고, modifier 및 적용 함수의 `metadata.modifier_flow`에
조건 분기와 각 `_`의 진입·복귀, 전후 실행 순서를 기록합니다. 여러 modifier는 앞에 적힌
modifier가 바깥쪽이 되도록 중첩하며 내부 modifier와 인자 평가도 각 `_`에서 다시 진입합니다.
`if/else`, `require/assert`, 명시적 revert/return, 반복문과 break/continue를 표현합니다.
modifier의 return은 해당 wrapper를 종료하며 바깥 modifier의 후처리로 복귀합니다.

`modifier_flow.nodes/edges`는 원문 위치·함수/호출 ID를 참조하는 제한된 제어 흐름 그래프입니다.
`applications`는 적용 순서의 기존 호출 ID, `body_execution`은 **구문상 정상 종료 경로**의
본문 실행 횟수 min/max입니다. 정상 종료하며 본문을 생략하면 min=0, 항상 두 번 실행하면
min=max=2, 본문을 반복하는 cycle이 정상 종료 경로에 있으면 max=null/unbounded=true입니다.
정상 종료 경로가 없으면 `normal_exit_reachable=false`로 본문 생략과 구분합니다.
조건 값·인자 치환·경로 간 제약을 풀지 않으므로 이 범위는 실제 실행 횟수의 증명이 아닙니다.
함수 본문·호출 대상은 하나의 실행 단위로 두며 내부 제어 흐름이나 revert 효과를 확장하지 않습니다.
실제 접근 통제 효과는 별도 분석이 필요합니다.

virtual modifier, assembly/try, 단락 평가/삼항 식의 내부 분기와 확장 상한 초과는
`complete=false`, `gaps`와 알 수 없는 실행 횟수로 남깁니다. 흐름 확장은 함수당 최대 384개
노드/깊이 64이며 누적 확장 예산은 8,192개 노드입니다. 소스 파싱 성공과 flow 완전성은 별도입니다.
기존 `reachable`은 생략된 본문의 호출도 포함할 수 있는 구조적 의존성 조회로 유지합니다.
`recon`의 slice에는 원문과 함께 `modifier_flows`를 제공하며, 원문 누락이나 byte 제한으로
제공하지 못한 흐름은 omitted counts와 coverage에 기록합니다.
`examples/solidity-modifier-target`은 생략·반복·중첩·조기 return·guard·loop 예제이며
`make demo-solidity`에서 함께 추출합니다.

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
initializer 실행·암묵적 base constructor는 확장하지 않습니다.
소스는 최대 256개, compiler 과정 timeout은 기본 30초, 도구 출력은 최대 64 MiB입니다.
`recon`/`plan`/`run --graph ... --recon ...`은 공통 계약으로 동일하게 사용할 수 있습니다.
Solidity 진입 함수의 노출·배포 정보를 자동으로 발견하는 adapter는 아직 없습니다.
확정된 직접 내부 호출은 인자 원문과 대응 매개변수, 매개변수 식별자/literal 출처를
선택적 그래프 metadata로 남깁니다. 외부·virtual·super 호출은 이 전달 사실으로
해결하지 않습니다. Solidity 정적 source/sink adapter와 함수 간 값 경로는 아직 없습니다.

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
  --graph runs/review-graph/graph.json --recon runs/review-recon/recon.json \
  --slice-bytes 16000 --max-calls 16 --max-queries 1
uv run --locked audit-harness run examples/go-review-target \
  --graph runs/review-graph/graph.json --recon runs/review-recon/recon.json \
  --max-calls 16 --max-queries 1 --replay examples/go-review-replay --output runs/review-run
```

출발 함수·조사 주석·등록 근거·관련 함수·참조 선언을 묶고, 직렬화한 `source_slice`에 byte 한도를 적용합니다.
빠진 함수·선언·호출·주석과 미검토 가설은 `coverage.json`에 기록합니다.
총 prompt·triage 후보·응답까지 포함한 token/금액 상한은 아닙니다.
`plan`은 `run`과 같은 호출·조회 상한을 받아 기본 analysis/triage 호출 수와 조회·두 번째
static 분석을 포함한 보수적 최대 호출 수를 별도로 보여줍니다. 실제 호출 수는 응답에 따라
달라지며, `--max-calls`는 모든 시도의 전역 상한입니다.
Go 표준 `http.HandleFunc`/`ServeMux.HandleFunc`의 직접 함수 등록만 현재 확인합니다.
wrapper·함수 변수·전역 초기화의 등록·다른 router는 자동으로 해석하지 않습니다.
입력 계획의 계약은 `src/agent_audit_harness/schemas/research-plan.json`입니다.
`recon.json`은 이 계획과 graph에서 재계산해 검증하며, source/config가 바뀌면 graph부터 다시 만듭니다.

`make demo-review`는 새 디렉터리에서 위 연결과 추가 호출 없는 재개를 한 번에 확인합니다.
기록된 응답을 사용하므로 실제 모델이 가설을 발견·기각했다는 실험은 아닙니다.

### agent가 조사 계획을 제안하게 하기

기존 `recon --spec`은 유지합니다. `--replay` 또는 명시적인 `--codex --model`을 선택하면
Go의 직접 HTTP handler 등록, Solidity의 구현된 public/external 함수, 선택적인 Python·Go 정적 source/sink/sanitizer 역할 근거를
제공합니다. 전체 함수 원문을 포함한 fact가 기본 16,000 byte 입력 예산에 들어갈 때만 전달합니다.
등록과 Solidity visibility는 배포·실제 외부 노출 증명이 아니며 static 역할은 선언된 모델입니다.

```sh
make demo-recon
uv run --locked audit-harness recon examples/static-target \
  --graph runs/python-graph/graph.json --static runs/python-static/static.json \
  --replay examples/recon-python-replay --output runs/proposed-recon
```

각 제안은 제공된 graph 함수 ID·해당 등록/visibility/source fact·진입 함수 원문과 byte column,
우선순위(1부터 조사)·조사 이유·미해결 사항을 요구합니다. 원문 밖 함수나 거짓 인용·노출 확인 필드는
거절합니다. `research-plan.json`과 `recon.json`이 생성되며 기존 `run --recon`으로 이어집니다.
정적 근거를 사용해 만든 계획은 `run`에 원래 `--static`도 함께 제공해야 합니다.
입력 누락·미선택 진입점·미확인 노출은 `recon_gap_ids`로 판정까지 남습니다.
예산 때문에 빠진 fact의 함수 ID·파일·줄·소스 hash는 로컬 `coverage.json`에 보존합니다.
빈 제안은 `no_hypotheses`이며 완료된 보안감사나 안전 판정을 뜻하지 않습니다.

제안 시도는 기본 1회입니다. timeout 후 `--resume --max-calls 2`처럼 상한을 명시적으로 늘려
재시도할 수 있고 시도별 원시 응답·실패 기록을 보존합니다. 성공한 재개는 응답을 재사용합니다.
입력 예산·source/graph/static·prompt/schema·provider/model·코드가 바뀌면 새 output을 사용합니다.
이 경로는 지원한 등록·visibility·정적 역할 범위에 한정되며 자동 전체 저장소 threat model은 아닙니다.
Solidity의 생성된 public 변수 getter, 프록시·배포 binding과 상속 후 외부 selector의 실제 노출은
아직 열거·검증하지 않습니다.

## 정적 분석 근거 연결하기

`make setup-static`은 Semgrep CE **1.180.0**을 별도 `.cache/semgrep` 환경에 wheel/hash lock으로
준비합니다. 분석에는 native core와 로컬 패턴만 사용하며 로그인·registry rule·대상 config를 읽지 않습니다.
첫 adapter는 Python·Go입니다. 기본 모델은 Python `input → os.system`, Go
`os.Getenv → exec.Command("sh", "-c", ...)`입니다. source의 공격자 통제와 실제 실행은 가정입니다.
신뢰한 로컬 JSON으로 모델을 바꿀 수 있으며
`src/agent_audit_harness/schemas/static-rules.json`이 계약입니다.
패턴 외 validators·remote config·autofix는 허용하지 않습니다.

```sh
make setup-static
make demo-static

# 새 결과 디렉터리에서; 위 graph/recon은 같은 target과 소스로 생성
uv run --locked audit-harness static /path/to/target \
  --graph runs/target-graph/graph.json --output runs/target-static
uv run --locked audit-harness plan /path/to/target \
  --graph runs/target-graph/graph.json --recon runs/target-recon/recon.json \
  --static runs/target-static/static.json
```

공통 graph v2는 그대로 유지합니다. `static.json`은 source/sink/sanitizer **패턴 관찰**과
실제 엔진이 보고한 **taint 결과**를 분리하고, source·sink·중간 변수의 원문/byte 위치/hash 및
함수·호출 참조를 검증합니다. 엔진·runtime·adapter·rule checksum도 기록합니다.
`analyzer-output.json`에는 snapshot 경로를 상대 경로로 정규화한 엔진 출력을 보존합니다.
source·graph·모델이 다른 artifact는 재사용할 수 없습니다.

CE의 함수 내부 결과만 사용합니다. 파일 간 `execute(value)` 호출은 구조 간선으로 남고
`interprocedural_not_analyzed`로 표시하며 taint 간선을 만들어 연결하지 않습니다.
미해결 callback은 `call_semantics_not_modeled`, trace/파싱/스캔 누락도 별도 gap입니다.
알 수 없는 함수가 입력을 그대로 반환한다고 보수적으로 처리한 엔진 결과는 `trace_status=partial`입니다.
sanitizer 일치나 결과가 없다는 사실로 안전을 판정하지 않습니다. Solidity/C++ taint adapter는 아직 없습니다.

`run`에도 같은 `--static` 옵션을 사용할 수 있습니다. 원문을 제공한 근거만 byte 한도 내에서
agent 입력에 첨부하며 누락은 `omitted_counts`와 `coverage.json`에 남깁니다.
각 분석 process의 기본 timeout은 30초, 단일 worker·256 MiB 엔진 메모리·파일당 2,000개 match·
최대 256개 파일·출력 64 MiB 상한을 사용합니다. 대상은 실행하지 않습니다.
분석 입력은 설치 후 로컬 자료만 사용하지만 OS 수준 네트워크 격리 worker는 아직 구현하지 않았습니다.

### 대상의 함수 이름으로 두 번째 분석하기

graph·recon·첫 `--static` 근거가 있는 `run`에서 analysis는 후보 대신 `model_proposals`를
제출할 수 있습니다. 각 제안은 source·sink의 graph 함수 ID, 제공된 원문 인용과 byte column,
역할의 이유와 가정을 요구합니다. 코어가 확인된 호출 위치에서 제한된 호출 패턴을 생성합니다.
agent가 임의 패턴·rule·코드·명령을 공급할 수 없으며 공통 graph v2는 유지합니다.

slice당 한 번, 최대 4개 모델입니다. source는 함수의 반환값, sink는 전체 호출을 뜻합니다.
인자별 역할·sanitizer·함수 간 taint는 지원하지 않습니다. 같은 이름의 동적/rebound 호출은
확정된 함수 binding으로 취급하지 않으며, 지원하지 않는 호출 표기와 모델의 의미는 gap으로 남깁니다.
첫 분석과 같은 고정 엔진·runtime·adapter·normalizer만 재사용합니다. 준비 환경이나 분석 코드가
바뀌었다면 첫 분석부터 새로 생성해야 합니다. 재분석은 기본 `.cache/semgrep`을 사용합니다.

첫 `static.json`은 보존하고 `models/<slice>/`에 확인된 제안, 생성된 rules, 새 정적 근거와
실패·재시도 기록을 저장합니다. 새 근거는 기존 slice byte 한도 안에서 전달하며, 상세 누락은 파일에
보존하고 agent에는 요약과 참조를 제공합니다. 원래 gap과 새 gap은 모두 triage·judgment로 전달합니다.
따라서 새 taint 결과가 생겨도 자동으로 `validated`가 되지 않습니다.

`make demo-models`는 첫 분석에서 없던 wrapper taint 결과가 새로 나타나는 경우, 상수 입력 대조군,
unknown callback과 Python 동명 함수 가림을 포함합니다. agent 응답은 replay이고 정적 엔진은 실제 실행합니다.

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
기본 최대 호출 수는 16회이고 설정 가능한 범위는 1..128회, timeout은 호출당 180초입니다.
호출 수는 토큰·금액 상한이 아닙니다.
Codex 원본 응답은 128 KiB, `events.jsonl`과 stderr는 각각 8 MiB에서 호출을 종료합니다.
replay는 regular JSON 파일 최대 128개·각 128 KiB·합계 8 MiB이며 symlink를 거절합니다.

`--repair-citations`를 명시하면 각 analysis/triage 호출의 소스 인용 실패에 한 번만
수정 기회를 줍니다. 최초 거절 응답과 오류 코드를 추가 입력으로 전달하고 같은 검증기를
다시 적용합니다. 이 시도도 `--max-calls`에 포함되며 기본값은 꺼짐입니다. 호출/스키마
오류에는 자동 재시도하지 않습니다. 수정 시도까지 실패하면 새 run이 필요하고,
수정 직전 호출 상한이 소진된 경우에는 같은 옵션으로 `--resume`할 수 있습니다.
수정 입력에는 실패한 JSON 필드·경로·행·UTF-8 byte 열과 입력 범위 안의 주변 원문
최대 3행·4 KiB를 제공합니다. 한 응답의 실패는 최대 8개까지 함께 전달하고, 제공된
fragment에서 같은 인용문이 정확히 시작하는 위치도 후보로 표시합니다. 후보 위치는 주장
검증이 아니며 모델은 모든 인용을 다시 확인해야 합니다. 입력 밖 위치, byte 예산 초과와
8개를 넘는 오류는 누락 수로 남깁니다.
`citation_repair_outcomes`는 인용 필드만 바뀐 `citation_corrected`, 후보 수가 줄어든
`candidates_withdrawn`, 다른 응답 내용도 바뀐 `reply_revised`를 구분합니다.
이는 원문 검증을 통과한 응답의 문자 비교이며 판단의 의미적 정확성이나 취약점 입증이 아닙니다.
`benchmark-attempts`에는 수정 재실패·미시작·미확정도 각각 `failed`·`pending`·`unknown`으로 남습니다.

```sh
uv run --locked audit-harness run examples/demo-target \
  --replay examples/citation-repair-replay --max-slices 1 \
  --repair-citations --output runs/citation-repair-demo
```

## 실행 산출물

| 파일 | 용도 |
| --- | --- |
| `manifest.json` | 입력 식별자, 실행 상태, 실패 유형, 누적 호출 시도 수 |
| `index.json` / `slices.json` | 파일 hash와 실제 agent 입력 범위 |
| `graph.json` / `recon.json` | 관계 기반 실행에서 사용한 그래프와 근거를 가진 조사 계획 |
| `recon-context.json` | 계획 제안에 실제 제공한 fact·원문·입력 예산·누락; 원래 graph/static에서 재계산 |
| `static.json` | 선택적으로 사용한 정적 모델·역할·taint trace·미해결 경계와 identity |
| `calls/<slice>.<stage>/` | prompt, 검증된 응답, checksum, 시간; `attempt-<번호>/`에 시도별 원시 응답·이벤트·오류 |
| `queries/`, `investigations/` | 추가 조회 checkpoint와 slice별 요청·근거·예산·실패/누락 기록 |
| `models/<slice>/` | 원문 기반 모델·생성 rules·두 번째 정적 분석·context·누락·실패와 재개 checkpoint |
| `coverage.json` | 선택한 줄과 제외된 파일·미검토 범위 |
| `findings.json` | 오탐을 포함한 모든 triage 결과 |
| `clusters.json` | 제안한 공통 원인·수정 방법별 그룹, 전체 후보 ID와 개별 판정 집계 |
| `validation-queue.json` | 추가 검증이 필요한 후보와 불확실한 후보 |
| `metrics.json` / `report.md` | 실행 지표와 읽을 수 있는 보고서 |

`complete`는 선택한 범위의 분석과 triage 완료를 뜻합니다. 보안감사 전체 완료를 뜻하지 않습니다.
`run`의 실제 취약점 확인 수와 동적 검증 실행 수는 0입니다. 별도 `validate`의 실행 결과는
worker의 `result.json`에 기록하며 기존 분석 지표나 triage 판정을 덮어쓰지 않습니다.

triage 응답은 `groups` 안에 공통 `root_cause`와 후보별 `decisions`를 제공합니다.
원인에는 위반한 `invariant`, 통제 위치, 공통 `fix.strategy`와 수정 위치를 지정합니다.
모든 근거는 입력의 경로·실제 줄·UTF-8 byte column·정확한 인용으로 검증하며 source hash를 붙입니다.
기각에는 원문 근거를 가진 `counterevidence`, 불확실에는 `unresolved` 주장을 요구합니다.
자료가 없는 주장은 `unresolved.evidence=null`로 남습니다.

서로 다른 slice도 원인·수정 전략과 두 인용 위치/원문/hash가 모두 일치하면 한 그룹으로 묶입니다.
CWE가 같아도 통제 또는 수정 방법이 다르면 별개입니다. 원인을 모르면 단독 그룹으로 남깁니다.
같은 그룹의 개별 판정이 다르면 `mixed`이며 다른 후보의 판정으로 덮어쓰지 않습니다.
`findings.json`의 후보별 `input_gaps`는 미해결/외부 호출, 정적 분석 gap, modifier gap,
연결되지 않은 주석과 입력 누락을 원본 artifact/coverage에 연결합니다. agent가 근거를 생략해도
harness가 보존하며, 입력 예산 때문에 제공되지 않은 자료를 agent가 읽었다고 간주하지 않습니다.
검증 대기열에서 기각 후보는 제외되지만 `findings.json`과 그룹의 회원 목록에는 남습니다.

이 계약 변경 전 `decisions` 형식의 replay와 run은 재사용할 수 없습니다. 기존 결과는 보존하고
새 형식으로 replay를 갱신한 뒤 새 출력 디렉터리를 사용합니다. 공통 graph v2 계약은 그대로입니다.
형식·원문 일치는 확인하지만 원인·반증의 보안 의미를 증명하지는 않습니다. 표현이나 인용 범위가
다른 동일 원인은 별개 그룹으로 남을 수 있으며, 실모델 평가와 동적 검증이 필요합니다.

## 외부 후보에서 독립적으로 시작하기

`import-review`는 앞선 agent 단계를 거치지 않은 후보를 기존 검증 대기열로 연결합니다.
입력은 [후보 예제](examples/candidate-import.json)의 strict JSON 계약을 사용합니다.
대상의 현재 filtered source index hash, fragment별 hash·줄 범위, analysis 후보,
triage 결정과 외부에서 확인하지 못한 `gaps`가 필요합니다. 실행 명령이나 `validated` 판정은 입력할 수 없습니다.

```sh
uv run --locked audit-harness import-review examples/judgment-target \
  --spec examples/candidate-import.json --output runs/imported-review

# 준비된 graph/static 근거를 함께 제공할 수 있음
uv run --locked audit-harness import-review examples/static-target \
  --spec examples/static-candidate-import.json \
  --graph runs/target-graph/graph.json --static runs/target-static/static.json \
  --output runs/imported-static-review
```

spec와 output은 대상 밖에 있어야 하며, 기존 output을 덮어쓰거나 재개하지 않습니다.
기본 원문 입력 한도는 16,000 byte(`--input-bytes` 1,024..64,000), fragment는 최대 32개·각 200줄,
후보는 최대 8개입니다. 겹치는 범위, 중복 후보, 변경된 원문·graph·설정·static,
잘못된 인용·UTF-8 byte column과 누락된 triage 결정을 거절합니다.
`hypothesis_id`가 있으면 후보 ID에도 포함하며 기존 analysis/triage와 같은 ID 규칙을 씁니다.

원본은 `import-input.json`, 외부 gap과 core가 추가한 진입점 미확인 근거는 `import-gaps.json`에 남습니다.
원인·수정 가설별 cluster, 기각·불확실·반증·미해결은 그대로 보존하고 기각 후보는 queue에서 제외합니다.
graph/static을 제공하면 부분 원문 밖의 같은 함수에서 알려진 미해결 호출·modifier 한계·정적 gap도
후보에 연결합니다. 공급하지 못한 정적 항목은 `coverage.json`과 `omitted_counts`에 남습니다.
가져온 판정의 의미를 신뢰하거나 원문 인용만으로 실제 진입·taint·취약점을 확정하지 않습니다.
원본을 저장한 뒤 검사에 실패하면 raw input과 `manifest.json`의 실패 이유를 보존합니다.

`validate --run runs/imported-review`로 기존 worker에 연결할 수 있습니다. 준비된 로컬 image와
별도의 검토한 recipe가 필요하며 가져오기 자체는 실행하지 않습니다.
[수정 전 recipe](examples/intake-baseline-recipe.json)와 [수정 후 recipe](examples/intake-fixed-recipe.json)는
합성 CLI fixture의 실제 요청·admin 양성 대조군·guest 음성 대조군에 한정한 oracle과
import gap 해소 조건을 미리 고정합니다. 해소 조건이 빠지면 수정 비교가 성공해도 승격되지 않습니다.
PoC 제안과 별도의 검토 기록, 설정별 build matrix는 아래 흐름으로 연결합니다.

## PoC 제안과 연구자 검토

완료된 review의 후보 하나에 대해 `poc`가 검증 코드·frozen oracle·필요 설정·미해결을
strict JSON으로 저장합니다. 코드와 명령은 이 단계에서 실행하지 않습니다.
다중 파일 원문, graph/static의 알려진 gap과 누락, 원래 판정·반증을 제안 입력에 보존합니다.
기본 입력 예산은 16,000 byte(`--input-bytes` 1,024..64,000), source 범위는 최대 32개·각 200줄입니다.
큰 review 범위는 원문을 잃지 않고 나누며 전체 예산을 넘으면 명시적으로 거절합니다.
추가 조사에서 발견한 후보는 현재 원문을 대조한 뒤 제한된 주변 범위를 추가합니다.
빌드에 필요한 파일이 slice 밖에 있으면 `--support-file <review된 상대 경로>`를 반복 지정합니다.
최대 16개·합계 256 KiB의 source hash만 PoC 입력에 추가하며, 이 경로 자체는 호출·진입점
근거가 아닙니다. 현재 source index와 불일치하거나 이미 slice에 든 파일은 거절합니다.

```sh
# 먼저 위 import-review 예제로 runs/imported-review를 생성
uv run --locked audit-harness poc examples/judgment-target \
  --run runs/imported-review --candidate f-d71ac5092c87347c \
  --replay examples/poc-replay --output runs/poc-proposal

# 동일 입력의 완료 응답을 재사용
uv run --locked audit-harness poc examples/judgment-target \
  --run runs/imported-review --candidate f-d71ac5092c87347c \
  --replay examples/poc-replay --output runs/poc-proposal --resume
```

실제 제안은 `--replay` 대신 `--codex --model <명시한 모델>`을 사용합니다. 유료 호출이며
research agent는 실행 도구가 없습니다. 호출 한도는 기본 1회(`--max-calls` 1..16)입니다.
실패한 시도도 한도를 사용하고 raw·실패·checkpoint를 보존합니다. timeout 이후에는 같은 identity로
명시적으로 한도를 늘려 재개할 수 있습니다. 변경된 source·설정·provider·prompt·schema·검사 코드는
새 output을 요구하며 저장된 응답·원문·제안을 바꾸면 재개/검토를 거절합니다.

연구자는 `proposal.json`, `context.json`, `recipe-proposal.json`, `calls/`를 읽고 결정합니다.
아래 명령은 검토 결정만 기록합니다. `request_changes`와 `reject`는 원문 제안을 남기고
실행 가능한 recipe를 만들지 않습니다. 실제로 검토한 뒤 `approve`를 기록하면 `recipe.json`이 생성됩니다.
agent 응답에 승인·승격·target replacement 필드를 넣을 수 없습니다.

```sh
uv run --locked audit-harness poc-review examples/judgment-target \
  --run runs/imported-review --proposal runs/poc-proposal \
  --decision request_changes --reviewer researcher \
  --rationale '정상 진입점과 양성·음성 대조군을 검토한 뒤 결정한다.' \
  --output runs/poc-researcher

# 승인한 검토의 recipe만, 준비된 로컬 이미지로 실행
uv run --locked audit-harness poc-review examples/judgment-target \
  --run runs/imported-review --proposal runs/poc-proposal \
  --decision approve --reviewer researcher \
  --rationale '<실제로 검토한 근거와 이 실험을 허용하는 이유>' \
  --output runs/poc-approved

uv run --locked audit-harness validate examples/judgment-target \
  --run runs/imported-review --recipe runs/poc-approved/recipe.json \
  --poc-review runs/poc-approved --image 'sha256:<prepared-local-image-id>' \
  --output runs/poc-worker
```

attachment는 `poc/` 아래의 UTF-8 text이며 각각 최대 64 KiB·합계 128 KiB입니다.
검토 기록은 후보·review·queue·전체 source index·제안·recipe hash에 묶이고 worker에 함께 저장됩니다.
미검토 제안, 변경된 코드/관찰/설정/원문, credential 경로·입력 충돌과 supplied harness 변경을 거절합니다.
수정 후 recipe에는 기존 `replacements`만 추가할 수 있고 검토한 oracle/harness는 고정됩니다.
`judge`는 원래 candidate와 검토 기록을 보존하고 새 PoC 미해결 근거도 별도 issue로 판정합니다.
실행 성공이나 검토 승인만으로 취약점을 확정하지 않습니다.

`reviewer`는 로컬 운영자가 선언하는 이름이며 검토 hash는 전자서명이나 신원 인증이 아닙니다.
artifact 저장소를 신뢰할 수 있게 보호해야 합니다. `make demo-poc`의 `offline-fixture` 승인은
합성 계약 테스트이며 실제 연구자 승인·모델 결과·취약점 재현을 뜻하지 않습니다.
기존 수동 supplied-harness recipe도 계속 사용할 수 있습니다.
Go HTTP 사례는 `examples/go-http-poc-replay`와 `--support-file cmd/server/main.go`,
`--support-file probe.sh`로 그래프·recon·triage의 후보를 승인된 PoC recipe까지 잇는 offline
테스트를 포함합니다. FakeDocker 응답으로 worker·판정 계약만 검증하며 실제 서버 실행 증거는 아닙니다.

## 설정별 수정 전후 비교

검토할 recipe에 최대 4개의 `configurations`를 미리 선언합니다. 각 case는 ID·settings·target 원문,
고정 harness의 build/invocation 인용과 실제 설정을 관찰할 조건이 필요합니다.
worker에는 선택한 ID만 literal argument로 추가합니다. 원래 recipe·oracle·harness는 고정하며
수정 후에는 reviewed target의 `replacements`만 달라집니다. 설정의 이름이나 요청한 옵션을
그대로 출력한 로그는 적용 근거가 아닙니다. 검토한 probe가 실제 target의 속성을 관찰해야 합니다.

[합성 C 예제](examples/matrix-target/app.c)는 컴파일된 optimization 활성 여부와
`AUDIT_GUARD` 값을 출력합니다. [고정 probe](examples/matrix-probe.sh)는 두 build command로
프로그램을 컴파일한 뒤 정상 guest/admin 요청과 정확한 출력 byte를 확인합니다.
이는 원문의 assertion 옵션에 따라 결과가 달라지는 연구 사례에 대응하는 작은 fixture입니다.
optimization probe는 활성 여부를 확인하며 정확한 최적화 단계나 전체 build 설정을 증명하지 않습니다.

```sh
# 아래 spec/recipe/승인 기록은 실제로 검토한 입력을 사용
uv run --locked audit-harness prepare-matrix '<target>' --run '<review>' \
  --spec '<matrix-spec.json>' --output runs/build-matrix

# spec의 모든 image ID가 로컬에 준비돼 있을 때만 명시적으로 실행
uv run --locked audit-harness validate-matrix runs/build-matrix --max-runs 8

# 보존된 worker 결과만 읽으며 대상이나 명령은 실행하지 않음
uv run --locked audit-harness judge-matrix runs/build-matrix --output runs/matrix-judgment
```

strict [matrix 계약](src/agent_audit_harness/schemas/validation-matrix.json)은 별도 승인 경로/hash,
기본 recipe/hash, 수정 recipe/hash와 각 case의 immutable image ID를 요구합니다.
상대 경로는 spec 위치 기준입니다. 기본 recipe는 승인 디렉터리의 `recipe.json`이며 spec의
recipe hash와 같아야 합니다. 모든 선언 case를 정확히 한 번 포함하고, 다른 명령·관찰·검토 기록을
수정 비교에 넣을 수 없습니다. 준비는 원문/검토를 확인하고 spec·recipe·승인 기록을 복사한 뒤 identity를 고정합니다.

실행은 최대 8개 worker를 순서대로 사용합니다. `--max-runs`는 0..8이며 실패한 시도도 예산을 사용합니다.
case마다 수정 전후 image·선택 ID·source/review·oracle/harness와 정책이 같아야 비교합니다.
설정 관찰은 outcome/completion보다 앞에 있어야 하며 누락·중복·다른 case 관찰은 승격을 차단합니다.
적용 proof의 source 인용은 수정 후에도 유효해야 합니다. 인용 위치가 바뀌면 새 검토가 필요합니다.
cleanup 실패·실행 상태 미확인 또는 controller 오류에는 남은 worker를 시작하지 않습니다.
자동 재시작/재개는 없으며 새 matrix를 준비해야 합니다. 기존 기록은 덮어쓰지 않습니다.

`matrix-judgment.json`은 case별 판정·원래 후보/검토·반증/미해결·관찰·worker 참조를 남깁니다.
`validated_cases`는 해당 관찰 조건에서만 승격한 case이며, 다른 case의 실패/누락을 없애지 않습니다.
`coverage_complete`는 선언한 모든 case의 전후 실행과 설정 관찰이 완료됐다는 뜻입니다.
미재현이나 전체 저장소의 안전성을 뜻하지 않습니다. 예제의 guard 활성 case는 미재현으로 보존합니다.

`make demo-matrix`의 image ID와 승인은 합성 자료이고 worker 실행은 0입니다.
실제 테스트는 C compiler·sh·cmp·GNU base64가 있는 image를 미리 준비한 뒤,
그 로컬 ID를 `AUDIT_MATRIX_VALIDATION_IMAGE`로 지정해 `tests/test_matrix.py`를 실행합니다.
자동 compiler/image 설치, sanitizer 계측, 배포 설정 추정과 EVM 실행은 구현하지 않았습니다.

## 검증된 후보의 연결 가설

서로 다른 두 후보의 `validated` 판정 디렉터리와
[연결 가설 예제](examples/chain-hypothesis.json)를 준비한 뒤 순서대로 전달합니다.

```sh
uv run --locked audit-harness prepare-chain runs/first-judgment runs/second-judgment \
  --spec examples/chain-hypothesis.json --output runs/chain
```

spec의 `sequence`는 두 판정의 후보 ID와 같아야 합니다. `producer`와 `consumer`, 전제와
반증의 인용은 원본 worker 입력 source에서 확인합니다. 미검증 전제와 상태 전달은
`unresolved`에 남깁니다. `chain.json`의 `connection: unobserved`는 두 개별 후보가
재현됐어도 실제 연결을 아직 관찰하지 않았다는 뜻입니다. 출력은 대상과 판정 디렉터리 밖에
두어야 하며 원본 판정이나 worker 기록을 변경하지 않습니다. 예제 spec은 합성 계약 자료입니다.

두 번째 후보용으로 별도 승인된 PoC recipe가 있으면
[연결 관찰 계획 예제](examples/chain-experiment.json)를 연구자가 검토해 고정합니다.
PoC의 supplied harness는 첫 결과를 포착해 두 번째 정상 진입점으로 전달해야 합니다.

```sh
uv run --locked audit-harness chain-review runs/chain \
  --poc-review runs/combined-poc-approved --plan examples/chain-experiment.json \
  --decision approve --reviewer '<name>' --rationale '<reason>' \
  --output runs/chain-review
uv run --locked audit-harness validate '<target>' --run '<review>' \
  --recipe runs/chain-review/poc-review/recipe.json \
  --poc-review runs/chain-review/poc-review --image "sha256:<prepared-local-image-id>" \
  --output runs/chain-worker
uv run --locked audit-harness judge-chain runs/chain --review runs/chain-review \
  --worker runs/chain-worker --output runs/chain-judgment
```

`judge-chain`은 worker를 실행하지 않습니다. 고정한 진입·출력·입력·재현·잘못된 상태 거부·완료 관찰을
한 stream에서 순서대로 요구하고, 두 base64 값의 원래 byte hash와 길이를 비교합니다.
누락·역순·불일치·대조군 수락·실패·timeout은
연결 재현이 아닙니다. 남은 미해결·반증은 별도로 보존하며, 연결이 관찰돼도 영향은 승격하지 않습니다.
[상태 독립 예제](examples/chain-probe.sh)는 실제 격리 실행에서 대조군도 수락해 승격되지 않습니다.
[두 결함 예제](examples/chain-linked-target/app.sh)는 각각 수정 전후에 검증한 토큰 누출·무단 교환을
연결하며, 준비된 로컬 이미지의 실제 격리 실행에서 `connected`를 확인했습니다. 이 합성 결과는
운영 대상의 연결·영향 입증을 대신하지 않습니다.
두 경계를 재실행하려면 `/bin/sh`, `/usr/bin/cmp`, `/usr/bin/sed`, `/usr/bin/base64`가 있는
준비된 로컬 이미지 ID를 지정합니다. 테스트는 이미지를 자동으로 받거나 빌드하지 않습니다.

```sh
AUDIT_VALIDATION_IMAGE=sha256:<prepared-local-image-id> \
  uv run --locked pytest -q \
  tests/test_chain_experiment.py::test_real_worker_rejects_state_independent_chain \
  tests/test_chain_linked_docker.py
```

검토 영수증의 reviewer 이름과 SHA-256은 로컬 선언과 무결성 점검이며 서명이 아닙니다.

## 단계별 영향 측정 계획

검증된 단일 후보의 `judgment.json` 또는 연결된 `chain-judgment.json`을 입력으로 사용합니다.
연구자가 [계획 예제](examples/impact-plan.json)의 PoC 승인 경로를 실제 승인 artifact로 바꾸고
보안 속성·위협 문맥·대조군·성공/실패 조건을 검토합니다.

```sh
uv run --locked audit-harness impact-review --primitive runs/validated-judgment \
  --plan runs/impact-plan.json --decision approve \
  --reviewer '<name>' --rationale '<reason>' --output runs/impact-review
# 연결 결과를 입력으로 쓰는 경우 --primitive 대신 --chain runs/chain-judgment
```

`impact-review`는 원본 판정을 재계산하고 각 단계의 승인된 PoC recipe·source·실제 진입점·
관찰 marker를 확인해 보관합니다. 최소 setup, primitive, control, impact 네 단계이며
control은 명시적 음성 관찰이 필요합니다. 열린 가정과 그 해소 단계도 계획에 남깁니다.
`impact-review` 자체는 계획 검토만 수행합니다. 각 단계의 recipe는 **기존 격리 worker**로
따로 실행한 뒤 `impact-step`에 제출합니다. 아래 예시는 첫 단계이며, 이후 `primitive`,
`control`, `impact`를 새 worker 출력 디렉터리로 차례로 반복합니다.

```sh
uv run --locked audit-harness validate '<target>' --run '<review>' \
  --recipe runs/impact-review/stages/setup/poc-review/recipe.json \
  --poc-review runs/impact-review/stages/setup/poc-review \
  --image "sha256:<prepared-local-image-id>" --output runs/impact-worker-setup
uv run --locked audit-harness impact-step runs/impact-review \
  --worker runs/impact-worker-setup --stage setup --decision approve \
  --reviewer '<name>' --rationale '<observed-property>' \
  --output runs/impact-checkpoint
```

`impact-step`은 실행하지 않고 원본 worker 근거를 다시 읽습니다. 관찰 gate와 연구자 승인이 모두
통과해야 다음 단계로 넘어갑니다. 실패·timeout·미재현은 같은 단계에 기록하고, `retry`와
**새 worker**로만 재시도합니다(단계당 최대 3회). `reject`는 실험을 중단합니다.
마지막까지 완료돼도 열린 가정이나 반증은 `observed_with_open_issues`로 남습니다.
`impact_observed`는 승인된 실험의 한정된 속성 관찰이며 다른 배포·입력·영향을 뜻하지 않습니다.
[두 결함 합성 예제의 실제 격리 테스트](tests/test_chain_linked_docker.py)는 네 단계의 worker와
checkpoint를 남깁니다. 마지막 단계는 보호 기록 응답의 원본 바이트를 base64로 기록해
검토할 수 있게 합니다. 테스트의 연구자 승인은 합성 선언이며 운영 승인을 대신하지 않습니다.

## 동일 조건 replay 비교

`benchmark-replay`는 같은 대상 snapshot과 호출·slice·조회 예산으로 lexical baseline과
선택적인 graph/recon candidate를 각각 새로 실행합니다. 연구자가 지정한
[정답 위치 예제](examples/benchmark-truth.json)의 원문 인용과 CWE를 확인한 뒤,
정답별 후보 유지·기각·미제안, 정상 대조군의 오탐, 입력에 포함되지 않은 위치를 기록합니다.

```sh
uv run --locked audit-harness benchmark-replay examples/demo-target \
  --truth examples/benchmark-truth.json \
  --baseline-replay examples/replay --candidate-replay examples/replay \
  --output runs/benchmark-example
# graph 비교에는 --candidate-graph graph.json --candidate-recon recon.json을 추가
```

`benchmark.json`은 각 실행의 원본 metrics·coverage·artifact hash, 실행 시간과 label별 결과를
보존하고 `comparison`에 candidate−baseline 차이를 표시합니다. token이 보고되지 않으면
차이도 `null`이며 replay 시간은 로컬 orchestration 시간입니다.
정답은 연구자 선언이고 `positive`는 해당 위치의 조사 후보를 뜻합니다. replay 응답 비교는
모델 탐지율, 운영 취약점, 실제 token 비용을 입증하지 않습니다.
Go의 명령 선택, Python의 `input()`→`os.system()`/상수 명령, Solidity의 전체 잔액 전송/
상속된 owner modifier 대조군은 각각 `examples/go-review-benchmark-truth.json`,
`examples/python-benchmark-truth.json`, `examples/solidity-benchmark-truth.json`에 고정했습니다.
세 대상은 별도 평가 단위이며, 기록된 replay의 차이를 언어별 탐지율로 해석하지 않습니다.
새 평가용 truth는 같은 결함의 허용 가능한 다른 원문 위치를 `accepted_locations`로 최대
4개까지 사전 선언할 수 있습니다. 모든 위치·인용·CWE와 사례 간 중복을 검증하며 사례당
한 번만 채점합니다. 기존 실모델 평가의 단일 위치 정답과 점수는 소급 변경하지 않습니다.
고정 입력·호출 상한·프롬프트 byte와 제한적인 GPT-6 Luna 탐색 결과는
[모델 평가 계획](docs/model-evaluation.md)에 기록했습니다.

이미 완료된 두 `run`을 새 모델 호출 없이 비교하려면 다음 명령을 사용합니다.

```sh
uv run --locked audit-harness benchmark-runs '<target>' \
  --truth '<researcher-labels.json>' --baseline '<first-run>' \
  --candidate '<second-run>' --output '<new-comparison-directory>'
```

이 경로는 같은 source snapshot·도구 계약·호출/slice/조회 예산을 요구하며, Codex run끼리는
같은 모델·CLI/config 식별자와 인용 수정 설정을 요구합니다. 재개 cache hit가 있는 run이나
미확정 시도는 비교에서 제외합니다. 각 `reply.json`은 실제 성공 시도의 원본 응답·프롬프트와
대조하고, 인용 수정의 최초 거절 기록도 확인합니다. `recorded_call_seconds`는 실패를 포함한
모든 시도의 기록된 시간 합계이며 graph 준비와 전체 실행 시간은 포함하지 않습니다.
`attempt_reported_token_usage`와 `token_coverage`도 실패를 포함하고,
원래 `metrics.reported_token_usage`는 성공 응답의 합계를 유지합니다. 입력·출력 token이 모든 시도에서 보고된
두 run에만 token 차이를 계산합니다. 실행 artifact와 provider 식별자는 로컬
선언이므로 보관소 무결성과 정답 검토는 연구자가 관리해야 합니다.

실패하거나 중단된 Codex run의 호출 비용은 별도로 집계합니다. 이 명령은 모델을 호출하지 않습니다.

```sh
uv run --locked audit-harness benchmark-attempts '<run-directory>' \
  --output '<new-attempt-report-directory>'
```

`attempts.json`은 성공·실패·미확정 시도별 기록 시간과 provider가 보고한 token을
보존합니다. 사용량이 없는 시도는 `null`과 coverage로 표시하며, 시간 합계에는
graph/recon 준비가 포함되지 않습니다. 완료된 pair의 정답 채점에는 계속
`benchmark-runs`를 사용합니다.

독립된 pair 비교가 둘 이상 있으면 저장된 원본 run을 재확인한 뒤 변동을 요약할 수 있습니다.

```sh
uv run --locked audit-harness benchmark-summary '<target>' \
  --truth '<researcher-labels.json>' \
  --report '<first-benchmark-runs-directory>' \
  --report '<second-benchmark-runs-directory>' \
  --output '<new-summary-directory>'
```

같은 정답·소스·예산·모델/분석 설정과 서로 다른 run을 요구합니다. `benchmark-summary.json`은
정답별 대표 위치 판정 횟수와 원인 근거 인용 횟수를 분리하고,
candidate−baseline 차이의 값·중앙값·최솟값·최댓값을 보존합니다.
각 pair의 analysis/triage 프롬프트 바이트·기록된 호출 시간과 검증 대기 후보 수도 보존합니다.
프롬프트 바이트는 token이 아니며 대기 후보 수는 실제 연구자 검토 시간의 대리 지표입니다.
어느 pair든 token이 완전하지 않으면 token 차이의 분포는 `null`로 남습니다. 이 값들은
반복한 로컬 artifact의 기술 통계이며 작은 표본의 탐지율이나 병렬화 이득을 증명하지 않습니다.

## 격리된 검증 worker

완료된 review의 `validation-queue.json`에서 한 후보를 지정하고, 대상 밖에 둔
[검증 recipe 예제](examples/validation-recipe.json)를 `validate`에 전달합니다.
recipe는 후보 ID, 목적, 전달할 파일의 상대 경로와 SHA-256, 컨테이너 내부 명령 argv,
시간·CPU·메모리·프로세스·scratch·로그 한도를 요구합니다.
`validation_plan`의 설명 문자열은 자동 실행하지 않습니다.
이미지는 운영자가 미리 준비한 신뢰할 수 있는 Linux 이미지의 로컬 `sha256:` ID만 받습니다.
worker가 이미지를 다운로드하거나 프로젝트 build script를 호스트에서 실행하지 않습니다.

```sh
# Linux Docker daemon과 /usr/bin/env, /bin/sh가 있는 로컬 이미지를 먼저 준비
# 이 조회는 이미 준비된 이미지의 ID만 읽음
audit_validation_image=$(docker image inspect debian:bookworm-slim --format '{{.Id}}')

uv run --locked audit-harness run examples/validation-target \
  --replay examples/validation-replay --output runs/validation-review
uv run --locked audit-harness validate examples/validation-target \
  --run runs/validation-review --recipe examples/validation-recipe.json \
  --image "$audit_validation_image" --output runs/validation-worker

# 같은 흐름을 새 디렉터리에서 실행하는 demo
VALIDATION_IMAGE="$audit_validation_image" make demo-validation
```

recipe가 지정한 UTF-8 일반 파일만 복사합니다. review에 포함된 파일의 hash 변경,
symlink·경로 이탈·숨김 파일·일부 credential 이름/확장자, 기각 후보를 거절합니다.
파일당 512 KiB, 전체 32 MiB이며 복사본은 `/input`에 읽기 전용으로 연결합니다.
홈 디렉터리, Docker socket, SSH agent, 사용자 환경변수와 Docker 인증 설정을 전달하지 않습니다.
외부 네트워크는 `none`, 사용자 UID는 65532이며 root filesystem은 읽기 전용입니다.
capability를 제거하고 no-new-privileges와 기본 seccomp, CPU·메모리·PID 한도를 검사합니다.
`/work`와 `/tmp`는 용량을 제한한 tmpfs이며 image의 entrypoint와 healthcheck를 대체합니다.
실제 Docker 정책이 요구 사항과 다르면 실행 전에 중단합니다. Docker를 사용할 수 없을 때
호스트에서 실행하는 대체 경로도 없습니다.

예제는 10초, CPU 0.5개, 메모리 128 MiB, 32개 프로세스, `/work` 16 MiB,
stdout/stderr 각각 1 MiB를 사용합니다. timeout이나 로그 초과 시 컨테이너를 종료하고 제거합니다.
별도 폐기 타이머가 먼저 준비되며, 제어 프로세스가 강제 종료돼도 해당 컨테이너만 제거합니다.

| 결과 | 의미 |
| --- | --- |
| `completed` | 지정한 명령이 exit 0으로 종료되고 제거 완료; 취약점 입증과는 별개 |
| `process_failed` | 명령의 nonzero exit, OOM 또는 Docker가 보고한 실행 오류 |
| `timeout` / `output_limit` | 시간 또는 stream별 로그 한도에 도달하여 종료 |
| `worker_failed` | 입력·격리 정책·Docker 제어·증거 수집·제거 실패 |
| `interrupted` | 처리 가능한 사용자 중단; 기존 근거와 제거 결과 보존 |

`execution_attempted`와 Docker 상태에서 확인한 `execution_started`를 구분합니다.
실행 여부를 확인할 수 없으면 `null`로 남깁니다. `confirmed_findings`는 항상 0입니다.
CLI는 `completed`에만 exit 0을 반환합니다. 제거 실패는 container 이름과 오류를 기록합니다.
SIGKILL 시 최종 결과를 완성할 수 없으므로 진행 중 `result.json`과 별도 `watchdog.json`을 함께 확인합니다.
worker는 재개하거나 결과를 덮어쓰지 않으며 재시도에는 새 output이 필요합니다.

| worker 산출물 | 보존 근거 |
| --- | --- |
| `recipe.json` / `input/` | 실제 recipe와 전달한 파일 복사본 |
| `source-manifest.json` / `reviewed-input/` | 실제 실행 소스 hash와 수정한 파일의 원래 내용 |
| `candidate.json` | 원래 후보·원인·반증·보류·입력 gap |
| `create-arguments.json` / `policy.json` | 요청한 격리 설정과 실행 전 확인한 Docker 정책 |
| `logs/` / `state.json` | 제한된 stdout/stderr, 제어 로그, 실제 exit/OOM/종료 상태 |
| `watchdog.json` | 독립 폐기 타이머의 준비·취소·제거 또는 실패 기록 |
| `result.json` | 상태, 실패 단계, 이미지/recipe/review/source identity, 증거 파일 hash |

build/test 명령은 준비된 이미지에서 `/input`을 `/work`로 복사한 뒤 실행할 수 있습니다.
필요한 compiler와 의존성은 이미지에 미리 넣어야 합니다. compiler별 자동 계측과 EVM 검증,
자동 계측·검증 코드 생성은 아직 구현하지 않았습니다.
Docker는 daemon·kernel·신뢰한 이미지에 의존합니다. 이미지나 선택한 소스에 이미 들어 있는
비밀정보를 자동 제거하지 않으며, Docker daemon 장애로 제거가 실패하면 별도 정리가 필요합니다.

## Validation 결과 판정과 승격

`judge`는 worker의 기존 기록만 읽으며 명령을 실행하거나 agent를 호출하지 않습니다.
원래 triage 판정과 worker `result.json`은 유지하고 별도 `judgment.json`을 만듭니다.
실행 성공, 취약점 재현, 수정 검증을 서로 다른 결과로 기록합니다.

| 판정 | 의미 |
| --- | --- |
| `execution_only` | 실행은 정상 종료했지만 선언된 취약점 관찰 조건이 없거나 결과가 관찰되지 않음 |
| `not_reproduced` | 완료된 검사가 명시한 음성 결과를 관찰함; 후보 기각이나 전체 안전 판정은 아님 |
| `reproduced` | 취약점 관찰 조건을 만족했지만 진입점 또는 수정 비교 등 승격 조건이 부족함 |
| `inconclusive` | 실패·timeout·불완전/충돌 근거·비교 조건 불일치·미해결 주장으로 판단 보류 |
| `validated` | 재현·실제 진입점·동일 조건의 수정 효과·기존 근거 해소가 모두 확인된 검증 사례 |

승격에는 다음 조건을 모두 요구합니다.

1. recipe의 선택적 `oracle`에 실행 **전에** 재현·비재현·검사 완료의 관찰 조건을 고정합니다.
   source 인용과 별도 검증 코드(`harness_path`)를 요구합니다. 명령은 interpreter와
   `/input/<harness_path>`로 시작해야 합니다. 일반적인 exit 0이나 임의 crash만으로 재현하지 않습니다.
2. 출력의 **완전한 한 줄이 정확히 한 번** 나타나는지 검사합니다. 결과는 완료보다 먼저,
   진입점은 결과보다 먼저 같은 stream에서 관찰돼야 합니다. 부분 문자열·중복·양성/음성 충돌과
   완료 누락을 거절합니다. 필요한 로그의 경로·줄·원문·SHA-256을 판정에 연결합니다.
3. `entrypoint`에 실제 요청을 보내는 검증 코드의 인용, 대상 진입점의 원문과 런타임 관찰을 요구합니다.
   `kind=direct_call`, 호출 그래프 도달 관계, handler 등록 또는 이름만으로 승격하지 않습니다.
4. 수정 후에는 동일한 원본 review/후보, 검증 코드·명령/입력·oracle·자원 한도·image·worker·engine을
   사용합니다. 명시한 source `replacements`만 바꿀 수 있으며 검증 코드 자체는 수정할 수 없습니다.
   수정 전 양성, 수정 후 실제 진입점 도달·검사 완료·명시적 음성이 관찰돼야 합니다.
   수정 후 timeout, 결과 부재 또는 단순 성공은 수정 검증이 아닙니다.
5. 기존 `unresolved`, `counterevidence`, 미해결/외부 호출·static/modifier gap·입력 누락을
   안정적인 issue ID로 보존합니다. oracle의 `resolutions`에는 해소할 ID, 요구하는 검증 단계,
   연구자의 이유를 지정합니다. 그 단계가 실제로 통과해야 해소되며, 연결되지 않은 근거는 승격을 막습니다.
   원래 주장과 반증은 삭제하지 않고 `issues[].evidence_refs`로 관찰 기록을 연결합니다.

`replacements`는 경로·수정 전후 SHA-256·새 UTF-8 내용을 요구합니다. review에 포함된 입력 파일만
복사본에서 바꾸며 원본 레포는 수정하지 않습니다. 변경 전 파일은 `reviewed-input/`, 실제 실행 파일은
`input/`에 보존합니다. 변조·symlink·미완성 result·hash 누락/불일치는 승격을 막고 실패를 기록합니다.
기존 oracle 없는 recipe와 worker 기록은 계속 사용할 수 있지만 실행 결과만 판정합니다.

```sh
# 준비된 로컬 이미지로 합성 CLI 요청의 수정 전후를 실행하고 판정
VALIDATION_IMAGE="$audit_validation_image" make demo-judgment

# 이미 실행한 두 worker의 기록만 평가; Docker 실행이나 모델 호출 없음
uv run --locked audit-harness judge runs/case-baseline \
  --fixed runs/case-fixed --output runs/case-judgment
```

[예제 원본](examples/judgment-target/app.sh)은 guest 요청에도 `DATA private-record`를 반환합니다.
[검증 코드](examples/judgment-target/probe.sh)는 정상 CLI dispatcher를 호출하고 응답으로 양성/음성을
판단합니다. [수정 recipe](examples/judgment-fixed-recipe.json)는 admin 이외 요청에 `DENIED`를 반환하게
복사본만 변경합니다. 두 실행의 진입점·완료를 확인하고 기존 미해결 주장 두 개를 해당 근거로 해소합니다.
두 예제의 검증 코드는 대상 출력과 판정 메시지를 구분하고 응답의 정확한 byte 일치를 검사합니다.
admin 요청이 계속 비공개 자료를 받을 수 있어야 하므로 모든 요청을 거절하는 수정은 통과하지 않습니다.
CLI 출력의 원래 bytes는 base64로, HTTP 응답은 인용·escape한 형태로 로그에 보존합니다.

`judgment.json`에는 원래 후보, 각 실행의 상태·source 인용·관찰 위치/hash, 비교된 변경,
전체 issue/해소 이유/근거 참조, `promotion.requirements`와 차단 사유, 입력 결과와 판정 코드의 identity가
남습니다. 승격되면 `promotion.eligible=true`, `validated_findings=1`입니다.
원래 analysis/worker의 `confirmed_findings=0`과 graph 계약은 바꾸지 않습니다.
`judge`의 CLI exit 0은 평가 완료이며 승격 여부는 `verdict`와 `promotion.eligible`로 확인합니다.

oracle의 보안 의미와 계측은 연구자가 검토해야 합니다. 로그 문자열이나 source 인용의 형식 검사가
임의 프로그램의 진실성을 입증하지는 않습니다. `validated`는 선언한 요청·환경·관찰 조건의 결과이며
운영 배포 도달, 모든 입력의 안전, exploit 영향이나 수정의 완전성을 뜻하지 않습니다.
SHA-256은 저장된 기록의 무결성 확인이며 기록 작성자의 인증·서명은 아닙니다.

같은 Go HTTP 예제를 처음부터 끝까지 연결하려면 [개발 안내](docs/development.md)의
`make setup-validation-go`로 고정 이미지를 명시적으로 준비한 뒤,
`VALIDATION_IMAGE=<준비된 로컬 sha256 ID> make demo-go-http`를 실행합니다.
`/private` 등록 → handler → service → store의 호출 그래프와 replay 후보가 같은 review에 남고,
worker는 컨테이너 내부의 실제 guest GET을 관찰합니다. 수정 전 `200`·비공개 자료,
수정 후 `403`·거절 응답과 두 실행의 admin 성공이 기록되면 `judge`가 해당 사례의 근거별 승격을 판정합니다.
worker는 review에 저장된 그래프의 identity와 설정 해시도 확인합니다. 검토된 `go.mod`·`go.sum`이
바뀌면 recipe 해시를 갱신해도 실행 전에 거절하며, 새 graph/recon/review가 필요합니다.
검증 요청·oracle과 수정은 이 예제에 고정되어 있으며 결과는 운영 서비스의 안전 판정이 아닙니다.

새 Go 파일 선택 사례는 별도 snapshot인 `examples/go-file-selection-target`에서 검증합니다.
준비된 같은 이미지로 `VALIDATION_IMAGE=<준비된 로컬 sha256 ID> make demo-go-file-selection`을
실행하면 graph → recon → 오프라인 후보 → 격리된 실제 HTTP 요청 → 수정 전후 판정을 기록합니다.
`/download?asset=private.txt`는 수정 전 비공개 파일을 반환하고, `storage.Open`의 허용 목록
수정 후 차단됩니다. 공개 파일 요청과 요청값과 무관한 `/notice`는 양쪽에서 성공해야 합니다.
이 snapshot과 검증 결과는 앞선 고정 실모델 평가 입력·점수를 바꾸지 않습니다.

## 개발 안내

agent의 추가 조사 흐름은 `make demo-investigation`으로 확인할 수 있습니다.
analysis가 `resolve`·`reachable`·indexed 원문 요청을 반환하면 harness가 예산 안에서 조회하고
다음 analysis와 triage에 근거를 전달합니다. 실패·누락은 후보의 미해결 근거로 남습니다.
추가로 읽은 함수의 미해결 호출·정적 분석·modifier gap도 함께 보존합니다.
부분 원문의 함수 참조는 전체 함수 검토나 실행·데이터 흐름의 증명이 아닙니다.
요청·응답·예산과 재개 checkpoint는 run의 `investigations/`, `queries/`에 저장됩니다.
`run --max-queries 4 --query-bytes 16000`이 기본값이며 전체 agent 호출은 `--max-calls`로 제한합니다.
대상 실행이나 모델에 shell/file 도구 권한을 추가하는 기능은 아닙니다.

- [구조 분석과 효율성 평가](docs/architecture.md)
- [agent 개발 방법과 검증 명령](docs/development.md)
- [다음 구현 단계와 완료 조건](docs/roadmap.md)
- [agent가 먼저 읽는 작업 규칙](AGENTS.md)

graph/recon을 제공하지 않은 실행은 파일 이름 순서의 연속된 줄 묶음을 사용합니다.
현재 graph는 C/C++·Go·Solidity·Python의 정적 호출 구조를 지원합니다. 함수 포인터·가상 호출은 미해결로 남기며,
생성자·암묵적인 소멸자·template·link 조건의 전체 해석과 함수 간 taint는 지원하지 않습니다.
호출 도달 관계만으로 공격자 입력의 도달 가능성을 주장하지 않습니다.
자동 threat model·노출 우선순위 추정, 언어별 노출 adapter,
Go의 points-to·reflection·패키지 전역 initializer 실행 관계는 아직 구현하지 않았습니다.
UTF-8 소스만 읽으며, 제외 디렉터리·symlink·큰 파일·긴 줄은 coverage에 기록합니다.
`.gitignore`를 해석하거나 소스에 들어 있는 비밀정보를 자동 제거하지는 않습니다.

Codex 호출은 별도 임시 작업 디렉터리와 제한된 도구 설정을 사용합니다.
CLI의 read-only 설정은 호스트 읽기 격리나 VM 경계를 보장하지 않습니다.
원본 응답·event·stderr와 replay 입력에는 위의 파일 수/byte 상한을 적용합니다.
원시 소스·응답·로그는 민감한 자료일 수 있으므로 실행 결과를 기본 Git 제외 대상으로 두었습니다.
동적 명령은 명시적인 recipe로 `validate`에 전달한 경우에만 격리 worker에서 실행합니다.
