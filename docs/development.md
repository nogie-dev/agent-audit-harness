# Agent 개발 환경

## 빠른 반복

`make setup`으로 lockfile 기반 환경을 설치하고 `make check`로 로컬 검증한다.
개발 의존성은 pytest와 Ruff다. 런타임 추가 의존성은 agent 출력의 신뢰 경계를 검사하는 jsonschema 하나다.
graph DB, agent SDK, queue 서버와 웹 UI는 현재 단계에 필요하지 않다.
호출 구조 작업에는 분석 언어에 따라 Clang, Go 또는 Node.js가 필요하다.
`make setup-go`는 helper의 고정 의존성(x/tools 0.30.0, x/mod 0.23.0, x/sync 0.11.0)을 준비한다.
`make setup-solidity`는 locked solc-js 0.8.30을 `.cache/solidity-extractor`에 준비한다.
`make demo-graph`/`make demo-go`/`make demo-solidity`로 실제 compiler 경로를 검증한다.
`make demo-python`은 추가 의존성 없이 격리된 표준 AST 파서를 사용한다.
처음에는 graph를 만들고 `resolve`/`reachable`로 구조를 확인한다.
`make demo-review`는 graph → source-backed recon → 다중 파일 slice → replay → resume을 검증한다.
`make demo-investigation`은 agent의 추가 graph/원문 요청과 실패 gap, query/reply 재사용을 검증한다.
`plan`/`run`에 `--graph`와 `--recon`을 함께 제공하면 관계 기반 입력을 사용한다.
`make setup-static`은 hash-locked Semgrep CE 1.180.0과 CA/native library를 별도 캐시에 준비한다.
첫 준비에는 네트워크가 필요하며 설치한 뒤 분석은 대상 snapshot과 생성한 로컬 rule만 사용한다.
`make demo-static`은 Python graph → 실제 CE 근거 → recon → replay/triage → resume을 검증한다.
`make demo-models`는 Python·Go의 첫 CE 근거 → 원문 기반 wrapper 모델 → 두 번째 CE → replay/resume을 검증한다.
`make demo-recon`은 등록/정적 역할 근거 → 계획 제안 → 기존 slicing/triage → 재개를 검증한다.
`static ... --graph ... --output ...` 산출물을 `plan`/`run --static .../static.json`에 전달한다.
graph 계약은 그대로 유지하고 역할 관찰과 taint·미해결 경계를 별도 artifact로 전달한다.
`validate`는 완료된 대기열 후보와 명시적 recipe를 준비된 로컬 Docker image ID에 연결한다.
`VALIDATION_IMAGE=sha256:<id> make demo-validation`은 replay → 실제 worker를 새 디렉터리에서 실행한다.
`VALIDATION_IMAGE=sha256:<id> make demo-judgment`은 같은 probe의 수정 전후 worker → 판정/승격 기준을 확인한다.
Docker 준비와 image/의존성 다운로드는 운영자의 별도 단계이며 worker에는 자동 pull/build가 없다.

`AGENTS.md`는 코드 책임, 실행 명령과 유지할 계약만 담는다.
agent가 매 작업마다 전체 설계 문서를 읽지 않도록 자세한 내용은 docs에 분리했다.
파일과 schema는 package에 포함되므로 editable 설치와 wheel 설치에서 같은 계약을 사용한다.
Go helper의 소스·go.mod·go.sum도 wheel에 포함하며 로컬 toolchain으로 컴파일한다.
Solidity helper의 JS·package/lock도 포함하되 node_modules는 배포하지 않는다.
wheel 설치에서도 실행 디렉터리의 `.cache/solidity-extractor`에 같은 lock으로 npm 의존성을 준비해야 한다.
추출은 이 캐시를 읽기만 한다. 대상 디렉터리 내부에 compiler 캐시를 둘 수 없다.
Semgrep의 rule/requirements/schema도 package에 포함하고 native 실행 파일·venv는 배포하지 않는다.
실행 디렉터리의 `.cache/semgrep`을 먼저 준비해야 한다. 정적 rule spec도 대상 밖에 있어야 한다.

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
추가 analysis는 `s0001.q0001.analysis`처럼 별도 call로 계산한다. 실제 provider 시도마다
`calls/<call>/attempt-<누적 번호>/`에 prompt·raw response·오류 기록을 남겨 재시도가 이전 실패를 덮지 않는다.
성공하고 원문 검증을 통과한 응답만 call의 `reply.json`에 저장한다.
`--repair-citations`는 기본 꺼짐인 인용 수정 옵션이다. 인용 오류 코드·거절 응답을
`citation-repair.json`에 고정하고 같은 계약으로 한 번만 다시 요청한다. 시도별 입력과
raw는 모두 남고 global 호출 상한을 소비한다. 상한 때문에 아직 수정하지 못했다면
재개할 수 있지만, 이미 수정 시도가 시작됐다가 실패/중단되면 자동 반복하지 않는다.
성공 checkpoint는 실제 시도 번호와 추가 입력 hash를 묶고 재개 시 원본도 대조한다.
`citation_details`에는 실패한 JSON 필드와 인용 위치, 해당 입력 fragment의 주변 원문
최대 3행·4 KiB 및 첫 정확한 인용의 UTF-8 byte 열을 기록한다. 같은 응답의 인용 실패는
최대 8개를 `errors`에 모으고 나머지는 `omitted_error_count`로 남긴다. 각 오류에는 제공된
fragment에서 동일 quote가 정확히 시작하는 위치를 최대 8개 기록하지만 자동 적용하지 않는다.
입력 밖 파일을 읽거나 다른 행의 인용을 자동으로 선택하지 않는다. 큰 행·입력 밖 위치는
명시적으로 원문을 생략한다.
재개 시 검증기를 다시 적용해 feedback을 재계산하고 최초 실패 기록·수정 입력을 대조한다.
성공 응답은 `citation_repair_outcome`을 저장한다. 인용 필드만 고친 경우와 후보 철회,
그 밖의 응답 내용 변경을 구분한다. `metrics.json`/보고서와 `benchmark-attempts`에도 집계하며,
후자는 수정 재실패·pending·unknown을 보존한다. 이전 feedback 없는 checkpoint는 읽기 전용
비교에서 기존 prompt를 그대로 재구성하며, 이전 원본을 수정하지 않는다.

## Agent의 추가 근거 조회

analysis 응답은 최종 `candidates` 또는 `candidates=[]`와 `requests`를 반환한다.
한 응답에 최대 4개 요청을 허용하며 candidates와 요청을 함께 반환하면 실패한다.
`resolve`는 함수/파일/scope, `reachable`은 한 함수의 확정 직접 호출 관계를 조회한다.
둘 모두 정의·호출 위치의 indexed 원문을 함께 제공하고 미해결 호출을 유지한다.
`source`는 indexed 경로와 최대 200개 물리적 줄을 읽는다. symlink·secret·대상 밖 경로·
index에서 제외된 파일은 읽지 않으며 대상 파일을 다시 열거나 import/build하지 않는다.

```json
{"candidates": [], "requests": [{"operation": "source", "path": "web/handler.go", "first_line": 10, "last_line": 13, "reason": "Check the local authorization branch."}]}
```

`--max-queries`는 slice당 시도 한도(기본 4, 0..32), `--query-bytes`는 제공한 query data의 누적
직렬화 UTF-8 byte 한도(기본 16,000, 1,024..65,536)다. 실패한 lookup도 시도 한도를 소비한다.
전체 응답이 남은 byte 한도를 넘으면 일부 원문을 잘라 제공하지 않고 data=null·required_bytes와
omission 이유를 기록한다. 요청·상태·gap bookkeeping과 기본 slice/prompt는 이 byte 계산 밖이며
전체 token 상한을 뜻하지 않는다. global `--max-calls`와 기존 provider timeout은 계속 적용한다.
query 수가 소진되면 agent는 최종 답변을 해야 하며 추가 요청은 incomplete failure로 남긴다.

`queries/`는 요청/입력·결과 hash를 가진 checkpoint, `investigations/`는 slice별 누적 응답과 예산이다.
재개는 graph/source·prompt/schema·provider/model·조회 코드/예산 identity가 같을 때만 재사용한다.
조회 한도 변경은 새 output이 필요하다. 추가로 받은 원문만 인용 검증에 추가하고 triage에도 같은
근거를 전달한다. 조회 실패/누락의 ID는 후보 `input_gaps.investigation_gap_ids`에 보존되므로
동적 판정에서 명시적으로 해소하지 않은 근거는 승격을 막는다. source 추가 제공은 초기 slice의
누락 기록을 자동 삭제하거나 미해결 호출을 해결하지 않는다.

graph가 있는 원문 조회는 요청한 줄의 호출 사실과 겹치는 함수의 ID를 함께 제공한다.
부분 원문만 제공되어도 해당 함수의 알려진 미해결 호출·static gap·modifier gap은 참조로
보존한다. 이 참조는 추가로 인용 가능한 원문이나 함수 전체를 읽었다는 뜻이 아니다.
gap 상세와 static artifact identity도 query data의 byte 예산에 포함하며, 예산을 넘으면
원문과 참조를 모두 생략하고 query gap을 남긴다. 최종 triage는 초기 가설과 추가로 읽은
함수의 한계를 함께 선택한다. `make demo-static`의 `query-review/`는 초기 raw 가설 밖의
dynamic sink 한 줄을 조회하고 callback/static gap의 agent 입력·후보·재개 보존을 확인한다.

첫 구현은 분석에 필요한 증거를 추가 조사한다. PoC 제안 및
실제 모델의 조사 품질은 후속 단계다. `make demo-investigation`은 Go launcher 원문을 추가로
조회하고 없는 Authenticate selector를 gap으로 남긴 뒤 replay로 uncertain 후보와 재개를 확인한다.
이 예제는 보강된 호출·gap 참조까지 포함해 명시적인 32,000 byte 조회 예산을 사용한다.
기본값 16,000 byte는 유지한다.

## 대상 모델 제안과 두 번째 정적 분석

analysis는 candidates/requests와 함께 보내지 않는 `model_proposals`를 선택할 수 있다.
graph·recon·첫 `--static`이 필요하며 slice당 한 번·최대 4개다. 각 source/sink는 graph 함수 ID,
제공된 함수 원문 evidence(path/line/UTF-8 byte column/quote), rationale과 가정을 갖는다.
없는 함수는 unavailable gap, 알려진 함수의 틀린 인용·위치·ID는 엔진 실행 전에 실패한다.
코어만 resolved 호출에서 ASCII dotted `name(...)`을 생성한다. 역할당 8개 표기·전체 16개 rule
상한을 넘기거나 Unicode/generic 등 지원하지 않는 호출은 gap이다. 임의 rule/code/config는 받지 않는다.

source는 call 반환값, sink는 whole call이다. 인자별 역할·sanitizer 모델은 지원하지 않고
wrapper의 의미·실제 노출·함수 간 흐름은 가정이다. 새 관찰 위치가 해당 resolved 함수 호출과
유일하게 일치하지 않으면 `model_endpoint_binding_unverified`를 남긴다. 이 검사는 artifact를
다시 읽을 때도 수행하므로 checksum을 다시 만든 입력도 필요한 gap을 지울 수 없다.

첫 static의 engine/runtime/adapter/normalizer가 같은 준비 환경에서만 재분석한다.
`models/<slice>/plan.json`, `attempt-<번호>/rules.json`, `analysis/`의 새 static/raw 결과,
`failure.json`, `result.json` checkpoint를 보존한다. 모델 계획·raw/rules·identity가 변한 cache는 거절한다.
성공한 재개는 CE를 재실행하지 않고 timeout 재개는 다음 attempt에 기록한다.

`contexts/`에 첫/새 artifact hash·byte 한도·제공 데이터·상세 누락을 저장한다. agent에는 제한된
데이터와 누락 요약·참조를 전달하며 누락 목록으로 입력이 계속 커지지 않게 한다.
추가 조회로 원문을 얻어도 앞서 생긴 누락을 삭제하지 않는다. 기존 `static_gap_ids`에 더해
`model_gap_ids`와 `model_static_gap_ids`가 원본 참조와 함께 triage·judgment의 승격 gate에 남는다.
`metrics.json`은 second pass/cache hit/gap 수, `coverage.json`은 첫 분석과 새 분석 기록을 분리한다.

## 근거에 연결한 recon 계획 제안

수동 `recon --spec`을 유지한다. `recon --replay/--codex --model`은 `recon_proposal.py`의
단독 제안 단계다. Go direct HandleFunc 등록과 선택적 Python/Go static 역할 근거를 공급한다.
전체 함수 원문·역할/등록 fact·함수 식별자를 묶어 기본 `--input-bytes 16000` 안에 들어가는
묶음만 제공한다(1,024..64,000). 세부 누락은 `coverage.json`에, agent에는 요약·참조를 전달한다.
등록의 노출·정적 역할의 공격자 통제/통제 효과는 확인된 사실이 아니다.

strict recon-proposal 계약은 기존 hypothesis에 selection을 요구한다. 제공된 entry 함수 ID와
그 entry의 registration/source fact, 함수 원문·UTF-8 byte column, priority/rationale/unresolved를
검증한다. priority가 낮은 순서로 조사하고 동점은 ID로 정렬한다. annotation에도 byte column이
필요하며 다른 함수·원문 밖 인용과 노출 확인 필드를 거절한다. 원래 수동 주석은 호환된다.

출력의 `research-plan.json`은 선택적 selection/proposal_origin이 있는 기존 계획 계약이다.
`recon.json`은 원문·graph/source identity에서 다시 검증한다. 조사 이유·미확인 노출·누락·
미선택 entry·unresolved가 slice와 `recon_gap_ids`에 남고 judgment의 승격 gate로 이어진다.
정적 근거로 생성한 계획은 `run`에 원래 `--static`이 있어야 한다. 각 역할의 의미와 계획 순위는
가설이며 전체 threat model과 실제 agent의 계획 품질을 검증한 것은 아니다.
계획에 원래 input byte 한도를 기록하고 `run`은 같은 graph/static/source에서 입력 context를
재계산해 hash와 fact/entry 대응을 확인한다. 계획의 checksum을 다시 만들더라도 다른 entry의
fact로 바꿀 수 없다. `recon-context.json`에 fact와 전체 누락을 보존하고 후보가 이를 참조한다.
static 없이 등록만으로 만든 계획에 나중에 static 근거를 더할 수 있지만 초기 누락은 유지한다.

제안의 기본 `--max-calls`는 1이고 재시도까지 누적한다(상한 16). timeout 재개는 명시적으로
상한을 늘려야 한다. 성공 cache는 source/graph/static·provider/model·prompt/schema·코드·예산과
saved context/graph/static, raw/reply checksum, 저장된 plan/recon을 확인한다. 실패 후에도
기존 결과 identity를 유지하므로 다음 재개에서 변조 검사가 느슨해지지 않는다.
`calls/r0001.recon/attempt-<번호>/`에 원시 응답·prompt·실패를 보존하고 manifest에 상태를 기록한다.
빈 제안은 `no_hypotheses`로 남고 recon을 만들지 않는다. 빈 출력은 안전의 근거가 아니다.

동일 실행의 동시 쓰기는 `.lock`으로 막는다. 정상 종료와 처리 가능한 오류에서는 해제한다.
프로세스를 강제 종료하면 lock이 남을 수 있으므로 기록된 PID가 실제로 종료됐는지 확인한 뒤 제거한다.
동일 PID가 재사용될 수 있으므로 숫자만으로 프로세스를 종료하지 않는다.

## 외부 후보 가져오기

`intake.py`는 모델이나 대상 실행 없이 strict `candidate-import.json`을 검사합니다.
현재 source index/fragment hash와 bounded 원문에서 공통 analysis·triage 검사를 재사용하고,
외부 gap 인용과 원인·수정·반증의 byte column을 확인합니다. 검사 전 raw input을 보존하며
완료 직전에 spec/source/graph/static을 다시 확인합니다. output은 대상 밖의 새 디렉터리만 허용합니다.
`hypothesis_id`는 선택 사항이며 있을 때 canonical 후보 ID에 포함합니다.

graph 함수와 fragment의 겹침에서 `context_function_ids`를 core가 계산합니다.
`triage.input_gaps`는 이 소유 함수의 전체 알려진 미해결/외부 호출·modifier 한계·정적 gap을 보존합니다.
부분 원문이나 예산 때문에 제공하지 못한 정적 항목은 같은 `attach_records`로 omission을 기록합니다.
가설이 없는 독립 입력의 omission은 `hypothesis_id=null`이며 원문 근거나 관계를 만들지 않습니다.
원본 graph/static은 output에 함께 보존합니다. scanner 원문과 자동 진입점 미확인 gap은
`import-gaps.json`·후보의 `import_gap_ids`로 연결하고 기존 judgment의 issue gate를 사용합니다.

`make demo-intake`는 합성 후보와 부분 Python 원문의 가져오기를 확인합니다.
`tests/test_intake.py`는 성공/실패 raw 보존, strict 계약·hash·인용·예산·경로·소스 변경,
기각/불확실/mixed cluster·반증과 빈 결과, 실제 Python graph/CE의 원문 누락·byte 누락,
Go의 미해결 호출·Solidity modifier gap과 기존 worker/judgment 연결을 검증합니다.
worker 응답은 기존 FakeDocker fixture이며 실제 대상이나 recipe를 실행하지 않습니다.
import gap 해소 누락·timeout·실패·변경된 source의 승격 거절을 확인합니다.
import 재개와 build matrix는 이 첫 단계에 구현하지 않았습니다.

## PoC 자료와 검토 기록

`poc.py`는 기존 Replay/Codex agent, intake의 bounded source frame과 triage의 issue 검사를
재사용합니다. `poc-proposal.json`은 exact 후보 evidence, source hash inputs, `poc/` text attachment,
absolute container argv, frozen oracle, requirements와 unresolved를 요구합니다.
제안은 replacement/approval/validated 필드를 받지 않으며 명령은 실행하지 않습니다.
현재 source와 저장된 fragments/graph/static/config를 대조하고 source 범위를 최대 32개·200줄로
나눕니다. source가 누락된 조사 후보는 현재 source에서 인용을 확인하고 bounded 주변 범위를 보충합니다.
원래 candidate와 전체 소유 함수의 gap/정적 omission을 보존하며 최종 context도 byte 예산을 검사합니다.

시도 횟수를 호출 전에 저장하고 raw/prompt/failure를 남깁니다. 재개는 provider·source/context·prompt·schema·
검사 코드 identity와 checkpoint/원본 응답/저장 결과를 모두 대조합니다. failed call도 한도를 소모합니다.
완료 직전 source/context를 다시 검사합니다. `poc-review`는 같은 근거와 완료 상태·raw/checkpoint를
대조한 뒤 explicit approve/reject/request_changes, reviewer/rationale와 hash 결합을 기록합니다.
reject/request_changes에는 recipe가 없습니다. receipt는 로컬 결정 선언이며 서명·신원 인증이 아닙니다.

worker는 `--poc-review`가 있어야 attachment를 허용하고 source index·검토 seal·원래 candidate/queue·
제안 recipe를 대조합니다. 입력과 frozen attachment는 readonly snapshot에 쓰고 recipe·proposal·receipt를
worker evidence에 포함합니다. fix는 기존 reviewed target replacement만 허용합니다.
판정은 attachment byte/hash·receipt·전후 recipe 결합을 다시 검사하고 original candidate와 PoC issue를
보존합니다. timeout/process/cleanup 실패에도 제안의 미해결을 남깁니다. 승인 자체는 promotion 근거가 아닙니다.

`make demo-poc`는 recorded proposal → resume → 합성 운영자 결정을 실행하며 model/worker 호출은 없습니다.
`tests/test_poc.py`는 성공과 strict response 거절, byte/call 예산·timeout 재개, source 변경·raw/checkpoint
변조·별도 검토 결정, 미검토 attachment의 Docker 이전 거절, frozen harness와 full index 변경,
FakeDocker의 비교/실패/판정 evidence를 확인합니다. 실제 Go multi-file/config와 부분 Python CE gap도
context에서 확인합니다. 기존 수동 recipe는 그대로 유지합니다.

## Build case의 적용 근거와 비교

recipe의 optional `configurations`는 최대 4개이며 ID/settings, target source와 frozen harness invocation,
runtime observation을 요구합니다. PoC schema/prompt도 같은 계약을 사용합니다.
`validation.execution_command`는 선언한 ID 하나를 literal argument로 추가하고 create/policy/read_worker가
같은 계산을 사용합니다. 선택 누락·미선언 ID·중복은 실행 전 거절합니다. 기본 recipe와 approval seal은
바뀌지 않습니다. configuration source/invocation 인용과 관찰의 구별을 `check_oracle`에서 확인합니다.

`evaluate_run`은 선택 설정의 유일한 observation이 outcome 전에 나타나는지 확인하고 다른 case의
관찰이 함께 나오면 적용을 인정하지 않습니다. configuration evidence는 일반 observation과 source proof,
issue 해소 참조로 연결합니다. 전후 선택 ID도 같아야 비교합니다. 설정 gate는 기존 재현/진입점/수정
gate와 함께 필요하며 실패·gap을 기존 판정에 남깁니다. probe가 관찰하는 속성 범위만 증명합니다.

`matrix.py`는 strict `validation-matrix.json`을 검사하고 승인 recipe·fixed recipe·receipt·proposal과
원본 spec을 복사해 hash를 고정합니다. source/context와 검토 hash를 대조한 뒤 준비를 완료합니다.
`validate-matrix`만 기존 worker를 순서대로 호출합니다. 최대 8회, 호출 전 시도 기록, frozen input 재검사,
실패 raw/참조와 모든 case를 보존합니다. cleanup/실행 상태 미확인·controller 실패·입력 변경에는 중단합니다.
완료/partial/interrupted 실행은 terminal 기록이며 재개·재시작은 지원하지 않습니다.

`judge-matrix`는 실행하지 않습니다. preparation/execution seal, case 순서·image·선택 ID·frozen recipe와
worker hash/approval을 검사하고 기존 judge를 case별로 호출합니다. 다른 case를 전후 run으로 섞지 않습니다.
없는 run·잘못된 artifact·실패와 원래 issue를 모두 남기며 마지막에 입력을 다시 대조합니다.
전체 coverage와 case별 validated 목록을 분리하고 negative 결과로 안전성을 추정하지 않습니다.

`make demo-matrix`는 합성 C 자료의 제안/검토 → matrix 준비 → missing case 보고만 실행합니다.
`tests/test_matrix.py`는 FakeDocker 제어 응답으로 실제 설정 관찰/순서, case별 전후/guard 활성 미재현,
예산/누락·변조·timeout/process/정책/cleanup·중단/재시작 거절을 검사합니다. C compiler를 host에서
실행하지 않습니다. 별도 `AUDIT_MATRIX_VALIDATION_IMAGE=sha256:<prepared-compiler-image-id>`를 명시한 경우에만
실제 compiler/Docker 통합 테스트 한 개가 활성화됩니다. 이미지 pull/build는 자동으로 하지 않습니다.
2026-10-13에는 이미 준비된 Go 이미지의 `/usr/bin/cc`로 이 테스트를 실제 실행해 통과했습니다.
`runs/matrix-docker.pWXauy/`의 release/guarded 전후 worker 네 개와 raw/정책/판정을 보존했습니다.
이 환경에서는 credential 제거 컨트롤러의 Docker 접속에 sandbox 밖 접근 권한이 필요했습니다.
격리 정책은 기존 worker가 확인하며 이미지나 소스에 따라 다른 결과가 날 수 있습니다.

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

`tests/test_static_analysis.py`는 실제 CE로 Python/Go source·sink·변수 흐름과 상수 음성 대조군,
모델에 선언한 sanitizer, 미해결 callback 및 파일 간 호출의 분석 경계를 확인한다.
UTF-8/CRLF 위치, source/model/checksum 변조, trace 누락·parse 실패·timeout·잘못된 엔진 출력,
대상 config/ignore/주석과 환경변수 미사용, source 동반 byte 예산 및 replay/resume을 검증한다.
엔진을 준비하지 않으면 integration test가 skip된다. CI에서는 `make setup-static`을 먼저 실행한다.
정적 분석기의 네트워크 OS 격리·타 언어 taint·함수 간 흐름·실모델 탐지율 검증은 포함하지 않는다.

offline test는 실제 소스와 인용 대응, strict schema, byte 분할, 중복·후보 ID,
false-positive triage, 부분 coverage, 재개·1..128 호출 cap·cache 손상·동시 실행을 검증한다.
Codex adapter는 로컬 가짜 CLI로 stdin, 제한 설정, 별도 cwd, 환경변수 필터,
오류와 timeout, event/stderr 상한 종료, 제한이 무시될 때 호출 거절을 검사한다.
replay loader의 파일 수·개별/누적 byte 상한과 symlink 거절도 별도로 검사한다.
실제 설치된 CLI의 feature 제한 사전 확인도 모델 호출 없이 검사했다.
이는 Codex 서비스의 실제 동작이나 보안 격리 검증이 아니다.

`tests/test_triage.py`는 원인·통제 위치와 수정 전략/위치 일치, 다른 원인/수정 분리,
혼합 판정·기각·불확실·원인 미상 singleton 보존, UTF-8 byte 위치·거짓 근거 거절을 검사한다.
새 형식은 prompt/schema/replay를 함께 갱신하며 과거 계약의 run을 조용히 재사용하지 않는다.
`test_recon.py`의 Go replay는 서로 다른 slice의 두 후보를 공통 수정 위치로 병합하고
기각 반증 2개와 interface/callback unknown 2개, 새 호출 없는 재개를 확인한다.
`test_static_analysis.py`는 byte 예산으로 빠진 정적 gap의 원본 참조와 불확실 주장을
findings/대기열/replay 재개에서 유지하는지 검사한다. 원인 판단의 의미 정확도는 이 테스트 범위 밖이다.
Solidity modifier test는 flow가 입력에서 빠져도 원본 graph의 gap 참조가 triage 결과에 남는지 확인한다.

`tests/test_validation.py`는 Docker 제어 응답 fixture로 정책 위반 시 실행 거절, source/queue/recipe
변조·symlink/FIFO/credential 경로 거절, 환경 제거, 실패·OOM·timeout·로그 한도·제거 실패와
증거 hash를 검사한다. 신뢰한 Python 제어 코드만으로 bounded pipe를 검사하며 대상은 호스트에서 실행하지 않는다.
폐기 타이머가 준비되지 않으면 실행을 거절하고 사용자 중단 시 pending 근거를 보존하는지도 검사한다.

`tests/test_validation_docker.py`는 아래와 같이 명시적으로 활성화한 실제 Linux Docker 검증이다.
기본 `make check`에서는 이 테스트만 skip하므로 offline 정책 테스트를 실제 격리 증명으로 보고하지 않는다.
image에는 `/usr/bin/env`, sh/bash/awk/coreutils가 필요하고 현재 검증한 engine은 cgroup v2를 제공한다.
테스트는 local image ID만 사용하며 임의 사용자 container를 정리하지 않는다.

```sh
audit_validation_image=$(docker image inspect debian:bookworm-slim --format '{{.Id}}')
AUDIT_VALIDATION_IMAGE="$audit_validation_image" UV_CACHE_DIR=.cache/uv \
  uv run --locked pytest -q tests/test_validation_docker.py tests/test_judgment_docker.py
VALIDATION_IMAGE="$audit_validation_image" make demo-validation
VALIDATION_IMAGE="$audit_validation_image" make demo-judgment
```

실제 테스트는 host credential/environment와 비선택 host 파일의 부재, root/input 쓰기 거절,
network 연결 실패, cgroup CPU/RAM/PID 설정, OOM/fork/scratch 상한, 실패/timeout/출력 초과를 확인한다.
제어 프로세스 SIGKILL 후 독립 타이머가 container를 제거하는 사례도 실행한다.
실행 중 로그를 flush하여 강제 종료 전 수집한 prefix를 남긴다. `result.json`이 pending인 경우
`watchdog.json`의 폐기 상태를 확인하며 미관찰 exit를 성공으로 해석하지 않는다.
Docker 장애로 제거가 실패하면 기록된 job 이름과 오류로 별도 정리한다. 실패 run은 재사용하지 않는다.

`make doctor`는 Clang/Go를 포함한 도구 존재와 Docker daemon 상태를 확인한다.
Docker는 동적 `validate`에만 필요하며 source/graph/replay 작업은 daemon 없이 개발할 수 있다.
VM 격리·kernel escape·운영 배포의 실제 취약점·원격 CI는 이 worker 검증으로 입증하지 않는다.

`tests/test_judgment.py`는 Docker 응답 fixture로 실행/재현 구분, 실제 entrypoint 관찰과 직접 호출의
분리, 비교 조건·harness/source hash, 수정 후 timeout/OOM/양성/불완전한 음성, 원래 반증/불확실/gap의
보존과 근거별 해소를 검사한다. 관찰의 완전한 줄·유일성·stream/순서, 임의 resolved boolean,
미완성/변조/symlink artifact와 일치하지 않는 종료 상태도 승격되지 않아야 한다.
이 테스트의 reseal은 의도적인 offline 계약 fixture 구성이며 실제 Docker 실행 기록으로 보고하지 않는다.

`tests/test_judgment_docker.py`는 준비된 image에서 합성 CLI 요청의 수정 전 양성/수정 후 음성을
같은 probe로 실행한다. dispatcher 진입·완료·기존 미해결 근거 해소와 원본 source 미변경을 확인한다.
oracle 없는 정상 실행은 execution_only여야 한다. 실제 Docker 테스트는 위 env를 지정한 경우에만 실행한다.

Go HTTP 연결 사례는 별도의 고정 Go 이미지를 명시적으로 준비한다. 이 단계만 image를 다운로드하며
`validate`는 로컬 image ID만 사용한다. 대상 Go 프로그램과 HTTP 검증 코드는 호스트에서 실행하지 않는다.

```sh
make setup-validation-go
audit_go_image=$(docker image inspect \
  'golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee' \
  --format '{{.Id}}')
audit_go_socket=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
VALIDATION_IMAGE="$audit_go_image" VALIDATION_DOCKER_HOST="$audit_go_socket" make demo-go-http
AUDIT_GO_VALIDATION_IMAGE="$audit_go_image" AUDIT_GO_DOCKER_HOST="$audit_go_socket" \
  UV_CACHE_DIR=.cache/uv \
  uv run --locked pytest -q tests/test_go_http.py
```

`demo-go-http`는 graph → recon → replay/resume → 격리 worker의 수정 전후 실 HTTP GET → `judge`를
한 예제에서 잇는다. 검증 코드는 준비된 이미지의 Go 컴파일러를 사용해 컨테이너 안에서만 빌드하고,
네트워크 차단 상태에서 127.0.0.1의 임시 포트로만 요청한다. 서버는 source의 정상 `main`과
`ServeMux` 등록 경로로 실행된다. 작업용 tmpfs를 사용하고 컴파일 산출물은 호스트에 내보내지 않는다.
이 사례의 `X-Role`은 합성 신원 값이며 운영 인증 체계를 검증하지 않는다.
`tests/test_go_http.py`의 offline 검사는 그래프·입력 연결, recipe/source hash와 변경 범위를 검사한다.
실제 Docker 검사는 승인된 PoC와 수동 recipe의 정상 요청·수정 전후, 잘못된 경로의
진입점 미도달과 출력 marker 위조·잘못된 전체 차단 수정의 기각을 검사한다.
명시한 socket은 로컬 `unix:///` 경로여야 하며, 이미지 pull/build는 검증 중 수행하지 않는다.
대상 로그는 `TARGET guest/admin stdout`, HTTP 응답은 `HTTP guest/admin body`로 구분하며
Go의 인용 escape로 응답 bytes를 보존한다. 판정 줄은 검증 코드가 정확한 응답 비교 후에만 출력한다.
CLI 예제는 원래 출력 bytes를 base64로 보존하고 `cmp`로 전체 응답을 비교한다.
두 예제 모두 admin 성공을 대조군으로 요구한다. unknown 응답·위조 판정 문자열·NUL·모든 요청을
거절하는 수정은 재현 또는 검증된 수정으로 승격하지 않는다. 이 의미는 supplied harness에 고정된
예제 계약이며 임의 검증 코드의 올바름을 형식 검사로 보장하는 기능은 아니다.
worker는 graph가 있는 review에서 보존된 graph/source identity와 `input_config`의 실제 해시를
검사한다. 설정 변경·누락·graph 변조는 snapshot 또는 Docker 시작 전에 실패하며,
설정을 바꾸려면 graph/recon/review를 새로 만들어야 한다.

`judge BASELINE --fixed FIXED --output NEW`는 기록만 평가한다. status=complete/CLI exit 0과
promotion.eligible은 다르므로 승격은 judgment.verdict와 requirements/blockers를 확인한다.
불완전한 worker 결과는 재실행 전에 보존하고 판정도 새 output을 사용한다.
