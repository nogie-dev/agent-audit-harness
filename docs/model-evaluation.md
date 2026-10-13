# M5 실모델 평가 기록

이 평가는 [Quarkslab 연구](https://blog.quarkslab.com/from-ai-agents-to-rce-building-a-vulnerability-research-workflow.html)의 graph 기반 조사 흐름이 이 harness에서 후보 유지·검토 비용을 개선하는지 측정한다. 정답은 실제 취약점 확정이 아니라 소스 위치에 대한 조사 후보의 연구자 선언이다. 세 언어는 별도 대상이며 각 대상에서 lexical 입력과 graph/recon 입력을 비교한다.

## 고정 입력과 오프라인 사전 점검

`make demo-model-evaluation`의 2026-10-13 실행 결과를 `runs/model-eval-preflight.5qoxtn/`에 로컬로 보존했다. `runs/`는 Git에 포함되지 않는다. `summary.json`과 각 언어의 `comparison/benchmark.json`에는 Go, Python, Solidity 합성 소스 복사본·graph/recon·기록된 응답 비교의 결과가 있다. 도구 식별자는 `5cc34d965150390f1040f2bbf1b76a0b6048e63c21345dea894b24d1e5a647b9`다. 모든 graph는 준비된 로컬 도구로 소스만 파싱했고, 세 대상의 양성·음성 라벨 2개씩이 양쪽 입력에 모두 포함된다. `benchmark-replay`와 `benchmark-runs`가 각 대상에서 통과했으며, 호출 수와 프롬프트 byte는 아래 표와 같았다. 이 오프라인 사전 점검은 모델, 대상 코드, EVM을 실행하지 않았다.

새 체크아웃에서는 `make setup-go`와 `make setup-solidity`로 고정된 추출기 의존성을 명시적으로 준비한 뒤 `make demo-model-evaluation`을 실행하면 된다. 커밋된 소스·정답·replay에서 새 소스 복사본, graph/recon, 양쪽 입력과 `benchmark-runs` 비교를 `runs/model-eval-preflight.XXXXXX/`에 다시 만들고 `summary.json`에 도구 식별자·라벨·호출 상한·프롬프트 byte·준비 시간을 기록한다. 의존성이 없으면 실패하며 자동 다운로드하지 않는다. `tests/test_benchmark.py`도 같은 세 언어의 평가 경계를 검사한다. 아래 실모델 명령의 입력 경로는 새 실행에서 출력한 경로로 바꿔야 한다.

동일 설정은 slice 최대 8개, slice당 16,000 byte, 조회 1회·16,000 byte다. 한 언어의 두 arm은 같은 호출 상한을 사용한다. 현재 `plan`에서 Go는 lexical 15회/graph 9회가 가능해 양쪽 상한을 15회로, Python·Solidity는 각각 6회/6회라 양쪽 상한을 6회로 정했다. 아래 값은 JSON 프롬프트를 **기록된 응답**으로 다시 만든 결과이며 token이나 가격이 아니다. 프롬프트에는 slice 내 파일의 총 행 수와 인용 위치 안내가 추가됐다. 프롬프트 생성 코드도 도구 identity에 포함해 이전 형식의 run과 혼합 비교하지 않는다. lexical replay 응답은 의도적으로 빈 후보이며 triage 호출도 없어, 아래 결과의 후보 유지 차이와 전체 프롬프트 차이는 입력 방식의 성능 차이를 측정하지 않는다.

| 대상 | lexical/graph slice | 정상 경로 최대 호출 lexical/graph | 기록된 analysis 프롬프트 byte lexical/graph | 기록된 전체 프롬프트 byte lexical/graph |
| --- | ---: | ---: | ---: | ---: |
| Go | 5/3 | 15/9 | 28,763/42,533 | 28,763/84,779 |
| Python | 2/2 | 6/6 | 11,350/15,163 | 11,350/22,880 |
| Solidity | 2/2 | 6/6 | 11,582/21,889 | 11,582/30,312 |

한 번의 로컬 측정에서 원문 색인·lexical slice와 graph/recon 준비 시간은 다음과 같았다(초, 0.000은 밀리초 반올림값). 소스 복사·의존성 준비·모델 호출 시간은 포함하지 않는다. graph/recon은 대상 snapshot당 한 번 만들 수 있으므로 반복 호출 비용과 구분한다.

| 대상 | lexical 색인·slice | graph 추출 | recon 생성 |
| --- | ---: | ---: | ---: |
| Go | 0.001 | 0.668 | 0.005 |
| Python | 0.000 | 0.061 | 0.002 |
| Solidity | 0.000 | 0.599 | 0.003 |

이 값은 작은 합성 대상의 단일 wall-clock 표본이며 실모델의 전체 처리 시간이나 대규모 저장소의 준비 비용을 예측하지 않는다.

들여쓰기 축소 뒤, 위치 안내를 넣기 전 graph 전체 프롬프트는 Go 80,417, Python 20,677, Solidity 28,097 byte였다. 위치 안내 뒤에는 각각 82,817, 21,899, 29,331 byte로 늘었고 기록된 응답의 판정·coverage는 같았다. Go에서는 graph가 초기 analysis 호출을 5회에서 3회로 줄였지만, analysis 프롬프트 합계는 여전히 늘었다. Python과 Solidity도 graph 입력의 프롬프트가 더 크다. 실제 모델 응답이 조회·triage를 다르게 선택할 수 있으므로 위 byte와 호출 수는 실측 결과가 아니다.
인용 수정 안내를 추가한 현재 기본 프롬프트는 graph 전체가 각각 84,779, 22,880,
30,312 byte다. 위 오프라인 기본 경로에는 실제 수정 시도가 없다. 수정이 발생하면
거절 응답과 반복 입력의 byte/token/시간도 추가되며, 비용 절감 효과를 가정하지 않는다.
이 비교는 **graph와 연구자 작성 recon 계획을 함께** 넣는 방식이다. lexical arm에는 같은
연구 가설이 주어지지 않으므로 차이가 생겨도 graph만의 효과로 분리할 수 없다. 또한 언어당
양성·음성 라벨이 하나씩인 합성 사례이므로 탐지율이나 일반화 성능을 추정할 표본이 아니다.
저장된 원본 프롬프트의 UTF-8 byte를 세며, 비ASCII 원문의 byte 계측도 회귀 테스트로 확인한다.

## GPT-6 Luna 탐색 실행 결과

사용자가 선택한 모델의 공식 ID `gpt-6-luna`로 합성 대상만 분석했다. 비교 대상 run 8개 중 4개가 완료됐고 4개는 모델의 소스 인용 위치 오류로 실패했다. 별도 초기 진단 run 2개는 모델 출력 스키마 오류(HTTP 400)를 드러냈고, 로컬 sandbox에서 막힌 시도 1개는 모델을 호출하지 못했다. 이후 모델용 strict schema의 선택 필드·타입을 바로잡고 원본 JSON과 정규화 응답을 따로 보존했다. 비교 대상 8개의 총 호출 시도는 46회이며, 완료된 모델 turn이 보고한 입력 token은 합계 721,859개다. 초기 진단을 합쳐도 승인된 12개 유료 run·108회 호출 시도 상한 아래인 10개 run·49회 시도였다. 가격은 확인하지 않았다.

| 대상·반복 | lexical | graph/recon | 같은 pair 비교 |
| --- | --- | --- | --- |
| Python 1 | 후보 행 오류로 실패(2회 시도) | triage UTF-8 byte 열 오류로 실패(3회) | 불가 |
| Solidity 1 | 후보 행 오류로 실패(5회) | 완료, `uncertain` 1건(4회) | 불가 |
| Go 1 | 완료(12회) | 완료(6회) | 가능 |
| Go 2 | 완료(11회) | triage UTF-8 byte 열 오류로 실패(3회) | 불가 |

Go 1의 미리 고정한 **대표 행·CWE** 채점은 lexical이 양성 1/1 유지·음성 1/1 통과, graph/recon은 양성 0/1 유지·음성 1/1 통과였다. graph/recon 후보의 대표 행은 입력 진입점이었지만, 검증된 `root_cause.evidence`는 정답의 sink 행을 인용했다. 이는 `runs/model-eval-live/go-r1-comparison-v3/benchmark.json`의 별도 `root_cause_candidate_ids`에 기록하며, 사후에 1차 점수를 바꾸지 않는다. 이 pair에서 graph/recon은 호출 12→6회, 기록된 성공 호출 시간 69.189→49.059초, 보고된 입력 token 190,789→101,092개였다. 반면 성공 호출의 프롬프트 합계는 62,976→79,940 byte로 늘었다. 시간·token에는 graph/recon 준비나 실패 run의 비용이 포함되지 않는다.

Solidity의 완료된 graph/recon run은 `releaseA`를 `CWE-862`·대표 9행으로 제시했지만, 고정 정답은 `CWE-284`·전송 10행이다. 후보가 정책상 유의미할 수 있어도 1차 채점에서는 양성 미탐이다. Go·Solidity의 일부 source 조회는 모델이 실제 파일 끝을 넘는 범위를 요청해 `invalid_source_range` gap으로 남았다. 이 결과는 2회 완료 pair가 아니며 graph의 탐지 우위·일반화·가격 효율을 입증하지 않는다. 다음 실험에서는 인용 행/byte 열 실패를 줄이되 검증을 완화하지 않고, 파일 길이 정보를 명시하며, 대표 행과 원인 근거·CWE 동등성의 채점 규칙을 실행 전에 고정해야 한다.

관찰된 오류에 따라 source 조회 시 slice에 나온 파일의 실제 총 행 수를 전달하고,
triage에 행 앞 공백을 포함한 `column=1` 인용을 권장했다. 검증기는 변경하지 않았다.
같은 Go 합성 대상의 새 프롬프트 진단 pair는 두 run 모두 완료됐다. lexical은 11회·
45.442초·입력 151,063 token, graph/recon은 5회·30.163초·84,875 token이었다.
고정된 1차 채점은 다시 lexical 양성 1/1·음성 1/1, graph/recon 양성 0/1·음성
1/1이었다. graph 후보의 검증된 원인 근거는 정답 sink 행을 인용했으며
`runs/model-eval-live/go-prompt-pilot-comparison/benchmark.json`에 보조 지표로 남았다.
이번 graph/recon 조회에는 파일 끝 초과가 없었지만, 부정확한 selector로
`selector_missing_or_ambiguous` gap이 생겼다. 한 번의 진단으로 프롬프트 개선의
인과 효과나 안정성을 주장할 수 없다. 초기 스키마 진단을 포함해 유료 run은 총
12개·호출 시도는 65회였고, 이전 승인 범위의 run 상한을 모두 사용했다.

`benchmark-attempts`로 12개 run의 저장된 모든 시도를 읽기 전용으로 재검사했다.
65회 중 실패 기록 6회, 미확정 0회였고, 완료된 모델 turn 63회에서 보고된 입력
token은 합계 971,369개였다. HTTP 400으로 종료된 2회는 provider 사용량이 없어
총 사용량을 0으로 간주하지 않는다. 시도별 기록 시간 합계는 357.870초이며
graph/recon 준비, 대기·provider 외부 시간 및 가격은 포함하지 않는다. 개별 결과는
`runs/model-eval-live/account-*/attempts.json`에 남겼다.

별도로 저장된 실패 응답을 현재 검증기에 오프라인 대조했다. 응답 원문이 있는
4건은 후보 인용 행 불일치 2건과 triage UTF-8 byte 열 불일치 2건이었다.
응답 원문이 없는 시도 3건은 이 방식으로 분류하지 않는다. 이후 run은 인용 실패에
고정된 `citation_code`를 남겨 호출 오류와 구분하고, 기존 원본에는 소급 적용하지 않는다.

선택적인 `--repair-citations`를 추가해 인용 오류에만 logical call당 한 번 수정
기회를 줄 수 있다. 기본값은 꺼짐이며, 거절 원본을 보존하고 같은 검증기를 적용한다.
수정도 기존 호출 상한을 소비한다. 비교 시 양쪽 arm의 설정은 같아야 하며 모든
시도의 시간·프롬프트·보고 token을 포함한다. 기존 run metrics의 성공 응답 합계는
별도로 유지한다. 기록된 응답과 합성 event로 이 경로를 검사했으며 유료 모델에서
실패율의 인과적 개선은 입증하지 않았다. 추가 실모델 관찰은 아래에 기록했다.
아래 재실행 예제는 기본 설정이다.
이 옵션을 사용하는 다음 실험은 두 arm에 모두 명시하고 새 실험으로 기록한다.

## 재실행 절차

다음 반복 평가의 채점 규칙은 실행 전에 고정한다. 1차 양성 유지는 후보의 대표
`path`·`line`·`CWE`가 정답과 모두 같고 판정이 `rejected`가 아닐 때만 인정한다.
음성은 그 조건을 만족하는 유지 후보가 없을 때 통과로 센다. slice가 정답 행을
포함했는지는 별도 coverage로 남긴다. 2차 `root_cause.evidence` 인용은 검증된
소스 hash·경로·행·인용 문구와 후보 CWE가 정답에 맞는지 기록하는 보조 지표다.
이는 기각된 후보에도 존재할 수 있으므로 양성 유지로 승격하지 않는다.
`benchmark-summary`는 두 지표의 정답별 반복 횟수를 분리한다. CWE 별칭이나
상하위 관계는 자동 동등 처리하지 않는다. 규칙을 바꾸려면 새 정답·실험으로
평가하며, 이미 관찰한 출력의 점수를 사후 변경하지 않는다. 실패한 run이 낀
pair는 성능 차이에서 제외하고 `benchmark-attempts`로 실패율과 보고된 비용을
함께 제시한다.

선택 모델은 GPT-6 Luna의 공식 ID인 `gpt-6-luna`다([Codex 모델 문서](https://learn.chatgpt.com/docs/models)). 로컬 Codex CLI 0.155.0에서 모델 응답을 받았으며 가격은 확인하지 않았다. `run` 출력은 매번 새 디렉터리를 사용한다. 실패한 run은 원본을 보존하고 해당 pair의 시간 비교에서 제외한다. 평가용 run은 cache 재개를 하지 않는다.
아래 명령은 새 유료 모델 호출이며, 이전에 승인된 12개 run 범위는 위 진단까지 사용했다.

각 언어마다 같은 고정 target, `--max-slices 8 --slice-bytes 16000 --max-queries 1 --query-bytes 16000 --timeout 180`과 같은 모델을 사용한다. `--max-calls`는 Go 15, Python·Solidity 6이며 같은 언어의 두 arm에서는 같다. baseline에는 graph/recon을 넣지 않고 candidate에만 해당 snapshot의 `graph/graph.json`과 `recon/recon.json`을 넣는다. 예를 들어 Go의 첫 pair는 다음과 같다.

```sh
uv run --locked audit-harness run runs/model-eval-preflight.5qoxtn/go/target \
  --codex --model gpt-6-luna --max-slices 8 --slice-bytes 16000 \
  --max-calls 15 --max-queries 1 --query-bytes 16000 --timeout 180 \
  --output runs/model-eval-live/go-next-baseline
uv run --locked audit-harness run runs/model-eval-preflight.5qoxtn/go/target \
  --graph runs/model-eval-preflight.5qoxtn/go/graph/graph.json \
  --recon runs/model-eval-preflight.5qoxtn/go/recon/recon.json \
  --codex --model gpt-6-luna --max-slices 8 --slice-bytes 16000 \
  --max-calls 15 --max-queries 1 --query-bytes 16000 --timeout 180 \
  --output runs/model-eval-live/go-next-candidate
uv run --locked audit-harness benchmark-runs runs/model-eval-preflight.5qoxtn/go/target \
  --truth examples/go-review-benchmark-truth.json \
  --baseline runs/model-eval-live/go-next-baseline \
  --candidate runs/model-eval-live/go-next-candidate \
  --output runs/model-eval-live/go-next-comparison
```

Python은 `python/target`, `python/graph/graph.json`, `python/recon/recon.json`, `examples/python-benchmark-truth.json`을 사용한다. Solidity는 대응하는 `solidity/` 경로와 `examples/solidity-benchmark-truth.json`을 사용한다. 각 대상의 두 번째 pair도 동일 설정과 새 출력 디렉터리에서 독립 실행하고, 호출 순서 영향을 줄이도록 candidate를 먼저 실행한다. 대상별 두 `benchmark-runs` 결과를 `benchmark-summary --report ... --report ...`로 다시 검증한다. 대상별 positive retained/missed, negative flagged/clear, coverage, 원본 호출 시간, 보고된 token 사용량과 프롬프트 byte를 함께 제시한다. token 누락은 `null`로 남긴다.

정상 응답 경로의 계획상 최대는 한 반복에서 세 언어 합계 48회, 두 반복에서 96회다. **승인 범위의 엄격한 상한은 Go run당 15회, Python·Solidity run당 6회로 한 반복 6개 run에서 54회, 두 반복 12개 run에서 108회**이며 실패 시도도 포함한다. 호출 수 제한은 token·금액 상한이 아니다. 실측 병목과 오류를 확인하기 전에는 병렬 호출을 추가하지 않는다.

추가 실모델 평가는 snapshot `runs/model-eval-preflight.5qoxtn/`과 같은
정답·모델·예산에서 두 arm 모두 `--repair-citations`를 켜는 별도 실험이다.
Go run당 15회, Python·Solidity run당 6회의 상한을 늘리지 않고 수정 시도도 포함한다.
두 반복은 최대 12개 run·108회 시도이며, 재실패나 호출 상한 소진은 그대로 남긴다.
완료된 pair만 차이를 계산하고 모든 run의 시도 비용과 실패율을 함께 제시한다.
이전 프롬프트의 탐색 run은 반복 표본에 합치지 않는다. 사용자가 2026-10-13에
추가 평가 실행을 승인했다. 새 실행은 `runs/model-eval-repair.tjM9VK/`에 보존하며,
이전 승인 범위와 분리해 최대 12개 run·108회 시도를 적용한다.

## 인용 수정 옵션을 적용한 추가 실행 — 2026-10-13

승인한 12개 run을 모두 순차 실행했다. 첫 반복은 Python·Solidity·Go 순서로 각
lexical 다음 graph/recon, 두 번째 반복은 같은 언어 순서로 graph/recon 다음 lexical이었다.
두 arm 모두 `--repair-citations`를 켰으며 모델·소스·정답·도구·예산은 위 설정으로
고정했다. `study.json`에 실행 순서·명령·파일 hash·상한·종료 코드를 남겼다.
각 run마다 `benchmark-attempts`를 실행했고, 완료된 pair만 `benchmark-runs`로 비교했다.
실패 run을 재개하거나 추가 run으로 교체하지 않았으며 대상 코드는 실행하지 않았다.

| 대상·반복 | lexical 상태·시도 수 | graph/recon 상태·시도 수 | pair 비교 |
| --- | --- | --- | --- |
| Python 1 | 완료·6 | 완료·4 | 가능 |
| Solidity 1 | 완료·5 | 인용 수정 후 실패·4 | 불가 |
| Go 1 | 완료·11 | 완료·7 | 가능 |
| Python 2 | 인용 수정 후 실패·3 | 완료·4 | 불가 |
| Solidity 2 | 완료·5 | 인용 수정 후 실패·4 | 불가 |
| Go 2 | 인용 수정 후 실패·9 | 완료·6 | 불가 |

총 **68회 시도, 8개 완료 run, 4개 실패 run**이었다. 시도별 실패 기록은 10건,
미확정은 0건이다. 68회 모두 provider 사용량이 남아 보고된 입력 token은
**1,244,956**, 그중 cached input은 **714,752**, 출력은 **13,941**이었다.
cached input은 입력의 일부이므로 입력에 더하지 않는다. 모든 시도의 기록 시간은
**401.650초**이며 graph/recon 준비·CLI 준비·대기·전체 provider 처리 시간을 대체하지 않는다.
가격은 확인하지 않았다. 실패한 run의 사용량과 시간도 이 합계에 포함한다.

실패 코드는 `candidate_quote_mismatch` 6건, `triage_column_mismatch` 4건이었다.
수정 요청 6건 중 2건은 검증을 통과했고 4건은 재실패했다. 통과한 두 건 모두
Solidity lexical의 `s0002.q0001.analysis`에서 원래 후보를 `candidates: []`로
철회한 응답이다. 두 lexical run의 양성 라벨도 미탐이었다. 따라서 두 수정의 통과는
정확한 인용 수정이나 후보 유지의 성공으로 해석하지 않는다. 거절 응답·수정 응답·실패 코드와
사용량은 원본 그대로 남았다. 이전 프롬프트의 탐색 run과 이 표본을 합치지 않는다.

완료된 두 pair의 1차 채점과 모든 시도 비용은 다음과 같다. 양성 유지는 대표
경로·행·CWE와 미기각 판정을 모두 요구한다. 시간·입력·프롬프트는 lexical→graph/recon이다.

| pair | 양성 유지 lexical/graph | 음성 통과 lexical/graph | 시도 수 | 기록 시간(초) | 보고된 입력 token | 프롬프트 byte |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Python 1 | 1/1 | 1/1 | 6→4 | 26.914→28.086 | 82,800→90,017 | 36,091→39,795 |
| Go 1 | 1/0 | 1/1 | 11→7 | 49.689→48.929 | 165,435→172,400 | 65,466→102,713 |

Go 1의 graph 후보는 대표 위치를 HTTP handler에 두었으므로 1차 양성 유지에서는
미탐이지만, 검증된 원인 근거는 정답 sink를 인용했다. 이는 별도 보조 지표이며 1차 점수를
바꾸지 않는다. 독립적으로 완료된 Go 2 graph run은 대표 sink·CWE까지 맞아 양성 1건을
유지했다. Python graph run 둘도 양성 1건씩을 유지했다. 그러나 대응 lexical run의
실패 때문에 두 번째 pair의 성능 차이는 계산하지 않는다. 음성 통과는 정해진 라벨 위치에
유지 후보가 없다는 뜻이며, 라벨 밖 후보의 정확도나 전체 저장소의 안전성을 말하지 않는다.

완료 run의 모든 라벨은 입력에 포함됐다. lexical Python/Go가 요청한 graph 조회의
미제공 입력 gap, graph Go의 모호한 selector 등은 원본 investigation과 coverage에 남았다.
도구 기능이 다른 두 arm의 차이는 graph와 연구자 recon을 함께 제공한 효과이며,
graph 하나의 효과로 분리할 수 없다.

원본과 읽기 전용 관찰 요약은 `runs/model-eval-repair.tjM9VK/`의 `study.json`,
`observations.json`, 각 `*-attempts/attempts.json`과 완료된 두
`*-r1-comparison/benchmark.json`에 있다. `summarize_study.py`는 기존 source 채점과
원본 시도 검증 함수를 이용해 완료 run만 따로 채점하며 모델이나 대상을 실행하지 않는다.
언어별 완료 pair가 2개씩 없으므로 `benchmark-summary` 결과는 생성하지 않았다.

이번 실행은 **다언어 반복 평가 gate를 충족하지 못했다.** 인용 수정의 안정성이 먼저
필요하다. 다음 구현은 오류가 난 근거의 필드·경로·행·byte 열을 특정한 피드백과 제한된 원문을
제공하되 같은 검증기를 유지하고, 수정 후 후보 철회를 인용 수정 성공과 구분해 기록하는 것이다.
저장된 실패 원문으로 오프라인 회귀를 먼저 만들고 이후 별도 승인 범위에서 새 실험을 고정한다.
현재 결과로 graph/recon의 탐지·비용 우위나 병렬화 필요성을 주장하지 않는다.

## 후속 오프라인 구현

실패 원문 10건을 source fragment와 함께 커밋 가능한 회귀 fixture로 고정했다.
인용 오류에는 실패한 JSON 필드·경로·행·byte 열과 제공된 fragment의 주변 최대
3행·4 KiB를 전달한다. 실제 인용이 같은 행에 있으면 첫 UTF-8 byte 열도 제공하며,
입력 밖이나 큰 행은 원문을 생략한다. 임의 파일 읽기·행 이동이나 검증 완화는 없다.
accepted 응답은 인용만 수정/후보 철회/기타 응답 변경을 문자 비교로 구분한다.
원본 인용·CWE·판정의 채점 규칙은 유지했다. 이전 12개 run의 읽기 전용 재집계에서도
68회 시도와 후보 철회 2건·수정 실패 4건이 동일하게 확인됐다. 이전 원본은 바꾸지 않았다.
이 변경은 위 실모델 연구 이후의 새 도구/prompt 조건이며 같은 반복 표본으로 합칠 수 없다.

`make check`는 Ruff와 726개 테스트 통과·23개 skip, 집중 검사는 163개 통과였다.
`make demo` fresh/resume와 새 CLI 인용 수정 replay(3회 시도·실패 보존 1회·
`citation_corrected` 1회·최종 후보 기각)도 확인했다. 새 오프라인 preflight는
`runs/model-eval-preflight.ZH4c4l/`이며 세 언어의 source 라벨 포함과 완료된 replay pair
비교가 통과했다. 도구 hash는
`852e274c8916d3353d5921da0935086ab5e18f6144ebbe217b43bbf742fbc442`다.
전체 replay 프롬프트 byte의 lexical/graph는 Go 31,168/87,920,
Python 12,312/24,408, Solidity 12,544/31,840이었다. baseline replay는 빈 후보라
이 byte 차이는 실제 모델 응답이나 후보 품질의 측정이 아니다.

다음 실험의 새 입력/정답/도구/모델/예산/순서를
`runs/model-eval-feedback.c645kqlr/protocol.json`에 고정했다. Go/Python/Solidity,
lexical/graph+recon, 각 2회, gpt-6-luna, 양쪽 `--repair-citations`, 최대 12개 run·
108회 시도다. 이전 실험과 합치지 않고, 실패 run의 대체·자동 재개 없이 모든 시도 비용과
수정 결과를 함께 집계한다.

## 오류 위치 피드백을 적용한 추가 실행 — 2026-10-13

사용자 승인 후 동결 순서대로 12개 run을 실행했다. 총 **68회 시도, 9개 완료 run,
3개 실패 run**이었고 실패 시도 8건·미확정 0건을 모두 보존했다. 보고된 사용량은 입력
1,123,809 token, 그중 cached input 691,968 token, 출력 15,145 token이며 기록된 호출
시간 합계는 402.198초다. 가격은 확인하지 않았다. 대상 코드는 실행하지 않았다.

| 대상·반복 | lexical 상태·시도 수 | graph/recon 상태·시도 수 | 양성 유지 lexical/graph | 음성 통과 lexical/graph |
| --- | --- | --- | ---: | ---: |
| Python 1 | 실패·3 | 완료·5 | 비교 제외 | 비교 제외 |
| Python 2 | 실패·3 | 완료·4 | 비교 제외 | 비교 제외 |
| Solidity 1 | 완료·5 | 실패·4 | 비교 제외 | 비교 제외 |
| Solidity 2 | 완료·5 | 완료·5 | 0/0 | 1/1 |
| Go 1 | 완료·11 | 완료·5 | 1/0 | 1/1 |
| Go 2 | 완료·13 | 완료·5 | 1/1 | 0/1 |

인용 수정 요청 5건 중 2건이 검증을 통과했고 3건은 다시 실패했다. 통과한 두 응답도
인용 필드만 바뀐 `citation_corrected`가 아니라 다른 내용이 함께 바뀐 `reply_revised`다.
실패는 `candidate_quote_mismatch` 5건과 `triage_column_mismatch` 3건이었다. 상세 오류 위치와
제한된 원문을 제공해 완료 run은 이전 실행의 8개에서 9개로 늘었지만, 정확한 인용 수정은
한 건도 관찰하지 못했다.

Go에서 graph/recon은 두 반복 모두 호출 수를 11→5, 13→5로 줄였고 보고된 입력 token도
각각 94,800개와 109,626개 적었다. 반면 첫 반복에서 양성 라벨을 놓쳤고 두 번째 반복에서만
lexical의 음성 오탐을 제거했다. Solidity의 유일한 완료 pair는 양쪽 모두 양성을 놓쳤으며
graph/recon 입력 token이 24,320개 더 많았다. Python은 lexical 두 run이 모두 실패해 pair
비교가 없다. 따라서 Go의 비용 감소는 재현됐지만 탐지 품질 우위는 재현되지 않았고,
언어별 반복 결과도 완성되지 않았다.

원본은 `runs/model-eval-feedback.c645kqlr/`에 있다. `protocol.json`이 승인 범위와 실행
순서를, `observations.json`이 전체 시도·수정 결과·완료 pair를, 각 `*-attempts/attempts.json`이
실패 비용을 보존한다. Go 두 pair는 `go-summary/benchmark-summary.json`으로 반복 검증했다.
**M5 다언어 반복 평가 gate는 여전히 미충족**이다. 현재 결과로 graph/recon의 일반적인
정확도 우위나 실험 병렬화를 주장하지 않는다.

실패 원본을 대조하니 Python 응답은 여러 후보의 행이 함께 틀렸지만 첫 오류만 피드백됐고,
Solidity 수정 응답은 지적된 열을 바꾸면서 새 counterevidence에 같은 잘못된 열을 추가했다.
후속 오프라인 구현은 한 응답의 인용 오류를 최대 8개 모아 한 번에 전달하고, 각 quote가
supplied fragment 안에서 정확히 시작하는 위치만 최대 8개 제시한다. 초과 수와 입력 gap은
보존하며 행·열을 자동 적용하지 않는다. 다중 analysis 인용의 1회 수정 성공과 여러 triage
byte 열 실패를 회귀 검사했다. 앞선 승인 범위에서는 이 변경의 실모델 효과를 측정하지 않았다.
변경된 prompt/tool identity의 오프라인 preflight는
`runs/model-eval-preflight.8KZtd9/`, 도구 hash는
`71e59876f654514357e0e31f5d6699931b50897717949cf33bfbe6bf5eda2cb0`다. 전체 replay
프롬프트 byte의 lexical/graph는 Go 32,938/90,053, Python 13,020/25,473,
Solidity 13,252/32,905이며 세 언어의 source 라벨 포함과 replay pair 검증이 통과했다.
이 identity로 같은 세 언어·두 arm·두 반복을 비교하는 프로토콜을
`runs/model-eval-batch-feedback.qz1odqas/protocol.json`에 고정했고, 별도 승인 후 아래와
같이 실행했다.
최종 오프라인 검사는 `make check` **731개 통과·23개 skip**, 집중 검사 92개,
`make demo` fresh/resume, `make demo-python`, `make demo-benchmark`와 위 preflight가 통과했다.

## 다중 인용 피드백을 적용한 실행 — 2026-10-13

사용자 승인 후 고정 순서의 12개 run을 `gpt-6-luna`로 순차 실행했다. 총 **75회 시도,
9개 완료 run, 3개 실패 run**이며 실패 시도 6건·미확정 0건이다. 보고된 사용량은 입력
1,275,700 token, 그중 cached input 641,280 token, 출력 16,354 token이고 기록된 호출
시간 합계는 427.328초다. 가격은 확인하지 않았고 대상 코드는 실행하지 않았다.

| 대상·반복 | lexical 상태·시도 수 | graph/recon 상태·시도 수 | 양성 유지 lexical/graph | 음성 통과 lexical/graph |
| --- | --- | --- | ---: | ---: |
| Python 1 | 실패·6 | 완료·4 | 비교 제외 | 비교 제외 |
| Python 2 | 실패·6 | 완료·4 | 비교 제외 | 비교 제외 |
| Solidity 1 | 완료·6 | 완료·4 | 0/0 | 1/1 |
| Solidity 2 | 실패·6 | 완료·3 | 비교 제외 | 비교 제외 |
| Go 1 | 완료·11 | 완료·7 | 1/0 | 1/1 |
| Go 2 | 완료·11 | 완료·7 | 1/0 | 1/1 |

인용 검증 실패는 `candidate_quote_mismatch` 4건과 `triage_column_mismatch` 2건이었다.
수정 결과는 `citation_corrected` 1건, `reply_revised` 4건, call cap 전에 후속 수정 호출을
시작하지 못한 `pending` 1건이다. 정확한 인용만 고친 한 건도 이후 단계에서 예산을 소진한
Python lexical run에 속하므로 완료 pair를 늘리지 못했다. 다중 오류 피드백은 저장·검증됐지만
이 표본에서 run 완료율을 이전 실행의 9/12보다 높이지 못했다.

Go graph/recon은 두 반복 모두 호출을 11→7로 줄였다. 입력 token 차이는 각각 -2,840과
+5,206으로 방향이 반복되지 않았고 중앙값은 +1,183이다. 기록된 호출 시간도 각각 4.050초와
2.636초 늘었으며 prompt byte는 54,031과 38,569만큼 컸다. 고정된 1차 채점에서는 두 번 모두
후보 대표 위치를 HTTP 입력 행으로 잡아 sink 행 라벨을 놓쳤다. 다만 같은 후보의 검증된
root-cause evidence는 두 번 모두 정답 sink인 `runner/execute.go:6`을 인용했다. 따라서 graph가
다중 파일 원인 경로를 제공한 사실과 대표 위치 기반 탐지 점수는 구분해야 한다.

Solidity의 유일한 완료 pair는 graph/recon이 2회 적게 호출되고 입력 token 35,815개와
기록 시간 10.139초가 적었지만, 양쪽 모두 함수 선언을 대표 위치로 골라 전송 행의 양성 라벨을
놓쳤다. Python은 lexical 두 run의 call cap 소진으로 완료 pair가 없다. 실행 전 sandbox가
Codex app-server 초기화를 거절한 한 건은 모델 호출·사용량 없이
`infra-failures/python-r1-baseline-sandbox/`에 따로 보존해 위 수치에서 제외했다.

원본 protocol은 `complete`이며 `observations.json`이 전체 시도와 완료 pair를 묶는다. 각
`*-attempts/attempts.json`, 세 완료 pair의 `benchmark.json`, Go 두 반복의
`go-summary/benchmark-summary.json`은 저장된 원본 호출을 다시 검증한다. **M5 다언어 반복
평가 gate는 계속 미충족**이다. 이 실행은 graph/recon의 일반적인 품질·token·시간 우위를
입증하지 않으며, 현재 작은 Go fixture에서는 호출 수 감소가 더 큰 prompt와 triage 비용으로
상쇄됐다.

이 실행은 단일 대표 행·CWE를 실행 전에 고정했으므로, 입력 행이나 함수 선언을 후보 위치로
고른 응답은 원인 근거가 정확해도 1차 점수에서 제외했다. 다음 평가용 truth에는 같은 사례의
허용 위치를 `accepted_locations`로 미리 선언할 수 있게 했다. 각 위치의 원문·CWE와 사례 간
중복을 검증하고 한 사례를 한 번만 센다. 기존 truth 파일과 이 실행의 점수는 바꾸지 않았다.
실패한 arm의 품질은 여전히 비교할 수 없으며, 다음 M5 평가는 위치 계약과 호출 예산을
실행 전에 함께 고정해야 한다.

## 다음 평가용 신규 입력의 오프라인 고정

앞선 모델 응답으로 정답을 수정하지 않도록 Go·Python·Solidity에 새 합성 소스와 별도
truth/계획을 만들었다. Go와 Python은 서로 다른 파일의 호출을 통해 외부에서 받은
파일명을 읽는 경로와 고정 파일명 대조군을 갖는다. Solidity는 상속된 `onlyOwner`
modifier가 없는 payout 변경과 modifier가 있는 변경을 비교한다. Solidity의 양성은
선언된 owner-only 정책에 대한 후보이며, 자금 유출은 자금이 든 배포와 이후 owner의
`release` 호출에 달려 있다. 양성·음성 모두 작업 행과 진입·전달 행을
`accepted_locations`로 실행 전에 선언했다. 그래야 안전한 대조군의 호출부에 붙은
경고도 오탐으로 센다. Solidity의 접근 통제 문제는 일반 범주 `CWE-284`와 더 구체적인
`CWE-862`를 양쪽 사례의 같은 행에 미리 허용했다. 다른 CWE를 자동 동등 처리하지 않는다.

`make demo-model-evaluation-prospective`는 새 소스를 `runs/`에 복사하고 graph/recon,
truth 대조, 같은 예산의 lexical/graph-recon replay 비교를 다시 만든다. 두 arm 모두
의도적으로 빈 후보 응답을 사용하므로 품질이나 비용의 실모델 측정은 아니다.
`runs/model-eval-prospective.yEMrOO/`의 오프라인 실행에서 세 언어 모두 양성·음성
행이 양쪽 slice에 포함됐고 교차 파일 Go·Python 호출과 Solidity 상속 modifier 관계가
추출됐다. 이 디렉터리의 `target/`, `plan.json`, `truth.json`, graph/recon은 새 복사본이며
`summary.json`에 계획·정답 hash, `protocol.json`에 소스별 hash·실행 순서와 상한을
보존했다. 프로토콜의 `not_requested/not_started`는 승인 전 고정 당시의 상태다. 도구 hash는
`eaaa62558c96ed53095240d8220eb766602b40fe8ebaf117a603e6040d03d6bc`다.
이전 `runs/model-eval-prospective.SNIzAy/`는 recon 도구 변경으로 현재 도구 hash와
달라져 실모델 실행 전에 대체했다. 그 입력에서도 모델 호출은 없었다.
앞서 준비한 `runs/model-eval-prospective.9xAXNz/`는 음성의 대체 위치를 빠뜨려
실행 전에 철회했고 모델 호출은 없었다. 아래 수치와 향후 채점은 새 프로토콜에만 적용한다.

| 언어 | lexical/graph slice | arm당 호출 상한 | 빈 응답 prompt byte lexical/graph |
| --- | ---: | ---: | ---: |
| Go | 3/2 | 18 | 19,655/23,527 |
| Python | 2/2 | 12 | 12,892/17,783 |
| Solidity | 2/2 | 12 | 13,338/22,481 |

상한은 slice당 analysis·최대 조회 1회·triage의 각 호출에 인용 수정 1회를 허용하는
현재 `plan`의 최악 경로(최대 6회)에 맞췄다. 두 arm·두 반복·세 언어의 새 실모델
평가는 최대 **12 run·168회 호출 시도**가 된다. 이 수치는 token·금액 상한이 아니다.
이전 승인과 기록된 점수는 이 truth에 적용하지 않았다. 아래 최종 실측은 별도 승인을 받아 실행했다.
한 언어당 합성 양성·음성 하나인 설계이므로 완료된 반복 결과도 운영 저장소 전체의
탐지율로 일반화할 수 없다.

## 현재 버전의 최종 반복 실측

2026-10-13 사용자가 `gpt-6-luna`의 새 평가를 승인한 뒤 고정된 순서로 12개 run을
순차 실행했다. `runs/model-eval-prospective.yEMrOO/execution-result.json`은 원래
`protocol.json`의 hash와 각 run의 manifest·시도 보고서 hash를 연결한다. 프로토콜
원본은 승인 전 기록으로 보존했다. `benchmark-runs`로 6개 pair를, `benchmark-summary`로
각 언어의 2개 반복을 재계산했다. 아래 token과 시간은 실패·수정 시도를 포함한
`benchmark-attempts` 원본 보고서 합계다. 시간은 기록된 모델 호출의 합이며 전체
작업 시간이나 가격이 아니다.

| 언어 | 양성 유지 lexical → graph/recon | 음성 통과 | 호출 시도 | 보고 입력 token | 기록 호출 초 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Go | 0/2 → 0/2 | 양쪽 2/2 | 14 → 7 | 237,510 → 129,567 | 80.313 → 60.466 |
| Python | 1/2 → 2/2 | 양쪽 2/2 | 11 → 9 | 154,032 → 195,762 | 64.129 → 61.051 |
| Solidity | 2/2 → 2/2 | 양쪽 2/2 | 10 → 8 | 154,769 → 140,031 | 58.178 → 62.678 |
| 합계 | 3/6 → 4/6 | 양쪽 6/6 | 35 → 24 | 546,311 → 465,360 | 202.620 → 184.195 |

총 59회 시도는 승인한 168회 상한 안이다. Python lexical 첫 반복과 Solidity lexical
둘째 반복에서 인용 오류가 한 번씩 발생했고, 각 수정 응답이 검증돼 모든 run이 완료됐다.
실패 2회도 token·시간 합계에 포함했다. 미확정 시도는 0회이며 모든 시도에 입력·출력
token과 경과 시간이 보고됐다. 각 언어의 `summaries/<언어>/benchmark-summary.json`,
`comparisons/<언어>-r<반복>/benchmark.json`, `attempts/<run>/attempts.json`에서
원본별 판단을 재확인할 수 있다.

M5의 **반복 측정 gate는 충족**했다. graph/recon은 이 작은 입력에서 매번 호출 수가
적었고 Python 양성 유지가 한 번 더 많았지만, Go 양성은 두 arm 모두 놓쳤다.
Python은 graph/recon의 보고 입력 token이 더 많았고 Solidity는 기록 호출 시간이
더 길었다. 한 언어당 양성·음성 하나씩의 합성 사례이고 lexical과 graph/recon은
제공 문맥도 다르다. 따라서 일반적인 탐지율·비용·시간 우위나 실제 취약점 재현을
이 결과로 주장하지 않는다.

## Go 인자 전달·정적 역할 보강 후 적응적 평가

기존 M5의 Go 실패를 검토한 뒤 Go 호출 인자/매개변수 사실, HTTP query·파일 읽기 역할,
recon의 직접 호출 관계를 추가했다. 고정된 Go 합성 소스와 truth를 새
`runs/model-eval-go-transfer-20261013/`에 복사하고 lexical과
graph+recon+static을 `gpt-6-luna`로 각각 두 번 비교했다. 이는 **이전 응답을 본 뒤 만든
후속 진단**이므로 앞의 신규 입력 평가와 독립적인 성능 검증이 아니다. candidate의 세
근거를 한꺼번에 제공했으므로 어느 요소가 결과를 바꿨는지도 분리할 수 없다.

`protocol-transfer-v2.json`에는 source/truth/graph/recon/static·도구 hash, 실행 순서와
4 run·최대 72회 시도, run당 18회 상한을 실행 전에 고정했다. 처음 로컬 샌드박스에서
Codex app-server 초기화가 거절되어 모델 호출 전 실패한 시도는 원본 stderr와 함께 남겼다.
새 프로토콜은 그 실패 hash를 참조하고 Codex CLI가 초기화되는 실행 환경에서 네 run을
순서대로 수행했다. `execution-result-v2.json`은 완료 run·pair·attempt 보고서 hash를
연결한다. 실패한 인용 수정 1회를 포함해 실제 호출 시도는 21회, 미확정은 0회다.

| Go 2회 반복 | lexical | graph+recon+static |
| --- | ---: | ---: |
| 엄격 양성 유지 | 0/2 | 0/2 |
| 음성 통과 | 2/2 | 2/2 |
| `CWE-73` 유지 후보 | 0/2 | 2/2 |
| 정답 위치의 원인 근거 | 0/2 | 1/2 |
| 호출 시도 | 12 | 9 |
| 보고 입력 token | 182,192 | 242,279 |
| 기록 호출 시간 | 54.357초 | 63.477초 |

graph arm의 두 후보는 모두 `web/handlers.go:10`의 query 입력 행을 대표 위치로 골랐다.
사전 truth는 `store/files.go:6` 파일 읽기와 `web/handlers.go:11` 전달 호출을 허용했으므로
엄격 점수는 0이다. 첫 반복의 검증된 원인 근거는 sink를 인용했다. 두 번째 반복은
인용 오류를 수정한 뒤 후보를 유지했지만 원인 위치 일치가 없었다. lexical은 세 slice에서
이용할 수 없는 graph 조회를 요구한 뒤 후보를 내지 않았다. `benchmark.json`의
`diagnostics`는 대표 위치·원인 위치·출력 CWE·판정을 분리하며 정답이나 원래 점수를
변경하지 않는다.

이 실험에서 graph arm은 후보 분류를 `CWE-73`으로 바꿨으나 엄격 발견률과 비용은
개선되지 않았다. 모델 반복 수와 합성 사례가 작고 정적 역할까지 함께 제공했으므로
일반적인 감사 성능 결론은 낼 수 없다. 실제 HTTP 진입과 수정 전후 결과는 별도의
격리 worker 증거로만 판단한다.

## 새 Go 값 경로와 대표 위치 계약의 3-arm 평가 — 2026-10-13

`examples/go-eval-next-target`은 `Download → relay.Fetch → storage.Open → os.ReadFile(key)`와
요청값을 무시하고 상수 파일명을 여는 `Notice`를 가진 새 합성 입력이다. 모델 응답을 보기
전에 truth를 `storage/files.go:6`의 파일 열기/CWE-73 양성과 10행의 상수 음성으로
고정했다. 세 arm은 같은 `gpt-6-luna`, source, truth, 20KB slice, 조회 1회/16KB,
run당 호출 시도 24회와 인용 수정 조건을 썼다. 1회차는 lexical→graph+recon→
graph+recon+static/value, 2회차는 역순이다. 마지막 arm의 정적 역할과 새 값 경로는
함께 들어가며 각각의 기여는 분리되지 않는다.

첫 프로토콜 `runs/model-eval-go-value-20261013/protocol.json`은 실행 전 소스·정답·
도구 hash를 고정했다. 6 run·38회 시도 중 인용 실패 4회를 포함하며 미확정은 0회다.
엄격 양성은 lexical 2/2, graph 1/2, static/value 2/2, 음성은 모두 2/2였다.
그래프 arm 첫 반복은 sink 위치를 골랐지만 `CWE-22`라 엄격 점수에서 빠졌다.
이후 값 경로에서 주소 이탈·클로저·변환과 상태 상한을 보수적으로 처리하는 코드 변경을
했으므로, 이 결과는 최종 코드 평가로 표시하지 않는다. 원본과 실패 비용은
`runs/model-eval-go-value-20261013/execution-result.json`에 hash로 연결했다.

최종 코드의 별도 프로토콜 `runs/model-eval-go-value-20261013-v2/protocol.json`은
같은 source/truth와 새로운 도구·graph·static·recon hash, 같은 순서·상한을 다시 고정했다.
6 run·33회 시도, 실패·미확정 0회였고 모든 호출에 token 보고가 있다.

| 최종 코드 2회 반복 | lexical | graph+recon | graph+recon+static/value |
| --- | ---: | ---: | ---: |
| 엄격 양성 유지 | 1/2 | 2/2 | 2/2 |
| 음성 통과 | 2/2 | 2/2 | 2/2 |
| 호출 시도 | 18 | 8 | 7 |
| 실패 포함 입력 token | 269,520 | 173,940 | 153,484 |
| 기록된 모델 호출 시간 | 89.154초 | 48.160초 | 46.207초 |

최종 코드의 lexical 첫 반복은 정답 sink 후보 외에 `web/download.go:11`의
`CWE-22` 후보도 남겼고, 두 번째 반복은 후보가 없었다. graph와 static/value는
두 번 모두 정답 sink/CWE-73을 `needs_validation`으로 남겼다. 음성 상수 파일 열기를
취약점으로 승격한 run은 없었다. `benchmark-runs` 4개 pair와 `benchmark-summary`
2개 반복 보고서, 6개 `benchmark-attempts` 보고서를 읽기 전용 재검산했으며
`runs/model-eval-go-value-20261013-v2/execution-result.json`이 그 hash를 연결한다.

두 번째 프로토콜은 첫 모델 응답을 본 뒤의 **동일 fixture 재실행**이다. 양성 하나·음성
하나인 작은 합성 입력에서 graph arm의 우수한 반복 결과와 호출 절약은 관찰값일 뿐,
독립 저장소의 탐지율이나 일반적 비용 우위가 아니다. 특히 static/value arm은
graph+recon 대비 엄격 점수가 같아 값 경로 자체의 증분 효과를 입증하지 못했다.
이 실험은 실행 중인 HTTP 진입점이나 수정 전후를 검증하지 않았으며, 그런 결론은
격리 worker의 별도 증거가 있어야 한다.
기존 `examples/go-http-target`에 대해서는 준비된 로컬 이미지로
`runs/go-http-demo.rJ9Luj/`의 수정 전후 HTTP 요청과 `judge`의 `validated`를
다시 확인했다. 그 결과는 이 파일 선택 fixture의 동적 판정으로 이전하지 않는다.
# 값 경로 분리 비교와 새 Go 합성 입력 — 2026-10-13

기존 파일 선택 입력의 적응적 분리 실험은
`runs/go-value-ablation-20261013/protocol-v2.json`에 모델 호출 전에 고정했다.
같은 소스·정답·직접 호출 구조·Semgrep 역할 4건을 사용하고 Go call metadata의
`argument_origins`, `argument_transfers`, `argument_transfer_gap`만 제거한
static-only arm과 원본 full arm을 각각 두 번 비교했다. 각 양성은 대표
`storage/files.go:6`·`CWE-73`과 미기각 판정을 요구한다. 양쪽 모두 양성 2/2,
상수 음성 2/2였다. static-only/full의 실패 포함 호출은 10/6회,
보고된 입력 token은 263,158/114,865개, 기록된 호출 시간은 83.507/51.098초였다.
static-only의 인용 실패 1회는 후보 철회로 수정됐고 원본 시도도 남겼다. 처음
로컬 sandbox에서 Codex app-server 초기화가 거절된 1회는 모델 출력 전에 실패해
별도 `protocol.json`에 보존하고 새 프로토콜로 다시 고정했다. 동일 fixture를
이전 평가에서 이미 본 뒤 실행했으므로 탐지 효과나 일반 비용 우위를 뜻하지 않는다.
원본 검산 결과는 `execution-result.json`, 두 comparison, 반복 summary,
네 attempt 보고서에 있다.

추가로 모델 실행에 쓰이지 않았던 `examples/go-eval-holdout-target`의
환경값→다중 패키지→쉘 명령 구성 경로와 고정 문자열 대조군을 먼저 고정했다.
`runs/go-holdout-20261013/protocol.json`의 순서대로 lexical, static-only,
full을 두 번씩 `gpt-6-luna`로 실행했다. 총 6 run·29회 시도, 실패·미확정 0회다.
세 arm 모두 양성 `runner/runner.go:6`·`CWE-78`을 2/2 유지했고 10행 음성은
2/2 통과했다. lexical/static-only/full의 호출은 14/8/7회, 보고된 입력 token은
212,437/160,814/126,634개, 기록된 호출 시간은 75.906/60.144/59.919초다.
static-only→full의 반복별 호출 차이는 +1/-2회, 입력 token 차이는
+22,822/-57,002개로 방향이 일관되지 않았다. 이 표본에서 값 경로의 탐지
향상은 관찰되지 않았고 비용 개선도 일반화할 수 없다. 이 입력은 모델에는 새로
공급됐지만 작성자가 설계한 합성 사례이며 제3자 저장소나 실행 가능한 쉘 취약점
검증은 아니다. 네 pair comparison, 두 반복 summary, 여섯 attempt 보고서와
해시를 묶은 `execution-result.json`을 로컬 `runs/go-holdout-20261013/`에 보존했다.
이 두 프로토콜의 도구 hash는 이후 Python·Solidity 그래프 확장 전의 코드에 묶인다.
Go 평가 수치를 확장 후 코드의 새 실행 결과로 취급하지 않는다.
