# DeFiHackLabs 실사례 평가: 첫 파일럿과 채점 경계

[DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)는 과거 사고의 Foundry 재현 코드와
사건 링크를 제공한다. PoC의 `Attacker`/`ContractTest`를 감사 대상 계약으로 넣으면
피해 원인 탐지 성능을 측정할 수 없다. 대상 입력은 사고 시점의 피해 구현 원문이어야
하며, PoC·사고 설명·정답은 분석 입력에서 제외하고 평가 후에만 대조한다.
PoC나 실제 체인 fork는 이 평가 준비 과정에서 실행하지 않는다.

## 2025-01 UniLend 진단 파일럿

- 사건 앵커: DeFiHackLabs 커밋
  [`e1e641e`](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/e1e641e71ff42d79104bb88029f6055cfd7df84c/src/test/2025-01/Unilend_exp.sol)의
  `Unilend_exp.sol`. 파일은 프록시 `0x4e34...d0d0`와 사고 트랜잭션을 가리키며,
  피해 구현 본문은 포함하지 않는다.
- 피해 원문: Ethereum(체인 ID 1)의 검증된 프록시·구현
  [`0xc86d...330e`](https://etherscan.io/address/0xc86d2555f8c360d3c5e8e4364f42c1f2d169330e#code).
  Etherscan의 두 주소 응답은 동일한 7개 소스와 `v0.8.2` 컴파일러를 보고했다.
  7개 파일 모두 사고 전 [UniLend 공식 커밋
  `a3f026d`](https://github.com/UniLend/unilendv2/tree/a3f026ddfbffd2be150dd42a71c6b6ef0d6b3ac5/contracts)의
  해당 파일과 바이트 단위로 같았다. `contracts/pool.sol` SHA-256은
  `2b7caaa4bfdf1d36d730917aa72d57cf8eb08cf929036ee707e81843bc3b0311`이다.
  현재 프록시 메타데이터만으로 사고 블록의 binding·저장 상태가 증명되지는 않는다.
- 독립 원인 근거: [SlowMist 사고 분석](https://slowmist.medium.com/analysis-of-the-unilend-hack-90022fa35a54)은
  상환 과정의 잔액/지분 갱신 순서 때문에 건전성 검사에 오래된 풀 잔액이 들어갔다고
  설명한다. 이를 CWE와 한 행으로 단정하기보다 다음 여러 소스 위치의 인과관계로 검토한다.

`runs/defihacklabs-pilot/`의 읽기 전용 소스 snapshot을 현재 solc-js 0.8.30으로
구문 분석했다. 7/7 파일 파싱, 함수 91개·호출 306개이며 bytecode·대상 빌드·PoC는
실행하지 않았다. 컴파일러가 검증 원본의 0.8.2와 달라
`configuration_verified=false`다. 그래프에서 `contracts/pool.sol`의
`redeemUnderlying`은 620행 `_burnLPposition`, 623행 `checkHealthFactorLtv1`,
625행 `transferToUser`에 확정된 직접 호출을 가진다. 검사는 `userHealthFactorLtv`
→ `userBalanceOftoken0`으로 이어지고, 후자는 282행의 외부 `balanceOf` 조회를
포함한다. 이 간선과 원문 위치는 구조적 선행 근거다. 지분 소각이 잔액 계산에
미치는 상태 효과, 사고 블록의 값, 건강도 우회는 그래프만으로 판정할 수 없다.

원문에서 확인한 순서는 `redeemUnderlying` 620행 → `_burnLPposition`의
`token0lendShare`·`totalLendShare` 갱신(449–450행) → 623행 건전성 검사 →
`userBalanceOftoken0`의 외부 `balanceOf`(282행) → 625행 토큰 전송이다.
그래프는 내부 호출과 외부 호출의 위치를 제공하지만, 저장 참조 별칭
`_positionMt`/`_tm0`의 쓰기 대상이나 `balanceOf`의 반환 시점·값을 연결하지
않는다. 따라서 이 순서를 취약점 재현의 증거로 승격하지 않는다.

| 비교 기준 | 이번 파일럿의 관찰 | 다음 개선의 통과 조건 |
| --- | --- | --- |
| 피해 소스 입력 | PoC와 분리한 검증 원문 7개 파일을 7/7 파싱 | compiler·프록시 연결의 불확실성을 기록하고 같은 snapshot을 유지 |
| 호출 구조 | 소각 → 검사 → 전송과 검사 내부 잔액 조회를 찾음 | 함수 간 호출 순서와 직접 저장 쓰기/읽기 위치를 원문에 묶고 별칭·분기 미해결을 표시 |
| 원인 판정 | 상태 변화와 외부 잔액의 관계를 증명하지 못함 | 독립 label과 실제 음성 대조군을 먼저 고정한 뒤 양성·오탐·미해결을 함께 측정 |
| 동적 검증 | 실행하지 않음 | 동일한 사고 시점 상태·격리 recipe·관찰 조건이 준비된 경우에만 별도 검증 |

현재 `static` 명령은 Solidity 규칙 adapter가 없어 명시적으로 실패했다.
따라서 이 사례에 모델 탐지 점수·오탐률·`validated`를 매기지 않는다. 현행
`benchmark-truth`는 양성·음성 쌍과 정확한 위치/CWE를 요구한다. 이 사례에
임의의 음성 위치나 CWE를 만들어 넣지 않는다.

## 반복 개선 절차

1. DeFiHackLabs의 사건 커밋·PoC hash와 피해 구현 소스·컴파일러·배포 주소를
   고정한다. 피해 소스가 없거나 구현/프록시 매칭이 불확실하면 `unscorable`로 남긴다.
2. 사고 분석과 원문을 별도 검토해 원인·대표 위치·허용 가능한 CWE와 진짜 음성
   대조군을 고정한다. label/PoC/사고 설명은 모델 입력에 넣지 않는다.
3. 동일 소스·예산으로 lexical, graph/recon, 추가 정적 근거를 비교한다. 엄격 위치·
   CWE, 음성 오탐, 불확실/기각, 누락, 실패 포함 호출·token·시간을 모두 기록한다.
4. 개발 사례에서 **한 가지 측정된 실패 원인**만 고친 뒤 원래 사례와 손대지 않은
   holdout을 재실행한다. 기존 정답·원본 시도를 바꾸지 않고 개선과 회귀를 함께 보고한다.
5. 재현은 별도 승인된 고정 recipe·이미지·oracle이 있을 때 격리 worker에서만 한다.
   체인 fork, RPC credential 또는 DeFiHackLabs PoC를 호스트에서 실행하지 않는다.

첫 개선 후보는 Solidity 함수 호출 순서와 저장 상태 read/write의 **근거**를
분리해서 agent에게 공급하는 것이다. `balanceOf` 외부 결과와 실제 건강도 효과는
미해결로 유지한다. 또 Solidity 정적 역할 adapter는 별도 gate이며, UniLend의
회계 순서 문제를 단순 source→sink taint로 판정하는 규칙을 만들지 않는다.
