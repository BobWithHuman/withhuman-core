# 배포 현황

2026-11-02 기준입니다. `main`은 `8c1afd3`이고, staging `imageTag`도 이 커밋입니다.

**요약:** 이미지 빌드부터 GitOps 기록까지의 CI/CD는 동작합니다. 아직 실제 클러스터는 없으며, 배포를 마치려면 staging 인프라를 만들고 Argo CD를 연결해야 합니다.

```text
main 병합 → 이미지 빌드, GHCR 푸시 → CI가 withhuman-gitops에 SHA 커밋 → Argo CD → 클러스터
└────────────────── 구현 완료 ──────────────────┘    └── 남음: 실제 연결 ──┘
```

## 구현 완료

| 항목 | 내용 | 검증 |
|---|---|---|
| 서비스 이미지 | Collector, Generator, Decision을 GHCR에 게시, 커밋 SHA 태그 | GitHub Actions 실행 성공 |
| Helm 차트 | `deploy/k8s/withhuman`: 서비스, AgentGateway, Ingress, 스키마 Job, PDB, HPA, NetworkPolicy | minikube 설치 |
| 무중단 종료 | 세 서비스 SIGTERM 처리, Collector HTTP와 gRPC 동시 종료, `preStop` 대기 | 아래 시험 결과 |
| 배포 순서 | sync wave: Decision → Generator → Collector → AgentGateway | minikube Argo CD |
| GitOps 저장소 | `withhuman-gitops`: Application, 환경별 값, 운영 절차 | Application 서버 측 dry-run |
| 자동 기록 | `deploy-staging` job이 staging `imageTag` 커밋 | GitHub Actions 실행 성공 |
| MCP 판정 적용 | 차트 기본값 `WITHHUMAN_MCP_ENFORCE=hook` | 렌더링 확인 |
| CI 검사 | Rustfmt, Clippy, Nextest, Cargo Deny, E2E, Helm | PR에서 통과 |

### minikube 시험 결과

Kubernetes 1.37, Decision은 `mock` provider로 시험했습니다.

| 시험 | 결과 |
|---|---|
| 세 서비스 롤링 재시작 | 요청 6,720건 실패 0, 호출 3,545건 전부 판정 기록 |
| AgentGateway 재시작 4회 | 요청 1,253건 실패 0 |
| SIGTERM 종료 시간 | 5.4~6초(`preStop` 5초 포함) |
| Git 커밋으로 자동 배포 | 요청 522건 실패 0 |
| 잘못된 이미지 배포 | 첫 단계에서 멈춤, 기존 파드가 요청 795건 처리 |
| 수동 변경 복구 | 약 4초 만에 Git 값으로 복귀 |

## 배포 완료까지 남은 일

순서대로 진행합니다.

### 1. 인프라 결정

특정 클라우드에 묶이지 않게 AWS, Azure, GCP 어디서든 같은 구성으로 배포합니다.

- [x] 첫 staging 대상: AWS
- [x] 리전: 서울(`ap-northeast-2`)
- [ ] 비용 범위
- [x] Neo4j 운영 방식: 전용 VM(AWS는 EC2 `r7i.large`)
- [x] 클라우드 공통 진입점과 인증서 방식: Traefik, cert-manager(Let's Encrypt)
- [x] 클라우드 공통 시크릿 방식: External Secrets
- [ ] staging 도메인

### 2. staging 인프라

AWS용 Terraform은 `infra/aws`에 작성했고 `terraform validate`까지 통과했습니다. 실제 생성(`apply`)은 아직입니다.


- [ ] 관리형 Kubernetes 클러스터: EKS(코드 작성 완료)
- [ ] Neo4j: 힙 6GB, 페이지 캐시 6GB, 일일 스냅숏(코드 작성 완료)
- [ ] Redis 호환 저장소: ElastiCache Valkey(코드 작성 완료)
- [ ] Secrets Manager의 엔진 시크릿과 Jev 키 시크릿(코드 작성 완료, Jev 키는 직접 입력)
- [ ] 클러스터 부가 구성: Argo CD, Traefik, cert-manager, External Secrets(공통 모듈 `infra/modules/platform` 작성, minikube 검증 완료)
- [ ] Ingress 컨트롤러와 TLS 인증서
- [ ] `withhuman-staging` 네임스페이스와 `withhuman` Secret(`neo4j-password`, `jev-api-key`, `redis-url`)
- [ ] GHCR 이미지 pull 인증(`imagePullSecrets`)
- [ ] Jev 호출을 위한 외부 통신(NAT)

### 3. Argo CD 연결

- [ ] 클러스터에 Argo CD 설치(Terraform 공통 모듈에 포함)
- [ ] `withhuman-gitops` 읽기 전용 Deploy key를 클라우드 시크릿 저장소에 등록
- [ ] `envs/staging/values.yaml`의 Neo4j 주소와 호스트 작성
- [ ] `apps/staging.yaml` 적용
- [ ] 코드 저장소의 차트와 GitOps 저장소의 값을 함께 읽는 구성의 실제 동기화 확인

### 4. staging 검증

- [ ] `deploy/client/settings.json`의 훅 주소를 staging 호스트로 변경해 실제 Claude Code 연결
- [ ] 실제 Jev로 판정 확인
- [ ] 실제 클러스터에서 무중단 재시작 재확인
- [ ] NetworkPolicy 적용 확인(minikube는 kindnet이라 미검증)
- [ ] 스케일 아웃한 파드에 트래픽이 나뉘는지 확인
- [ ] 지속 부하 테스트로 파드 수와 Neo4j 크기 확정

### 5. production 오픈

- [ ] production 인프라와 `envs/prod/values.yaml`
- [ ] `apps/prod.yaml`의 차트 버전 고정
- [ ] `shadow` 모드로 오픈
- [ ] 오탐률 확인 후 `enforce` 전환

## 배포 후 진행

배포를 마친 뒤 다룹니다.

- [ ] 구조화 로그: 서비스의 JSON 로그 출력
- [ ] 지표: `/metrics`, Prometheus, Grafana, 알림
- [ ] `main` 푸시 CI와 통합 테스트 건너뜀 방지
- [ ] 스키마 마이그레이션 이력 관리
- [ ] README, CONTRIBUTING, `.env.example` 정리
- [ ] Azure, GCP용 Terraform
- [ ] Collector와 Valkey 사이 TLS(Redis 클라이언트에 TLS 기능 추가)

## 미결정

- **훅 인증:** 현재는 `x-withhuman-client` 헤더를 그대로 사용합니다.

## 알려진 위험

- **Neo4j 메모리:** 개발용 EC2에서 힙 512MB로 GC가 폭주해 판정 타임아웃과 훅 502가 발생했습니다. 무엇이 힙을 소모했는지는 밝히지 못했습니다.
- **Jev 의존:** 외부 API 장애 시 `closed` 정책에서는 도구 호출이 차단될 수 있습니다.
- **Neo4j 단일 인스턴스:** 파드를 늘려도 Neo4j 쓰기 처리량은 늘지 않습니다.
