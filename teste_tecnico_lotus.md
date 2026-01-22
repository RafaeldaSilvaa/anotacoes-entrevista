# Guia Aprofundado para Entrevista Sênior — CI/CD, AWS, Docker, Terraform, PySpark e Machine Learning (v3)

Esta versão (v3) é uma revisão ampliada e consolidada do material anterior. Ela inclui, para cada tema, definições, internals, padrões arquiteturais, melhores práticas, piores práticas (anti-padrões), como testar local e em CI, observability (logs/metrics/tracing), segurança, exemplos completos e checklist de perguntas para entrevistas.

Objetivo: eliminar lacunas encontradas nas versões anteriores (especialmente: cobertura de testes, observability, falhas operacionais e práticas ruins comuns), e entregar um guia que você possa usar tanto para estudar quanto para provar competência em entrevistas sênior.

---

Índice (rápido)
- CI/CD: GitHub Actions (tests, security, OIDC, examples)
- CI/CD: AWS (CodeBuild/CodePipeline/CodeDeploy, testing, strategies)
- Docker & Dockerfile (build, test, scanning, runtime policies)
- Terraform (state, modules, testing, policies)
- PySpark (unit/integration tests, tuning, debugging)
- Machine Learning (testing, MLOps, monitoring, fairness)
- Checklists finais e conjunto de perguntas para entrevista

---

## Convenção de leitura
- Cada seção tem: 1) Definição curta, 2) Por que importa, 3) Internals resumidos, 4) Quando usar, 5) Melhores práticas, 6) Piores práticas, 7) Testes e CI (o que testar e como), 8) Observability e debugging, 9) Segurança e compliance, 10) Exemplo prático e 11) Perguntas para entrevista.

---

## CI/CD — GitHub Actions

1) Definição curta
- Plataforma de automação do GitHub que executa workflows descritos em YAML. Workflows são acionados por eventos (push, PR, schedule) e executados em runners.

2) Por que importa
- Torna possível garantir qualidade (tests, linters), build reprodutível, geração de artefatos e deploy automatizado com integração a revisões (PR checks).

3) Internals resumidos
- Event payload -> runner scheduler -> job que executa containers/VMs -> steps executam comandos/actions.
- Cada job é isolado; steps compartilham filesystem do runner. Runners hosted são efêmeros.

4) Quando usar
- Repositórios hospedados no GitHub; para integração com PRs, checks e marketplaces de actions. Ótimo para pipelines multi-cloud.

5) Melhores práticas (detalhado)
- Separar pipelines: CI (unit + lint + fast tests), Integration (integration tests, contract tests), CD (deploy) com gates.
- Build once, deploy many: produza artefatos imutáveis (image:sha) e reuse-os entre ambientes.
- Testes rápidos em PR: execute lint, unit tests e security static checks. Deixe testes mais pesados para pipelines periódicos (nightly) ou pre-release.
- Cache: use actions/cache para dependências; use cache para Docker layers (buildx) em CI para acelerar.
- Secrets e OIDC: armazene secrets no GitHub Secrets; prefira OIDC para acessar AWS/GCP sem long-lived keys.
- Minimal permissions: configure `permissions:` no workflow para reduzir escopo do `GITHUB_TOKEN`.
- Artifacts e test reports: use upload-artifact para relatar coverage, junit xml e debug artifacts.
- Fail fast: configure jobs para falhar rápido (lint/format) evitando wasted compute.

6) Piores práticas (anti-padrões)
- Incluir secrets plaintext no YAML.
- Fazer deploy diretamente em branchs sem aprovação (ex.: deploy on push master sem protected branches).
- Ter um único job monolítico que instala, testa e deploya tudo.
- Não versionar actions internas ou usar actions de terceiros sem revisão.

7) Testes e CI (o que testar e como)
- Unit tests: rápidos, sem dependências externas; executar em cada PR.
- Linters/formatters: flake8/black, eslint, style checks; rodar em PR.
- Integration tests: tests que usam infra minimal (localstack, testcontainers, ephemeral db); rodar em uma pipeline separada ou em job condicional.
- End-to-end: em ambiente staging com dados controlados; executar antes do deploy para production (gated deploy).
- Security checks: SAST (semgrep), dependency scan (dependabot, GitHub native), container scan (Trivy) — rodar no CI.
- Contract tests: verificar contratos de APIs (Pact) entre serviços.

8) Observability e debugging
- Logs: GitHub fornece logs por step; configure upload de arquivos de log importantes.
- Debugging: re-run with debug flags, usar `ACTIONS_STEP_DEBUG` quando necessário; adicionar steps temporários para inspeção (env dump, ls -la) — cuidado com secrets.
- Metrics: exportar pipeline metrics para Prometheus/Grafana (via actions that push metrics) para observar tempo médio de CI, flakiness.

9) Segurança e compliance
- OIDC para cloud access (AWS IAM role trust with condition for repo/branch). Use least privilege roles for CI.
- Scan containers and code; sign artifacts (cosign) and verify signatures before deploy.
- Enforce branch protection, required reviews, and require passing checks before merge.

10) Exemplo prático (workflow completo com testes separados)

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [ main ]

permissions:
  contents: read
  id-token: write

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: python-version: '3.10'
      - run: pip install -r requirements-dev.txt
      - run: flake8 src
      - run: black --check src

  unit-tests:
    needs: lint
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt
      - run: pytest --junitxml=results.xml
      - uses: actions/upload-artifact@v4
        with:
          name: junit-${{ matrix.python-version }}
          path: results.xml

  integration-tests:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: unit-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/run-integration-tests.sh
      - uses: actions/upload-artifact@v4
        with:
          name: integration-logs
          path: logs/

  build-and-push:
    if: github.ref == 'refs/heads/main'
    needs: [unit-tests, integration-tests]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Login to ECR via OIDC
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::ACCOUNT_ID:role/github-ci-role
          aws-region: us-east-1
      - name: Build and push image
        run: |
          IMAGE=${{ github.sha }}
          docker build -t $ECR/repo:$IMAGE .
          aws ecr get-login-password | docker login --username AWS --password-stdin $ECR
          docker push $ECR/repo:$IMAGE

  deploy:
    if: github.ref == 'refs/heads/main'
    needs: build-and-push
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to ECS with role
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::ACCOUNT_ID:role/github-deploy-role
          aws-region: us-east-1
      - run: ./scripts/deploy-ecs.sh ${{ github.sha }}
```

11) Perguntas de entrevista
- "Como garantir que dependabot não quebre a build?" → lockfile tests in CI (install from lockfile), pin transitive dependencies in CI smoke tests, integration tests.
- "Como medir flakiness?" → track test failure rates over time, rerun failed tests automatically and count flaky patterns.

---

## CI/CD na AWS (CodeBuild, CodePipeline, CodeDeploy — versão ampliada)

1) Definição curta
- Serviços nativos AWS para orquestração, build e deploy de aplicações com integração profunda no ecossistema AWS.

2) Por que importa
- Integração com IAM, CloudWatch, CloudFormation facilita políticas de segurança, monitoramento e auditoria.

3) Internals essenciais
- CodeBuild: executa containers com permissões do IAM role anexado; usa `buildspec.yml`.
- CodePipeline: compõe stages (Source → Build → Test → Deploy). Pode incluir approvals.
- CodeDeploy: orquestra estratégias de deploy, suporta hooks/lifecycle events.

4) Quando usar
- Use quando infra e requisitos operacionais residem majoritariamente em AWS ou quando compliance exige tudo dentro de contas AWS.

5) Melhores práticas
- Segregação de roles (build role com permissão limitada; deploy role com menos privilégios de leitura de source).
- Implementar etapas de teste: unit (in-code), integration (connect to ephemeral resources), acceptance (smoke test in staging). Use artifacts do CodeBuild para transportar artefatos para stages seguintes.
- Imutabilidade de artefatos (imagem com digest); use digests em task definitions.
- Use approvals human-in-the-loop para production deploys (manual approvals in CodePipeline).

6) Piores práticas
- Deploy direto sem testes ou approvals; permissões amplas para roles; usar `latest` sem controle.

7) Testes e CI
- Unit tests: incluir no build container antes de produzir artifact.
- Integration tests: use test clusters (ephemeral) ou mock services (localstack) para validar infra calls.
- Smoke tests: um step de deploy que roda um healthcheck endpoint e valida resposta antes de finalizar deploy.

8) Observability e debugging
- CloudWatch Logs: configure log groups e retention. Use CloudWatch Metrics e Alarms tied to health checks.
- X-Ray para tracing distribuído. Use structured logs (JSON) para fácil agregação.

9) Segurança
- KMS para cifrar artifacts; Parameter Store/Secrets Manager para secrets; IAM least-privilege for roles. Use VPC endpoints for S3/ECR to avoid internet exposure.

10) Exemplo: buildspec com steps de teste e scan

```yaml
version: 0.2
env:
  variables:
    IMAGE_REPO: my-app
phases:
  install:
    runtime-versions:
      docker: 20
    commands:
      - pip install -r requirements-dev.txt
  pre_build:
    commands:
      - echo logging into ecr
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com
  build:
    commands:
      - pytest tests/unit --junitxml=unit-results.xml
      - docker build -t $IMAGE_REPO:$CODEBUILD_RESOLVED_SOURCE_VERSION .
  post_build:
    commands:
      - docker push $ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$IMAGE_REPO:$CODEBUILD_RESOLVED_SOURCE_VERSION
      - trivy image --severity HIGH,CRITICAL $ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$IMAGE_REPO:$CODEBUILD_RESOLVED_SOURCE_VERSION || true
artifacts:
  files:
    - unit-results.xml
```

11) Perguntas de entrevista
- "Como você implementa canary usando CodePipeline + ECS?" → criar step que atualiza service with a new task set, shift traffic percentage via Application Load Balancer and monitor alarms before completing deployment.

---

## Docker & Dockerfile (com testes e scanner integrados)

1) Definição curta
- Docker empacota aplicações e dependências em imagens que são executadas como containers.

2) Por que importa
- Garante consistência de runtime, portabilidade e facilita CI/CD.

3) Internals rápidos
- Cada instrução gera camada; union FS aplica camadas.

4) Quando usar
- Microservices, ambientes replicáveis e para criar componentes facilmente distribuíveis.

5) Melhores práticas detalhadas
- Multi-stage builds, pin base image versions, minimize layers, clean caches.
- Security scan during CI (Trivy/Grype), sign images (cosign), and verify at deploy.
- Runtime policy: run as non-root, set resource limits, use seccomp and read-only root FS.

6) Piores práticas
- Baking secrets into images, using `latest` tag in prod, leaving package managers and build tools in final image.

7) Testes e CI
- Lint Dockerfile: hadolint in CI.
- Build tests: try run health endpoint in CI container (smoke test), run containerized unit tests.
- Security scanning: trivy image, fail build on HIGH/CRITICAL vulnerabilities (policy can be configurable).

8) Observability and debugging
- Container logs to stdout/stderr; use centralized logging (Fluentd/CloudWatch/ELK).
- Use docker inspect and run container with interactive shell in debug runs.

9) Segurança
- Sign images (cosign), verify signatures in deploy stage; use registry auth controls; image immutability.

10) Exemplo CI snippet (lint + build + scan + smoke)

```yaml
jobs:
  docker-lint-build-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Hadolint
        uses: hadolint/hadolint-action@v2
        with: { dockerfile: 'Dockerfile' }
      - name: Build image
        run: docker build -t my-app:test .
      - name: Run smoke test
        run: |
          docker run --rm -d --name smoke my-app:test
          sleep 3
          curl -f http://localhost:8080/health || (docker logs smoke && exit 1)
      - name: Scan with Trivy
        run: trivy image --exit-code 1 --severity HIGH,CRITICAL my-app:test
```

11) Perguntas de entrevista
- "Como lidar com CVEs em imagens base?" → Pin base versions, monitor CVE feeds, rotate base images and rebake images regularly, apply image signing and runtime denial if unsigned.

---

## Terraform (práticas extensivas e testes)

1) Definição curta
- IaC declarativa que cria e mantém recursos em provedores.

2) Por que importa
- Padronização, auditabilidade e repeatability da infra.

3) Internals
- `terraform plan` gera dif entre state e config; provider plugins implement API calls; state armazena mapping entre recursos e IDs reais.

4) Quando usar
- Infra que precisa ser reproduzível, auditável e versionada.

5) Melhores práticas
- Backend remoto com lock (S3 + DynamoDB), use workspaces/environments isolados por team/env, modularize (modules por domínio), version modules sem breaking changes.
- Policy as Code: OPA/Sentinel for security guardrails.
- Automate `plan` in PRs and require approval for `apply` to production.

6) Piores práticas
- State local, editar infra manualmente sem registrar, permissões amplas no bucket de state, não versionar módulos.

7) Testes e CI
- `terraform validate`, `terraform fmt` and `tflint` on PR.
- Security static analysis: checkov/terrascan.
- Integration tests: Terratest (Go) create real infra in ephemeral accounts or use mocks for expensive resources.

8) Observability and debugging
- Keep detailed plan outputs in artifacts for audits; use logs from provers and cloud consoles.

9) Segurança
- Encrypt state with KMS; restrict access with IAM; avoid plaintext secrets in variables (use vault/secrets manager + data sources).

10) Example pipeline for Terraform (PR + apply)

- PR: run `terraform init -backend=false` + `terraform validate` + `terraform plan -out=tfplan` and upload tfplan as artifact for reviewers.
- Merge: pipeline assumes role and runs `terraform apply tfplan` in a controlled environment.

11) Perguntas de entrevista
- "Como testar módulos que criam RDS?" → use Terratest to create ephemeral resources in isolated account or use mocks and unit tests (validate plan) combined with smoke tests on minimal infra.

---

## PySpark (com foco em testes e produção)

1) Definição curta
- API Python do Apache Spark para processamento distribuído (batch/stream).

2) Por que importa
- Facilita ETL/ELT em grandes volumes com otimizações internas.

3) Internals resumidos
- Catalyst optimizer, Tungsten engine, driver/executors, shuffle mechanics.

4) Quando usar
- Processos que excedem capacidade de single-node: joins grandes, aggregations e transformações massivas.

5) Melhores práticas
- Usar DataFrame API e SQL queries; evitar UDFs quando possível.
- Explicit schema, partition pruning, broadcast for small tables, tune shuffle partitions and memory.
- Use AQE (Spark 3.x) para dinamically otimizations.

6) Piores práticas
- UDFs Python sem necessidade; `collect()` em produção; gerar small files; não particionar dados adequadamente.

7) Testes e CI
- Unit tests: isolate pure functions; use `SparkSession.builder.master('local[*]')` in pytest fixtures.
- Integration tests: run small datasets in local-mode or via dockerized Spark; use sample datasets and assert counts/aggregations.
- Performance tests: run with representative data sizes in a sandbox cluster and measure shuffle/read/write times.

8) Observability e debugging
- Spark UI, event logs and History Server; tail executor logs for OOM, GC pauses.
- Add checkpoints in streaming and monitor offsets.

9) Segurança
- IAM roles for S3 access, encrypt data at rest and in transit, limit who can submit jobs to cluster.

10) Exemplo de teste unitário (pytest fixture)

```python
import pytest
from pyspark.sql import SparkSession

@pytest.fixture(scope='session')
def spark():
    spark = SparkSession.builder.master('local[2]').appName('pytest').getOrCreate()
    yield spark
    spark.stop()

def test_filter_and_flag(spark):
    df = spark.createDataFrame([(1, 10.0), (2, None)], ['id','value'])
    df2 = df.filter(df.value.isNotNull()).withColumn('flag', (df.value > 5).cast('string'))
    assert df2.count() == 1
```

11) Perguntas de entrevista
- "Como identificar que job está causando OOM?" → olhar GC logs, executor metrics, task memory usage in Spark UI; verificar operations that cause shuffle/aggregation on skewed keys.

---

## Machine Learning (MLOps completo: testes, deploy, monitoramento e governança)

1) Definição curta
- Conjunto de práticas para construir, validar, versionar, deployar e monitorar modelos ML em produção.

2) Por que importa
- Modelos degradam sem monitoramento; decisão errada em produção pode causar prejuízo e riscos legais (viés, privacidade).

3) Internals e componentes
- Data ingestion, feature engineering, training, model registry, deployment, monitoring and feedback loop.

4) Quando usar
- Sempre que um modelo for consumido em escala ou impactar decisões de negócio. Para POC mantenha pipelines leves mas com estratégia para produção.

5) Melhores práticas
- Data validation (Great Expectations) antes do treino e antes da inferência.
- Unit tests for transforms, contract tests for features; integration tests that run training on small dataset.
- Model contract and canary deploys: validate performance vs baseline before promotion.
- Version everything: data, code, features, model artifacts.

6) Piores práticas
- Deploy direto de notebooks; treinar e usar features inconsistentes entre treino e inference; não monitorar performance.

7) Testes e CI
- Unit tests for preprocessing & feature transformations.
- Integration tests: run training pipeline on small dataset, assert model metrics above baseline.
- Regression tests: ensure new model improves or matches baseline on holdout dataset.

8) Observability and monitoring
- Monitor model metrics (AUC, accuracy, business KPIs), input feature distributions, prediction distributions, latency and error rates.
- Implement alerts for drift and degraded metrics; capture explainability output (SHAP) for top incidents.

9) Segurança and governance
- PII protections: hashing/tokenization, access controls on datasets and model artifacts.
- Audit trails: who trained which model with which data and hyperparams.

10) Example: CI pipeline for ML (sketch)

- PR: run unit tests for transforms, lint, run training with small dataset and check metrics.
- Build: create image with model binary and push to registry.
- Deploy: canary to small % of traffic, run A/B comparison for X hours, promote if metrics good.

11) Perguntas de entrevista
- "Como garantir que features entre treino e inference são consistentes?" → Feature store / shared code for transformations / serialized feature schema and tests that compare stats.

---

## Checklists práticos (resumidos)

- GitHub Actions CI:
  - Lint, unit tests, coverage, dependency scan in PR.
  - Integration tests in staging.
  - Build artifacts immutable and signed.
  - OIDC for cloud credentials.

- AWS CI/CD:
  - CodeBuild runs tests and builds artifacts.
  - CodePipeline enforces manual approval for production.
  - CloudWatch alarms + health checks for rollback.

- Docker:
  - Hadolint, Trivy in CI; cosign image signing; non-root runtime, resource limits.

- Terraform:
  - `terraform validate`, fmt, tflint, checkov; plan in PR; apply by pipeline with approvals.

- PySpark:
  - Unit tests local; integration on sample datasets; tune partitions, avoid UDFs.

- ML:
  - Data validation, unit tests for transforms, model registry, canary deploy + monitoring.

---

## Perguntas rápidas para treinar (30–90s respostas)

1. "Explique OIDC com GitHub Actions e AWS." — GitHub Issues a short-lived OIDC token; IAM Role trusts token for repo/branch; workflow assumes role and obtains temporary creds.

2. "Por que evitar UDFs Python no Spark?" — UDFs quebram otimizações Catalyst; são mais lentos e não se beneficiam de whole-stage codegen.

3. "Como detectar data drift?" — Compare distribuições (PSI/KL), track model performance per cohort and set thresholds that trigger retraining pipelines.

4. "Que testes colocar no CI para ML?" — Unit tests for transforms, integration test training pipeline, regression tests vs baseline metrics.

---

Se quiser, implemento agora um dos templates executáveis (A-E) que citamos antes. Recomendo começar por A (pipeline GitHub Actions + OIDC + Terraform minimal + deploy ECS) — digo em seguida as etapas que vou executar se aprovar.

Fim da v3.
