# Guia Aprofundado para Entrevista Sênior — CI/CD, AWS, Docker, Terraform, PySpark e Machine Learning

Este guia foi reorganizado e expandido para ser didático e completo: cada tema começa com definições básicas, passa por conceitos internos, apresenta padrões arquiteturais, exemplos práticos (com comandos), práticas recomendadas e armadilhas comuns. Ao final de cada seção há perguntas de entrevista e respostas-síntese.

Use este arquivo como material de estudo longo prazo. Se quiser, eu crio exercícios práticos e repositórios de exemplo para cada seção.

---

## Como este arquivo está organizado

- Para cada tecnologia: Definição curta → Por que importa → Conceitos e internals → Quando usar / quando não usar → Padrões e arquiteturas comuns → Exemplo prático (com comandos) → Operações e debugging → Segurança e custos → Melhores e piores práticas → Perguntas de entrevista com respostas curtas.

---

## 1) CI/CD com GitHub Actions

Definição
- GitHub Actions é um sistema de automação nativo do GitHub que executa pipelines (workflows) descritos em arquivos YAML. Um workflow reage a eventos (push, pull_request, schedule, manual) e é executado por runners (hosted ou self-hosted).

Por que importa
- Automatiza build, teste e deploy; integra-se nativamente com GitHub (PRs, checks, secrets) e permite implementar políticas de qualidade e segurança desde o PR.

Conceitos e internals
- Workflow: arquivo YAML com triggers, jobs e steps.
- Jobs: unidades paralelizáveis que executam em runners isolados.
- Steps: comandos ou actions que compõem um job; compartilham workspace local do runner.
- Runner: ambiente (VM/container) que executa steps. Hosted runners são gerenciados pelo GitHub; self-hosted são mantidos por você.
- Matrix: executa variações (ex.: várias versões de Python) em paralelo.

Quando usar / quando não usar
- Use: projetos com repositório no GitHub, necessidade de integração com PRs e checks, automações multi-cloud.
- Não use (ou use com cautela): quando políticas de compliance proíbem runners externos (use self-hosted em rede privada) ou para tarefas com requisitos de hardware muito específicos (prefira runners com GPU dedicados).

Padrões e estratégias
- Build once, deploy many: gerar artefato único e reutilizá-lo entre ambientes (staging/prod).
- PR checks (CI) vs gated deploys (CD): separar responsabilidades.
- OIDC / short-lived credentials: evite secrets de longa duração usando OIDC para trocar por credenciais cloud temporárias.

Exemplo prático completo (com explicação passo a passo)

- Objetivo: rodar testes em PR, buildar imagem ao push na main e fazer deploy para ECS usando OIDC.

Workflow (resumo):

```yaml
name: CI-CD
on:
  pull_request:
  push:
    branches: [ main ]

permissions:
  contents: read
  id-token: write

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.10' }
      - run: pip install -r requirements.txt
      - run: pytest -q

  build-and-push:
    if: github.ref == 'refs/heads/main'
    needs: ci
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS creds via OIDC
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::ACCOUNT_ID:role/github-ci-role
          aws-region: us-east-1
      - name: Build and push
        run: |
          docker build -t repo/app:${{ github.sha }} .
          aws ecr get-login-password | docker login --username AWS --password-stdin $ECR
          docker tag repo/app:${{ github.sha }} $ECR/repo/app:${{ github.sha }}
          docker push $ECR/repo/app:${{ github.sha }}
```

Operações e debugging
- Logs: GitHub exibe logs por step. Para debugging, adicione steps que capturem artefatos e variáveis de ambiente (cuidado com secrets).
- Re-execute jobs, use `ACTIONS_RUNNER_DEBUG` para logs ampliados quando necessário.

Segurança e custos
- Minimizar `permissions:` no workflow; usar GitHub Secrets para segredos pequenos e OIDC para credenciais cloud.
- Self-hosted runners reduzem custos por execução em larga escala, mas aumentam custo operacional e requerem hardening (CIS, controle de rede).

Melhores práticas (resumo rápido)
- Cache de dependências, build-only-once, testes rápidos em PR, integração de scanners de segurança no pipeline, controle de permissões.

Erros comuns a evitar
- Colocar chaves em texto puro; rodar deploy diretamente em branches sem revisão; usar `latest` como tag de imagem.

Perguntas de entrevista (exemplos)
- "Explique OIDC entre GitHub Actions e AWS." → GitHub fornece um token OIDC; configure trust policy na Role; workflow troca token por creds temporários para assumir role.
- "Como reduzir tempo de CI?" → dividir testes por tipo, usar selection tests, cache e paralelização (matrix/xdist).

---

## 2) CI/CD na AWS (CodePipeline, CodeBuild, CodeDeploy, ECR, ECS, EKS)

Definição
- Serviços AWS usados para construir pipelines nativos: CodePipeline (orquestração), CodeBuild (build), CodeDeploy (deploy). ECR é o registry para imagens; ECS/EKS executam containers.

Por que importa
- Integração profunda com IAM, CloudWatch, CloudFormation e outros serviços AWS; útil para times que desejam manter tudo dentro da conta AWS por compliance ou simplicidade operacional.

Conceitos e internals
- CodeBuild: roda jobs dentro de containers; usa `buildspec.yml` para fases (install, pre_build, build, post_build).
- CodePipeline: liga estágios de source → build → deploy e suporta actions e approval gates.
- CodeDeploy: executa estratégias (in-place, blue/green) para EC2, ECS e Lambda.

Quando usar / quando não usar
- Use: se infra estiver majoritariamente em AWS e você precisa de integração nativa com serviços AWS.
- Não use: quando deseja multi-cloud/CI centralizado (GitHub Actions pode ser melhor).

Padrões e estratégias
- Blue/Green com ALB para ECS: provisionar nova task definition e novo target group; trocar tráfego com validações.
- Canary deploys para alterar percentual de tráfego gradualmente.

Exemplo prático — buildspec minimal

```yaml
version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
  build:
    commands:
      - docker build -t my-app:$CODEBUILD_RESOLVED_SOURCE_VERSION .
      - docker tag my-app:$CODEBUILD_RESOLVED_SOURCE_VERSION $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/my-app:$CODEBUILD_RESOLVED_SOURCE_VERSION
  post_build:
    commands:
      - docker push $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/my-app:$CODEBUILD_RESOLVED_SOURCE_VERSION
      - printf '[{"name":"my-app","imageUri":"%s"}]' $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/my-app:$CODEBUILD_RESOLVED_SOURCE_VERSION > imagedefinitions.json
artifacts:
  files:
    - imagedefinitions.json
```

Operações e troubleshooting
- Ver logs do CodeBuild (CloudWatch Logs). Para deploys em ECS, verifique events do service, e logs do container (CloudWatch/Fluentd).
- Para problemas de networking, verifique security groups, IAM policies e permissões de role.

Segurança
- Separe roles: deploy role não precisa de permissões de escrita em source code; use KMS para criptografia de artifacts.

Melhores práticas e armadilhas
- Não usar tags mutáveis (ex.: `latest`) em produção; use digests ou SHA tags. Habilitar scans de imagem e criação de políticas para rejeitar imagens com CVEs críticos.

Perguntas de entrevista (exemplos)
- "Como faria rollback automático em ECS?" → Use blue/green + CloudWatch alarms + CodeDeploy hooks para reverter o tráfego se health checks falharem.

---

## 3) Docker & Dockerfile

Definição
- Docker é uma plataforma para empacotar aplicações e dependências em imagens portáveis. Um Dockerfile descreve passos para construir essa imagem.

Por que importa
- Consistência entre ambientes (dev, staging, prod), isolamento de dependências e facilidade de deployment.

Conceitos e internals
- Camadas: cada instrução no Dockerfile cria uma camada; camadas são cacheadas e read-only.
- Union filesystem: camadas sobrepostas formam o sistema de arquivos final do container.
- Build cache: rede de caches por instrução acelera builds repetidos.

Quando usar / quando não usar
- Use: microservices, reproducible builds, ambientes isolados.
- Evite: scripts simples que não precisam de isolamento ou quando PaaS simplifica deploy sem containers.

Padrões arquiteturais
- Multi-stage builds: separar etapas de build de runtime para imagens menores.
- Distroless/scratch runtime images para reduzir superfície de segurança.

Exemplo prático (multi-stage Python + explicação)

```dockerfile
FROM python:3.10-slim AS builder
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install --upgrade pip && pip install poetry && poetry config virtualenvs.create false && poetry install --no-dev
COPY . .
RUN python -m build -w dist/

FROM python:3.10-slim AS runtime
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /app /app
USER 1000
EXPOSE 8000
CMD ["gunicorn", "app.main:app", "-w", "2", "-b", "0.0.0.0:8000"]
```

Operações e debugging
- `docker history` mostra camadas da imagem.
- `docker inspect` e `docker logs` para debugging em containers locais.

Segurança e custos
- Scanner (Trivy) integrado ao CI. Assinatura de imagens com `cosign` para garantir procedência.

Melhores práticas e anti-padrões
- Não inclua secrets em build args; prefira runtime secrets manager. Evite `apt-get upgrade` no Dockerfile em produção.

Perguntas de entrevista
- "Como reduzir tamanho de imagem?" → multi-stage, remover caches, usar distroless, minimizar dependências.

---

## 4) Terraform

Definição
- Terraform é uma ferramenta declarativa de infraestrutura como código (IaC) que gerencia recursos via providers (AWS, GCP, Azure, etc.).

Por que importa
- Reproducibilidade e versionamento de infra, colaboração entre equipes e automação de criação/alteração de recursos.

Conceitos e internals
- Configuration: arquivos .tf com recursos e módulos.
- State: arquivo que mapeia recursos declarados para IDs reais no provedor.
- Provider: plugin que implementa CRUD para recursos.

Quando usar / quando não usar
- Use para infra que precisa ser versionada, reproduzível e auditável. Evite para perubahan temporárias rápidas sem controle de versão (scripts ad-hoc podem ser suficientes, mas registre mudanças depois).

Arquiteturas e patterns
- Módulos reutilizáveis, backends remotos com locking (S3 + DynamoDB na AWS), CI que executa `terraform plan` em PRs.

Exemplo prático (backend S3)

```hcl
terraform {
  backend "s3" {
    bucket = "my-tfstate-bucket"
    key    = "envs/prod/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table = "tf-lock"
  }
}
```

Operações e debugging
- `terraform plan` para visualizar mudanças; `terraform apply -auto-approve` para aplicar. Use `terraform state` para manipular estado quando necessário (com cautela).

Segurança
- Criptografar state e restringir acesso via IAM. Evitar armazenar secrets no state (use Secrets Manager ou SSM Parameter Store e referencie via data sources com acesso controlado).

Melhores práticas e erros comuns
- Validar e formatar com `terraform fmt` e `terraform validate`. Não editar state manualmente sem backups.

Perguntas de entrevista
- "Como organizar infra para múltiplas equipes?" → separar state por domínio/produto, usar módulos e políticas (OPA/Sentinel) para governança.

---

## 5) PySpark — explicação detalhada e prática

Definição
- Apache Spark é um engine distribuído para processamento de dados (batch e streaming). PySpark é a API Python para Spark, focada em DataFrames, SQL e Structured Streaming.

Por que importa
- Permite processar TBs-PBs de dados distribuídos com abstrações de alto nível e otimizações internas (Catalyst, Tungsten).

Conceitos e internals (explicados para quem está começando)
- Transformações vs Ações: Transformações (map, filter, select) constroem um plano lógico; ações (count, collect, write) executam o plano.
- DAG: Directed Acyclic Graph de operações; o planner gera este DAG e o executor o executa em tasks.
- Partições: unidade de paralelismo. Cada partition é processada por uma task.
- Shuffle: redistribuição de dados entre executors (quando faz joins, groupBy, repartition).

Quando usar / quando não usar
- Use: ETL em larga escala, joins e agregações distribuídas, processamento de streaming tolerante a falhas.
- Evite: datasets pequenos que cabem em memória de uma única máquina (uso desnecessário de cluster e complexidade).

Padrões e estratégias comuns
- Broadcast join para pequenas tabelas.
- Repartition por chave que será usada em joins subsequentes.
- Cache/persist apenas quando dados serão reutilizados múltiplas vezes.

Exemplo introdutório com explicação passo-a-passo

```python
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when

spark = SparkSession.builder.master('local[*]').appName('example').getOrCreate()

# Leitura com schema explícito (mais rápido que inferir)
schema = 'id INT, ts TIMESTAMP, user_id STRING, value DOUBLE'
df = spark.read.schema(schema).parquet('./data/raw/')

# Transformações (lazy)
df2 = df.filter(col('value').isNotNull()).withColumn('flag', when(col('value')>100, 'high').otherwise('low'))

# Ação: gravar em parquet particionado
df2.repartition('date').write.mode('overwrite').partitionBy('date').parquet('./data/processed/')
```

Operações, tuning e debugging
- Spark UI (porta 4040 para local, History Server para clusters) mostra DAG, stages e tasks.
- Ajustes chave: `spark.sql.shuffle.partitions`, `executor.memory`, `executor.cores`, `spark.serializer=KryoSerializer`.
- Evitar UDFs Python quando possível; UDFs quebram otimizações do Catalyst.

Segurança e custos
- Em cloud, leia/escreva com permissões mínimos (IAM roles). Evite manter dados sensíveis em plain-parquet sem criptografia.

Melhores práticas e armadilhas
- Evitar small files: agrupe e reescreva arquivos pequenos; particione por colunas amplamente utilizadas.
- Use AQE (Adaptive Query Execution) em Spark 3.x para otimizações dinâmicas.

Perguntas de entrevista (exemplos)
- "Por que Kryo?" → Serialização eficiente e mais rápida que Java serializer; reduz overhead em shuffle.
- "O que é AQE?" → Ajustes dinâmicos do plano de execução em runtime (repartition coalesce, mudar join strategy).

---

## 6) Machine Learning — engenharia e produção

Definição
- Machine Learning (ML) é o campo da IA que cria modelos capazes de fazer previsões a partir de dados. MLOps aplica práticas de engenharia de software e DevOps ao ciclo de vida de modelos ML.

Por que importa
- Modelos em produção impactam negócios; controlar reprodutibilidade, monitoramento e governança é essencial para evitar regressões e viés.

Conceitos e internals
- Feature Store: armazenamento organizado de features para treino e inferência com consistência.
- Model Registry: versionamento de modelos (MLflow, etc) com estágios e metadados.
- Drift detection: técnicas para detectar mudanças estatísticas nas entradas ou saídas do modelo.

Quando usar / quando não usar
- Use: problemas com volume de dados, necessidade de automação de previsões e feedback loop.
- Evite: prototypes ad-hoc para POC sem pipeline de produção; sempre planeje transição para produção com testes.

Padrões; deployment e serving
- Online serving: REST/gRPC endpoints; cuidadosa com latência e escala.
- Batch scoring: quando latência não é crítica, processe em lote eficiente.
- Canary/A-B testing: deploy incremental e comparação estatística.

Exemplo prático simples (training + MLflow)

```python
import mlflow
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.datasets import load_breast_cancer

X, y = load_breast_cancer(return_X_y=True)
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

with mlflow.start_run():
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(X_train, y_train)
    acc = clf.score(X_val, y_val)
    mlflow.log_metric('val_acc', acc)
    mlflow.sklearn.log_model(clf, 'model')
```

Operações e monitoramento
- Monitore latência, throughput, taxas de erro, e distribuição das features e das predições. Integre com Prometheus/Grafana e logs para troubleshooting.

Segurança e fairness
- Remova/anonimize PII; teste fairness antes de promover modelos para produção; mantenha auditoria de features e dados de treino.

Melhores práticas e armadilhas
- Tenha testes automatizados para transforms, smoke tests para modelo em staging e monitoramento ativo para drift.

Perguntas de entrevista
- "Como detectar data drift?" → Compare distribuições (PSI/KL), monitore performance por cohort, alimente pipeline de retraining quando thresholds excedidos.

---

## Dicas finais e plano de estudo

- Estudo dirigido: intercale teoria com hands-on; construa mini-projetos (um pipeline CI/CD com deploy, um job PySpark local e um modelo ML com tracking).
- Pratique respostas curtas (30–90s) e detalhadas (5–10 min) para cada pergunta técnica.

Se quiser, começo implementando o template A (GitHub Actions + OIDC -> AWS + Terraform minimal + ECS deploy) e escrevo um README com passos para rodar localmente e validações básicas.

---

Arquivo gerado: `interview_senior_tech_guide_v2.md`
