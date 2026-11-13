# Changelog

All notable changes to byoc-infra-discovery are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] - 2026-11-13

### Added
- Initial release of the BYOC Infrastructure Discovery Agent
- Region, availability zone, AMI, instance-type, and Amazon EKS metadata discovery for any AWS Region, including Regions not enabled in the account
- Account-independent primary sources (SSM global-infrastructure parameters, AWS Price List API) with live read-only calls as enrichment when a Region is enabled
- Two query modes: fact passthrough and readiness investigation
- Deployability verdict (`ready` / `degraded` / `blocked`) with blockers and confidence computed in code, not by the model
- Strands agent on Amazon Bedrock (Claude Sonnet 4.5 inference profile by default) that gathers facts and narrates results
- Data-retrieval tools: `resolve_regions`, `resolve_availability_zones`, `resolve_service_availability`, `resolve_instance_types`, `resolve_instance_offerings`, `resolve_amis`, `lookup_curated_data`
- Compute tools: `count_azs`, `filter_instance_types`, `compute_deployability`, `format_response`
- Resilient live calls with fast-fail timeouts and graceful fallback for unreachable or SCP-blocked regional endpoints
- Curated datasets with `_source` and `_last_updated` provenance: EKS add-on ECR registries, ENI max pods, S3 location constraints, EKS end-of-support dates
- Two-tier cache (in-memory + `/tmp`) with configurable TTL
- Environment-variable configuration with no hardcoded values
- AWS CDK stack: Lambda, read-only execution role, Amazon Bedrock Guardrail (content filters), structured log group, X-Ray tracing, CloudWatch alarms for error rate and P99 latency
- Reference read-only IAM policy in `infra/policies/execution-role-policy.json`
- Unit and integration tests with mocked AWS clients (86 tests)
- Documentation: README, SECURITY.md with STRIDE threat model, scope and limitations
