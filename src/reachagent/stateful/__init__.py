"""Stateful API exploration primitives.

The package turns schema/traffic facts into bounded, replayable request plans.
It never writes findings; confirmations remain in the existing oracle seam.
"""

from reachagent.stateful.explorer import (
    DependencyFact,
    IdentifierFact,
    ObservedExchange,
    ObservedRequest,
    RequestTemplate,
    RuntimeBindings,
    SequenceRole,
    StatefulExecution,
    StatefulExplorer,
    StatefulOracleCheck,
    StatefulPlan,
    StatefulPlanError,
    StatefulRunResult,
    StatefulStep,
    StateTransition,
    ValueSelector,
    build_request_templates,
    build_stateful_prompt,
    generate_boundary_values,
    ingest_api_spec,
    ingest_graphql_schema,
    ingest_observed_traffic,
    learn_dependencies,
    validate_stateful_plan,
)

__all__ = [
    "IdentifierFact",
    "DependencyFact",
    "ObservedExchange",
    "ObservedRequest",
    "RequestTemplate",
    "RuntimeBindings",
    "SequenceRole",
    "StatefulExecution",
    "StatefulExplorer",
    "StatefulOracleCheck",
    "StatefulPlan",
    "StatefulPlanError",
    "StatefulRunResult",
    "StatefulStep",
    "StateTransition",
    "ValueSelector",
    "build_request_templates",
    "build_stateful_prompt",
    "generate_boundary_values",
    "ingest_api_spec",
    "ingest_graphql_schema",
    "ingest_observed_traffic",
    "learn_dependencies",
    "validate_stateful_plan",
]
